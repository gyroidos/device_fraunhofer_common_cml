/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#define _GNU_SOURCE

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "uevent.h"
#include <arpa/inet.h>
#include <sched.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <grp.h>

#include "cmld.h"
#include "container.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/network.h"
#include "common/nl.h"
#include "common/proc.h"
#include "common/str.h"

#ifndef UEVENT_SEND
#define UEVENT_SEND 16
#endif

static nl_sock_t *uevent_netlink_sock = NULL;
static event_io_t *uevent_io_event = NULL;

// registerd uev events
static list_t *uevent_uev_kernel_list = NULL;
static list_t *uevent_uev_udev_list = NULL;

// track usb devices mapped to containers
static list_t *uevent_container_dev_mapping_list = NULL;
//
// track net devices mapped to containers
static list_t *uevent_container_netdev_mapping_list = NULL;

#define UDEV_MONITOR_TAG "libudev"
#define UDEV_MONITOR_MAGIC 0xfeedcafe

struct uevent_uev {
	uevent_uev_type_t type;
	unsigned actions;
	void (*func)(unsigned actions, uevent_event_t *event, void *data);
	void *data;
};

struct uevent_usbdev {
	char *i_serial;
	uint16_t id_vendor;
	uint16_t id_product;
	int major;
	int minor;
	bool assign;
	uevent_usbdev_type_t type;
};

uevent_usbdev_t *
uevent_usbdev_new(uevent_usbdev_type_t type, uint16_t id_vendor, uint16_t id_product,
		  char *i_serial, bool assign)
{
	uevent_usbdev_t *usbdev = mem_new0(uevent_usbdev_t, 1);
	usbdev->type = type;
	usbdev->id_vendor = id_vendor;
	usbdev->id_product = id_product;
	usbdev->i_serial = mem_strdup(i_serial);
	usbdev->assign = assign;
	usbdev->major = -1;
	usbdev->minor = -1;
	// usbdev->devpath = NULL;
	return usbdev;
}

struct udev_monitor_netlink_header {
	/* "libudev" prefix to distinguish libudev and kernel messages */
	char prefix[8];
	/*
         * magic to protect against daemon <-> library message format mismatch
         * used in the kernel from socket filter rules; needs to be stored in network order
         */
	unsigned int magic;
	/* total length of header structure known to the sender */
	unsigned int header_size;
	/* properties string buffer */
	unsigned int properties_off;
	unsigned int properties_len;
	/*
         * hashes of primary device properties strings, to let libudev subscribers
         * use in-kernel socket filters; values need to be stored in network order
         */
	unsigned int filter_subsystem_hash;
	unsigned int filter_devtype_hash;
	unsigned int filter_tag_bloom_hi;
	unsigned int filter_tag_bloom_lo;
};

struct uevent_event {
	union {
		struct udev_monitor_netlink_header nlh;
		char raw[UEVENT_BUF_LEN]; //!< The raw string that we get from the kernel
	} msg;
	size_t msg_len;	       //!< The length of the uevent
	char *action;	       //!< The uevent ACTION, points inside of raw
	char *subsystem;       //!< The uevent SUBSYSTEM, points inside of raw
	char *devname;	       //!< The uevent DEVNAME, points inside of raw
	char *devpath;	       //!< The uevent DEVPATH, points inside of raw
	char *devtype;	       //!< The uevent DEVTYPE, points inside of raw
	char *driver;	       //!< The uevent DRIVER, points inside of raw
	int major;	       //!< The major number of the device
	int minor;	       //!< The minor number of the device
	char *type;	       //!< The uevent TYPE, points inside of raw
	char *product;	       //!< The uevent PRODUCT, points inside of raw (usb relevant)
	uint16_t id_vendor_id; //!< The udev event ID_VENDOR_ID inside of raw (usb relevenat)
	uint16_t id_model_id;  //!< The udev event ID_MODEL_ID of the device (usb relevant)
	char *id_serial_short; //!< The udev event ID_SERIAL_SHORT of the device (usb relevant)
	char *interface;       //!< The uevent INTERFACE, points inside of raw
	char *synth_uuid;      //!< The uevent SYNTH_UUID, points inside of raw (coldboot relevant)
};

typedef struct uevent_container_dev_mapping {
	container_t *container;
	uevent_usbdev_t *usbdev;
	bool assign;
} uevent_container_dev_mapping_t;

typedef struct uevent_net_dev_mapping {
	container_t *container;
	container_pnet_cfg_t *pnet_cfg;
	uint8_t mac[6];
} uevent_container_netdev_mapping_t;

uint16_t
uevent_usbdev_get_id_vendor(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->id_vendor;
}

uint16_t
uevent_usbdev_get_id_product(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->id_product;
}

uevent_usbdev_type_t
uevent_usbdev_get_type(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->type;
}

char *
uevent_usbdev_get_i_serial(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->i_serial;
}

bool
uevent_usbdev_is_assigned(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->assign;
}

void
uevent_usbdev_set_major(uevent_usbdev_t *usbdev, int major)
{
	ASSERT(usbdev);
	usbdev->major = major;
}

void
uevent_usbdev_set_minor(uevent_usbdev_t *usbdev, int minor)
{
	ASSERT(usbdev);
	usbdev->minor = minor;
}

int
uevent_usbedv_get_major(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->major;
}

int
uevent_usbdev_get_minor(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->minor;
}

static uevent_container_dev_mapping_t *
uevent_container_dev_mapping_new(container_t *container, uevent_usbdev_t *usbdev)
{
	uevent_container_dev_mapping_t *mapping = mem_new0(uevent_container_dev_mapping_t, 1);
	mapping->container = container;
	mapping->usbdev = mem_new0(uevent_usbdev_t, 1);
	mapping->usbdev->i_serial = mem_strdup(usbdev->i_serial);
	mapping->usbdev->id_vendor = usbdev->id_vendor;
	mapping->usbdev->id_product = usbdev->id_product;
	mapping->usbdev->major = usbdev->major;
	mapping->usbdev->minor = usbdev->minor;
	mapping->usbdev->assign = usbdev->assign;
	mapping->usbdev->type = usbdev->type;

	return mapping;
}

static void
uevent_container_dev_mapping_free(uevent_container_dev_mapping_t *mapping)
{
	if (mapping->usbdev) {
		if (mapping->usbdev->i_serial)
			mem_free0(mapping->usbdev->i_serial);
		mem_free0(mapping->usbdev);
	}
	mem_free0(mapping);
}

static void
uevent_container_netdev_mapping_free(uevent_container_netdev_mapping_t *mapping)
{
	mem_free0(mapping);
}

static uevent_container_netdev_mapping_t *
uevent_container_netdev_mapping_new(container_t *container, container_pnet_cfg_t *pnet_cfg)
{
	uevent_container_netdev_mapping_t *mapping = mem_new0(uevent_container_netdev_mapping_t, 1);
	mapping->container = container;
	mapping->pnet_cfg = pnet_cfg;

	// We only accept mac strings in pnet config for mappings
	if (-1 == network_str_to_mac_addr(pnet_cfg->pnet_name, mapping->mac)) {
		uevent_container_netdev_mapping_free(mapping);
		return NULL;
	}

	return mapping;
}

static void
uevent_trace(uevent_event_t *uevent, char *raw_p)
{
	int i = 0;
	char *_raw_p = raw_p;
	while (*_raw_p || _raw_p < uevent->msg.raw + uevent->msg_len) {
		TRACE("uevent_raw[%d] '%s'", i++, _raw_p);
		/* advance to after the next \0 */
		while (*_raw_p++)
			;
	}
}

static void
uevent_parse(uevent_event_t *uevent, char *raw_p)
{
	ASSERT(uevent);

	uevent->action = "";
	uevent->devpath = "";
	uevent->devname = "";
	uevent->devtype = "";
	uevent->major = -1;
	uevent->minor = -1;
	uevent->devname = "";
	uevent->subsystem = "";
	uevent->product = "";
	uevent->id_model_id = 0;
	uevent->id_vendor_id = 0;
	uevent->id_serial_short = "";
	uevent->interface = "";
	uevent->synth_uuid = "";

	uevent_trace(uevent, raw_p);

	/* Parse the uevent->raw buffer and set the pointer in the uevent
	 * struct to point into the buffer at the correct locations */
	// TODO check if running out of the buffer
	while (*raw_p) {
		if (!strncmp(raw_p, "ACTION=", 7)) {
			raw_p += 7;
			uevent->action = raw_p;
		} else if (!strncmp(raw_p, "DEVPATH=", 8)) {
			raw_p += 8;
			uevent->devpath = raw_p;
		} else if (!strncmp(raw_p, "SUBSYSTEM=", 10)) {
			raw_p += 10;
			uevent->subsystem = raw_p;
		} else if (!strncmp(raw_p, "MAJOR=", 6)) {
			raw_p += 6;
			uevent->major = atoi(raw_p);
		} else if (!strncmp(raw_p, "MINOR=", 6)) {
			raw_p += 6;
			uevent->minor = atoi(raw_p);
		} else if (!strncmp(raw_p, "DEVNAME=", 8)) {
			raw_p += 8;
			uevent->devname = raw_p;
		} else if (!strncmp(raw_p, "DEVTYPE=", 8)) {
			raw_p += 8;
			uevent->devtype = raw_p;
		} else if (!strncmp(raw_p, "DRIVER=", 7)) {
			raw_p += 7;
			uevent->driver = raw_p;
		} else if (!strncmp(raw_p, "PRODUCT=", 8)) {
			raw_p += 8;
			uevent->product = raw_p;
		} else if (!strncmp(raw_p, "ID_VENDOR_ID=", 13)) {
			raw_p += 13;
			sscanf(raw_p, "%hx", &uevent->id_vendor_id);
		} else if (!strncmp(raw_p, "ID_MODEL_ID=", 12)) {
			raw_p += 12;
			sscanf(raw_p, "%hx", &uevent->id_model_id);
		} else if (!strncmp(raw_p, "ID_SERIAL_SHORT=", 16)) {
			raw_p += 16;
			uevent->id_serial_short = raw_p;
		} else if (!strncmp(raw_p, "INTERFACE=", 10)) {
			raw_p += 10;
			uevent->interface = raw_p;
		} else if (!strncmp(raw_p, "SYNTH_UUID=", 11)) {
			raw_p += 11;
			uevent->synth_uuid = raw_p;
		}

		/* advance to after the next \0 */
		while (*raw_p++)
			;

		/* check if message ended */
		if (raw_p >= uevent->msg.raw + uevent->msg_len)
			break;
	}

	TRACE("uevent { '%s', '%s', '%s', '%s', %d, %d, '%s'}", uevent->action, uevent->devpath,
	      uevent->subsystem, uevent->devname, uevent->major, uevent->minor, uevent->interface);
}

static uevent_event_t *
uevent_replace_member(const uevent_event_t *uevent, char *oldmember, char *newmember)
{
	ASSERT(uevent);
	ASSERT(oldmember > uevent->msg.raw && oldmember < uevent->msg.raw + uevent->msg_len);

	uevent_event_t *newevent = mem_new(uevent_event_t, 1);
	//interface name is located in name and devpath members
	int diff_len = strlen(newmember) - strlen(oldmember);

	newevent->msg_len = uevent->msg_len + diff_len;

	//copy netlink header to cloned uevent
	if (!memcpy(&newevent->msg.nlh, &uevent->msg.nlh,
		    sizeof(struct udev_monitor_netlink_header))) {
		ERROR("Failed to clone netlink header");
		goto error;
	}
	newevent->msg.nlh.properties_len = uevent->msg.nlh.properties_len + diff_len;

	//copy uevent up to position of interface string
	int off_member = oldmember - uevent->msg.raw;
	if (!memcpy(newevent->msg.raw, uevent->msg.raw, off_member)) {
		ERROR("Failed to copy beginning of uevent");
		goto error;
	}

	//copy new member to uevent
	if (!strcpy(newevent->msg.raw + off_member, newmember)) {
		ERROR("Failed to new member to uevent");
		goto error;
	}

	//copy uevent after interface string
	size_t off_after_old = off_member + strlen(oldmember) + 1;
	size_t off_after_new = off_member + strlen(newmember) + 1;

	if (!memcpy(newevent->msg.raw + off_after_new, uevent->msg.raw + off_after_old,
		    uevent->msg_len - off_after_old)) {
		ERROR("Failed to copy remainder of uevent");
		goto error;
	}

	uevent_parse(newevent, newevent->msg.raw);

	return newevent;

error:
	if (newevent)
		mem_free0(newevent);

	return NULL;
}

static char *
uevent_replace_devpath_new(const char *str, const char *oldstr, const char *newstr)
{
	char *ptr_old = NULL;
	int len_diff = strlen(newstr) - strlen(oldstr);

	if (!(ptr_old = strstr(str, oldstr))) {
		DEBUG("Could not find %s in %s", oldstr, str);
		return NULL;
	}

	unsigned int off_old;
	char *str_replaced = mem_alloc0((strlen(str) + 1) + len_diff);
	unsigned int pos_new = 0;

	off_old = ptr_old - str;

	strncpy(str_replaced, str, off_old);
	pos_new += off_old;

	strcpy(str_replaced + pos_new, newstr);
	pos_new += strlen(newstr);

	strcpy(str_replaced + pos_new, ptr_old + strlen(oldstr));

	return str_replaced;
}

char *
uevent_rename_ifi_new(const char *oldname, const char *infix)
{
	static unsigned int cmld_wlan_idx = 0;
	static unsigned int cmld_eth_idx = 0;

	//generate interface name that is unique
	//in the root network namespace
	unsigned int *ifi_idx;
	char *newname = NULL;

	ifi_idx = !strcmp(infix, "wlan") ? &cmld_wlan_idx : &cmld_eth_idx;

	if (-1 == asprintf(&newname, "%s%s%d", "cml", infix, *ifi_idx)) {
		ERROR("Failed to generate new interface name");
		return NULL;
	}

	*ifi_idx += 1;

	INFO("Renaming %s to %s", oldname, newname);

	if (network_rename_ifi(oldname, newname)) {
		ERROR("Failed to rename interface %s", oldname);
		mem_free0(newname);
		return NULL;
	}

	return newname;
}

static uevent_event_t *
uevent_rename_interface(const uevent_event_t *uevent)
{
	char *new_ifname = uevent_rename_ifi_new(uevent->interface, uevent->devtype);

	IF_NULL_RETVAL(new_ifname, NULL);

	// replace ifname in cmld's available netifs
	if (cmld_netif_phys_remove_by_name(uevent->interface))
		cmld_netif_phys_add_by_name(new_ifname);

	char *new_devpath =
		uevent_replace_devpath_new(uevent->devpath, uevent->interface, new_ifname);

	if (!(new_ifname && new_devpath)) {
		DEBUG("Failed to prepare renamed uevent members");
		return NULL;
	}

	uevent_event_t *uev_chname = uevent_replace_member(uevent, uevent->interface, new_ifname);

	if (!uev_chname) {
		ERROR("Failed to rename interface name %s in uevent", uevent->interface);
		return NULL;
	}
	DEBUG("Injected renamed interface name %s into uevent", new_ifname);
	uevent_parse(uev_chname, uev_chname->msg.raw);

	uevent_event_t *uev_chdevpath = uevent_replace_member(uevent, uevent->devpath, new_devpath);

	if (!uev_chdevpath) {
		ERROR("Failed to rename devpath %s in uevent", uevent->devpath);
		mem_free0(uev_chname);
		return NULL;
	}
	DEBUG("Injected renamed devpath %s into uevent", new_ifname);
	uevent_parse(uev_chdevpath, uev_chdevpath->msg.raw);

	return uev_chname;
}

static uint16_t
uevent_get_usb_vendor(uevent_event_t *uevent)
{
	if (uevent->id_vendor_id != 0)
		return (uint16_t)uevent->id_vendor_id;
	uint16_t id_vendor = 0;
	uint16_t id_product = 0;
	uint16_t version = 0;
	sscanf(uevent->product, "%hx/%hx/%hx", &id_vendor, &id_product, &version);

	return id_vendor;
}

static uint16_t
uevent_get_usb_product(uevent_event_t *uevent)
{
	if (uevent->id_model_id != 0)
		return (uint16_t)uevent->id_model_id;

	uint16_t id_vendor = 0;
	uint16_t id_product = 0;
	uint16_t version = 0;
	sscanf(uevent->product, "%hx/%hx/%hx", &id_vendor, &id_product, &version);

	return id_product;
}

char *
uevent_event_get_synth_uuid(uevent_event_t *event)
{
	ASSERT(event);
	return event->synth_uuid;
}

char *
uevent_event_get_devname(uevent_event_t *event)
{
	ASSERT(event);
	return event->devname;
}

char *
uevent_event_get_devtype(uevent_event_t *event)
{
	ASSERT(event);
	return event->devtype;
}

int
uevent_event_get_minor(uevent_event_t *event)
{
	ASSERT(event);
	return event->minor;
}

int
uevent_event_get_major(uevent_event_t *event)
{
	ASSERT(event);
	return event->major;
}

uevent_event_t *
uevent_event_replace_synth_uuid_new(uevent_event_t *event, char *uuid_string)
{
	ASSERT(event);
	uevent_event_t *event_new = uevent_replace_member(event, event->synth_uuid, uuid_string);
	return event_new;
}


/**
 * This function forks a new child in the target netns (and userns) of netns_pid
 * in which the uevents should be injected. In the child the UEVENT netlink socket
 * is connected and a new message containing the raw uevent will be created and
 * sent to that socket.
 */
int
uevent_event_inject_into_netns(uevent_event_t *event, pid_t netns_pid, bool join_userns)
{
	int status;
	char *uevent = event->msg.raw;
	size_t size = event->msg_len;

	pid_t pid = fork();

	if (pid == -1) {
		ERROR_ERRNO("Could not fork for switching to netns of %d", netns_pid);
		return -1;
	} else if (pid == 0) {
		if (join_userns) {
			char *usrns = mem_printf("/proc/%d/ns/user", netns_pid);
			int usrns_fd = open(usrns, O_RDONLY);
			if (usrns_fd == -1)
				FATAL_ERRNO("Could not open userns file %s!", usrns);
			mem_free0(usrns);
			if (setns(usrns_fd, CLONE_NEWUSER) == -1)
				FATAL_ERRNO("Could not join uesr namespace of pid %d!", netns_pid);
			if (setuid(0) < 0)
				FATAL_ERRNO("Could setuid to root in user namespace of pid %d!",
					    netns_pid);
			if (setgid(0) < 0)
				FATAL_ERRNO("Could setgid to root in user namespace of pid %d!",
					    netns_pid);
			if (setgroups(0, NULL) < 0)
				FATAL_ERRNO("Could setgroups to root in user namespace of pid %d!",
					    netns_pid);
			//INFO("joined userns");
		}
		char *netns = mem_printf("/proc/%d/ns/net", netns_pid);
		int netns_fd = open(netns, O_RDONLY);
		if (netns_fd == -1)
			FATAL_ERRNO("Could not open netns file %s!", netns);
		mem_free0(netns);
		if (setns(netns_fd, CLONE_NEWNET) == -1)
			FATAL_ERRNO("Could not join network namespace of pid %d!", netns_pid);
		nl_sock_t *target = nl_sock_uevent_new(0);
		if (NULL == target)
			FATAL("Could not connect to nl socket!");
		nl_msg_t *nl_msg = nl_msg_new();
		if (NULL == nl_msg)
			FATAL_ERRNO("Could not allocate nl_msg!");
		if (nl_msg_set_type(nl_msg, UEVENT_SEND) < 0)
			FATAL("Could not set type UEVENT_SEND of nl_msg!");
		if (nl_msg_set_flags(nl_msg, NLM_F_ACK | NLM_F_REQUEST))
			FATAL("Could not set flages for acked request of nl_msg!");
		if (nl_msg_set_buf_unaligned(nl_msg, uevent, size) < 0)
			FATAL_ERRNO("Could not add uevent to nl_msg!");
		if (nl_msg_send_kernel(target, nl_msg) < 0)
			FATAL_ERRNO("Could not inject uevent!");
		if (nl_msg_receive_and_check_kernel(target))
			FATAL_ERRNO("Could not verify resp to injected uevent!");
		nl_sock_free(target);
		nl_msg_free(nl_msg);
		_exit(0);
	} else {
		if (waitpid(pid, &status, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for '%d'", pid);
		} else if (!WIFEXITED(status)) {
			ERROR("Child %d in netns_pid '%d' terminated abnormally", pid, netns_pid);
		} else {
			return WEXITSTATUS(status) ? -1 : 0;
		}
	}
	return -1;
}

static int
uevent_netdev_move(uevent_event_t *uevent)
{
	uint8_t iface_mac[6];
	char *macstr = NULL;

	if (network_get_mac_by_ifname(uevent->interface, iface_mac)) {
		ERROR("Iface '%s' with no mac, skipping!", uevent->interface);
		goto error;
	}

	container_t *container = NULL;
	container_pnet_cfg_t *pnet_cfg = NULL;
	for (list_t *l = uevent_container_netdev_mapping_list; l; l = l->next) {
		uevent_container_netdev_mapping_t *mapping = l->data;
		if (0 == memcmp(iface_mac, mapping->mac, 6)) {
			container = mapping->container;
			pnet_cfg = mapping->pnet_cfg;
			break;
		}
	}

	// no mapping found move to c0
	if (!container)
		container = cmld_containers_get_c0();

	if ((!container) || (container_get_state(container) != COMPARTMENT_STATE_BOOTING) ||
	    (container_get_state(container) != COMPARTMENT_STATE_RUNNING) ||
	    (container_get_state(container) != COMPARTMENT_STATE_STARTING)) {
		WARN("Target container is not running, skip moving %s", uevent->interface);
		goto error;
	}

	if (!pnet_cfg)
		pnet_cfg = container_pnet_cfg_new(uevent->interface, false, NULL);

	// rename network interface to avoid name clashes when moving to container
	DEBUG("Renaming new interface we were notified about");
	uevent_event_t *newevent = uevent_rename_interface(uevent);

	// uevent pointer is not freed inside this function, therefore we can safely drop it
	if (newevent) {
		DEBUG("using renamed uevent");
		uevent = newevent;
	} else {
		ERROR("failed to rename interface %s. injecting uevent as it is",
		      uevent->interface);
	}

	macstr = network_mac_addr_to_str_new(iface_mac);
	if (cmld_container_add_net_iface(container, pnet_cfg, false)) {
		ERROR("cannot move '%s' to %s!", macstr, container_get_name(container));
		goto error;
	} else {
		INFO("moved phys network interface '%s' (mac: %s) to %s", uevent->interface, macstr,
		     container_get_name(container));
	}

	// if mac_filter is applied we have a bridge interface and do not
	// need to send the uevent about the physical if
	if (pnet_cfg->mac_filter) {
		mem_free0(macstr);
		return 0;
	}

	// if moving was successful also inject uevent
	if (uevent_event_inject_into_netns(uevent, container_get_pid(container),
				     container_has_userns(container)) < 0) {
		WARN("could not inject uevent into netns of container %s!",
		     container_get_name(container));
	} else {
		TRACE("successfully injected uevent into netns of container %s!",
		      container_get_name(container));
	}

	mem_free0(macstr);
	return 0;
error:
	mem_free0(macstr);
	return -1;
}

static void
uevent_sysfs_netif_timer_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);
	uevent_event_t *uevent_cb = data;
	uevent_parse(uevent_cb, uevent_cb->msg.raw);

	// if sysfs is not ready in case of wifi just return and retry.
	IF_TRUE_RETURN(!strcmp(uevent_cb->devtype, "wlan") &&
		       !network_interface_is_wifi(uevent_cb->interface));

	if (uevent_netdev_move(uevent_cb) == -1)
		WARN("Did not move net interface!");
	else
		INFO("Moved net interface to target.");

	mem_free0(uevent_cb);
	event_remove_timer(timer);
	event_timer_free(timer);
}

static int
uevent_usbdev_sysfs_foreach_cb(const char *path, const char *name, void *data)
{
	uint16_t id_product, id_vendor;
	char buf[256];
	int len;
	bool found;
	int dev[2];

	uevent_usbdev_t *usbdev = data;
	IF_NULL_RETVAL(usbdev, -1);

	char *id_product_file = mem_printf("%s/%s/idProduct", path, name);
	char *id_vendor_file = mem_printf("%s/%s/idVendor", path, name);
	char *i_serial_file = mem_printf("%s/%s/serial", path, name);
	char *dev_file = mem_printf("%s/%s/dev", path, name);

	TRACE("id_product_file: %s", id_product_file);
	TRACE("id_vendor_file: %s", id_vendor_file);
	TRACE("i_serial_file: %s", i_serial_file);

	IF_FALSE_GOTO_TRACE(file_exists(id_product_file), out);
	IF_FALSE_GOTO_TRACE(file_exists(id_vendor_file), out);
	IF_FALSE_GOTO_TRACE(file_exists(dev_file), out);

	len = file_read(id_product_file, buf, sizeof(buf));
	IF_TRUE_GOTO((len < 4), out);
	IF_TRUE_GOTO((sscanf(buf, "%hx", &id_product) < 0), out);
	found = (id_product == uevent_usbdev_get_id_product(usbdev));
	TRACE("found: %d", found);

	len = file_read(id_vendor_file, buf, sizeof(buf));
	IF_TRUE_GOTO((len < 4), out);
	IF_TRUE_GOTO((sscanf(buf, "%hx", &id_vendor) < 0), out);
	found &= (id_vendor == uevent_usbdev_get_id_vendor(usbdev));
	TRACE("found: %d", found);

	if (file_exists(i_serial_file)) {
		len = file_read(i_serial_file, buf, sizeof(buf));
		TRACE("%s len=%d", buf, len);
		TRACE("%s len=%zu", uevent_usbdev_get_i_serial(usbdev),
		      strlen(uevent_usbdev_get_i_serial(usbdev)));
		found &= (0 == strncmp(buf, uevent_usbdev_get_i_serial(usbdev),
				       strlen(uevent_usbdev_get_i_serial(usbdev))));
		TRACE("found: %d", found);
	} else {
		buf[0] = '\0';
	}
	IF_FALSE_GOTO_TRACE(found, out);

	// major = minor = -1;
	dev[0] = dev[1] = -1;
	len = file_read(dev_file, buf, sizeof(buf));
	IF_TRUE_GOTO((sscanf(buf, "%d:%d", &dev[0], &dev[1]) < 0), out);
	IF_FALSE_GOTO((dev[0] > -1 && dev[1] > -1), out);

	uevent_usbdev_set_major(usbdev, dev[0]);
	uevent_usbdev_set_minor(usbdev, dev[1]);

	return 0; /* Shouldn't this be -1 to avoid further calls by dir_foreach()? */

out:
	mem_free0(id_product_file);
	mem_free0(id_vendor_file);
	mem_free0(i_serial_file);
	mem_free0(dev_file);
	return 0;
}

int
uevent_usbdev_set_sysfs_props(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	const char *sysfs_path = "/sys/bus/usb/devices";

	// for the first time iterate through sysfs to find device
	if (0 > dir_foreach(sysfs_path, &uevent_usbdev_sysfs_foreach_cb, usbdev)) {
		WARN("Could not open %s to find usb device!", sysfs_path);
		return -1;
	}

	return 0;
}

/*
 * return true if uevent is handled completely, false if uevent should process further
 * in calling funtion
 */
static bool
uevent_handle_usb_device(uevent_event_t *uevent)
{
	IF_TRUE_RETVAL_TRACE(strncmp(uevent->subsystem, "usb", 3) ||
				     strncmp(uevent->devtype, "usb_device", 10),
			     false);

	if (0 == strncmp(uevent->action, "remove", 6)) {
		TRACE("remove");
		for (list_t *l = uevent_container_dev_mapping_list; l; l = l->next) {
			uevent_container_dev_mapping_t *mapping = l->data;
			if ((uevent->major == mapping->usbdev->major) &&
			    (uevent->minor == mapping->usbdev->minor)) {
				if (UEVENT_USBDEV_TYPE_TOKEN == mapping->usbdev->type) {
					INFO("UEVENT USB TOKEN removed");
					container_token_detach(mapping->container);
				} else {
					container_device_deny(mapping->container,
							      mapping->usbdev->major,
							      mapping->usbdev->minor);
				}
				INFO("Denied access to unbound device node %d:%d mapped in container %s",
				     mapping->usbdev->major, mapping->usbdev->minor,
				     container_get_name(mapping->container));
			}
		}
	}

	if (0 == strncmp(uevent->action, "add", 3)) {
		TRACE("add");

		char *serial_path = mem_printf("/sys/%s/serial", uevent->devpath);
		char *serial = NULL;

		if (file_exists(serial_path))
			serial = file_read_new(serial_path, 255);

		mem_free0(serial_path);

		if (!serial || strlen(serial) < 1) {
			TRACE("Failed to read serial of usb device");
			return false;
		}

		if ('\n' == serial[strlen(serial) - 1]) {
			serial[strlen(serial) - 1] = 0;
		}

		for (list_t *l = uevent_container_dev_mapping_list; l; l = l->next) {
			uevent_container_dev_mapping_t *mapping = l->data;
			uint16_t vendor_id = uevent_get_usb_vendor(uevent);
			uint16_t product_id = uevent_get_usb_product(uevent);

			INFO("check mapping: %04x:%04x '%s' for %s bound device node %d:%d -> container %s",
			     vendor_id, product_id, serial, (mapping->assign) ? "assign" : "allow",
			     uevent->major, uevent->minor, container_get_name(mapping->container));

			if ((mapping->usbdev->id_vendor == vendor_id) &&
			    (mapping->usbdev->id_product == product_id) &&
			    (0 == strcmp(mapping->usbdev->i_serial, serial))) {
				mapping->usbdev->major = uevent->major;
				mapping->usbdev->minor = uevent->minor;
				INFO("%s bound device node %d:%d -> container %s",
				     (mapping->assign) ? "assign" : "allow", mapping->usbdev->major,
				     mapping->usbdev->minor,
				     container_get_name(mapping->container));
				if (UEVENT_USBDEV_TYPE_TOKEN == mapping->usbdev->type) {
					INFO("UEVENT USB TOKEN added");
					container_token_attach(mapping->container);
				}
				container_device_allow(mapping->container, mapping->usbdev->major,
						       mapping->usbdev->minor, mapping->assign);
			}
		}
		mem_free0(serial);
	}
	return false;
}

static unsigned
uevent_action_from_string(const char *action)
{
	if (!strcmp(action, "add"))
		return UEVENT_ACTION_ADD;
	if (!strcmp(action, "bind"))
		return UEVENT_ACTION_BIND;
	if (!strcmp(action, "change"))
		return UEVENT_ACTION_CHANGE;
	if (!strcmp(action, "remove"))
		return UEVENT_ACTION_REMOVE;
	if (!strcmp(action, "unbind"))
		return UEVENT_ACTION_UNBIND;

	return 0;
}

static void
handle_kernel_event(uevent_event_t *uevent, char *raw_p)
{
	TRACE("handle_kernel_event");
	uevent_parse(uevent, raw_p);

	/* handle registerd uev events */
	for (list_t *l = uevent_uev_kernel_list; l; l = l->next) {
		uevent_uev_t *uev = l->data;
		unsigned action = uevent_action_from_string(uevent->action);
		if (action & uev->actions)
			uev->func(action, uevent, uev->data);
	}

	/* just handle add,remove or change events to containers */
	IF_TRUE_RETURN_TRACE(strncmp(uevent->action, "add", 3) &&
			     strncmp(uevent->action, "remove", 6) &&
			     strncmp(uevent->action, "change", 6));

	/*
	 * if handler returns true the event is completely handled
	 * otherwise event should be checked for possible forwarding
	 */
	IF_TRUE_RETURN_TRACE(uevent_handle_usb_device(uevent));

	TRACE("Got new add/remove/change uevent");

	/* move network ifaces to containers */
	if (!strncmp(uevent->action, "add", 3) && !strcmp(uevent->subsystem, "net") &&
	    !strstr(uevent->devpath, "virtual") && !cmld_is_hostedmode_active()) {
		// got new physical interface, initially add to cmld tracking list
		cmld_netif_phys_add_by_name(uevent->interface);

		uevent_event_t *uevent_cb = mem_new0(uevent_event_t, 1);
		memcpy(uevent_cb, uevent, sizeof(uevent_event_t));

		// give sysfs some time to settle if iface is wifi
		event_timer_t *e = event_timer_new(100, EVENT_TIMER_REPEAT_FOREVER,
						   uevent_sysfs_netif_timer_cb, uevent_cb);
		event_add_timer(e);
	}
}

static void
handle_udev_event(uevent_event_t *uevent, char *raw_p)
{
	TRACE("handle_udev_event");

	uevent_parse(uevent, raw_p);

	/* handle registerd uev udev events */
	for (list_t *l = uevent_uev_udev_list; l; l = l->next) {
		uevent_uev_t *uev = l->data;
		unsigned action = uevent_action_from_string(uevent->action);
		if (action & uev->actions)
			uev->func(action, uevent, uev->data);
	}
	return;
}

static void
uevent_handle(UNUSED int fd, UNUSED unsigned events, UNUSED event_io_t *io, UNUSED void *data)
{
	uevent_event_t *uev = mem_new0(uevent_event_t, 1);

	// read uevent into raw buffer and assure that last char is '\0'
	if ((uev->msg_len = nl_msg_receive_kernel(uevent_netlink_sock, uev->msg.raw,
						  sizeof(uev->msg.raw) - 1, true)) <= 0) {
		WARN("could not read uevent");
		goto err;
	}

	char *raw_p = uev->msg.raw;

	if (strncmp(uev->msg.nlh.prefix, "libudev", uev->msg_len) == 0) {
		/* udev message needs proper version magic */
		if (uev->msg.nlh.magic != htonl(UDEV_MONITOR_MAGIC)) {
			WARN("unrecognized message signature (%x != %x)", uev->msg.nlh.magic,
			     htonl(UDEV_MONITOR_MAGIC));
			goto err;
		}
		if (uev->msg.nlh.properties_off + 32 > uev->msg_len) {
			WARN("message smaller than expected (%u > %zd)",
			     uev->msg.nlh.properties_off + 32, uev->msg_len);
			goto err;
		}
		raw_p += uev->msg.nlh.properties_off;
		handle_udev_event(uev, raw_p);
	} else if (strchr(raw_p, '@')) {
		/* kernel message */
		TRACE("kernel uevent: %s", raw_p ? raw_p : "NULL");
		raw_p += strlen(raw_p) + 1;
		handle_kernel_event(uev, raw_p);
	} else {
		/* kernel message */
		TRACE("no uevent: %s", raw_p);
	}
err:
	mem_free0(uev);
}

int
uevent_init()
{
	if (uevent_netlink_sock != NULL) {
		ERROR("Uevent netlink_socket already exists.");
		return -1;
	}
	if (uevent_io_event != NULL) {
		ERROR("Uevent io_event already exists.");
		return -1;
	}

	// Initially rename all physical interfaces before starting uevent handling.
	for (list_t *l = cmld_get_netif_phys_list(); l; l = l->next) {
		const char *ifname = l->data;
		const char *prefix = (network_interface_is_wifi(ifname)) ? "wlan" : "eth";
		char *if_name_new = uevent_rename_ifi_new(ifname, prefix);
		if (if_name_new) {
			mem_free0(l->data);
			l->data = if_name_new;
		}
	}

	/* find the udevd started by cml's init */
	pid_t udevd_pid = proc_find(1, "systemd-udevd");
	pid_t eudevd_pid = proc_find(1, "udevd");

	if (eudevd_pid < udevd_pid && eudevd_pid > 0)
		udevd_pid = eudevd_pid;

	if (!(uevent_netlink_sock = nl_sock_uevent_new(udevd_pid))) {
		ERROR("Could not open netlink socket");
		return -1;
	}

	if (fd_make_non_blocking(nl_sock_get_fd(uevent_netlink_sock))) {
		ERROR("Could not set fd of netlink sockt to non blocking!");
		nl_sock_free(uevent_netlink_sock);
		return -1;
	}

	uevent_io_event = event_io_new(nl_sock_get_fd(uevent_netlink_sock), EVENT_IO_READ,
				       &uevent_handle, NULL);
	event_add_io(uevent_io_event);

	return 0;
}

void
uevent_deinit()
{
	if (uevent_io_event) {
		event_remove_io(uevent_io_event);
		event_io_free(uevent_io_event);
	}
	if (uevent_netlink_sock) {
		nl_sock_free(uevent_netlink_sock);
	}
}

int
uevent_register_usbdevice(container_t *container, uevent_usbdev_t *usbdev)
{
	uevent_container_dev_mapping_t *mapping =
		uevent_container_dev_mapping_new(container, usbdev);
	uevent_container_dev_mapping_list = list_append(uevent_container_dev_mapping_list, mapping);

	INFO("Registered usbdevice %04x:%04x '%s' [c %d:%d] for container %s",
	     mapping->usbdev->id_vendor, mapping->usbdev->id_product, mapping->usbdev->i_serial,
	     mapping->usbdev->major, mapping->usbdev->minor,
	     container_get_name(mapping->container));

	return 0;
}

int
uevent_unregister_usbdevice(container_t *container, uevent_usbdev_t *usbdev)
{
	uevent_container_dev_mapping_t *mapping_to_remove = NULL;

	for (list_t *l = uevent_container_dev_mapping_list; l; l = l->next) {
		uevent_container_dev_mapping_t *mapping = l->data;
		if ((mapping->container == container) &&
		    (mapping->usbdev->id_vendor == usbdev->id_vendor) &&
		    (mapping->usbdev->id_product == usbdev->id_product) &&
		    (0 == strcmp(mapping->usbdev->i_serial, usbdev->i_serial))) {
			mapping_to_remove = mapping;
		}
	}

	IF_NULL_RETVAL(mapping_to_remove, -1);

	uevent_container_dev_mapping_list =
		list_remove(uevent_container_dev_mapping_list, mapping_to_remove);

	INFO("Unregistered usbdevice %04x:%04x '%s' for container %s",
	     mapping_to_remove->usbdev->id_vendor, mapping_to_remove->usbdev->id_product,
	     mapping_to_remove->usbdev->i_serial, container_get_name(mapping_to_remove->container));

	uevent_container_dev_mapping_free(mapping_to_remove);

	return 0;
}

int
uevent_register_netdev(container_t *container, container_pnet_cfg_t *pnet_cfg)
{
	uevent_container_netdev_mapping_t *mapping =
		uevent_container_netdev_mapping_new(container, pnet_cfg);

	IF_NULL_RETVAL(mapping, -1);

	uevent_container_netdev_mapping_list =
		list_append(uevent_container_netdev_mapping_list, mapping);
	char *macstr = network_mac_addr_to_str_new(mapping->mac);

	INFO("Registered netdev '%s' for container %s", macstr,
	     container_get_name(mapping->container));

	mem_free0(macstr);
	return 0;
}

int
uevent_unregister_netdev(container_t *container, uint8_t mac[6])
{
	uevent_container_netdev_mapping_t *mapping_to_remove = NULL;

	for (list_t *l = uevent_container_netdev_mapping_list; l; l = l->next) {
		uevent_container_netdev_mapping_t *mapping = l->data;
		if ((mapping->container == container) && (0 == memcmp(mapping->mac, mac, 6))) {
			mapping_to_remove = mapping;
		}
	}

	IF_NULL_RETVAL(mapping_to_remove, -1);

	uevent_container_netdev_mapping_list =
		list_remove(uevent_container_netdev_mapping_list, mapping_to_remove);

	char *macstr = network_mac_addr_to_str_new(mapping_to_remove->mac);

	INFO("Unregistered netdev '%s' for container %s", macstr,
	     container_get_name(mapping_to_remove->container));

	uevent_container_netdev_mapping_free(mapping_to_remove);
	mem_free0(macstr);

	return 0;
}

uevent_uev_t *
uevent_uev_new(uevent_uev_type_t type, unsigned actions,
	       void (*func)(unsigned actions, uevent_event_t *event, void *data), void *data)
{
	uevent_uev_t *uev;

	IF_FALSE_RETVAL(actions, NULL);
	IF_NULL_RETVAL(func, NULL);

	uev = mem_new0(uevent_uev_t, 1);
	uev->type = type;
	uev->actions = actions;
	uev->func = func;
	uev->data = data;

	return uev;
} 

void
uevent_uev_free(uevent_uev_t *uev)
{
	mem_free0(uev);
}

int
uevent_add_uev(uevent_uev_t *uev)
{
	IF_NULL_RETVAL(uev, -1);

	if (uev->type == UEVENT_UEV_TYPE_KERNEL) {
		uevent_uev_kernel_list = list_append(uevent_uev_kernel_list, uev);
	} else if (uev->type == UEVENT_UEV_TYPE_UDEV) {
		uevent_uev_udev_list = list_append(uevent_uev_udev_list, uev);
	} else {
		ERROR("Unknown type %d for uev", uev->type);
		return -1;
	}

	TRACE("Added uev uevent %p (func=%p, data=%p, actions=0x%x)", (void *)uev,
	      CAST_FUNCPTR_VOIDPTR uev->func, uev->data, uev->actions);

	return 0;
}

void
uevent_remove_uev(uevent_uev_t *uev)
{
	IF_NULL_RETURN(uev);
	TRACE("Removing uev uevent %p", (void *)uev);

	if (uev->type == UEVENT_UEV_TYPE_KERNEL) {
		uevent_uev_kernel_list = list_remove(uevent_uev_kernel_list, uev);
	} else if (uev->type == UEVENT_UEV_TYPE_UDEV) {
		uevent_uev_udev_list = list_remove(uevent_uev_udev_list, uev);
	} else {
		ERROR("Unknown type %d for uev", uev->type);
		return;
	}

	TRACE("Removed uev event %p (func=%p, data=%p, actions=0x%x)", (void *)uev,
	      CAST_FUNCPTR_VOIDPTR uev->func, uev->data, uev->actions);
}

struct uevent_udev_coldboot_data {
	const uuid_t *synth_uuid;
	bool (*filter)(int major, int minor, void *data);
	void *data;
};

static int
uevent_trigger_coldboot_foreach_cb(const char *path, const char *name, void *data)
{
	int ret = 0;
	char buf[256];
	int major, minor;

	struct uevent_udev_coldboot_data *coldboot_data = data;
	IF_NULL_RETVAL(coldboot_data, -1);

	char *full_path = mem_printf("%s/%s", path, name);
	char *dev_file = NULL;

	if (file_is_dir(full_path)) {
		if (0 > dir_foreach(full_path, &uevent_trigger_coldboot_foreach_cb, data)) {
			WARN("Could not trigger coldboot uevents! No '%s'!", full_path);
			ret--;
		}
	} else if (!strcmp(name, "uevent")) {
		dev_file = mem_printf("%s/dev", path);

		IF_FALSE_GOTO_TRACE(file_exists(dev_file), out);

		major = minor = -1;
		IF_TRUE_GOTO(-1 == file_read(dev_file, buf, sizeof(buf)), out);
		IF_TRUE_GOTO((sscanf(buf, "%d:%d", &major, &minor) < 0), out);
		IF_FALSE_GOTO((major > -1 && minor > -1), out);

		// only trigger for allowed devices
		if (coldboot_data->filter)
			IF_FALSE_GOTO_TRACE(
				coldboot_data->filter(major, minor, coldboot_data->data), out);

		char *trigger = mem_printf("add %s", uuid_string(coldboot_data->synth_uuid));
		if (-1 == file_printf(full_path, trigger)) {
			WARN("Could not trigger event %s <- %s", full_path, trigger);
			ret--;
		} else {
			DEBUG("Trigger event %s <- %s", full_path, trigger);
		}
		mem_free0(trigger);
	}
out:
	mem_free0(full_path);
	mem_free0(dev_file);
	return ret;
}

void
uevent_udev_trigger_coldboot(const uuid_t *synth_uuid,
			     bool (*filter)(int major, int minor, void *data), void *data)
{
	const char *sysfs_devices = "/sys/devices";
	struct uevent_udev_coldboot_data coldboot_data = { .synth_uuid = synth_uuid,
							   .filter = filter,
							   .data = data };
	// for the first time iterate through sysfs to find device
	if (0 > dir_foreach(sysfs_devices, &uevent_trigger_coldboot_foreach_cb, &coldboot_data)) {
		WARN("Could not trigger coldboot uevents! No '%s'!", sysfs_devices);
	}
}
