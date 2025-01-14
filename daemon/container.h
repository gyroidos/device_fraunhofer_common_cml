/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2022 Fraunhofer AISEC
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file container.h
 *
 * Module agic to avoid code duplication and
 * functions implementd by submodules using those macros
 * This module wrappes the low-level compartment API and provides aditional
 * API and state which is implemented in container modules which are also
 * registerd at the low-level container object.
 */

#ifndef CONTAINER_H
#define CONTAINER_H

#include "container_module.h"

#include "common/uuid.h"
#include "common/list.h"
#include "compartment.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Path for mapped service binary
 */
#define CSERVICE_TARGET "/sbin/cservice"

/**
 * Opaque container type.
 * (only used as pointer outside of the container module)
 */
typedef struct container container_t;

/**
 * Opaque container observer callback type.
 * (only used as pointer outside of the container module)
 */
typedef struct container_callback container_callback_t;

/**
 * Represents the type of a container. Could be either
 * CONTAINER_TYPE_CONTAINER for a namspaced os-level virtualized
 * or CONTAINER_TYPE_KVM for a full virtulized execution of the
 * child's init process.
 */
typedef enum {
	CONTAINER_TYPE_CONTAINER = 1,
	CONTAINER_TYPE_KVM,
} container_type_t;

/**
 * Represents the type of token which the container is associated with.
 * The token is used to i.a. wrap the container's disk encryption key.
 */
typedef enum {
	CONTAINER_TOKEN_TYPE_NONE = 1,
	CONTAINER_TOKEN_TYPE_SOFT,
	CONTAINER_TOKEN_TYPE_USB,
} container_token_type_t;

typedef enum container_usbdev_type {
	CONTAINER_USBDEV_TYPE_GENERIC = 1,
	CONTAINER_USBDEV_TYPE_TOKEN,
	CONTAINER_USBDEV_TYPE_PIN_ENTRY
} container_usbdev_type_t;

/**
 * Structure to define the mapping of hotplug event to usb device

 * It defines the usb vendor and product as show by lsusb
 * and if there is any, the serial of a device, e.g. from uTrust Token.
 * Further, it is defined if the device should be assigned exclusivly
 * to the container or if just the access is allowed.
 */
typedef struct container_usbdev container_usbdev_t;

/**
 * Structure to define the configuration for a virtual network
 * interface in a container. It defines the name and if cmld
 * should configure it in its c_net submodule.
 */
typedef struct container_vnet_cfg {
	char *vnet_name;
	char *rootns_name;
	uint8_t vnet_mac[6];
	bool configure;
} container_vnet_cfg_t;

/**
 * Structure to define a phyiscal NIC that is accesible from inside a container.
 * The CML bridges or moves the physical IF into the container and enforces
 * filtering of layer 2 frames based on MAC adresses
 */
typedef struct container_pnet_cfg {
	char *pnet_name;
	bool mac_filter;
	list_t *mac_whitelist;
} container_pnet_cfg_t;

/**
 * Represents an error that happened during smartcard handling of a container.
 */
enum container_smartcard_error {
	CONTAINER_SMARTCARD_LOCK_FAILED = 1,
	CONTAINER_SMARTCARD_UNLOCK_FAILED,
	CONTAINER_SMARTCARD_PASSWD_WRONG,
	CONTAINER_SMARTCARD_LOCKED_TILL_REBOOT,
	CONTAINER_SMARTCARD_TOKEN_UNINITIALIZED,
	CONTAINER_SMARTCARD_TOKEN_UNPAIRED,
	CONTAINER_SMARTCARD_PAIRING_SECRET_FAILED,
	CONTAINER_SMARTCARD_WRAPPING_ERROR,
	CONTAINER_SMARTCARD_CHANGE_PIN_SUCCESSFUL,
	CONTAINER_SMARTCARD_CHANGE_PIN_FAILED,
	CONTAINER_SMARTCARD_CB_OK,
	CONTAINER_SMARTCARD_CB_FAILED,
};

/**
 * constructor that creates a new container instance
 * with the given parameters.
 *
 * TODO: Document parameters.
 * @return The new container instance.
 */
container_t *
container_new(const uuid_t *uuid, const char *name, container_type_t type, bool ns_usr, bool ns_net,
	      const void *os, const char *config_filename, const char *images_dir,
	      unsigned int ram_limit, const char *cpus_allowed, uint32_t color,
	      bool allow_autostart, bool allow_system_time, const char *dns_server,
	      list_t *pnet_cfg_list, list_t *allowed_module_list, char **allowed_devices,
	      char **assigned_devices, list_t *vnet_cfg_list, list_t *usbdev_list, const char *init,
	      char **init_argv, char **init_env, size_t init_env_len, list_t *fifo_list,
	      container_token_type_t ttype, bool usb_pin_entry, bool xorg_compat);

/**
 * Free a container data structure.
 */
void
container_free(container_t *container);

/**
 * Checks if a given container is stoppable
 */
bool
container_is_stoppable(container_t *container);

/**
 * Checks if a given container is startable
 */
bool
container_is_startable(container_t *container);

/**
 * Return the directory where the container stores its images.
 */
const char *
container_get_images_dir(const container_t *container);

/**
 * Get the container config filename.
 */
const char *
container_get_config_filename(const container_t *container);

/*
 * Retrive the corresponding GuestOS (as generic object) which is running in this container
 */
const void *
container_get_guestos(const container_t *container);

/**
 * Wipe a container. Removes the images but keeps the config in place.
 */
int
container_wipe(container_t *container);

/**
 * Remove a container persistently from disk, i.e. remove its configuration and
 * wipe its images. This does not free the container object, this must be done
 * seperately by the module that called container_new in the first place.
 *
 * @param container The container to be destroyed.
 * @return 0 if ok, negative values indicate errors.
 */
int
container_destroy(container_t *container);

/**
 * Gets the (user defined) container color.
 *
 * @param container The container object.
 * @return The container color.
 */
uint32_t
container_get_color(const container_t *container);

/**
 * Gets the (user defined) container color as an RGB string.
 *
 * @param container The container object.
 * @return The container color as an RGB string.
 */
char *
container_get_color_rgb_string(const container_t *container);

unsigned int
container_get_ram_limit(const container_t *container);

const char *
container_get_cpus_allowed(const container_t *container);

bool
container_get_allow_autostart(container_t *container);

/**
 * Returns the ip address currently set for container.
 */
const char *
container_get_dns_server(const container_t *container);

const char **
container_get_dev_allow_list(const container_t *container);

const char **
container_get_dev_assign_list(const container_t *container);

list_t *
container_get_usbdev_list(const container_t *container);

/**
 * Returns the type of the token that is used with the container
 */
container_token_type_t
container_get_token_type(const container_t *container);

/**
 * Returns whether the pin should be requested interactively via a usb pin reader during
 * container start
 */
bool
container_get_usb_pin_entry(const container_t *container);

list_t *
container_get_pnet_cfg_list(const container_t *container);

list_t *
container_get_vnet_cfg_list(const container_t *container);

list_t *
container_get_fifo_list(const container_t *container);

/**
 * Initialize a container_usbdev_t data structure and allocate needed memory
 */
container_usbdev_t *
container_usbdev_new(container_usbdev_type_t type, uint16_t id_vendor, uint16_t id_product,
		     char *i_serial, bool assign);

void
container_usbdev_free(container_usbdev_t *usbdev);

uint16_t
container_usbdev_get_id_vendor(container_usbdev_t *usbdev);

uint16_t
container_usbdev_get_id_product(container_usbdev_t *usbdev);

char *
container_usbdev_get_i_serial(container_usbdev_t *usbdev);

container_usbdev_type_t
container_usbdev_get_type(container_usbdev_t *usbdev);

bool
container_usbdev_is_assigned(container_usbdev_t *usbdev);

void
container_usbdev_set_major(container_usbdev_t *usbdev, int major);

void
container_usbdev_set_minor(container_usbdev_t *usbdev, int minor);

int
container_usbdev_get_major(container_usbdev_t *usbdev);

int
container_usbdev_get_minor(container_usbdev_t *usbdev);

/**
 * Initialize a container_vnet_cfg_t data structure and allocate needed memory
 */
container_vnet_cfg_t *
container_vnet_cfg_new(const char *if_name, const char *rootns_name, const uint8_t mac[6],
		       bool configure);

/**
 * Free all memory used by a container_vnet_cfg_t data structure
 */
void
container_vnet_cfg_free(container_vnet_cfg_t *vnet_cfg);

/**
 * This function provides the container's runtime config
 * of veth interfaces in form of a container_vnet_cfg_t* list.
 * The elements contain the veth name inside the container and
 * the runtime generated interface name of the rootns endpoint.
 */
list_t *
container_get_vnet_runtime_cfg_new(const container_t *container);

/**
 * Registers the corresponding handler for container_get_vnet_runtime_cfg_new
 */
void
container_register_get_vnet_runtime_cfg_new_handler(const char *mod_name,
						    list_t *(*handler)(void *data));

/**
 * Initialize a container_pnet_cfg_t data structure and allocate needed memory.
 * @if_name may be either the name or the MAC of the phyiscal NIC
 */
container_pnet_cfg_t *
container_pnet_cfg_new(const char *if_name, bool mac_filter, list_t *mac_whitelist);

/**
 * Free all memory used by a container_pnet_cfg_t data structure, including
 * the internal mac_whitelist.
 */
void
container_pnet_cfg_free(container_pnet_cfg_t *pnet_cfg);

/**
 * Update name attribute of pnet_cfg data structure
 */
void
container_pnet_cfg_set_pnet_name(container_pnet_cfg_t *pnet_cfg, const char *pnet_name);

/**
 * Get the list of usb devices which are set in container config.
 */
list_t *
container_get_usbdev_list(const container_t *container);

/**
 * Get the list of module names which are allowed in container config.
 */
const list_t *
container_get_module_allow_list(const container_t *container);

const char **
container_get_dev_allow_list(const container_t *container);

const char **
container_get_dev_assign_list(const container_t *container);

/**
 * Returns the the type of the container.
 */
container_type_t
container_get_type(const container_t *container);

// ##################################################################
// compartment wrappers
// ##################################################################
container_callback_t *
container_register_observer(container_t *container,
			    void (*cb)(container_t *, container_callback_t *, void *), void *data);

void
container_unregister_observer(container_t *container, container_callback_t *cb);

void
container_finish_observers(container_t *container, void (*cb)(void *), void *data);

void
container_init_env_prepend(container_t *container, char **init_env, size_t init_env_len);

const uuid_t *
container_get_uuid(const container_t *container);

bool
container_uuid_is_c0id(const uuid_t *uuid);

const char *
container_get_name(const container_t *container);

const char *
container_get_description(const container_t *container);

pid_t
container_get_pid(const container_t *container);

pid_t
container_get_service_pid(const container_t *container);

void
container_oom_protect_service(const container_t *container);

bool
container_get_sync_state(const container_t *container);

void
container_set_sync_state(container_t *container, bool state);

bool
container_is_privileged(const container_t *container);

int
container_start(container_t *container);

int
container_stop(container_t *container);

void
container_kill(container_t *container);

int
container_bind_socket_before_start(container_t *container, const char *path);

void
container_set_state(container_t *container, compartment_state_t state);

compartment_state_t
container_get_state(const container_t *container);

compartment_state_t
container_get_prev_state(const container_t *container);

const char *
container_get_key(const container_t *container);

void
container_set_key(container_t *container, const char *key);

bool
container_has_netns(const container_t *container);

bool
container_has_userns(const container_t *container);

void
container_set_setup_mode(container_t *container, bool setup);

bool
container_has_setup_mode(const container_t *container);

bool
container_contains_pid(const container_t *container, pid_t pid);

void
container_wait_for_child(container_t *container, char *name, pid_t pid);

// ##################################################################
// end compartment wrappers
// ##################################################################

/*
 * container functions implemented by c_* submodules
 */

/*
 * Add process with given PID to cgroups of given container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(add_pid_to_cgroups, int, pid_t pid)

/*
 * Set capapilites for calling process as for given container's init
 */
CONTAINER_MODULE_WRAPPER_DECLARE(set_cap_current_process, int)

/**
 * Get socket fd used to communicate with process executed in container context
 * by using the control run interface
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_console_sock_cmld, int, int session_fd)

/**
 * Get the information if the conatiner has encrypted volumes.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(is_encrypted, bool)

/**
 * Run a given command inside a container
 *
 * @return session id of the running session in the container, -1 on error
 */
CONTAINER_MODULE_WRAPPER_DECLARE(run, int, int create_pty, char *cmd, ssize_t argc, char **argv,
				 int session_fd)

/**
 * Registers the corresponding handler for container_write_exec_input
 */
CONTAINER_MODULE_WRAPPER_DECLARE(write_exec_input, int, char *exec_input, int session_fd)

/**
 * Freeze a container.
 *
 * @return 0 if ok, negative values indicate errors.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(freeze, int)

/**
 * Unfreeze a container.
 *
 * @return 0 if ok, negative values indicate errors.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(unfreeze, int)

/**
 * Registers the corresponding handler for container_allow_audio
 */
CONTAINER_MODULE_WRAPPER_DECLARE(allow_audio, int)

/**
 * Registers the corresponding handler for container_deny_audio
 */
CONTAINER_MODULE_WRAPPER_DECLARE(deny_audio, int)

/**
 * Adds a network interface to the container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(add_net_interface, int, container_pnet_cfg_t *pnet_cfg)

/**
 * Removes a network interface from the container.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(remove_net_interface, int, const char *iface)

/**
 * Registers the corresponding handler for container_setuid0
 */
CONTAINER_MODULE_WRAPPER_DECLARE(setuid0, int)

/**
 * Allow device access for device of type 'b'|'c' by major, minor number.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(device_allow, int, char type, int major, int minor, bool assign)

/**
 * Remove previously allowed access for device of type 'b'|'c' and major, minor number.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(device_deny, int, char type, int major, int minor)

/**
 * Checks if the device specified by the type 'b'|'c' and the major, minor is allowed in this container.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(is_device_allowed, bool, char type, int major, int minor)

/**
 * Prepares a mount for shifted uid and gids of directory/file for the container's userns.
 *
 * Needs to be called in rootns for each file system image which should be mounted
 * with shifted ids in child. This is also be used to shift single files in the
 * in uevent module for container allowed devices.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(shift_ids, int, const char *src, const char *dst,
				 const char *ovl_lower)

/**
 * Returns the uid which is mapped to the root user inside the container
 *
 * if userns is enabled this would be a uid grater than 0.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_uid, int)

/**
 * Opens an file descriptor to a userns with the corresponding containers
 * uid mappings.
 *
 * Returns the opened namespace fd
 */
CONTAINER_MODULE_WRAPPER_DECLARE(open_userns, int)

/**
 * Returns the directory where the container's file system tree
 * is mounted in init mount namspace.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_rootdir, char *)

/**
 * Returns a generic pointer to the mount table
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_mnt, void *)

/**
 * Returns the last ACK hash that has been received from this container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_get_last_ack, const char *)

/**
 * Stores the last ACK hash that has been received for this container.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_set_last_ack, int, const char *last_ack)

/**
 * Returns wether an ACK is currently being processed for this container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_get_processing_ack, bool)

/**
 * Stores if an ACK hash is currently being processed for this container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_set_processing_ack, int, bool processing_ack)

/**
 * Send audit record to container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_record_notify, int, uint64_t remaining_storage)

/**
 * Send audit event to container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_record_send, int, const uint8_t *buf, uint32_t buflen)

/**
 * Declares the corresponding handler for container_audit_notify_complete
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_notify_complete, int)

/**
 * Declares the corresponding handler for container_audit_set_loginuid
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_set_loginuid, int, uint32_t uid)

/**
 * Declares the corresponding handler for container_audit_get_loginuid
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_get_loginuid, uint32_t)

CONTAINER_MODULE_WRAPPER_DECLARE(ctrl_with_smartcard, int, int (*success_cb)(container_t *),
				 const char *pw)

CONTAINER_MODULE_WRAPPER_DECLARE(set_smartcard_error_cb, int, void (*err_cb)(int error, void *data),
				 void *cbdata)

CONTAINER_MODULE_WRAPPER_DECLARE(scd_release_pairing, int)

CONTAINER_MODULE_WRAPPER_DECLARE(change_pin, int, const char *pw, const char *newpw)

/**
 * Handles attachment of a container token.
 *
 * @return 0 if the given USB serial belongs to a container token and
 *	the attachment procedure could be performed properly, -1 otherwise
 */
CONTAINER_MODULE_WRAPPER_DECLARE(token_attach, int)

/**
 * Handles detachment of a container token.
 *
 * @return 0 if the given USB serial belongs to a container token and
 * 	the detachment procedure could be performed properly, -1 otherwise
 */
CONTAINER_MODULE_WRAPPER_DECLARE(token_detach, int)

CONTAINER_MODULE_WRAPPER_DECLARE(has_token_changed, bool, container_token_type_t type,
				 const char *serial)

/**
 * Registers the corresponding handler for container_get_uptime
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_uptime, time_t)

/**
 * Registers the corresponding handler for container_get_creation_time
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_creation_time, time_t)

#endif /* CONTAINER_H */
