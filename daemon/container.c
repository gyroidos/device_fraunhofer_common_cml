/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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
#include <sched.h>

#include "container.h"

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/list.h"
#include "common/nl.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/proc.h"
#include "common/ns.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include <pty.h>

#define CLONE_STACK_SIZE 8192
/* Define some missing clone flags in BIONIC */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

/* Timeout for a container boot. If the container does not come up in that time frame
 * it is killed forcefully */
/* TODO is that enough time for all benign starts? */
#define CONTAINER_START_TIMEOUT 800000
/* Timeout until a container to be stopped gets killed if not yet down */
#define CONTAINER_STOP_TIMEOUT 45000

struct container {
	container_state_t state;
	container_state_t prev_state;
	uuid_t *uuid;
	char *name;
	container_type_t type;
	bool ns_net;
	bool ns_usr;
	bool ns_ipc;
	char *config_filename;
	char *images_dir;
	char *key;
	uint32_t color;
	bool allow_autostart;
	unsigned int ram_limit; /* maximum RAM space the container may use */
	char *cpus_allowed;

	char *description;

	list_t *csock_list; /* List of sockets bound inside the container */
	const void *os;	    /* weak reference */
	pid_t pid;	    /* PID of the corresponding /init */
	pid_t pid_early;    /* PID of the corresponding early start child */
	int exit_status;    /* if the container's init exited, here we store its exit status */

	char *init;	     /* init to be execed in container */
	char **init_argv;    /* command line parameters for init */
	char **init_env;     /* environment variables passed to init */
	size_t init_env_len; /* len of init_env array */

	list_t *observer_list; /* list of function callbacks to be called when the state changes */
	event_timer_t *stop_timer;  /* timer to handle container stop timeout */
	event_timer_t *start_timer; /* timer to handle a container start timeout */

	/* TODO maybe we should try to get rid of this state since it is only
	 * useful for the starting phase and only there to make it easier to pass
	 * the FD to the child via clone */
	int sync_sock_parent; /* parent sock for start synchronization */
	int sync_sock_child;  /* child sock for start synchronization */

	// Submodules
	list_t *module_instance_list;

	// list of allowed devices (rules)
	char **device_allowed_list;

	// list of exclusively assigned devices (rules)
	char **device_assigned_list;

	// list of uevent_usbdev_t devices to allow/assign for container
	list_t *usbdev_list;

	char *dns_server;
	bool setup_mode;

	container_token_type_t token_type;

	bool usb_pin_entry;

	// indicate if the container is synced with its config
	bool is_synced;

	// virtual network interfaces from container config
	list_t *vnet_cfg_list;
	// network interfaces from container config
	list_t *pnet_cfg_list;

	list_t *fifo_list;
};

struct container_callback {
	void (*cb)(container_t *, container_callback_t *, void *);
	void *data;
	bool todo;
};

typedef struct {
	int sockfd; /* The socket FD */
	char *path; /* The path the socket should be/is (pre/post start) bound to */
} container_sock_t;

/**
 * These are used for synchronizing the container start between parent
 * and child process
 */
enum container_start_sync_msg {
	CONTAINER_START_SYNC_MSG_GO = 1,
	CONTAINER_START_SYNC_MSG_STOP,
	CONTAINER_START_SYNC_MSG_SUCCESS,
	CONTAINER_START_SYNC_MSG_ERROR,
};

static list_t *container_module_list = NULL;

void
container_register_module(container_module_t *mod)
{
	ASSERT(mod);

	container_module_list = list_append(container_module_list, mod);
	DEBUG("Container module %s registered, nr of hooks: %d)", mod->name,
	      list_length(container_module_list));
}

typedef struct {
	container_module_t *module;
	void *instance;
} container_module_instance_t;

static container_module_instance_t *
container_module_instance_new(container_t *container, container_module_t *module)
{
	IF_NULL_RETVAL(module->container_new, NULL);

	void *instance = module->container_new(container);
	IF_NULL_RETVAL(instance, NULL);

	container_module_instance_t *c_mod = mem_new0(container_module_instance_t, 1);
	c_mod->module = module;
	c_mod->instance = instance;

	return c_mod;
}

static void
container_module_instance_free(container_module_instance_t *c_mod)
{
	IF_NULL_RETURN(c_mod);

	container_module_t *module = c_mod->module;

	if (module->container_free)
		module->container_free(c_mod->instance);

	mem_free0(c_mod);
}

static void *
container_module_get_instance_by_name(const container_t *container, const char *mod_name)
{
	ASSERT(container);
	ASSERT(mod_name);

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (!strcmp(module->name, mod_name))
			return c_mod->instance;
	}
	return NULL;
}

/* Functions usually implemented and registered by c_user module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(setuid0, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(setuid0, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(shift_ids, int, void *, const char *, bool)
CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(shift_ids, int, 0, const char *, bool)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(shift_mounts, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(shift_mounts, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_uid, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(get_uid, int, 0)

/* Functions usually implemented and registered by c_net module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(add_net_interface, int, void *, container_pnet_cfg_t *)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(add_net_interface, int, 0, container_pnet_cfg_t *)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(remove_net_interface, int, void *, const char *)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(remove_net_interface, int, 0, const char *)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_vnet_runtime_cfg_new, list_t *, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(get_vnet_runtime_cfg_new, list_t *, NULL)

/* Functions usually implemented and registered by c_cgroups module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(freeze, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(freeze, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(unfreeze, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(unfreeze, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(allow_audio, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(allow_audio, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(deny_audio, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(deny_audio, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(device_allow, int, void *, int, int, bool)
CONTAINER_MODULE_FUNCTION_WRAPPER4_IMPL(device_allow, int, 0, int, int, bool)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(device_deny, int, void *, int, int)
CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(device_deny, int, 0, int, int)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(is_device_allowed, bool, void *, int, int)
CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(is_device_allowed, bool, true, int, int)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(add_pid_to_cgroups, int, void *, pid_t)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(add_pid_to_cgroups, int, 0, pid_t)

/* Functions usually implemented and registered by c_vol module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_rootdir, char *, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(get_rootdir, char *, NULL)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_mnt, void *, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(get_mnt, void *, NULL)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(is_encrypted, bool, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(is_encrypted, bool, false)

/* Functions usually implemented and registered by c_service module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_record_send, int, void *, const uint8_t *, uint32_t)
CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(audit_record_send, int, 0, const uint8_t *, uint32_t)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_record_notify, int, void *, uint64_t)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(audit_record_notify, int, 0, uint64_t)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_notify_complete, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(audit_notify_complete, int, 0)

/* Functions usually implemented and registered by c_time module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_creation_time, time_t, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(get_creation_time, time_t, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_uptime, time_t, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(get_uptime, time_t, 0)

/* Functions usually implemented and registered by c_cap module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(set_cap_current_process, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(set_cap_current_process, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(exec_cap_systime, int, void *, char *const *)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(exec_cap_systime, int, -1, char *const *)

/* Functions usually implemented and registered by c_run module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(run, int, void *, int, char *, ssize_t, char **, int)
CONTAINER_MODULE_FUNCTION_WRAPPER6_IMPL(run, int, -1, int, char *, ssize_t, char **, int)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(write_exec_input, int, void *, char *, int)
CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(write_exec_input, int, -1, char *, int)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_console_sock_cmld, int, void *, int)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(get_console_sock_cmld, int, -1, int)

/* Functions usually implemented and registered by c_audit module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_get_last_ack, const char *, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(audit_get_last_ack, const char *, "")
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_set_last_ack, int, void *, const char *)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(audit_set_last_ack, int, 0, const char *)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_get_processing_ack, bool, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(audit_get_processing_ack, bool, false)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_set_processing_ack, int, void *, bool)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(audit_set_processing_ack, int, 0, bool)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_get_loginuid, uint32_t, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(audit_get_loginuid, uint32_t, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(audit_set_loginuid, int, void *, uint32_t)
CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(audit_set_loginuid, int, 0, uint32_t)

/* Functions usually implemented and registered by c_smartcard module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(ctrl_with_smartcard, int, void *, int (*)(container_t *),
				       const char *)
CONTAINER_MODULE_FUNCTION_WRAPPER3_1_IMPL(ctrl_with_smartcard, int, -1, int (*cb)(container_t *),
					  cb, const char *pw, pw)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(set_smartcard_error_cb, int, void *, void (*)(int, void *),
				       void *)
CONTAINER_MODULE_FUNCTION_WRAPPER3_1_IMPL(set_smartcard_error_cb, int, -1, void (*cb)(int, void *),
					  cb, void *cbdata, cbdata)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(scd_release_pairing, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(scd_release_pairing, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(change_pin, int, void *, const char *, const char *)
CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(change_pin, int, 0, const char *, const char *)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(token_attach, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(token_attach, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(token_detach, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(token_detach, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(has_token_changed, bool, void *, container_token_type_t,
				       const char *)
CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(has_token_changed, bool, false, container_token_type_t,
					const char *)

void
container_free_key(container_t *container)
{
	ASSERT(container);

	IF_NULL_RETURN(container->key);

	mem_memset0(container->key, strlen(container->key));
	mem_free0(container->key);

	INFO("Key of container %s was freed", container->name);
}

container_t *
container_new(const uuid_t *uuid, const char *name, container_type_t type, bool ns_usr, bool ns_net,
	      const void *os, const char *config_filename, const char *images_dir,
	      unsigned int ram_limit, const char *cpus_allowed, uint32_t color,
	      bool allow_autostart, const char *dns_server, list_t *pnet_cfg_list,
	      char **allowed_devices, char **assigned_devices, list_t *vnet_cfg_list,
	      list_t *usbdev_list, const char *init, char **init_argv, char **init_env,
	      size_t init_env_len, list_t *fifo_list, container_token_type_t ttype,
	      bool usb_pin_entry)
{
	container_t *container = mem_new0(container_t, 1);

	container->state = CONTAINER_STATE_STOPPED;
	container->prev_state = CONTAINER_STATE_STOPPED;

	container->uuid = uuid_new(uuid_string(uuid));
	container->name = mem_strdup(name);
	container->type = type;

	/* do not forget to update container->description in the setters of uuid and name */
	container->description =
		mem_printf("%s (%s)", container->name, uuid_string(container->uuid));

	/* initialize pid to a value indicating it is invalid */
	container->pid = -1;
	container->pid_early = -1;

	/* initialize exit_status to 0 */
	container->exit_status = 0;

	container->ns_usr = ns_usr;
	container->ns_net = ns_net;
	container->ns_ipc = file_exists("/proc/self/ns/ipc");

	/* Allow config_filename to be NULL for "configless"/"anonymous" containers */
	if (config_filename)
		container->config_filename = mem_strdup(config_filename);
	else
		container->config_filename = NULL;

	container->images_dir = mem_strdup(images_dir);
	if (mkdir(images_dir, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Cound not mkdir container directory %s", images_dir);
		goto error;
	}

	container->color = color;

	container->allow_autostart = allow_autostart;

	container->os = os;

	container->csock_list = NULL;
	container->observer_list = NULL;
	container->stop_timer = NULL;
	container->start_timer = NULL;

	container->ram_limit = ram_limit;
	container->cpus_allowed = (cpus_allowed) ? mem_strdup(cpus_allowed) : NULL;

	// virtual network interfaces from container config
	for (list_t *elem = vnet_cfg_list; elem != NULL; elem = elem->next) {
		container_vnet_cfg_t *vnet_cfg = elem->data;
		DEBUG("vnet: %s will be added to conatiner (%s)", vnet_cfg->vnet_name,
		      (vnet_cfg->configure) ? "configured" : "unconfigured");
	}
	container->vnet_cfg_list = vnet_cfg_list;

	// network interfaces from container config
	for (list_t *elem = pnet_cfg_list; elem != NULL; elem = elem->next) {
		container_pnet_cfg_t *pnet_cfg = elem->data;
		DEBUG("List element in net_ifaces: %s", pnet_cfg->pnet_name);
	}
	container->pnet_cfg_list = pnet_cfg_list;

	container->fifo_list = fifo_list;

	// construct an argv buffer for execve
	container->init_argv = init_argv;

	container->init = mem_strdup(init);
	// allocate and set init_env
	container->init_env_len = 0;
	container_init_env_prepend(container, init_env, init_env_len);

	container->dns_server = dns_server ? mem_strdup(dns_server) : NULL;
	container->device_allowed_list = allowed_devices;
	container->device_assigned_list = assigned_devices;
	container->usbdev_list = usbdev_list;

	container->setup_mode = false;

	container->token_type = ttype;

	container->usb_pin_entry = usb_pin_entry;
	container->is_synced = true;

	/* Create submodules */
	for (list_t *l = container_module_list; l; l = l->next) {
		container_module_t *module = l->data;
		if (module->container_new) {
			container_module_instance_t *c_mod =
				container_module_instance_new(container, module);
			if (!c_mod) {
				WARN("Could not initialize %s subsystem for container %s (UUID: %s)",
				     module->name, container->name, uuid_string(container->uuid));
				goto error;
			}
			container->module_instance_list =
				list_append(container->module_instance_list, c_mod);

			INFO("Initialized %s subsystem for container %s (UUID: %s)", module->name,
			     container->name, uuid_string(container->uuid));
		}
	}

	return container;

error:
	container_free(container);
	return NULL;
}

bool
container_uuid_is_c0id(const uuid_t *uuid)
{
	ASSERT(uuid);
	uuid_t *uuid_c0 = uuid_new("00000000-0000-0000-0000-000000000000");
	bool ret = uuid_equals(uuid, uuid_c0);
	uuid_free(uuid_c0);
	return ret;
}

void
container_init_env_prepend(container_t *container, char **init_env, size_t init_env_len)
{
	IF_TRUE_RETURN(init_env == NULL || init_env_len <= 0);

	// construct a NULL terminated env buffer for execve
	size_t total_len;
	if (__builtin_add_overflow(container->init_env_len, init_env_len, &total_len)) {
		WARN("Overflow detected when calculating buffer size for container's env");
		return;
	}
	if (__builtin_add_overflow(total_len, 1, &total_len)) {
		WARN("Overflow detected when calculating buffer size for container's env");
		return;
	}
	char **init_env_old = container->init_env;
	container->init_env = mem_new0(char *, total_len);

	size_t i = 0;
	for (; i < init_env_len; i++)
		container->init_env[i] = mem_strdup(init_env[i]);
	for (size_t j = 0; j < container->init_env_len; ++j)
		container->init_env[i + j] = mem_strdup(init_env_old[j]);

	if (init_env_old) {
		for (char **arg = init_env_old; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(init_env_old);
	}
	container->init_env_len = total_len;
}

void
container_free(container_t *container)
{
	ASSERT(container);

	/* free module instances */
	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_instance_free(c_mod);
	}
	list_delete(container->module_instance_list);

	container_free_key(container);

	uuid_free(container->uuid);
	mem_free0(container->name);

	for (list_t *l = container->csock_list; l; l = l->next) {
		container_sock_t *cs = l->data;
		mem_free0(cs->path);
		mem_free0(cs);
	}
	list_delete(container->csock_list);

	if (container->config_filename)
		mem_free0(container->config_filename);

	mem_free0(container->cpus_allowed);

	mem_free0(container->init);
	if (container->init_argv) {
		for (char **arg = container->init_argv; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(container->init_argv);
	}
	if (container->init_env) {
		for (char **arg = container->init_env; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(container->init_env);
	}

	if (container->dns_server)
		mem_free0(container->dns_server);
	mem_free0(container->device_allowed_list);
	mem_free0(container->device_assigned_list);

	for (list_t *l = container->usbdev_list; l; l = l->next) {
		mem_free0(l->data);
	}
	list_delete(container->usbdev_list);

	for (list_t *l = container->vnet_cfg_list; l; l = l->next) {
		container_vnet_cfg_t *vnet_cfg = l->data;
		mem_free0(vnet_cfg->vnet_name);
		mem_free0(vnet_cfg);
	}
	list_delete(container->vnet_cfg_list);

	for (list_t *l = container->pnet_cfg_list; l; l = l->next) {
		container_pnet_cfg_t *pnet_cfg = l->data;
		container_pnet_cfg_free(pnet_cfg);
	}
	list_delete(container->pnet_cfg_list);

	for (list_t *l = container->fifo_list; l; l = l->next) {
		mem_free0(l->data);
	}
	list_delete(container->fifo_list);

	mem_free0(container);
}

const uuid_t *
container_get_uuid(const container_t *container)
{
	ASSERT(container);
	return container->uuid;
}

const void *
container_get_guestos(const container_t *container)
{
	ASSERT(container);
	return container->os;
}

const char *
container_get_name(const container_t *container)
{
	ASSERT(container);
	return container->name;
}

const char *
container_get_images_dir(const container_t *container)
{
	ASSERT(container);
	return container->images_dir;
}

/* TODO think about setters for name etc.
 * Old references retrieved with the getter should not become
 * invalid! */

const char *
container_get_description(const container_t *container)
{
	ASSERT(container);
	return container->description;
}

pid_t
container_get_pid(const container_t *container)
{
	ASSERT(container);
	return container->pid;
}

pid_t
container_get_service_pid(const container_t *container)
{
	/* Determine PID of container's init */
	pid_t init = container_get_pid(container);
	if (init <= 0) {
		DEBUG("Could not determine PID of container's init");
		return -1;
	}

	/* Determine PID of container's zygote */
	pid_t zygote = proc_find(init, "main");
	if (zygote <= 0) {
		DEBUG("Could not determine PID of container's zygote");
		return -1;
	}

	/* Determine PID of container's trustme service */
	pid_t service = proc_find(zygote, "trustme.service");
	if (service <= 0) {
		DEBUG("Could not determine PID of container's service");
		return -1;
	}

	return service;
}

void
container_oom_protect_service(const container_t *container)
{
	ASSERT(container);

	pid_t service_pid = container_get_service_pid(container);
	if (service_pid < 0) {
		WARN("Could not determine PID of container's service to protect against low memory killer. Ignoring...");
		return;
	}

	DEBUG("Setting oom_adj of trustme service (PID %d) in container %s to -17", service_pid,
	      container_get_description(container));
	char *path = mem_printf("/proc/%d/oom_adj", service_pid);
	int ret = file_write(path, "-17", -1);
	if (ret < 0)
		ERROR_ERRNO("Failed to write to %s", path);
	mem_free0(path);
}

bool
container_get_sync_state(const container_t *container)
{
	ASSERT(container);
	return container->is_synced;
}

void
container_set_sync_state(container_t *container, bool state)
{
	ASSERT(container);
	container->is_synced = state;
}

int
container_get_exit_status(const container_t *container)
{
	ASSERT(container);
	return container->exit_status;
}

uint32_t
container_get_color(const container_t *container)
{
	ASSERT(container);
	return container->color;
}

char *
container_get_color_rgb_string(const container_t *container)
{
	ASSERT(container);
	return mem_printf("#%02X%02X%02X", (container->color >> 24) & 0xff,
			  (container->color >> 16) & 0xff, (container->color >> 8) & 0xff);
}

const char *
container_get_config_filename(const container_t *container)
{
	ASSERT(container);
	return container->config_filename;
}

bool
container_is_privileged(const container_t *container)
{
	ASSERT(container);
	return container_uuid_is_c0id(container->uuid);
}

/**
 * This function should be called only on a (physically) not-running container and
 * should make sure that the container and all its submodules are in the same
 * state they had immediately after their creation with _new().
 * Return values are not gathered, as the cleanup should just work as the system allows.
 * It also sets container state to rebooting if 'is_rebooting' is set and
 * stopped otherwise.
 */
static void
container_cleanup(container_t *container, bool is_rebooting)
{
	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->cleanup)
			continue;

		module->cleanup(c_mod->instance, is_rebooting);
	}

	container->pid = -1;
	container->pid_early = -1;

	/* timer can be removed here, because container is on the transition to the stopped state */
	if (container->stop_timer) {
		DEBUG("Remove container stop timer for %s", container_get_description(container));
		event_remove_timer(container->stop_timer);
		event_timer_free(container->stop_timer);
		container->stop_timer = NULL;
	}
	if (container->start_timer) {
		DEBUG("Remove container start timer for %s", container_get_description(container));
		event_remove_timer(container->start_timer);
		event_timer_free(container->start_timer);
		container->start_timer = NULL;
	}

	container_state_t state =
		is_rebooting ? CONTAINER_STATE_REBOOTING : CONTAINER_STATE_STOPPED;
	container_set_state(container, state);
}

void
container_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	ASSERT(data);

	container_t *container = data;

	TRACE("SIGCHLD handler called for container %s with PID %d",
	      container_get_description(container), container->pid);

	/* In the start function the childs init process gets set a process group which has
	 * the same pgid as its pid. We wait for all processes belonging to our container's
	 * process group, but only change the containers state to stopped if the init exited */
	pid_t container_pid = container->pid;
	pid_t pid = 0;
	int status = 0;
	while ((pid = waitpid(-(container_pid), &status, WNOHANG))) {
		if (pid == container_pid) {
			bool rebooting = false;
			if (WIFEXITED(status)) {
				INFO("Container %s terminated (init process exited with status=%d)",
				     container_get_description(container), WEXITSTATUS(status));
				container->exit_status = WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				INFO("Container %s killed by signal %d",
				     container_get_description(container), WTERMSIG(status));
				/* Since Kernel 3.4 reboot inside pid namspaces
				 * are signaled by SIGHUP (see manpage REBOOT(2)) */
				if (WTERMSIG(status) == SIGHUP)
					rebooting = true;
			} else {
				continue;
			}
			/* remove the sigchld callback for this container from the event loop */
			event_remove_signal(sig);
			event_signal_free(sig);
			/* cleanup and set states accordingly to notify observers */
			container_cleanup(container, rebooting);

		} else if (pid == -1) {
			if (errno == ECHILD) {
				DEBUG("Process group of container %s terminated completely",
				      container_get_description(container));
			} else {
				WARN_ERRNO("waitpid failed for container %s",
					   container_get_description(container));
			}
			break;
		} else {
			DEBUG("Reaped a child with PID %d for container %s", pid,
			      container_get_description(container));
		}
	}

	TRACE("No more childs to reap. Callback exiting...");
}

void
container_sigchld_early_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	container_t *container = data;
	ASSERT(container);

	pid_t pid;
	int status = 0;

	TRACE("SIGCHLD handler called for container %s early start child with PID %d",
	      container_get_description(container), container->pid);

	if ((pid = waitpid(container->pid_early, &status, WNOHANG)) > 0) {
		TRACE("Reaped early container child process: %d", pid);
		/* remove the sigchld callback for this early child from the event loop */
		event_remove_signal(sig);
		event_signal_free(sig);
		// cleanup if early child returned with an error
		if ((WIFEXITED(status) && WEXITSTATUS(status)) || WIFSIGNALED(status)) {
			container_set_state(container, CONTAINER_STATE_STOPPED);
			container->pid_early = -1;
		}
	}
}

static int
container_close_all_fds_cb(UNUSED const char *path, const char *file, UNUSED void *data)
{
	int fd = atoi(file);

	DEBUG("Closing file descriptor %d", fd);

	if (close(fd) < 0)
		WARN_ERRNO("Could not close file descriptor %d", fd);

	return 0;
}

static int
container_close_all_fds()
{
	if (dir_foreach("/proc/self/fd", &container_close_all_fds_cb, NULL) < 0) {
		WARN("Could not open /proc/self/fd directory, /proc not mounted?");
		return -1;
	}

	return 0;
}

static int
container_start_child(void *data)
{
	ASSERT(data);

	int ret = 0;

	container_t *container = data;
	char *kvm_root = mem_printf("/tmp/%s", uuid_string(container->uuid));

	/*******************************************************************/
	// wait on synchronization socket for start message code from parent
	// check if everything went ok in the parent (else goto error)
	char msg;
	if (read(container->sync_sock_child, &msg, 1) != 1) {
		WARN_ERRNO("Could not read from sync socket");
		goto error;
	}

	DEBUG("Received message from parent %d", msg);
	if (msg == CONTAINER_START_SYNC_MSG_STOP) {
		DEBUG("Received stop message, exiting...");
		return 0;
	}

	/* Reset umask and sigmask for /init */
	sigset_t sigset;
	umask(0);
	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);

	/* Make sure /init in node doesn`t kill CMLD daemon */
	if (setpgid(0, 0) < 0) {
		WARN("Could not move process group of container %s", container->name);
		goto error;
	}

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_child)
			continue;

		if ((ret = module->start_child(c_mod->instance)) < 0) {
			goto error;
		}
	}

	char *root = (container->type == CONTAINER_TYPE_KVM) ? kvm_root : "/";
	if (chdir(root) < 0) {
		WARN_ERRNO("Could not chdir to \"%s\" in container %s", root,
			   uuid_string(container->uuid));
		goto error;
	}

	// bind sockets in csock_list
	// make sure this is done *after* the c_vol hook, which brings the childs mounts into place
	for (list_t *l = container->csock_list; l; l = l->next) {
		container_sock_t *cs = l->data;
		sock_unix_bind(cs->sockfd, cs->path);
	}
	// send success message to parent
	DEBUG("Sending CONTAINER_START_SYNC_MSG_SUCCESS to parent");
	char msg_success = CONTAINER_START_SYNC_MSG_SUCCESS;
	if (write(container->sync_sock_child, &msg_success, 1) < 0) {
		WARN_ERRNO("Could not write to sync socket");
		goto error;
	}

	/* Block on socket until the next sync message is sent by the parent */
	if (read(container->sync_sock_child, &msg, 1) != 1) {
		WARN_ERRNO("Could not read from sync socket");
		goto error;
	}

	DEBUG("Received message from parent %d", msg);

	if (msg == CONTAINER_START_SYNC_MSG_STOP) {
		DEBUG("Received stop message, exiting...");
		return 0;
	}

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_pre_exec_child)
			continue;

		if ((ret = module->start_pre_exec_child(c_mod->instance)) < 0) {
			goto error;
		}
	}

	DEBUG("Will start %s after closing filedescriptors of %s", container->init,
	      container_get_description(container));

	DEBUG("init_argv:");
	for (char **arg = container->init_argv; *arg; arg++) {
		DEBUG("\t%s", *arg);
	}
	DEBUG("init_env:");
	for (char **arg = container->init_env; *arg; arg++) {
		DEBUG("\t%s", *arg);
	}

	if (container->type == CONTAINER_TYPE_KVM) {
		int fd_master;
		int pid = forkpty(&fd_master, NULL, NULL, NULL);

		if (pid == -1) {
			ERROR_ERRNO("Forkpty() failed!");
			goto error;
		}
		if (pid == 0) { // child
			char *const argv[] = { "/usr/bin/lkvm", "run", "-d", kvm_root, NULL };
			execv(argv[0], argv);
			WARN("Could not run exec for kvm container %s",
			     uuid_string(container->uuid));
		} else { // parent
			char buffer[128];
			ssize_t read_bytes;
			char *kvm_log =
				mem_printf("%s.kvm.log", container_get_images_dir(container));
			read_bytes = read(fd_master, buffer, 128);
			file_write(kvm_log, buffer, read_bytes);
			while ((read_bytes = read(fd_master, buffer, 128))) {
				file_write_append(kvm_log, buffer, read_bytes);
			}
			return CONTAINER_ERROR;
		}
	}

	if (container_get_state(container) != CONTAINER_STATE_SETUP) {
		DEBUG("After closing all file descriptors no further debugging info can be printed");
		if (container_close_all_fds()) {
			WARN("Closing all file descriptors failed, continuing anyway...");
		}
	}

	execve(container->init, container->init_argv, container->init_env);

	/* handle possibly empty rootfs in setup_mode */
	if (container_get_state(container) == CONTAINER_STATE_SETUP) {
		// fallback: if there is still no init, just idle to keep namespaces open
		event_reset();
		WARN("No init found for container '%s', just loop forever!",
		     uuid_string(container->uuid));
		event_loop();
	}

	WARN_ERRNO("Could not run exec for container %s", uuid_string(container->uuid));

	return CONTAINER_ERROR;

error:
	if (ret == 0) {
		ret = CONTAINER_ERROR;
	}

	// send error message to parent
	char msg_error = CONTAINER_START_SYNC_MSG_ERROR;
	if (write(container->sync_sock_child, &msg_error, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}

	// TODO call c_<module>_cleanup_child() hooks

	if (container_close_all_fds()) {
		WARN("Closing all file descriptors in container start error failed");
	}
	return ret; // exit the child process
}

static int
container_start_child_early(void *data)
{
	ASSERT(data);

	int ret = 0;

	container_t *container = data;

	close(container->sync_sock_parent);

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_child_early)
			continue;

		if ((ret = module->start_child_early(c_mod->instance)) < 0) {
			goto error;
		}
	}

	void *container_stack = NULL;
	/* Allocate node stack */
	if (!(container_stack = alloca(CLONE_STACK_SIZE))) {
		WARN_ERRNO("Not enough memory for allocating container stack");
		goto error;
	}
	void *container_stack_high = (void *)((const char *)container_stack + CLONE_STACK_SIZE);
	/* Set namespaces for node */
	/* set some basic and non-configurable namespaces */
	unsigned long clone_flags = 0;
	clone_flags |= SIGCHLD | CLONE_PARENT; // sig child to main process
	clone_flags |= CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID;
	if (container->ns_ipc)
		clone_flags |= CLONE_NEWIPC;

	container_module_instance_t *c_user =
		container_module_get_instance_by_name(container, "c_user");
	container_module_instance_t *c_net =
		container_module_get_instance_by_name(container, "c_net");
	// on reboots of c0 rejoin existing userns and netns
	if (container_uuid_is_c0id(container_get_uuid(container)) &&
	    container->prev_state == CONTAINER_STATE_REBOOTING) {
		if (c_user && c_user->module && c_user->module->join_ns) {
			IF_TRUE_GOTO((ret = c_user->module->join_ns(c_user->instance)) < 0, error);
		}
		if (c_net && c_net->module && c_net->module->join_ns) {
			IF_TRUE_GOTO((ret = c_net->module->join_ns(c_net->instance)) < 0, error);
		}
	} else {
		if (c_user && container->ns_usr)
			clone_flags |= CLONE_NEWUSER;
		if (c_net && container->ns_net)
			clone_flags |= CLONE_NEWNET;
	}

	container->pid = clone(container_start_child, container_stack_high, clone_flags, container);
	if (container->pid < 0) {
		ERROR_ERRNO("Double clone container failed");
		goto error;
	}

	char *msg_pid = mem_printf("%d", container->pid);
	if (write(container->sync_sock_child, msg_pid, strlen(msg_pid)) < 0) {
		ERROR_ERRNO("write pid '%s' to sync socket failed", msg_pid);
		goto error;
	}
	mem_free0(msg_pid);
	return 0;

error:
	if (ret == 0) {
		ret = CONTAINER_ERROR;
	}

	// send error message to parent
	char msg_error = CONTAINER_START_SYNC_MSG_ERROR;
	if (write(container->sync_sock_child, &msg_error, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}

	if (container_close_all_fds()) {
		WARN("Closing all file descriptors in container start error failed");
	}
	return ret; // exit the child process
}

static void
container_start_timeout_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);

	container_t *container = data;

	/* Only kill the container in case it is still in the booting state.
	 * If this is not the case then simply remove the timer and do nothing
	 * Note that we do NOT have a problem with repeated container starts
	 * and overlapping start timeouts since the start_timer is cleared in
	 * container_cleanup which is called by the SIGCHLD handler as soon
	 * as the container goes down. */
	if (container_get_state(container) == CONTAINER_STATE_BOOTING) {
		WARN("Reached container start timeout for container %s and the container is still booting."
		     " Killing it...",
		     container_get_description(container));
		/* kill container. SIGCHLD cb handles the cleanup and state change */
		container_kill(container);
	}

	DEBUG("Freeing container start timeout timer");
	event_timer_free(timer);
	container->start_timer = NULL;

	return;
}

static void
container_start_post_clone_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);

	char msg;
	container_t *container = data;

	DEBUG("Received event from child process %u", events);

	if (events == EVENT_IO_EXCEPT) {
		WARN("Received exception from child process");
		msg = CONTAINER_START_SYNC_MSG_ERROR;
	} else {
		// receive success or error message from started child
		if (read(fd, &msg, 1) != 1) {
			WARN_ERRNO("Could not read from sync socket");
			goto error;
		}
	}

	if (msg == CONTAINER_START_SYNC_MSG_ERROR) {
		WARN("Received error message from child process");
		return; // the child exits on its own and we cleanup in the sigchld handler
	}

	/********************************************************/
	/* on success call all c_<module>_start_pre_exec hooks */

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_pre_exec)
			continue;

		IF_TRUE_GOTO_WARN((module->start_pre_exec(c_mod->instance) < 0), error_pre_exec);
	}

	// skip setup of start timer and maintain SETUP state if in SETUP mode
	if (container_get_state(container) != CONTAINER_STATE_SETUP) {
		container_set_state(container, CONTAINER_STATE_BOOTING);

		/* register a timer to kill the container if it does not come up in time */
		container->start_timer = event_timer_new(CONTAINER_START_TIMEOUT, 1,
							 &container_start_timeout_cb, container);
		event_add_timer(container->start_timer);
	}

	/* Notify child to do its exec */
	char msg_go = CONTAINER_START_SYNC_MSG_GO;
	if (write(fd, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error;
	}

	/* Call all c_<module>_start_post_exec hooks */

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_post_exec)
			continue;

		IF_TRUE_GOTO_WARN(module->start_post_exec(c_mod->instance) < 0, error);
	}

	// if no service module is registered diretcly switch to state running
	container_module_instance_t *c_service =
		container_module_get_instance_by_name(container, "c_service");
	if (!c_service)
		container_set_state(container, CONTAINER_STATE_RUNNING);

	event_remove_io(io);
	event_io_free(io);
	close(fd);

	return;

error_pre_exec:
	DEBUG("A pre-exec container start error occured, stopping container");
	char msg_stop = CONTAINER_START_SYNC_MSG_STOP;
	if (write(fd, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error;
	}
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	return;
error:
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	container_kill(container);
}

static void
container_start_post_clone_early_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	int ret = 0;

	container_t *container = data;

	DEBUG("Received event from child process %u", events);

	if (events == EVENT_IO_EXCEPT) {
		ERROR("Received exception from child process");
		goto error_pre_clone;
	}

	// receive success or error message from started child
	char *pid_msg = mem_alloc0(34);
	if (read(container->sync_sock_parent, pid_msg, 33) <= 0) {
		WARN_ERRNO("Could not read from sync socket");
		mem_free0(pid_msg);
		goto error_pre_clone;
	}

	if (pid_msg[0] == CONTAINER_START_SYNC_MSG_ERROR) {
		WARN("Early child died with error!");
		mem_free0(pid_msg);
		goto error_pre_clone;
	}

	// release post_clone_early io handler
	event_remove_io(io);
	event_io_free(io);

	DEBUG("Received pid message from child %s", pid_msg);
	container->pid = atoi(pid_msg);
	mem_free0(pid_msg);

	/*********************************************************/
	/* REGISTER SOCKET TO RECEIVE STATUS MESSAGES FROM CHILD */
	event_io_t *sync_sock_parent_event =
		event_io_new(fd, EVENT_IO_READ, &container_start_post_clone_cb, container);
	event_add_io(sync_sock_parent_event);

	/* register SIGCHILD handler which sets the state and
	 * calls the appropriate cleanup functions if the child
	 * dies */
	event_signal_t *sig = event_signal_new(SIGCHLD, container_sigchld_cb, container);
	event_add_signal(sig);

	/*********************************************************/
	/* POST CLONE HOOKS */
	// execute all necessary c_<module>_start_post_clone hooks
	// goto error_post_clone on an error

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_post_clone)
			continue;

		if ((ret = module->start_post_clone(c_mod->instance)) < 0) {
			goto error_post_clone;
		}
	}

	/*********************************************************/
	/* NOTIFY CHILD TO START */
	char msg_go = CONTAINER_START_SYNC_MSG_GO;
	if (write(container->sync_sock_parent, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error_post_clone;
	}

	return;

error_pre_clone:
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	return;

error_post_clone:
	if (ret == 0)
		ret = CONTAINER_ERROR;
	char msg_stop = CONTAINER_START_SYNC_MSG_STOP;
	if (write(container->sync_sock_parent, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}
	container_kill(container);
	return;
}

int
container_start(container_t *container)
{
	ASSERT(container);

	if ((container_get_state(container) != CONTAINER_STATE_STOPPED) &&
	    (container_get_state(container) != CONTAINER_STATE_REBOOTING)) {
		ERROR("Container %s is not stopped and can therefore not be started",
		      container_get_description(container));
		return CONTAINER_ERROR;
	}

	int ret = 0;

	container_set_state(container, CONTAINER_STATE_STARTING);

	/*********************************************************/
	/* PRE CLONE HOOKS */

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_pre_clone)
			continue;

		if ((ret = module->start_pre_clone(c_mod->instance)) < 0) {
			goto error_pre_clone;
		}
	}

	/*********************************************************/
	/* PREPARE CLONE */

	void *container_stack = NULL;
	/* Allocate node stack */
	if (!(container_stack = alloca(CLONE_STACK_SIZE))) {
		WARN_ERRNO("Not enough memory for allocating container stack");
		goto error_pre_clone;
	}
	void *container_stack_high = (void *)((const char *)container_stack + CLONE_STACK_SIZE);

	unsigned long clone_flags = 0;
	clone_flags |= SIGCHLD;

	/* Create a socketpair for synchronization and save it in the container structure to be able to
	 * pass it around */
	int fd[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		WARN("Could not create socketpair for synchronization with child!");
		goto error_pre_clone;
	}
	container->sync_sock_parent = fd[0];
	container->sync_sock_child = fd[1];

	/*********************************************************/
	/* CLONE */

	// activate setup mode in perent and child
	if (container->setup_mode) {
		container_set_state(container, CONTAINER_STATE_SETUP);
		INFO("Container in setup mode!");
	}

	/* TODO find out if stack is only necessary with CLONE_VM */
	pid_t container_pid =
		clone(container_start_child_early, container_stack_high, clone_flags, container);
	if (container_pid < 0) {
		WARN_ERRNO("Clone container failed");
		goto error_pre_clone;
	}
	container->pid = container_pid;

	/* close the childs end of the sync sockets */
	close(container->sync_sock_child);

	/*********************************************************/
	/* REGISTER SOCKET TO RECEIVE STATUS MESSAGES FROM CHILD */
	event_io_t *sync_sock_parent_event =
		event_io_new(container->sync_sock_parent, EVENT_IO_READ,
			     &container_start_post_clone_early_cb, container);
	event_add_io(sync_sock_parent_event);

	// handler for early start child process which dies after double fork
	event_signal_t *sig = event_signal_new(SIGCHLD, container_sigchld_early_cb, container);
	event_add_signal(sig);

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->start_post_clone_early)
			continue;

		if ((ret = module->start_post_clone_early(c_mod->instance)) < 0) {
			goto error_post_clone;
		}
	}

	return 0;

error_pre_clone:
	container_cleanup(container, false);
	return ret;

error_post_clone:
	if (ret == 0)
		ret = CONTAINER_ERROR;
	char msg_stop = CONTAINER_START_SYNC_MSG_STOP;
	if (write(container->sync_sock_parent, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}
	container_kill(container);
	return ret;
}

void
container_kill(container_t *container)
{
	ASSERT(container);

	if (container_get_state(container) == CONTAINER_STATE_STOPPED) {
		DEBUG("Trying to kill stopped container... doing nothing.");
		return;
	}

	// TODO kill container (possibly register callback and wait non-blocking)
	DEBUG("Killing container %s with pid: %d", container_get_description(container),
	      container_get_pid(container));

	if (kill(container_get_pid(container), SIGKILL)) {
		ERROR_ERRNO("Failed to kill container %s", container_get_description(container));
	}
}

/* This callback determines the container's state and forces its shutdown,
 * when a container could not be stopped in time*/
static void
container_stop_timeout_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);

	container_t *container = data;
	DEBUG("Reached container stop timeout for container %s. Doing the kill now",
	      container_get_description(container));

	// kill container. sichld cb handles the cleanup and state change
	container_kill(container);

	event_timer_free(timer);
	container->stop_timer = NULL;

	return;
}

int
container_stop(container_t *container)
{
	ASSERT(container);

	int ret = 0;

	/* register timer with callback doing the kill, if stop fails */
	event_timer_t *container_stop_timer =
		event_timer_new(CONTAINER_STOP_TIMEOUT, 1, &container_stop_timeout_cb, container);
	event_add_timer(container_stop_timer);
	container->stop_timer = container_stop_timer;

	/* remove setup_mode for next run */
	if (container_get_state(container) == CONTAINER_STATE_SETUP)
		container_set_setup_mode(container, false);

	/* set state to shutting down (notifies observers) */
	container_set_state(container, CONTAINER_STATE_SHUTTING_DOWN);

	/* call stop hooks for c_* modules */
	DEBUG("Call stop hooks for modules");

	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->stop)
			continue;

		if ((ret = module->stop(c_mod->instance)) < 0) {
			DEBUG("Module '%s' could not be stopped successfully", module->name);
		}
	}

	// When the stop command was emitted, the TrustmeService tries to shut down the container
	// i.g. to terminate the container's init process.
	// we need to wait for the SIGCHLD signal for which we have a callback registered, which
	// does the cleanup and sets the state of the container to stopped.
	DEBUG("Stop container successfully emitted. Wait for child process to terminate (SICHLD)");

	return ret;
}

int
container_bind_socket_before_start(container_t *container, const char *path)
{
	ASSERT(container);

	container_sock_t *cs = mem_new0(container_sock_t, 1);
	if ((cs->sockfd = sock_unix_create(SOCK_STREAM)) < 0) {
		mem_free0(cs);
		return -1;
	}
	cs->path = mem_strdup(path);
	container->csock_list = list_append(container->csock_list, cs);

	return cs->sockfd;
}

int
container_bind_socket_after_start(UNUSED container_t *container, UNUSED const char *path)
{
	//	int sock = container_bind_socket_before_start(container, socket_type, path);
	//	// TODO find out what works and implement me
	//	// EITHER:
	//	char *bind_path = mem_printf("/proc/%s/root/%s", atoi(container->pid), path);
	//	sock_unix_bind(sock, path_into_ns);
	//
	//	// OR:
	//	// create a socketpair for synchronization
	//	int fd[2];
	//    pid_t pid;
	//    socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	//    pid = fork();
	//	if (pid == -1) {
	//		WARN_ERRNO("Fork failed");
	//		return -1;
	//	}
	//    if (pid == 0) {
	//		// TODO synchronization
	//		/* executed in child */
	//        close(fd[0]);
	//		char *mnt_ns_path = mem_printf("/proc/%s/ns/mnt", atoi(container->pid));
	//		ns_fd = open(mnt_ns_path, O_RDONLY);
	//		setns(ns_fd, 0); // switch into mount namespace of container
	//		sock_unix_bind(sock, path);
	//		exit(0);
	//    } else {
	//		/* executed in parent */
	//        close(fd[1]);
	//    }
	return 0;
}

int
container_snapshot(container_t *container)
{
	ASSERT(container);
	// TODO implement
	return 0;
}

static int
container_wipe_image_cb(const char *path, const char *name, UNUSED void *data)
{
	ASSERT(data);
	container_t *container = data;
	/* Only do the rest of the callback if the file name ends with .img */
	int len = strlen(name);
	if (len >= 4 && !strcmp(name + len - 4, ".img")) {
		char *image_path = mem_printf("%s/%s", path, name);
		DEBUG("Deleting image of container %s: %s", container_get_description(container),
		      image_path);
		if (unlink(image_path) == -1) {
			ERROR_ERRNO("Could not delete image %s", image_path);
		}
		mem_free0(image_path);
	}
	return 0;
}

int
container_wipe_finish(container_t *container)
{
	ASSERT(container);

	/* remove all images of the container */
	if (dir_foreach(container->images_dir, &container_wipe_image_cb, container) < 0) {
		WARN("Could not open %s images path for wiping container",
		     container_get_description(container));
		return -1;
	}
	return 0;
}

static void
container_wipe_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	ASSERT(container);

	/* skip if the container is not stopped */
	if (container_get_state(container) != CONTAINER_STATE_STOPPED)
		return;

	/* wipe the container */
	if (container_wipe_finish(container) < 0) {
		ERROR("Could not wipe container");
	}

	/* unregister observer */
	container_unregister_observer(container, cb);
}

int
container_wipe(container_t *container)
{
	ASSERT(container);

	INFO("Wiping container %s", container_get_description(container));

	if (container_get_state(container) != CONTAINER_STATE_STOPPED) {
		container_kill(container);

		/* Register observer to wait for completed container_stop */
		if (!container_register_observer(container, &container_wipe_cb, NULL)) {
			DEBUG("Could not register wipe callback");
			return -1;
		}
		return 0;
	} else {
		/* Container is already stopped */
		return container_wipe_finish(container);
	}
}

int
container_destroy(container_t *container)
{
	ASSERT(container);
	int ret = -1;

	INFO("Destroying container %s with uuid=%s", container_get_name(container),
	     uuid_string(container_get_uuid(container)));

	/* wipe the container */
	if (file_is_dir(container_get_images_dir(container))) {
		// wipe_finish only removes data images not configs */
		if ((ret = container_wipe_finish(container))) {
			ERROR("Could not wipe container");
			return ret;
		}
		if (rmdir(container_get_images_dir(container)))
			WARN("Could not delete leftover container dir");
	}

	/* call module hooks for destroy */
	for (list_t *l = container->module_instance_list; l; l = l->next) {
		container_module_instance_t *c_mod = l->data;
		container_module_t *module = c_mod->module;
		if (NULL == module->container_destroy)
			continue;

		module->container_destroy(c_mod->instance);
	}

	/* remove config files */
	if ((ret = unlink(container_get_config_filename(container))))
		ERROR_ERRNO("Can't delete config file!");
	return ret;
}

static void
container_notify_observers(container_t *container)
{
	for (list_t *l = container->observer_list; l; l = l->next) {
		container_callback_t *ccb = l->data;
		ccb->todo = true;
	}
	// call all observer callbacks
	for (list_t *l = container->observer_list; l;) {
		container_callback_t *ccb = l->data;
		if (ccb->todo) {
			ccb->todo = false;
			(ccb->cb)(container, ccb, ccb->data);

			if (container->observer_list)
				l = container->observer_list;
			else
				break;
		} else {
			l = l->next;
		}
	}
}

void
container_set_state(container_t *container, container_state_t state)
{
	ASSERT(container);

	if (container->state == state)
		return;

	// maintaining SETUP state in following cases
	if (container->state == CONTAINER_STATE_SETUP) {
		switch (state) {
		case CONTAINER_STATE_BOOTING:
		case CONTAINER_STATE_RUNNING:
			return;
		default:
			break;
		}
	}

	// save previous state
	container->prev_state = container->state;

	DEBUG("Setting container state: %d", state);
	container->state = state;

	container_notify_observers(container);
}

container_state_t
container_get_state(const container_t *container)
{
	ASSERT(container);
	return container->state;
}

container_state_t
container_get_prev_state(const container_t *container)
{
	ASSERT(container);
	return container->prev_state;
}

container_type_t
container_get_type(const container_t *container)
{
	ASSERT(container);
	return container->type;
}

container_callback_t *
container_register_observer(container_t *container,
			    void (*cb)(container_t *, container_callback_t *, void *), void *data)
{
	ASSERT(container);
	ASSERT(cb);

	container_callback_t *ccb = mem_new0(container_callback_t, 1);
	ccb->cb = cb;
	ccb->data = data;
	container->observer_list = list_append(container->observer_list, ccb);
	DEBUG("Container %s: callback %p registered (nr of observers: %d)",
	      container_get_description(container), CAST_FUNCPTR_VOIDPTR(cb),
	      list_length(container->observer_list));
	return ccb;
}

void
container_unregister_observer(container_t *container, container_callback_t *cb)
{
	ASSERT(container);
	ASSERT(cb);

	if (list_find(container->observer_list, cb)) {
		container->observer_list = list_remove(container->observer_list, cb);
		mem_free0(cb);
	}
	DEBUG("Container %s: callback %p unregistered (nr of observers: %d)",
	      container_get_description(container), CAST_FUNCPTR_VOIDPTR(cb),
	      list_length(container->observer_list));
}

const char *
container_get_key(const container_t *container)
{
	ASSERT(container);

	return container->key;
}

void
container_set_key(container_t *container, const char *key)
{
	ASSERT(container);
	ASSERT(key);

	if (container->key && !strcmp(container->key, key))
		return;

	container_free_key(container);

	container->key = strdup(key);

	container_notify_observers(container);
}

unsigned int
container_get_ram_limit(const container_t *container)
{
	ASSERT(container);

	return container->ram_limit;
}

const char *
container_get_cpus_allowed(const container_t *container)
{
	ASSERT(container);

	return container->cpus_allowed;
}

bool
container_get_allow_autostart(container_t *container)
{
	ASSERT(container);
	return container->allow_autostart;
}

const char *
container_get_dns_server(const container_t *container)
{
	ASSERT(container);
	return container->dns_server;
}

bool
container_has_netns(const container_t *container)
{
	ASSERT(container);
	return container->ns_net;
}

bool
container_has_userns(const container_t *container)
{
	ASSERT(container);
	return container->ns_usr;
}

const char **
container_get_dev_allow_list(const container_t *container)
{
	ASSERT(container);
	return (const char **)container->device_allowed_list;
}

const char **
container_get_dev_assign_list(const container_t *container)
{
	ASSERT(container);
	return (const char **)container->device_assigned_list;
}

list_t *
container_get_usbdev_list(const container_t *container)
{
	ASSERT(container);
	return container->usbdev_list;
}

void
container_set_setup_mode(container_t *container, bool setup)
{
	ASSERT(container);
	if (container->setup_mode == setup)
		return;

	container->setup_mode = setup;
}

bool
container_has_setup_mode(const container_t *container)
{
	ASSERT(container);
	return container->setup_mode;
}

container_vnet_cfg_t *
container_vnet_cfg_new(const char *if_name, const char *rootns_name, const uint8_t mac[6],
		       bool configure)
{
	IF_NULL_RETVAL(if_name, NULL);
	container_vnet_cfg_t *vnet_cfg = mem_new(container_vnet_cfg_t, 1);
	vnet_cfg->vnet_name = mem_strdup(if_name);
	memcpy(vnet_cfg->vnet_mac, mac, 6);
	vnet_cfg->rootns_name = rootns_name ? mem_strdup(rootns_name) : NULL;
	vnet_cfg->configure = configure;
	return vnet_cfg;
}

/**
 * Create a new container_pnet_cfg_t structure for physical NICs that should be
 * made accessible to a container.
 */
container_pnet_cfg_t *
container_pnet_cfg_new(const char *if_name_mac, bool mac_filter, list_t *mac_whitelist)
{
	container_pnet_cfg_t *pnet_cfg = mem_new0(container_pnet_cfg_t, 1);

	pnet_cfg->pnet_name = mem_strdup(if_name_mac);
	pnet_cfg->mac_filter = mac_filter;
	pnet_cfg->mac_whitelist = NULL;

	if (!mac_filter)
		return pnet_cfg;

	for (list_t *l = mac_whitelist; l; l = l->next) {
		uint8_t *mac = mem_alloc0(6);
		memcpy(mac, l->data, 6);
		pnet_cfg->mac_whitelist = list_append(pnet_cfg->mac_whitelist, mac);
	}

	return pnet_cfg;
}

void
container_pnet_cfg_free(container_pnet_cfg_t *pnet_cfg)
{
	IF_NULL_RETURN(pnet_cfg);

	for (list_t *l = pnet_cfg->mac_whitelist; l; l = l->next) {
		uint8_t *mac = l->data;
		mem_free0(mac);
	}
	list_delete(pnet_cfg->mac_whitelist);
	mem_free0(pnet_cfg);
}

void
container_vnet_cfg_free(container_vnet_cfg_t *vnet_cfg)
{
	IF_NULL_RETURN(vnet_cfg);
	if (vnet_cfg->vnet_name)
		mem_free0(vnet_cfg->vnet_name);
	if (vnet_cfg->rootns_name)
		mem_free0(vnet_cfg->rootns_name);
	mem_free0(vnet_cfg);
}

container_token_type_t
container_get_token_type(const container_t *container)
{
	ASSERT(container);
	return container->token_type;
}

bool
container_get_usb_pin_entry(const container_t *container)
{
	ASSERT(container);
	return container->usb_pin_entry;
}

list_t *
container_get_pnet_cfg_list(const container_t *container)
{
	ASSERT(container);
	return container->pnet_cfg_list;
}

list_t *
container_get_vnet_cfg_list(const container_t *container)
{
	ASSERT(container);
	return container->vnet_cfg_list;
}

list_t *
container_get_fifo_list(const container_t *container)
{
	ASSERT(container);
	return container->fifo_list;
}
