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

#include "container.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/list.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/uuid.h"
#include "compartment.h"

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

struct container {
	compartment_t *compartment;
	const void *os;		/* weak reference */
	unsigned int ram_limit; /* maximum RAM space the container may use */
	char *cpus_allowed;
	bool allow_autostart;
	uint32_t color;
	char *config_filename;
	char *images_dir;

	// list of allowed modules (names)
	list_t *module_allowed_list;

	// list of allowed devices (rules)
	char **device_allowed_list;

	// list of exclusively assigned devices (rules)
	char **device_assigned_list;

	// list of uevent_usbdev_t devices to allow/assign for container
	list_t *usbdev_list;

	// dns server for container which may be send by c_service submodule
	char *dns_server;

	container_token_type_t token_type;

	bool usb_pin_entry;

	// virtual network interfaces from container config
	list_t *vnet_cfg_list;
	// network interfaces from container config
	list_t *pnet_cfg_list;

	list_t *fifo_list;
};

struct container_callback {
	void (*cb)(container_t *, container_callback_t *, void *);
	compartment_callback_t *compartment_cb;
	void *data;
};

struct container_usbdev {
	char *i_serial;
	uint16_t id_vendor;
	uint16_t id_product;
	int major;
	int minor;
	bool assign;
	container_usbdev_type_t type;
};

static void
container_set_extension(void *extension_data, compartment_t *compartment)
{
	ASSERT(extension_data);
	ASSERT(compartment);

	container_t *container = extension_data;
	container->compartment = compartment;
}

container_t *
container_new(const uuid_t *uuid, const char *name, container_type_t type, bool ns_usr, bool ns_net,
	      const void *os, const char *config_filename, const char *images_dir,
	      unsigned int ram_limit, const char *cpus_allowed, uint32_t color,
	      bool allow_autostart, bool allow_system_time, const char *dns_server,
	      list_t *pnet_cfg_list, list_t *allowed_module_list, char **allowed_devices,
	      char **assigned_devices, list_t *vnet_cfg_list, list_t *usbdev_list, const char *init,
	      char **init_argv, char **init_env, size_t init_env_len, list_t *fifo_list,
	      container_token_type_t ttype, bool usb_pin_entry, bool xorg_compat)
{
	container_t *container = mem_new0(container_t, 1);

	/* Allow config_filename to be NULL for "configless"/"anonymous" compartments */
	container->config_filename = (config_filename) ? mem_strdup(config_filename) : NULL;

	container->images_dir = mem_strdup(images_dir);
	if (mkdir(images_dir, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Cound not mkdir compartment directory %s", images_dir);
		container_free(container);
		return NULL;
	}

	container->os = os;

	container->color = color;

	container->allow_autostart = allow_autostart;

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

	container->dns_server = dns_server ? mem_strdup(dns_server) : NULL;

	// module list from container config
	for (list_t *elem = allowed_module_list; elem != NULL; elem = elem->next) {
		char *mod_name = elem->data;
		DEBUG("List element in allowed_modules: %s", mod_name);
	}
	container->module_allowed_list = allowed_module_list;
	container->device_allowed_list = allowed_devices;
	container->device_assigned_list = assigned_devices;
	container->usbdev_list = usbdev_list;

	container->token_type = ttype;

	container->usb_pin_entry = usb_pin_entry;

	// set type specific flags for compartment
	uint64_t flags = 0;
	if (type == CONTAINER_TYPE_KVM)
		flags |= COMPARTMENT_FLAG_TYPE_KVM;
	else
		flags |= COMPARTMENT_FLAG_TYPE_CONTAINER;

	// set namespace flags for compartment
	if (ns_usr)
		flags |= COMPARTMENT_FLAG_NS_USER;
	if (ns_net)
		flags |= COMPARTMENT_FLAG_NS_NET;

	// set feature flags
	if (allow_system_time)
		flags |= COMPARTMENT_FLAG_SYSTEM_TIME;
	if (allowed_module_list)
		flags |= COMPARTMENT_FLAG_MODULE_LOAD;
	if (xorg_compat)
		flags |= COMPARTMENT_FLAG_XORG_COMPAT;

	// create internal compartment object with container as extension data
	compartment_extension_t *extension =
		compartment_extension_new(container_set_extension, container);
	container->compartment = compartment_new(uuid, name, flags, init, init_argv, init_env,
						 init_env_len, extension);

	if (!container->compartment) {
		ERROR("Could not create internal compartment object");
		compartment_extension_free(extension);
		container_free(container);
		return NULL;
	}

	// log output of compartment (only effective compartment has COMPARTMENT_FLAG_TYPE_KVM)
	compartment_set_debug_log_dir(container->compartment, images_dir);

	compartment_extension_free(extension);

	return container;
}

void
container_free(container_t *container)
{
	ASSERT(container);

	/*
	 * free compartment first, as c_*_free() may access
	 * container resources through extension pointer
	 */
	if (container->compartment)
		compartment_free(container->compartment);

	if (container->config_filename)
		mem_free0(container->config_filename);

	if (container->images_dir)
		mem_free0(container->images_dir);

	if (container->cpus_allowed)
		mem_free0(container->cpus_allowed);

	if (container->dns_server)
		mem_free0(container->dns_server);

	for (list_t *l = container->module_allowed_list; l; l = l->next) {
		mem_free0(l->data);
	}
	list_delete(container->module_allowed_list);

	if (container->device_allowed_list)
		mem_free0(container->device_allowed_list);
	if (container->device_assigned_list)
		mem_free0(container->device_assigned_list);

	for (list_t *l = container->usbdev_list; l; l = l->next) {
		container_usbdev_t *usbdev = l->data;
		container_usbdev_free(usbdev);
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

// ##################################################################
// wrappers for functionality/attributes implemented in compartment
// ##################################################################

static void
container_generic_compartment_observer_cb(compartment_t *compartment, compartment_callback_t *cb,
					  void *data)
{
	ASSERT(compartment);
	container_callback_t *container_cb = data;
	ASSERT(cb && cb == container_cb->compartment_cb);
	container_t *container = compartment_get_extension_data(compartment);

	container_cb->cb(container, container_cb, container_cb->data);
}

container_callback_t *
container_register_observer(container_t *container,
			    void (*cb)(container_t *, container_callback_t *, void *), void *data)
{
	ASSERT(container);
	ASSERT(cb);

	container_callback_t *container_cb = mem_new0(container_callback_t, 1);
	container_cb->cb = cb;
	container_cb->data = data;

	container_cb->compartment_cb = compartment_register_observer(
		container->compartment, container_generic_compartment_observer_cb, container_cb);
	if (!container_cb->compartment_cb) {
		ERROR("Failed to register observer on internal compartment object!");
		mem_free0(container_cb);
		return NULL;
	}

	return container_cb;
}

void
container_unregister_observer(container_t *container, container_callback_t *container_cb)
{
	ASSERT(container);
	ASSERT(container_cb);

	compartment_unregister_observer(container->compartment, container_cb->compartment_cb);
	mem_free0(container_cb);
}

void
container_finish_observers(container_t *container, void (*cb)(void *), void *data)
{
	ASSERT(container);
	ASSERT(cb);

	compartment_finish_observers(container->compartment, cb, data);
}

void
container_init_env_prepend(container_t *container, char **init_env, size_t init_env_len)
{
	ASSERT(container);
	compartment_init_env_prepend(container->compartment, init_env, init_env_len);
}

const uuid_t *
container_get_uuid(const container_t *container)
{
	ASSERT(container);
	return compartment_get_uuid(container->compartment);
}

bool
container_uuid_is_c0id(const uuid_t *uuid)
{
	ASSERT(uuid);
	return compartment_uuid_is_c0id(uuid);
}

const char *
container_get_name(const container_t *container)
{
	ASSERT(container);
	return compartment_get_name(container->compartment);
}

const char *
container_get_description(const container_t *container)
{
	ASSERT(container);
	return compartment_get_description(container->compartment);
}

pid_t
container_get_pid(const container_t *container)
{
	ASSERT(container);
	return compartment_get_pid(container->compartment);
}

pid_t
container_get_service_pid(const container_t *container)
{
	ASSERT(container);
	return compartment_get_service_pid(container->compartment);
}

void
container_oom_protect_service(const container_t *container)
{
	ASSERT(container);
	compartment_oom_protect_service(container->compartment);
}

bool
container_get_sync_state(const container_t *container)
{
	ASSERT(container);
	return compartment_get_sync_state(container->compartment);
}

void
container_set_sync_state(container_t *container, bool state)
{
	ASSERT(container);
	compartment_set_sync_state(container->compartment, state);
}

bool
container_is_privileged(const container_t *container)
{
	ASSERT(container);
	return compartment_is_privileged(container->compartment);
}

int
container_start(container_t *container)
{
	ASSERT(container);
	return compartment_start(container->compartment);
}

int
container_stop(container_t *container)
{
	ASSERT(container);
	return compartment_stop(container->compartment);
}

void
container_kill(container_t *container)
{
	ASSERT(container);
	compartment_kill(container->compartment);
}

int
container_bind_socket_before_start(container_t *container, const char *path)
{
	ASSERT(container);
	return compartment_bind_socket_before_start(container->compartment, path);
}

void
container_set_state(container_t *container, compartment_state_t state)
{
	ASSERT(container);
	compartment_set_state(container->compartment, state);
}

bool
container_is_stoppable(container_t *container)
{
	ASSERT(container);
	return compartment_is_stoppable(container->compartment);
}

bool
container_is_startable(container_t *container)
{
	ASSERT(container);
	return compartment_is_startable(container->compartment);
}

compartment_state_t
container_get_state(const container_t *container)
{
	ASSERT(container);
	return compartment_get_state(container->compartment);
}

compartment_state_t
container_get_prev_state(const container_t *container)
{
	ASSERT(container);
	return compartment_get_prev_state(container->compartment);
}

container_type_t
container_get_type(const container_t *container)
{
	ASSERT(container);
	uint64_t flags = compartment_get_flags(container->compartment);
	if (flags & COMPARTMENT_FLAG_TYPE_KVM)
		return CONTAINER_TYPE_KVM;

	return CONTAINER_TYPE_CONTAINER;
}

const char *
container_get_key(const container_t *container)
{
	ASSERT(container);
	return compartment_get_key(container->compartment);
}

void
container_set_key(container_t *container, const char *key)
{
	ASSERT(container);
	ASSERT(key);
	compartment_set_key(container->compartment, key);
}

bool
container_has_netns(const container_t *container)
{
	ASSERT(container);
	return compartment_has_netns(container->compartment);
}

bool
container_has_userns(const container_t *container)
{
	ASSERT(container);
	return compartment_has_userns(container->compartment);
}

void
container_set_setup_mode(container_t *container, bool setup)
{
	ASSERT(container);
	compartment_set_setup_mode(container->compartment, setup);
}

bool
container_has_setup_mode(const container_t *container)
{
	ASSERT(container);
	return compartment_has_setup_mode(container->compartment);
}

bool
container_contains_pid(const container_t *container, pid_t pid)
{
	ASSERT(container);
	return compartment_contains_pid(container->compartment, pid);
}

void
container_wait_for_child(container_t *container, char *name, pid_t pid)
{
	ASSERT(container);
	compartment_wait_for_child(container->compartment, name, pid);
}

// ##################################################################
// directly implemented in container
// ##################################################################

const void *
container_get_guestos(const container_t *container)
{
	ASSERT(container);
	return container->os;
}

const char *
container_get_images_dir(const container_t *container)
{
	ASSERT(container);
	return container->images_dir;
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

	/* remove all images of the compartment */
	if (dir_foreach(container->images_dir, &container_wipe_image_cb, container) < 0) {
		WARN("Could not open %s images path for wiping container",
		     container_get_description(container));
		return -1;
	}
	return 0;
}

static void
container_wipe_cb(compartment_t *compartment, compartment_callback_t *cb, void *data)
{
	ASSERT(compartment);
	container_t *container = data;

	/* skip if the compartment is not stopped */
	if (compartment_get_state(compartment) != COMPARTMENT_STATE_STOPPED)
		return;

	/* wipe the compartment */
	if (container_wipe_finish(container) < 0) {
		ERROR("Could not wipe compartment");
	}

	/* unregister observer */
	compartment_unregister_observer(compartment, cb);
}

int
container_wipe(container_t *container)
{
	ASSERT(container);

	INFO("Wiping container %s", container_get_description(container));

	if (container_get_state(container) != COMPARTMENT_STATE_STOPPED) {
		container_kill(container);

		/* Register observer to wait for completed compartment_stop */
		if (!compartment_register_observer(container->compartment, &container_wipe_cb,
						   container)) {
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
	int ret = 0;

	/* call destroy hooks of compartment modules */
	compartment_destroy(container->compartment);

	/* wipe the container */
	if (file_is_dir(container_get_images_dir(container))) {
		// wipe_finish only removes data images not configs
		if ((ret = container_wipe_finish(container))) {
			ERROR("Could not wipe container");
			return ret;
		}
		if (rmdir(container_get_images_dir(container)))
			WARN("Could not delete leftover container dir");
	}

	/* remove config files */
	if (unlink(container_get_config_filename(container)))
		WARN_ERRNO("Can't delete config file!");

	return ret;
}

const char *
container_get_config_filename(const container_t *container)
{
	ASSERT(container);
	return container->config_filename;
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

const list_t *
container_get_module_allow_list(const container_t *container)
{
	ASSERT(container);
	return (const list_t *)container->module_allowed_list;
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

container_usbdev_t *
container_usbdev_new(container_usbdev_type_t type, uint16_t id_vendor, uint16_t id_product,
		     char *i_serial, bool assign)
{
	container_usbdev_t *usbdev = mem_new0(container_usbdev_t, 1);
	usbdev->type = type;
	usbdev->id_vendor = id_vendor;
	usbdev->id_product = id_product;
	usbdev->i_serial = mem_strdup(i_serial);
	usbdev->assign = assign;
	usbdev->major = -1;
	usbdev->minor = -1;
	return usbdev;
}

void
container_usbdev_free(container_usbdev_t *usbdev)
{
	if (usbdev->i_serial)
		mem_free0(usbdev->i_serial);
	mem_free0(usbdev);
}

uint16_t
container_usbdev_get_id_vendor(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->id_vendor;
}

uint16_t
container_usbdev_get_id_product(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->id_product;
}

container_usbdev_type_t
container_usbdev_get_type(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->type;
}

char *
container_usbdev_get_i_serial(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->i_serial;
}

bool
container_usbdev_is_assigned(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->assign;
}

void
container_usbdev_set_major(container_usbdev_t *usbdev, int major)
{
	ASSERT(usbdev);
	usbdev->major = major;
}

void
container_usbdev_set_minor(container_usbdev_t *usbdev, int minor)
{
	ASSERT(usbdev);
	usbdev->minor = minor;
}

int
container_usbdev_get_major(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->major;
}

int
container_usbdev_get_minor(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->minor;
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

	mem_free0(pnet_cfg->pnet_name);
	mem_free0(pnet_cfg);
}

void
container_pnet_cfg_set_pnet_name(container_pnet_cfg_t *pnet_cfg, const char *pnet_name)
{
	IF_NULL_RETURN(pnet_cfg);

	if (pnet_cfg->pnet_name)
		mem_free0(pnet_cfg->pnet_name);

	pnet_cfg->pnet_name = mem_strdup(pnet_name);
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

bool
container_get_usb_pin_entry(const container_t *container)
{
	ASSERT(container);
	return container->usb_pin_entry;
}

/* Functions usually implemented and registered by c_user module */
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(setuid0, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(setuid0, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(shift_ids, int, void *, const char *, const char *,
				       const char *)
CONTAINER_MODULE_FUNCTION_WRAPPER4_IMPL(shift_ids, int, 0, const char *, const char *, const char *)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(get_uid, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(get_uid, int, 0)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(open_userns, int, void *)
CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(open_userns, int, 0)

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
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(device_allow, int, void *, char, int, int, bool)
CONTAINER_MODULE_FUNCTION_WRAPPER5_IMPL(device_allow, int, 0, char, int, int, bool)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(device_deny, int, void *, char, int, int)
CONTAINER_MODULE_FUNCTION_WRAPPER4_IMPL(device_deny, int, 0, char, int, int)
CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(is_device_allowed, bool, void *, char, int, int)
CONTAINER_MODULE_FUNCTION_WRAPPER4_IMPL(is_device_allowed, bool, true, char, int, int)
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
