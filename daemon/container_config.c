/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "container_config.h"

#include "container.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/list.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"

#include <stdint.h>
#include <inttypes.h>

#include "cmld.h"
#include "crypto.h"
#include "guestos.h"
#include "guestos_mgr.h"
#include "network.h"
#include "hotplug.h"

struct container_config {
	char *file;
	ContainerConfig *cfg;
};

#define C_CONFIG_VERIFY_HASH_ALGO SHA512

#define C_CONFIG_MAX_RAM_LIMIT (1 << 30) // TODO 1GB? (< 4GB due to uint32)
#define C_CONFIG_MAX_STORAGE (4LL << 30) // TODO 4GB?

#ifndef C_CONFIG_DEFAULT_VETH_NAME
#define C_CONFIG_DEFAULT_VETH_NAME "host0"
#endif

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
container_type_t
container_config_proto_to_type(ContainerType type)
{
	switch (type) {
	case CONTAINER_TYPE__CONTAINER:
		return CONTAINER_TYPE_CONTAINER;
	case CONTAINER_TYPE__KVM:
		return CONTAINER_TYPE_KVM;
	default:
		FATAL("Unhandled value for ContainerType: %d", type);
	}
}

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
container_token_type_t
container_config_proto_to_token_type(ContainerTokenType type)
{
	switch (type) {
	case CONTAINER_TOKEN_TYPE__NONE:
		return CONTAINER_TOKEN_TYPE_NONE;
	case CONTAINER_TOKEN_TYPE__SOFT:
		return CONTAINER_TOKEN_TYPE_SOFT;
	case CONTAINER_TOKEN_TYPE__USB:
		return CONTAINER_TOKEN_TYPE_USB;
	case CONTAINER_TOKEN_TYPE__PKCS11:
		return CONTAINER_TOKEN_TYPE_PKCS11;
	default:
		FATAL("Unhandled value for ContainerTokenType: %d", type);
	}
}

static container_usbdev_type_t
container_config_proto_to_usb_type(ContainerUsbType type)
{
	switch (type) {
	case CONTAINER_USB_TYPE__GENERIC:
		return CONTAINER_USBDEV_TYPE_GENERIC;
	case CONTAINER_USB_TYPE__TOKEN:
		return CONTAINER_USBDEV_TYPE_TOKEN;
	case CONTAINER_USB_TYPE__PIN_ENTRY:
		return CONTAINER_USBDEV_TYPE_PIN_ENTRY;
	default:
		FATAL("Unhandled value for ContainerTokenType: %d", type);
	}
}

/******************************************************************************/

/**
 * This function verifies the container configuration file at load time
 * as part of TSF.CML.SecureCompartmentInit
 */
static bool
container_config_verify(const char *prefix, uint8_t *conf_buf, size_t conf_len, uint8_t *sig_buf,
			size_t sig_len, uint8_t *cert_buf, size_t cert_len)
{
	ASSERT(conf_buf);
	bool ret = false;

	uint8_t *sig = NULL;
	uint8_t *cert = NULL;

	off_t sig_size = sig_len;
	off_t cert_size = cert_len;

	if (!cmld_uses_signed_configs()) {
		TRACE("Signed configuration is disabled, skipping!");
		return true;
	}

	if (sig_buf && cert_buf) {
		TRACE("Copy buffers for sig and cert!");
		sig = mem_new0(uint8_t, sig_len);
		memcpy(sig, sig_buf, sig_len);
		cert = mem_new0(uint8_t, cert_len);
		memcpy(cert, cert_buf, cert_len);
	} else {
		TRACE("Read sig and cert from files!");
		char *sig_file = mem_printf("%s.sig", prefix);
		char *cert_file = mem_printf("%s.cert", prefix);
		sig_size = file_size(sig_file);
		if (sig_size > 0) {
			sig = mem_alloc(sig_size);
			if (-1 == file_read(sig_file, (char *)sig, sig_size)) {
				ERROR("Failed to read sig file '%s'!", sig_file);
				mem_free0(sig);
				sig = NULL;
			}
		}
		cert_size = file_size(cert_file);
		if (cert_size > 0) {
			cert = mem_alloc(cert_size);
			if (-1 == file_read(cert_file, (char *)cert, cert_size)) {
				ERROR("Failed to read cert file '%s'!", cert_file);
				mem_free0(cert);
				cert = NULL;
			}
		}
		mem_free0(sig_file);
		mem_free0(cert_file);
	}

	// check cert and signature buffers
	IF_TRUE_GOTO(cert_size <= 0 || sig_size <= 0 || cert == NULL || sig == NULL, out);

	crypto_verify_result_t verify_result = crypto_verify_buf_block(
		conf_buf, conf_len, sig, sig_size, cert, cert_size, C_CONFIG_VERIFY_HASH_ALGO);

	ret = (verify_result == VERIFY_GOOD) ? true : false;
out:
	INFO("Verify Result of target with prefix '%s': %s", prefix, ret ? "GOOD" : "UNSIGNED");

	mem_free0(sig);
	mem_free0(cert);
	return ret;
}

container_config_t *
container_config_new(const char *file, const uint8_t *buf, size_t len, uint8_t *sig_buf,
		     size_t sig_len, uint8_t *cert_buf, size_t cert_len)
{
	ContainerConfig *ccfg = NULL;
	uint8_t *buf_internal = NULL;
	container_config_t *config = NULL;

	ASSERT(file);
	off_t conf_len = len;

	char *prefix = mem_strdup(file);
	size_t file_len = strlen(file);

	IF_TRUE_GOTO(file_len < 5 || strcmp(file + file_len - 5, ".conf"), out);

	prefix[file_len - 5] = '\0';

	// check if config comes from buffer or needs to be read from file
	if (buf == NULL) {
		DEBUG("Loading container config from file \"%s\".", file);
		conf_len = file_size(file);
		if (conf_len > 0) {
			buf_internal = mem_alloc(conf_len);
			if (-1 == file_read(file, (char *)buf_internal, conf_len)) {
				mem_free0(buf_internal);
				buf_internal = NULL;
			}
		}
	} else {
		DEBUG("Loading container config from buf storing to file \"%s\".", file);
		buf_internal = mem_new0(uint8_t, conf_len);
		memcpy(buf_internal, buf, conf_len);
	}

	if (!container_config_verify(prefix, buf_internal, conf_len, sig_buf, sig_len, cert_buf,
				     cert_len)) {
		ERROR("Failed verify signature of container config for file \"%s\".", file);
		goto out;
	}

	ccfg = (ContainerConfig *)protobuf_message_new_from_buf(buf_internal, conf_len,
								&container_config__descriptor);
	if (!ccfg) {
		WARN("Failed loading container config from buf");
		goto out;
	}

	// if config was provided by buf, update all files according to buffers
	if (buf) {
		if (-1 == file_write(file, (char *)buf, conf_len)) {
			WARN("Could not store configuration in file \"%s\".", file);
		} else if (cmld_uses_signed_configs()) {
			char *sig_file = mem_printf("%s.sig", prefix);
			char *cert_file = mem_printf("%s.cert", prefix);

			if (-1 == file_write(sig_file, (char *)sig_buf, sig_len))
				WARN("Could not update sig_file '%s'", sig_file);
			if (-1 == file_write(cert_file, (char *)cert_buf, cert_len))
				WARN("Could not update cert_file '%s'", cert_file);
		}
	}

	config = mem_new0(container_config_t, 1);
	config->file = mem_strdup(file);
	config->cfg = ccfg;
out:
	mem_free0(buf_internal);
	mem_free0(prefix);
	return config;
}

void
container_config_free(container_config_t *config)
{
	ASSERT(config);
	protobuf_free_message((ProtobufCMessage *)config->cfg);
	mem_free0(config->file);
	mem_free0(config);
}

int
container_config_write(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	ASSERT(config->file);

	if (cmld_uses_signed_configs()) {
		INFO("Signed configuration is enabled, skip writing in memory structure to disk!");
		return 0;
	}

	if (protobuf_message_write_to_file(config->file, (ProtobufCMessage *)config->cfg) < 0) {
		WARN("Could not write container config to \"%s\"", config->file);
		return -1;
	}

	return 0;
}

const char *
container_config_get_name(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->name;
}

void
container_config_set_name(container_config_t *config, UNUSED const char *name)
{
	ASSERT(config);
	ASSERT(config->cfg);
	if (config->cfg->name)
		mem_free0(config->cfg->name);
	config->cfg->name = mem_strdup(name);
}

const char *
container_config_get_guestos(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->guest_os;
}

void
container_config_set_guestos(container_config_t *config, const char *os)
{
	ASSERT(config);
	ASSERT(config->cfg);
	if (config->cfg->guest_os)
		mem_free0(config->cfg->guest_os);
	config->cfg->guest_os = mem_strdup(os);
}

unsigned int
container_config_get_ram_limit(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->ram_limit;
}

void
container_config_set_ram_limit(container_config_t *config, unsigned int ram_limit)
{
	ASSERT(config);
	ASSERT(config->cfg);
	// TODO sanity checks for max. number of potatoes, etc.
	if (ram_limit > C_CONFIG_MAX_RAM_LIMIT) {
		WARN("Cannot set ram_limit to %d, maximum is %d.", ram_limit,
		     C_CONFIG_MAX_RAM_LIMIT);
		return;
	}
	config->cfg->ram_limit = ram_limit;
}

void
container_config_fill_mount(const container_config_t *config, mount_t *mnt)
{
	ASSERT(config);
	ASSERT(config->cfg);

	// get size and real image name for each user-generated partition from container config
	ContainerConfig *cfg = config->cfg;
	for (size_t i = 0; i < cfg->n_image_sizes; i++) {
		char *name = cfg->image_sizes[i]->image_name;
		char *file = cfg->image_sizes[i]->image_file;
		ASSERT(name);
		mount_entry_t *mntent = mount_get_entry_by_img(mnt, name);
		if (!mntent) {
			WARN("Unknown mount entry \"%s\" in config for container \"%s\", skipping!",
			     name, cfg->name);
			continue;
		}

		// update alternative image file name if container provides containerspecific image
		// e.g. in guestos mige file name is ids but container should use ids-core
		mount_entry_set_img(mntent, file);

		if ((mount_entry_get_type(mntent) == MOUNT_TYPE_EMPTY) ||
		    (mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RW)) {
			uint64_t size = cfg->image_sizes[i]->image_size;
			mount_entry_set_size(mntent, size);
		} else {
			ERROR("Forbidden: Cannot override image size for mount entry \"%s\" "
			      "in config for container \"%s\"!",
			      name, cfg->name);
		}
	}
}

uint64_t
container_config_get_guestos_version(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->guestos_version;
}

void
container_config_set_guestos_version(container_config_t *config, uint64_t guestos_version)
{
	ASSERT(config);
	ASSERT(config->cfg);
	config->cfg->has_guestos_version = true;
	config->cfg->guestos_version = guestos_version;
}

list_t *
container_config_get_net_ifaces_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	list_t *net_ifaces_list = NULL;
	for (size_t i = 0; i < config->cfg->n_net_ifaces; i++) {
		bool mac_filter_enabled = config->cfg->net_ifaces[i]->n_mac_filter > 0;
		list_t *mac_whitelist = NULL;
		// check if MAC filtering is configured
		if (mac_filter_enabled) {
			// create list of whitelisted MAC adresses
			for (size_t j = 0; j < config->cfg->net_ifaces[i]->n_mac_filter; j++) {
				INFO("MAC Filter on for %s: allow '%s'",
				     config->cfg->net_ifaces[i]->netif,
				     config->cfg->net_ifaces[i]->mac_filter[j]);

				uint8_t *whitelisted_mac = mem_new(uint8_t, 6);
				if (0 != network_str_to_mac_addr(
						 config->cfg->net_ifaces[i]->mac_filter[j],
						 whitelisted_mac)) {
					mem_free0(whitelisted_mac);
				} else {
					mac_whitelist = list_append(mac_whitelist, whitelisted_mac);
				}
			}
		} else {
			INFO("MAC Filter off for %s: allow any MAC",
			     config->cfg->net_ifaces[i]->netif);
		}
		container_pnet_cfg_t *pnet_cfg = container_pnet_cfg_new(
			config->cfg->net_ifaces[i]->netif, mac_filter_enabled, mac_whitelist);
		if (pnet_cfg == NULL) {
			ERROR("Failed to create container_pnet_cfg for %s",
			      config->cfg->net_ifaces[i]->netif);
			continue;
		}

		// append to net_ifaces_list
		net_ifaces_list =
			list_append(net_ifaces_list, pnet_cfg); // append to net_ifaces_list
	}
	return net_ifaces_list;
}

list_t *
container_config_get_module_allow_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	list_t *module_list = NULL;
	for (size_t i = 0; i < config->cfg->n_allow_module; ++i) {
		module_list = list_append(module_list, mem_strdup(config->cfg->allow_module[i]));
	}
	return module_list;
}

char **
container_config_get_dev_allow_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	size_t total_len = ADD_WITH_OVERFLOW_CHECK(config->cfg->n_allow_dev, (size_t)1);
	char **dev_whitelist = mem_new0(char *, total_len);
	for (size_t i = 0; i < config->cfg->n_allow_dev; i++) {
		dev_whitelist[i] = mem_strdup(config->cfg->allow_dev[i]);
	}
	dev_whitelist[config->cfg->n_allow_dev] = NULL;
	return dev_whitelist;
}

char **
container_config_get_dev_assign_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	size_t total_len = ADD_WITH_OVERFLOW_CHECK(config->cfg->n_assign_dev, (size_t)1);
	char **dev_assign_list = mem_new0(char *, total_len);
	for (size_t i = 0; i < config->cfg->n_assign_dev; i++) {
		dev_assign_list[i] = mem_strdup(config->cfg->assign_dev[i]);
	}
	dev_assign_list[config->cfg->n_assign_dev] = NULL;
	return dev_assign_list;
}

const char *
container_config_get_dns_server(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->dns_server;
}

void
container_config_append_net_ifaces(const container_config_t *config, const char *iface)
{
	ASSERT(config);
	ASSERT(config->cfg);

	size_t n = config->cfg->n_net_ifaces++;
	ContainerPnetConfig **old_net_ifaces = config->cfg->net_ifaces;

	size_t total_len = ADD_WITH_OVERFLOW_CHECK(n, (size_t)1);
	config->cfg->net_ifaces = mem_new(ContainerPnetConfig *, total_len);

	for (size_t i = 0; i < n; i++) {
		ContainerPnetConfig *pnet_iface = mem_new(ContainerPnetConfig, 1);
		container_pnet_config__init(pnet_iface);
		pnet_iface->netif = mem_strdup(old_net_ifaces[i]->netif);
		pnet_iface->n_mac_filter = old_net_ifaces[i]->n_mac_filter;
		for (size_t j = 0; j < pnet_iface->n_mac_filter; j++) {
			pnet_iface->mac_filter[j] = mem_strdup(old_net_ifaces[i]->mac_filter[j]);
		}
		protobuf_free_message((ProtobufCMessage *)old_net_ifaces[i]);
		config->cfg->net_ifaces[i] = pnet_iface;
	}
	if (n > 0)
		mem_free0(old_net_ifaces);

	ContainerPnetConfig *pnet_iface = mem_new(ContainerPnetConfig, 1);
	container_pnet_config__init(pnet_iface);
	pnet_iface->netif = mem_strdup(iface);
	pnet_iface->n_mac_filter = 0;
	config->cfg->net_ifaces[n] = pnet_iface;
}

void
container_config_remove_net_ifaces(const container_config_t *config, const char *iface)
{
	ASSERT(config);
	ASSERT(config->cfg);

	int n = config->cfg->n_net_ifaces;
	int nremove = 0;
	ContainerPnetConfig **old_net_ifaces = config->cfg->net_ifaces;

	for (int i = 0; i < n; i++) {
		if (!strcmp(iface, old_net_ifaces[i]->netif))
			nremove++;
	}
	if (nremove == 0)
		return;

	config->cfg->net_ifaces = mem_new0(ContainerPnetConfig *, n - nremove);
	config->cfg->n_net_ifaces = n - nremove;

	for (int i = 0, j = 0; i < n; i++) {
		if (strcmp(iface, old_net_ifaces[i]->netif)) {
			ContainerPnetConfig *pnet_iface = mem_new(ContainerPnetConfig, 1);
			container_pnet_config__init(pnet_iface);
			pnet_iface->netif = mem_strdup(old_net_ifaces[i]->netif);
			pnet_iface->n_mac_filter = old_net_ifaces[i]->n_mac_filter;
			for (size_t k = 0; k < pnet_iface->n_mac_filter; k++) {
				pnet_iface->mac_filter[k] =
					mem_strdup(old_net_ifaces[i]->mac_filter[k]);
			}
			config->cfg->net_ifaces[j++] = pnet_iface;
		}
		protobuf_free_message((ProtobufCMessage *)old_net_ifaces[i]);
	}
	mem_free0(old_net_ifaces);
}

list_t *
container_config_get_vnet_cfg_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	list_t *if_cfg_list = NULL;
	for (size_t i = 0; i < config->cfg->n_vnet_configs; ++i) {
		uint8_t mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 };
		if (config->cfg->vnet_configs[i]->if_mac == NULL) {
			INFO("Generating new mac for if %s", config->cfg->vnet_configs[i]->if_name);
			if (file_read("/dev/urandom", (char *)mac, 6) < 0) {
				WARN_ERRNO("Failed to read from /dev/urandom");
			}
			config->cfg->vnet_configs[i]->if_mac = network_mac_addr_to_str_new(mac);
		} else {
			INFO("Using mac %s for if %s", config->cfg->vnet_configs[i]->if_mac,
			     config->cfg->vnet_configs[i]->if_name);
			if (network_str_to_mac_addr(config->cfg->vnet_configs[i]->if_mac, mac) ==
			    -1)
				WARN_ERRNO("Failed to parse mac from config!");
		}
		// sanitize mac veth otherwise kernel may reject the mac
		mac[0] &= 0xfe; /* clear multicast bit */
		mac[0] |= 0x02; /* set local assignment bit (IEEE802) */

		container_vnet_cfg_t *if_cfg =
			container_vnet_cfg_new(config->cfg->vnet_configs[i]->if_name,
					       config->cfg->vnet_configs[i]->if_rootns_name, mac,
					       config->cfg->vnet_configs[i]->configure);
		if_cfg_list = list_append(if_cfg_list, if_cfg);
	}

	if (if_cfg_list == NULL) {
		list_t *nw_name_list = NULL;
		nw_name_list = list_append(nw_name_list, C_CONFIG_DEFAULT_VETH_NAME);
		for (list_t *l = nw_name_list; l != NULL; l = l->next) {
			char *if_name = l->data;
			uint8_t mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 };
			if (file_read("/dev/urandom", (char *)mac, 6) < 0) {
				WARN_ERRNO("Failed to read from /dev/urandom");
			}
			mac[0] &= 0xfe; /* clear multicast bit */
			mac[0] |= 0x02; /* set local assignment bit (IEEE802) */
			container_vnet_cfg_t *if_cfg =
				container_vnet_cfg_new(if_name, NULL, mac, true);
			if_cfg_list = list_append(if_cfg_list, if_cfg);
		}
		list_delete(nw_name_list);
	}
	return if_cfg_list;
}

list_t *
container_config_get_usbdev_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	list_t *usbdev_list = NULL;
	for (size_t i = 0; i < config->cfg->n_usb_configs; ++i) {
		uint16_t vendor, product;
		sscanf(config->cfg->usb_configs[i]->id, "%hx:%hx", &vendor, &product);
		container_usbdev_t *usbdev = container_usbdev_new(
			container_config_proto_to_usb_type(config->cfg->usb_configs[i]->type),
			vendor, product, config->cfg->usb_configs[i]->serial,
			config->cfg->usb_configs[i]->assign);
		usbdev_list = list_append(usbdev_list, usbdev);
	}
	return usbdev_list;
}

size_t
container_config_get_init_env_len(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->n_init_env;
}

char **
container_config_get_init_env(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->init_env;
}

size_t
container_config_get_fifos_len(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->n_fifos;
}
char **
container_config_get_fifos(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->fifos;
}

container_token_type_t
container_config_get_token_type(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return container_config_proto_to_token_type(config->cfg->token_type);
}

char *
container_config_get_usbtoken_serial(const container_config_t *config)
{
	if (container_config_get_token_type(config) != CONTAINER_TOKEN_TYPE_USB) {
		return NULL;
	}
	for (size_t i = 0; i < config->cfg->n_usb_configs; i++) {
		if (config->cfg->usb_configs[i]->type == CONTAINER_USB_TYPE__TOKEN) {
			return config->cfg->usb_configs[i]->serial;
		}
	}
	return NULL;
}

bool
container_config_get_usb_pin_entry(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->usb_pin_entry;
}

const char *
container_config_get_cpus_allowed(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->assign_cpus;
}

bool
container_config_get_allow_autostart(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->allow_autostart;
}

bool
container_config_get_allow_system_time(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->allow_system_time;
}

bool
container_config_get_enable_xorg_compat(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->enable_xorg_compat;
}

const char *
container_config_get_pkcs11_module(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->pkcs11_module;
}

// hardcode some restricted config otpions in CC Mode
#ifdef CC_MODE
uint32_t
container_config_get_color(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	if (config->cfg->color != 0)
		WARN("Ignoring color in CC Mode. Setting default: '0'.");
	return 0;
}

container_type_t
container_config_get_type(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	if (container_config_proto_to_type(config->cfg->type) != CONTAINER_TYPE_CONTAINER)
		WARN("Ignoring container type in CC Mode. Setting default: 'CONTAINER_TYPE_CONTAINER'.");
	return CONTAINER_TYPE_CONTAINER;
}

bool
container_config_has_netns(UNUSED const container_config_t *config)
{
	return true;
}

bool
container_config_has_userns(UNUSED const container_config_t *config)
{
	return true;
}
#else
uint32_t
container_config_get_color(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->color;
}

container_type_t
container_config_get_type(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return container_config_proto_to_type(config->cfg->type);
}

bool
container_config_has_netns(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->netns;
}

bool
container_config_has_userns(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->userns;
}
#endif /* CC_MODE */
