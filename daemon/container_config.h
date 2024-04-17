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

/**
 * @file container_config.h
 *
 * This container configuration module implements abstract settings
 * that represent the configuration of a container.
 * The configuration can be loaded and stored in a file
 * using protobuf.
 */

#ifndef C_CONFIG_H
#define C_CONFIG_H

#include "common/list.h"

#include "container.h"
#include "mount.h"

#include <stdint.h>
#include <stdbool.h>

typedef struct container_config container_config_t;

/**
 * Create a new container_config object which can be used to parse or write a
 * configuration to a given filename.
 * Signature/Certificate buffers and corresponding lenght are optional and may
 * set to zero/NULL if configuration should not be integrity protected.
 *
 * @param filename Representation of the config on disk. Must NOT be NULL. If
 * the file exists it is used to initially fill the container_config object.
 * @param buf Config buffer to initialize the config object. If the config
 * file at filename already exists, the config buffer supersedes the content
 * of the config file.
 * @param len Length of the given buf.
 * @param sig_buf buffer containing the signature of the configuration
 * @param sig_len length of the given sig_buf
 * @param cert_buf buffer containing the certificate of the configuration
 * @param cert_len length of the given cert_buf
 * @return The new container_config_t object or NULL on an error.
 */
container_config_t *
container_config_new(const char *file, const uint8_t *buf, size_t len, uint8_t *sig_buf,
		     size_t sig_len, uint8_t *cert_buf, size_t cert_len);

/**
 * Release the container_config_t object.
 */
void
container_config_free(container_config_t *config);

int
container_config_write(const container_config_t *config);

/*************************/
/* GETTER + SETTER       */
/*************************/

/**
 * Get the container name.
 */
const char *
container_config_get_name(const container_config_t *config);

/**
 * Set the container name.
 */
void
container_config_set_name(container_config_t *config, const char *name);

/**
 * Get the 'guest' operating system type.
 */
const char *
container_config_get_guestos(const container_config_t *config);

/**
 * Set the 'guest' operating system type.
 */
void
container_config_set_guestos(container_config_t *config, const char *operatingsystem);

/**
 * Get the configured maximum RAM amount the container may use.
 */
unsigned int
container_config_get_ram_limit(const container_config_t *config);

/**
 * Set the maximum RAM amount the container may use.
 */
void
container_config_set_ram_limit(container_config_t *config, unsigned int ram_limit);

/**
 * Get the configured cpus which are assigned to a container.
 */
const char *
container_config_get_cpus_allowed(const container_config_t *config);

void
container_config_fill_mount(const container_config_t *config, mount_t *mnt);

uint32_t
container_config_get_color(const container_config_t *config);

container_type_t
container_config_get_type(const container_config_t *config);

uint64_t
container_config_get_guestos_version(const container_config_t *config);

void
container_config_set_guestos_version(container_config_t *config, uint64_t guestos_version);

/**
 * Indicates whether the container is allowed to be started automatically after a0.
 */
bool
container_config_get_allow_autostart(const container_config_t *config);

/**
 * Indicates whether the container is allowed to modify the system time.
 */
bool
container_config_get_allow_system_time(const container_config_t *config);

/**
 * Provides the list of network interfaces assigned to the container from the container's config file
 */
list_t *
container_config_get_net_ifaces_list_new(const container_config_t *config);

/**
 * Provides the list of modules explicitely allowed for the container
 *
 * Module loading is only allowed if the kernel enforces signatures.
 * Further, the acctual modules are loaded from the cmld's mount view.
 * Thus, no binary from the container itself is passed to the kernel.
 */
list_t *
container_config_get_module_allow_list_new(const container_config_t *config);

/**
 * Provides the list of hardware devices explicitely allowed for the container from the container's config file
 */
char **
container_config_get_dev_allow_list_new(const container_config_t *config);

/**
 * Provides the list of hardware devices exclusively assigned to the container from the container's config file
 */

char **
container_config_get_dev_assign_list_new(const container_config_t *config);

/**
 * Get the dns_server ip addr set for the container.
 */
const char *
container_config_get_dns_server(const container_config_t *config);

/**
 * Indicates whether the container has an own network namespace
 */
bool
container_config_has_netns(const container_config_t *config);

/**
 * Indicates whether the container has an own user namespace
 */
bool
container_config_has_userns(const container_config_t *config);

/**
 * Adds the given interface name to the list of network interfaces assigned to the container
 */
void
container_config_append_net_ifaces(const container_config_t *config, const char *iface);

/**
 * Removes the given interface name from the list of network interfaces assigned to the container
 */
void
container_config_remove_net_ifaces(const container_config_t *config, const char *iface);

/**
 * Reads the container config for vnet interfaces and returns a list of the
 * corresponding container_vnet_cfg structures.
 */
list_t *
container_config_get_vnet_cfg_list_new(const container_config_t *config);

/**
 * Reads the container config for usb devices and returns a list
 * of the corresponding uevent_usbdev_t structures.
 */
list_t *
container_config_get_usbdev_list_new(const container_config_t *config);

/**
 * Returns the container specific array used to appened to evn buffer on start
 */
char **
container_config_get_init_env(const container_config_t *cfg);

/**
 * Returns the size of init env array
 */
size_t
container_config_get_init_env_len(const container_config_t *cfg);

size_t
container_config_get_fifos_len(const container_config_t *config);

char **
container_config_get_fifos(const container_config_t *config);

/**
 * Returns the type of the token which is used for encryption
 */
container_token_type_t
container_config_get_token_type(const container_config_t *config);

char *
container_config_get_usbtoken_serial(const container_config_t *config);

bool
container_config_get_usb_pin_entry(const container_config_t *config);

bool
container_config_get_enable_xorg_compat(const container_config_t *config);

const char *
container_config_get_pkcs11_module(const container_config_t *config);

#endif /* C_CONFIG_H */
