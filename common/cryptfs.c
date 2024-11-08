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

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/ioctl.h>
#include <linux/unistd.h>
#include <linux/dm-ioctl.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/param.h>
#include <string.h>
#include <sys/mount.h>
#include <errno.h>
#include <linux/kdev_t.h>
#include <stdint.h>
#include <inttypes.h>

#include "cryptfs.h"
#include "macro.h"
#include "mem.h"
#include "proc.h"
#include "file.h"
#include "dm.h"

#define TABLE_LOAD_RETRIES 10
#define INTEGRITY_TAG_SIZE 32
#define CRYPTO_TYPE_AUTHENC "capi:authenc(hmac(sha256),xts(aes))-random"
#define CRYPTO_TYPE "aes-xts-plain64"

/* taken from vold */
#define DEVMAPPER_BUFFER_SIZE 4096
#define DM_CRYPT_BUF_SIZE 4096
#define DM_INTEGRITY_BUF_SIZE 4096

/* FIXME Rejig library to record & use errno instead */
#ifndef DM_EXISTS_FLAG
#define DM_EXISTS_FLAG 0x00000004
#endif

/******************************************************************************/

static unsigned long
get_provided_data_sectors(const char *real_blk_name);

char *
cryptfs_get_device_path_new(const char *label)
{
	return mem_printf("%s/%s", DM_PATH_PREFIX, label);
}

#if 0
/* Convert a binary key of specified length into an ascii hex string equivalent,
 * without the leading 0x and with null termination
 */
static void
convert_key_to_hex_ascii(unsigned char *master_key, unsigned int keysize,
			      char *master_key_ascii)
{
	unsigned int i, a;
	unsigned char nibble;

	for (i = 0, a = 0; i < keysize; i++, a += 2) {
		/* For each byte, write out two ascii hex digits */
		nibble = (master_key[i] >> 4) & 0xf;
		master_key_ascii[a] = nibble + (nibble > 9 ? 0x37 : 0x30);

		nibble = master_key[i] & 0xf;
		master_key_ascii[a + 1] = nibble + (nibble > 9 ? 0x37 : 0x30);
	}

	/* Add the null termination */
	master_key_ascii[a] = '\0';

}
#endif

static int
load_integrity_mapping_table(int fd, const char *real_blk_name, const char *meta_blk_name,
			     const char *name, int fs_size)
{
	// General variables
	int ioctl_ret;

	// Load mapping variables
	char mapping_buffer[DM_INTEGRITY_BUF_SIZE];
	struct dm_target_spec *tgt;
	struct dm_ioctl *mapping_io;
	char *integrity_params;
	char *extra_params = mem_printf("1 meta_device:%s", meta_blk_name);
	int mapping_counter;

	mapping_io = (struct dm_ioctl *)mapping_buffer;

	/* Load the mapping table for this device */
	tgt = (struct dm_target_spec *)&mapping_buffer[sizeof(struct dm_ioctl)];

	// Configure parameters for ioctl
	dm_ioctl_init(mapping_io, INDEX_DM_TABLE_LOAD, DM_INTEGRITY_BUF_SIZE, name, NULL, 0, 0, 0,
		      0);
	mapping_io->target_count = 1;
	tgt->status = 0;
	tgt->sector_start = 0;
	tgt->length = fs_size;
	strcpy(tgt->target_type, "integrity");

	// Write the intergity parameters at the end after dm_target_spec
	integrity_params = mapping_buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);

	// Write parameter
	// these parameters are used in [1] as well as by dmsetup when traced with strace
	snprintf(integrity_params,
		 DM_INTEGRITY_BUF_SIZE - sizeof(struct dm_ioctl) - sizeof(struct dm_target_spec),
		 "%s 0 %d J %s", real_blk_name, INTEGRITY_TAG_SIZE, extra_params);

	mem_free0(extra_params);

	// Set pointer behind parameter
	integrity_params += strlen(integrity_params) + 1;
	// Byte align the parameter
	integrity_params = (char *)(((unsigned long)integrity_params + 7) &
				    ~8); /* Align to an 8 byte boundary */
	// Set tgt->next right behind dm_target_spec
	tgt->next = integrity_params - mapping_buffer;

	for (mapping_counter = 0; mapping_counter < TABLE_LOAD_RETRIES; mapping_counter++) {
		ioctl_ret = dm_ioctl(fd, DM_TABLE_LOAD, mapping_io);

		if (ioctl_ret == 0) {
			DEBUG("DM_TABLE_LOAD successfully returned %d", ioctl_ret);
			break;
		}
		NANOSLEEP(0, 500000000)
	}

	// Check that loading the table worked
	if (mapping_counter >= TABLE_LOAD_RETRIES) {
		ERROR_ERRNO("Loading integrity mapping table did not work after %d tries",
			    mapping_counter);
		return -1;
	}
	return mapping_counter + 1;
}

static int
load_crypto_mapping_table(int fd, const char *real_blk_name, const char *master_key_ascii,
			  const char *name, int fs_size, bool integrity)
{
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	struct dm_target_spec *tgt;
	char *crypt_params;
	char *extra_params = integrity ? mem_printf("1 integrity:%d:aead", INTEGRITY_TAG_SIZE) :
					 mem_printf("1 allow_discards");

	const char *crypto_type = integrity ? CRYPTO_TYPE_AUTHENC : CRYPTO_TYPE;

	int i;
	int ioctl_ret;

	TRACE("Loading crypto mapping table (%s,%s,%s,%s,%d,%d)", real_blk_name, crypto_type,
	      master_key_ascii, name, fs_size, fd);

	io = (struct dm_ioctl *)buffer;

	/* Load the mapping table for this device */
	tgt = (struct dm_target_spec *)&buffer[sizeof(struct dm_ioctl)];

	dm_ioctl_init(io, INDEX_DM_TABLE_LOAD, DM_CRYPT_BUF_SIZE, name, NULL, DM_EXISTS_FLAG, 0, 0,
		      0);
	io->target_count = 1;
	tgt->status = 0;
	tgt->sector_start = 0;
	tgt->length = fs_size;
	strcpy(tgt->target_type, "crypt");

	crypt_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
	snprintf(crypt_params,
		 DM_CRYPT_BUF_SIZE - sizeof(struct dm_ioctl) - sizeof(struct dm_target_spec),
		 "%s %s 0 %s 0 %s", crypto_type, master_key_ascii, real_blk_name, extra_params);
	mem_free0(extra_params);

	crypt_params += strlen(crypt_params) + 1;
	crypt_params =
		(char *)(((unsigned long)crypt_params + 7) & ~8); /* Align to an 8 byte boundary */
	tgt->next = crypt_params - buffer;

	for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
		ioctl_ret = dm_ioctl(fd, DM_TABLE_LOAD, io);
		if (!ioctl_ret) {
			DEBUG("Loading device table successfull.");
			break;
		}
		NANOSLEEP(0, 500000000)
	}

	if (i == TABLE_LOAD_RETRIES) {
		/* We failed to load the table, return an error */
		ERROR_ERRNO("Loading crypto mapping table did not work after %d tries", i);
		return -1;
	} else {
		return i + 1;
	}
}

/**
 * Creates an integrity block device with DM_DEV_CREATE ioctl, reloads the mapping
 * table with DM_TABLE_LOADE ioctl and resumes the device with DM_DEV_SUSPEND ioctl
 *
 * [1] https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-integrity.html
 * [2] https://wiki.gentoo.org/wiki/Device-mapper#Integrity
 *
 * @return int 0 if successful, otherwise -1
 */
static int
create_integrity_blk_dev(const char *real_blk_name, const char *meta_blk_name, const char *name,
			 const unsigned long fs_size)
{
	int fd;
	int ioctl_ret;
	int load_count = -1;
	char create_buffer[DM_INTEGRITY_BUF_SIZE];
	struct dm_ioctl *create_io;
	int create_counter;

	// Open device mapper
	if ((fd = open(DM_CONTROL, O_RDWR)) < 0) {
		ERROR_ERRNO("Cannot open device-mapper");
	}

	// Create blk device
	// Initialize create_io struct
	create_io = (struct dm_ioctl *)create_buffer;
	dm_ioctl_init(create_io, INDEX_DM_DEV_CREATE, DM_INTEGRITY_BUF_SIZE, name, NULL, 0, 0, 0,
		      0);

	for (create_counter = 0; create_counter < TABLE_LOAD_RETRIES; create_counter++) {
		ioctl_ret = dm_ioctl(fd, DM_DEV_CREATE, create_io);
		if (!ioctl_ret) {
			DEBUG("Creating block device worked!");
			break;
		}

		NANOSLEEP(0, 500000000)
	}

	if (create_counter >= TABLE_LOAD_RETRIES) {
		ERROR_ERRNO("Failed to create block device after %d tries", create_counter);
		goto errout;
	}

	// Load Integrity map table
	DEBUG("Loading Integrity mapping table");

	load_count = load_integrity_mapping_table(fd, real_blk_name, meta_blk_name, name, fs_size);
	if (load_count < 0) {
		ERROR("Error while loading mapping table");
		goto errout;
	} else {
		INFO("Loading integrity map took %d tries", load_count);
	}

	// Resume this device to activate it
	DEBUG("Resuming the blk device");
	dm_ioctl_init(create_io, INDEX_DM_DEV_SUSPEND, DM_INTEGRITY_BUF_SIZE, name, NULL, 0, 0, 0,
		      0);

	ioctl_ret = dm_ioctl(fd, DM_DEV_SUSPEND, create_io);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("Cannot resume the dm-integrity device (ioctl ret: %d, errno:%d)",
			    ioctl_ret, errno);
		goto errout;
	}

	close(fd);
	return 0;

errout:
	ERROR("Failed integrity block creation");
	close(fd);
	return -1;
}

static int
create_crypto_blk_dev(const char *real_blk_name, const char *master_key, const char *name,
		      unsigned long fs_size, bool integrity)
{
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	int fd;
	int retval = -1;
	int load_count;
	int i;
	int ioctl_ret;

	DEBUG("Creating crypto blk device");
	if ((fd = open(DM_CONTROL, O_RDWR)) < 0) {
		ERROR("Cannot open device-mapper\n");
		goto errout;
	}

	io = (struct dm_ioctl *)buffer;
	dm_ioctl_init(io, INDEX_DM_DEV_CREATE, DM_CRYPT_BUF_SIZE, name, NULL, 0, 0, 0, 0);

	for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
		ioctl_ret = dm_ioctl(fd, DM_DEV_CREATE, io);

		if (!ioctl_ret) {
			DEBUG("Cryptp DM_DEV_CREATE worked!");
			break;
		}
		NANOSLEEP(0, 500000000)
	}

	if (i == TABLE_LOAD_RETRIES) {
		/* We failed to load the table, return an error */
		ERROR("Cannot create dm-crypt device");
		goto errout;
	}

	load_count =
		load_crypto_mapping_table(fd, real_blk_name, master_key, name, fs_size, integrity);
	if (load_count < 0) {
		ERROR("Cannot load dm-crypt mapping table");
		goto errout;
	} else if (load_count > 1) {
		INFO("Took %d tries to load dmcrypt table.\n", load_count);
	}

	/* Resume this device to activate it */
	dm_ioctl_init(io, INDEX_DM_DEV_SUSPEND, DM_CRYPT_BUF_SIZE, name, NULL, 0, 0, 0, 0);

	if (dm_ioctl(fd, DM_DEV_SUSPEND, io)) {
		ERROR_ERRNO("Cannot resume the dm-crypt device\n");
		goto errout;
	}

	/* We made it here with no errors.  Woot! */
	retval = 0;

errout:
	close(fd); /* If fd is <0 from a failed open call, it's safe to just ignore the close error */
	DEBUG("Returning %d from create_crypte_bkl_dev", retval);
	return retval;
}

/* TODO:
 * maybe we need to wait a bit before device is created
 */
static char *
create_device_node(const char *name)
{
	char *buffer = mem_new(char, DEVMAPPER_BUFFER_SIZE);

	int fd = open(DM_CONTROL, O_RDWR);
	if (fd < 0) {
		ERROR_ERRNO("Error opening devmapper");
		mem_free0(buffer);
		return NULL;
	}

	struct dm_ioctl *io = (struct dm_ioctl *)buffer;

	dm_ioctl_init(io, INDEX_DM_DEV_STATUS, DEVMAPPER_BUFFER_SIZE, name, NULL, 0, 0, 0, 0);
	if (dm_ioctl(fd, DM_DEV_STATUS, io)) {
		if (errno != ENXIO) {
			ERROR_ERRNO("DM_DEV_STATUS ioctl failed for lookup");
		}
		mem_free0(buffer);
		close(fd);
		return NULL;
	}
	close(fd);

	/* should not be necassery for android */
	mkdir("/dev/block", 00777);

	char *device = cryptfs_get_device_path_new(name);

	if (mknod(device, S_IFBLK | 00777, io->dev) != 0 && errno != EEXIST) {
		ERROR_ERRNO("Cannot mknod device %s", device);
		mem_free0(buffer);
		mem_free0(device);
		return NULL;
	} else if (errno == EEXIST) {
		DEBUG("Device %s already exists, continuing", device);
	}
	mem_free0(buffer);
	return device;
}

static int
delete_integrity_blk_dev(const char *name)
{
	int fd;
	char buffer[DM_INTEGRITY_BUF_SIZE];
	struct dm_ioctl *io;
	int ret = -1;

	fd = open(DM_CONTROL, O_RDWR);
	if (fd < 0) {
		ERROR_ERRNO("Cannot open device-mapper");
		goto error;
	}

	io = (struct dm_ioctl *)buffer;

	dm_ioctl_init(io, INDEX_DM_DEV_REMOVE, DM_INTEGRITY_BUF_SIZE, name, NULL, 0, 0, 0, 0);
	if (dm_ioctl(fd, DM_DEV_REMOVE, io) < 0) {
		ret = errno;
		if (errno != ENXIO)
			ERROR_ERRNO("Cannot remove dm-integrity device");
		goto error;
	}

	/* remove device node if necessary */
	char *device = cryptfs_get_device_path_new(name);
	unlink(device);
	mem_free0(device);

	DEBUG("Successfully deleted dm-integrity device");
	/* We made it here with no errors.  Woot! */
	ret = 0;

error:
	close(fd);
	return ret;
}

static unsigned long
get_provided_data_sectors(const char *real_blk_name)
{
	int fd;
	unsigned long provided_data_sectors = 0;
	char magic[8]; // "integrt" on a valid superblock

	if ((fd = open(real_blk_name, O_RDONLY)) < 0) {
		ERROR("Cannot open volume %s", real_blk_name);
		return 0;
	}

	int bytes_read = read(fd, magic, sizeof(magic));
	DEBUG("Bytes read: %d, '%s'", bytes_read, magic);
	if (bytes_read != sizeof(magic)) {
		ERROR("Cannot read superblock type from volume %s", real_blk_name);
		goto errout;
	}
	if (strcmp(magic, "integrt") != 0) {
		DEBUG("No existing integrity superblock detected on %s", real_blk_name);
		provided_data_sectors = 1;
		goto errout;
	}

	// 16 Bytes offset from start of superblock for provided_data_sectors
	lseek(fd, 16, SEEK_SET);
	bytes_read = read(fd, &provided_data_sectors, sizeof(provided_data_sectors));
	DEBUG("Read bytes is: %d", bytes_read);

	if (bytes_read != sizeof(provided_data_sectors) || provided_data_sectors == 0) {
		ERROR("Cannot read provided_data_sectors from volume %s", real_blk_name);
		goto errout;
	}

errout:
	DEBUG("Returning: provided_data_sectors= %ld", provided_data_sectors);
	close(fd);
	return provided_data_sectors;
}

static char *
cryptfs_setup_volume_integrity_new(const char *label, const char *real_blkdev,
				   const char *meta_blkdev, const char *key, unsigned long fs_size)
{
	bool initial_format = false;
	char *crypto_blkdev = NULL;
	char *integrity_dev_label = mem_printf("%s-%s", label, "integrity");
	TRACE("cryptfs_setup_volume_integrity_new");

	/* check if meta device is initialized */
	initial_format = get_provided_data_sectors(meta_blkdev) != fs_size;

	if (create_integrity_blk_dev(real_blkdev, meta_blkdev, integrity_dev_label, fs_size) < 0) {
		DEBUG("create_integrity_blk_dev failed!");
		goto error;
	}

	char *integrity_dev = create_device_node(integrity_dev_label);
	mem_free0(integrity_dev_label);
	if (!integrity_dev) {
		ERROR("Could not create device node");
		return NULL;
	} else {
		DEBUG("Successfully created device node");
	}

	if (create_crypto_blk_dev(integrity_dev, key, label, fs_size, true) < 0) {
		ERROR("Could not create crypto block device");
		return NULL;
	}

	crypto_blkdev = create_device_node(label);

	if (initial_format) {
		/*
		 * format crypto device, otherwise I/O errors may occur
		 * also during write attempts which are not bound to
		 * sector/block size for which no integrity data exist yet.
		 * This is due to the block has to be read first than.
		 */
		DEBUG("Formatting crypto blkdev %s. Generating initial MAC on "
		      "integrity_dev %s",
		      crypto_blkdev, integrity_dev);
		int fd;
		if ((fd = open(crypto_blkdev, O_WRONLY | O_DIRECT)) < 0) {
			ERROR("Cannot open volume %s", crypto_blkdev);
			goto error;
		}
		char zeros[DM_INTEGRITY_BUF_SIZE] __attribute__((__aligned__(512)));
		for (unsigned long i = 0; i < fs_size / 8; ++i) {
			if (write(fd, zeros, DM_INTEGRITY_BUF_SIZE) < DM_INTEGRITY_BUF_SIZE) {
				ERROR_ERRNO("Could not write empty block %lu to %s", i,
					    crypto_blkdev);
				close(fd);
				goto error;
			}
		}
		close(fd);
	}
	return crypto_blkdev;
error:
	mem_free0(integrity_dev_label);
	mem_free0(crypto_blkdev);
	return NULL;
}

char *
cryptfs_setup_volume_new(const char *label, const char *real_blkdev, const char *key,
			 const char *meta_blkdev)
{
	int fd;
	// The file system size in sectors
	uint64_t fs_size;

	/* Update the fs_size field to be the size of the volume */
	if ((fd = open(real_blkdev, O_RDONLY)) < 0) {
		ERROR("Cannot open volume %s", real_blkdev);
		return NULL;
	}
	// BLKGETSIZE64 returns size in bytes, we require size in sectors
	int sector_size = dm_get_blkdev_sector_size(fd);
	if (!(sector_size > 0)) {
		ERROR("dm_get_blkdev_sector_size returned %d\n", sector_size);
		return NULL;
	}
	fs_size = dm_get_blkdev_size64(fd) / sector_size;
	close(fd);

	if (fs_size == 0) {
		ERROR("Cannot get size of volume %s", real_blkdev);
		return NULL;
	}
	DEBUG("Crypto blk device size: %" PRIu64, fs_size);

	if (meta_blkdev)
		return cryptfs_setup_volume_integrity_new(label, real_blkdev, meta_blkdev, key,
							  fs_size);

	// do dmcrypt device setup only

	/* Use only the first 64 hex digits of master key for 512 bit xts mode */
	IF_TRUE_RETVAL(strlen(key) < CRYPTFS_FDE_KEY_LEN, NULL);
	char enc_key[CRYPTFS_FDE_KEY_LEN + 1];
	memcpy(enc_key, key, CRYPTFS_FDE_KEY_LEN);
	enc_key[CRYPTFS_FDE_KEY_LEN] = '\0';

	if (create_crypto_blk_dev(real_blkdev, enc_key, label, fs_size, false) < 0)
		return NULL;

	return create_device_node(label);
}

int
cryptfs_delete_blk_dev(int fd, const char *name)
{
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	int ret = -1;

	io = (struct dm_ioctl *)buffer;

	dm_ioctl_init(io, INDEX_DM_DEV_REMOVE, DM_CRYPT_BUF_SIZE, name, NULL, 0, 0, 0, 0);
	if (dm_ioctl(fd, DM_DEV_REMOVE, io) < 0) {
		ret = errno;
		if (errno != ENXIO)
			ERROR_ERRNO("Cannot remove dm-crypt device");
		goto error;
	}

	/* remove device node if necessary */
	char *device = cryptfs_get_device_path_new(name);
	unlink(device);
	mem_free0(device);

	DEBUG("Successfully deleted dm-crypt device");

	char *integrity_dev_name = mem_printf("%s-%s", name, "integrity");
	if (delete_integrity_blk_dev(integrity_dev_name) < 0) {
		mem_free0(integrity_dev_name);
		goto error;
	}

	mem_free0(integrity_dev_name);

	/* We made it here with no errors.  Woot! */
	ret = 0;

error:
	return ret;
}
