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
  * @file c_vol.c
  *
  * This module is responsible for mounting images (for a container, at its startup) into the filesystem.
  * It is capable of utilizing a decryption key for mounting encrypted images. When a new container thread
  * gets cloned, the root directory of the images filesystem (and e.g. the proc, sys, dev directories) is/are
  * created and the image is mounted there together with a chroot.
  */

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define _LARGEFILE64_SOURCE

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define MOD_NAME "c_vol"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/loopdev.h"
#include "common/cryptfs.h"
#include "common/dir.h"
#include "common/proc.h"
#include "common/sock.h"
#include "common/str.h"
#include "common/dm.h"
#include "common/event.h"

#include "cmld.h"
#include "guestos.h"
#include "guestos_mgr.h"
#include "lxcfs.h"
#include "audit.h"
#include "verity.h"

#include <unistd.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

#define MAKE_EXT4FS "mkfs.ext4"
#define BTRFSTUNE "btrfstune"
#define MAKE_BTRFS "mkfs.btrfs"
#define MDEV "mdev"

#define SHARED_FILES_PATH DEFAULT_BASE_PATH "/files_shared"
#define SHARED_FILES_STORE_SIZE 100

#define BUSYBOX_PATH "/bin/busybox"

#ifndef FALLOC_FL_ZERO_RANGE
#define FALLOC_FL_ZERO_RANGE 0x10
#endif

typedef struct c_vol {
	container_t *container;
	char *root;
	int overlay_count;
	const guestos_t *os;
	mount_t *mnt;
	mount_t *mnt_setup;
} c_vol_t;

/******************************************************************************/

/**
 * Allocate a new string with the full image path for one mount point.
 * TODO store img_path in mount_entry_t instances themselves?
 * @return A newly allocated string with the image path.
 */
static char *
c_vol_image_path_new(c_vol_t *vol, const mount_entry_t *mntent)
{
	const char *dir;

	ASSERT(vol);
	ASSERT(mntent);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
	case MOUNT_TYPE_SHARED_RW:
	case MOUNT_TYPE_FLASH:
	case MOUNT_TYPE_OVERLAY_RO:
		dir = guestos_get_dir(vol->os);
		break;
	case MOUNT_TYPE_DEVICE:
	case MOUNT_TYPE_DEVICE_RW:
	case MOUNT_TYPE_EMPTY:
	case MOUNT_TYPE_COPY:
	case MOUNT_TYPE_OVERLAY_RW:
		// Note: this is the upper img for overlayfs
		dir = container_get_images_dir(vol->container);
		break;
	case MOUNT_TYPE_BIND_FILE:
	case MOUNT_TYPE_BIND_FILE_RW:
		return mem_printf("%s/%s", SHARED_FILES_PATH, mount_entry_get_img(mntent));
	case MOUNT_TYPE_BIND_DIR:
		// Note: We just bind mount any absolut path of the host
		return mem_strdup(mount_entry_get_img(mntent));
	default:
		ERROR("Unsupported operating system mount type %d for %s",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		return NULL;
	}

	return mem_printf("%s/%s.img", dir, mount_entry_get_img(mntent));
}

static char *
c_vol_meta_image_path_new(c_vol_t *vol, const mount_entry_t *mntent)
{
	const char *dir;

	ASSERT(vol);
	ASSERT(mntent);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_DEVICE:
	case MOUNT_TYPE_DEVICE_RW:
	case MOUNT_TYPE_EMPTY:
	case MOUNT_TYPE_COPY:
	case MOUNT_TYPE_OVERLAY_RW:
		// Note: this is the upper img for overlayfs
		dir = container_get_images_dir(vol->container);
		break;
	default:
		ERROR("Unsupported operating system mount type %d for %s (intergity meta_device)",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		return NULL;
	}

	return mem_printf("%s/%s.meta.img", dir, mount_entry_get_img(mntent));
}

static char *
c_vol_hash_image_path_new(c_vol_t *vol, const mount_entry_t *mntent)
{
	const char *dir = NULL;

	ASSERT(vol);
	ASSERT(mntent);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
	case MOUNT_TYPE_SHARED_RW:
		dir = guestos_get_dir(vol->os);
		break;
	default:
		ERROR("Unsupported operating system mount type %d for %s (dm-verity hash device)",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
	}

	return mem_printf("%s/%s.hash.img", dir, mount_entry_get_img(mntent));
}

/**
 * Check wether a container image is ready to be mounted.
 * @return On error -1 is returned, otherwise 0.
 */
static int
c_vol_check_image(c_vol_t *vol, const char *img)
{
	int ret;

	ASSERT(vol);
	ASSERT(img);

	ret = access(img, F_OK);

	if (ret < 0)
		DEBUG_ERRNO("Could not access image file %s", img);
	else
		DEBUG("Image file %s seems to be fine", img);

	return ret;
}

static int
c_vol_create_sparse_file(const char *img, off64_t storage_size)
{
	int fd;

	ASSERT(img);

	INFO("Creating empty image file %s with %llu bytes", img, (unsigned long long)storage_size);

	fd = open(img, O_LARGEFILE | O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		ERROR_ERRNO("Could not open image file %s", img);
		return -1;
	}

	// create a sparse file without writing any data
	if (ftruncate64(fd, storage_size) < 0) {
		ERROR_ERRNO("Could not ftruncate image file %s", img);
		close(fd);
		return -1;
	}

	if (lseek64(fd, storage_size - 1, SEEK_SET) < 0) {
		ERROR_ERRNO("Could not lseek image file %s", img);
		close(fd);
		return -1;
	}

	if (write(fd, "\0", 1) < 1) {
		ERROR_ERRNO("Could not write to image file %s", img);
		close(fd);
		return -1;
	}

	// also allocate with  zeros for dm-integrity
	if (fallocate(fd, FALLOC_FL_ZERO_RANGE, 0, storage_size)) {
		ERROR_ERRNO("Could not write to image file %s", img);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int
c_vol_create_image_empty(const char *img, const char *img_meta, uint64_t size)
{
	off64_t storage_size;
	ASSERT(img);

	// minimal storage size is 10 MB
	storage_size = MAX(size, 10);
	storage_size *= 1024 * 1024;

	IF_TRUE_RETVAL(-1 == c_vol_create_sparse_file(img, storage_size), -1);

	if (img_meta) {
		off64_t meta_size = storage_size * MOUNT_DM_INTEGRITY_META_FACTOR;
		IF_TRUE_RETVAL(-1 == c_vol_create_sparse_file(img_meta, meta_size), -1);
	}

	return 0;
}

static int
c_vol_btrfs_regen_uuid(const char *dev)
{
	const char *const argv_regen[] = { BTRFSTUNE, "-f", "-u", dev, NULL };
	return proc_fork_and_execvp(argv_regen);
}

static int
c_vol_create_image_copy(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	const char *dir;
	char *src;
	int ret;

	dir = guestos_get_dir(vol->os);
	if (!dir) {
		ERROR("Could not get directory with operating system images");
		return -1;
	}

	src = mem_printf("%s/%s.img", dir, mount_entry_get_img(mntent));

	DEBUG("Copying file %s to %s", src, img);
	ret = file_copy_zero(src, img, -1, 0);
	if (ret < 0)
		ERROR("Could not copy file %s to %s", src, img);

	if (!strcmp("btrfs", mount_entry_get_fs(mntent))) {
		INFO("Regenerate UUID for btrfs filesystem on %s", img);
		ret = c_vol_btrfs_regen_uuid(img);
	}

	mem_free0(src);
	return ret;
}

static int
c_vol_create_image_device(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	const char *dev;
	int ret;

	ASSERT(vol);
	ASSERT(img);
	ASSERT(mntent);

	dev = mount_entry_get_img(mntent);
	if (!dev) {
		ERROR("Could not get block device path for hardware");
		return -1;
	}
	if (dev[0] != '/') {
		ERROR("Block device path %s is not absolute", dev);
		return -1;
	}

	ret = file_copy(dev, img, -1, 512, 0);
	if (ret < 0)
		ERROR("Could not copy file %s to %s", dev, img);

	return ret;
}

static int
c_vol_create_image(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	INFO("Creating image %s", img);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
	case MOUNT_TYPE_SHARED_RW:
		return 0;
	case MOUNT_TYPE_OVERLAY_RW:
	case MOUNT_TYPE_EMPTY: {
		char *img_meta = c_vol_meta_image_path_new(vol, mntent);
		int ret = c_vol_create_image_empty(img, img_meta, mount_entry_get_size(mntent));
		mem_free0(img_meta);
		return ret;
	}
	case MOUNT_TYPE_FLASH:
		return -1; // we cannot create such image files
	case MOUNT_TYPE_COPY:
		return c_vol_create_image_copy(vol, img, mntent);
	case MOUNT_TYPE_DEVICE:
	case MOUNT_TYPE_DEVICE_RW:
		return c_vol_create_image_device(vol, img, mntent);
	default:
		ERROR("Unsupported operating system mount type %d for %s",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		return -1;
	}

	return 0;
}

static int
c_vol_format_image(const char *dev, const char *fs)
{
	const char *mkfs_bin = NULL;
	if (0 == strcmp("ext4", fs)) {
		mkfs_bin = MAKE_EXT4FS;
	} else if (0 == strcmp("btrfs", fs)) {
		mkfs_bin = MAKE_BTRFS;
	} else {
		ERROR("Could not create filesystem of type %s on %s", fs, dev);
		return -1;
	}
	const char *const argv_mkfs[] = { mkfs_bin, dev, NULL };
	return proc_fork_and_execvp(argv_mkfs);
}

static int
c_vol_btrfs_create_subvol(const char *dev, const char *mount_data)
{
	IF_NULL_RETVAL(mount_data, -1);

	int ret = 0;
	char *token = mem_strdup(mount_data);
	char *subvol = strtok(token, "=");
	subvol = strtok(NULL, "=");
	if (NULL == subvol) {
		mem_free0(token);
		return -1;
	}

	char *subvol_path = NULL;
	char *tmp_mount = mem_strdup("/tmp/tmp.XXXXXX");
	tmp_mount = mkdtemp(tmp_mount);
	if (NULL == tmp_mount) {
		ret = -1;
		goto out;
	}
	if (-1 == (ret = mount(dev, tmp_mount, "btrfs", 0, 0))) {
		ERROR_ERRNO("temporary mount of btrfs root volume %s failed", dev);
		goto out;
	}
	subvol_path = mem_printf("%s/%s", tmp_mount, subvol);

	const char *const argv_list[] = { "btrfs", "subvol", "list", subvol_path, NULL };
	if (-1 == (ret = proc_fork_and_execvp(argv_list))) {
		const char *const argv_create[] = { "btrfs", "subvol", "create", subvol_path,
						    NULL };
		if (-1 == (ret = proc_fork_and_execvp(argv_create))) {
			ERROR_ERRNO("Could not create btrfs subvol %s", subvol);
		} else {
			INFO("Created new suvol %s on btrfs device %s", subvol, dev);
		}
	}
	if (-1 == (ret = umount(tmp_mount))) {
		ERROR_ERRNO("Could not umount temporary mount of btrfs root volume %s!", dev);
	}
out:
	if (tmp_mount)
		unlink(tmp_mount);
	if (subvol_path)
		mem_free0(subvol_path);
	if (tmp_mount)
		mem_free0(tmp_mount);
	if (token)
		mem_free0(token);
	return ret;
}

static int
c_vol_mount_overlay(c_vol_t *vol, const char *target_dir, const char *upper_fstype,
		    const char *lowerfs_type, int mount_flags, const char *mount_data,
		    const char *upper_dev, const char *lower_dev, const char *overlayfs_mount_dir)

{
	char *lower_dir, *upper_dir, *work_dir;
	lower_dir = upper_dir = work_dir = NULL;
	upper_dev = (upper_dev) ? upper_dev : "tmpfs";

	TRACE("Creating overlayfs mount directory %s\n", overlayfs_mount_dir);

	// create mountpoints for lower and upper dev
	if (dir_mkdir_p(overlayfs_mount_dir, 0755) < 0) {
		ERROR_ERRNO("Could not mkdir overlayfs dir %s", overlayfs_mount_dir);
		return -1;
	}
	lower_dir = mem_printf("%s-lower", overlayfs_mount_dir);
	upper_dir = mem_printf("%s/upper", overlayfs_mount_dir);
	work_dir = mem_printf("%s/work", overlayfs_mount_dir);

	TRACE("Mounting dev %s type %s to dir %s", upper_dev, upper_fstype, overlayfs_mount_dir);

	/*
	 * mount backing fs image for overlayfs upper and work dir
	 * (at least upper and work need to be on the same fs)
	 */
	if (mount(upper_dev, overlayfs_mount_dir, upper_fstype, mount_flags, mount_data) < 0) {
		ERROR_ERRNO("Could not mount %s to %s", upper_dev, overlayfs_mount_dir);
		goto error;
	}

	DEBUG("Successfully mounted %s to %s", upper_dev, overlayfs_mount_dir);

	TRACE("Creating upper dir %s and work dir %s\n", upper_dir, work_dir);

	// create mountpoint for upper dev
	if (dir_mkdir_p(upper_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir upper dir %s", upper_dir);
		goto error;
	}
	if (dir_mkdir_p(work_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir work dir %s", work_dir);
		goto error;
	}
	// create mountpoint for lower dev
	if (lower_dev) {
		TRACE("Creating mount dir %s for lower dir", lower_dir);
		if (dir_mkdir_p(lower_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir lower dir %s", lower_dir);
			goto error;
		}
		TRACE("Mounting dev %s type %s to dir %s", lower_dev, lower_dir, lowerfs_type);
		// mount ro image lower

		while (access(lower_dev, F_OK) < 0) {
			NANOSLEEP(0, 100000000);
			DEBUG("Waiting for %s", lower_dev);
		}

		if (mount(lower_dev, lower_dir, lowerfs_type, mount_flags | MS_RDONLY, mount_data) <
		    0) {
			ERROR_ERRNO("Could not mount %s to %s", lower_dev, lower_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s to %s", lower_dev, lower_dir);
	} else {
		lower_dir = mem_strdup(target_dir);
	}

	if (container_shift_ids(vol->container, overlayfs_mount_dir, target_dir, lower_dir)) {
		ERROR_ERRNO("Could not register ovl %s (lower=%s) for idmapped mount on target=%s",
			    overlayfs_mount_dir, lower_dir, target_dir);
		goto error;
	}

	mem_free0(lower_dir);
	mem_free0(upper_dir);
	mem_free0(work_dir);
	return 0;
error:
	if (file_is_link(lower_dir)) {
		if (unlink(lower_dir))
			WARN_ERRNO("could not remove temporary link %s", lower_dir);
	}
	mem_free0(lower_dir);
	mem_free0(upper_dir);
	mem_free0(work_dir);
	return -1;
}

static int
c_vol_mount_file_bind(const char *src, const char *dst, unsigned long flags)
{
	char *_src = mem_strdup(src);
	char *_dst = mem_strdup(dst);
	char *dir_src = dirname(_src);
	char *dir_dst = dirname(_dst);

	if (!(flags & MS_BIND)) {
		errno = EINVAL;
		ERROR_ERRNO("bind mount flag is not set!");
		goto err;
	}

	if (dir_mkdir_p(dir_src, 0755) < 0) {
		DEBUG_ERRNO("Could not mkdir %s", dir_src);
		goto err;
	}
	if (dir_mkdir_p(dir_dst, 0755) < 0) {
		DEBUG_ERRNO("Could not mkdir %s", dir_dst);
		goto err;
	}
	if (file_touch(src) == -1) {
		ERROR("Failed to touch source file \"%s\" for bind mount", src);
		goto err;
	}
	if (file_touch(dst) == -1) {
		ERROR("Failed to touch target file \"%s\"for bind mount", dst);
		goto err;
	}
	if (mount(src, dst, "bind", flags, NULL) < 0) {
		ERROR_ERRNO("Failed to bind mount %s to %s", src, dst);
		goto err;
	}
	/*
	 * ro bind mounts do not work directly, so we need to remount it manually
	 * see, https://lwn.net/Articles/281157/
	 */
	if (flags & MS_RDONLY) { // ro bind mounts do not work directly
		if (mount("none", dst, "bind", flags | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
			ERROR_ERRNO("Failed to remount bind"
				    " mount %s to %s read-only",
				    src, dst);
		}
	}
	DEBUG("Sucessfully bind mounted %s to %s", src, dst);

	mem_free0(_src);
	mem_free0(_dst);
	return 0;
err:
	mem_free0(_src);
	mem_free0(_dst);
	return -1;
}

static int
c_vol_mount_dir_bind(const char *src, const char *dst, unsigned long flags)
{
	if (!(flags & MS_BIND)) {
		errno = EINVAL;
		ERROR_ERRNO("bind mount flag is not set!");
		return -1;
	}

	// try to create mount point before mount, usually not necessary...
	if (dir_mkdir_p(dst, 0755) < 0)
		DEBUG_ERRNO("Could not mkdir %s", dst);

	TRACE("Mounting path %s to %s", src, dst);
	if (mount(src, dst, NULL, flags, NULL) < 0) {
		ERROR_ERRNO("Could not bind mount path %s to %s", src, dst);
		return -1;
	}

	/*
	 * ro bind mounts do not work directly, so we need to remount it manually
	 * see, https://lwn.net/Articles/281157/
	 */
	if (flags & MS_RDONLY) { // ro bind mounts do not work directly
		if (mount("none", dst, "bind", flags | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
			ERROR_ERRNO("Failed to remount bind mount %s to %s read-only", src, dst);
			if (umount(dst))
				WARN("Could not umount writable bind mount");
			return -1;
		}
	}
	DEBUG("Sucessfully bind mounted path %s to %s", src, dst);
	return 0;
}

/*
 * Copy busybox binary to target_base directory.
 * Remeber, this will only succeed if targetfs is writable.
 */
static int
c_vol_setup_busybox_copy(const char *target_base)
{
	int ret = 0;
	char *target_bin = mem_printf("%s%s", target_base, BUSYBOX_PATH);
	char *target_dir = mem_strdup(target_bin);
	char *target_dir_p = dirname(target_dir);
	if ((ret = dir_mkdir_p(target_dir_p, 0755)) < 0) {
		WARN_ERRNO("Could not mkdir '%s' dir", target_dir_p);
	} else if (file_exists("/bin/busybox")) {
		file_copy_zero("/bin/busybox", target_bin, -1, 0);
		INFO("Copied %s to container", target_bin);
		if (chmod(target_bin, 0755)) {
			WARN_ERRNO("Could not set %s executable", target_bin);
			ret = -1;
		}
	} else {
		WARN_ERRNO("Could not copy %s to container", target_bin);
		ret = -1;
	}

	mem_free0(target_bin);
	mem_free0(target_dir);
	return ret;
}

static int
c_vol_setup_busybox_install(void)
{
	// skip if busybox was not coppied
	IF_FALSE_RETVAL_TRACE(file_exists("/bin/busybox"), 0);

	IF_TRUE_RETVAL(dir_mkdir_p("/bin", 0755) < 0, -1);
	IF_TRUE_RETVAL(dir_mkdir_p("/sbin", 0755) < 0, -1);

	const char *const argv[] = { "busybox", "--install", "-s", NULL };
	return proc_fork_and_execvp(argv);
}

/**
 * Mount an image file. This function will take some time. So call it in a
 * thread or child process.
 * @param vol The vol struct for the container.
 * @param root The directory where the root file system should be mounted.
 * @param mntent The information for this mount.
 * @return -1 on error else 0.
 */
static int
c_vol_mount_image(c_vol_t *vol, const char *root, const mount_entry_t *mntent)
{
	char *img, *dev, *img_meta, *dev_meta, *dir, *img_hash;
	int fd = 0, fd_meta = 0;
	bool new_image = false;
	bool encrypted = mount_entry_is_encrypted(mntent);
	bool overlay = false;
	bool shiftids = false;
	bool verity = mount_entry_get_verity_sha256(mntent) != NULL;
	bool is_root = strcmp(mount_entry_get_dir(mntent), "/") == 0;
	bool setup_mode = container_has_setup_mode(vol->container);

	// default mountflags for most image types
	unsigned long mountflags = setup_mode ? MS_NOATIME : MS_NOATIME | MS_NODEV;

	img = dev = img_meta = dev_meta = dir = img_hash = NULL;

	if (mount_entry_get_dir(mntent)[0] == '/')
		dir = mem_printf("%s%s", root, mount_entry_get_dir(mntent));
	else
		dir = mem_printf("%s/%s", root, mount_entry_get_dir(mntent));

	img = c_vol_image_path_new(vol, mntent);
	if (!img)
		goto error;

	TRACE("Mount entry type: %d", mount_entry_get_type(mntent));

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
		shiftids = true; // Fallthrough
	case MOUNT_TYPE_DEVICE:
		mountflags |= MS_RDONLY; // add read-only flag for shared or device images types
		break;
	case MOUNT_TYPE_OVERLAY_RO:
		mountflags |= MS_RDONLY; // add read-only flag for upper image
		overlay = true;
		break;
	case MOUNT_TYPE_SHARED_RW:
	case MOUNT_TYPE_OVERLAY_RW:
		overlay = true;
		shiftids = true;
		break;
	case MOUNT_TYPE_DEVICE_RW:
	case MOUNT_TYPE_EMPTY:
		shiftids = true;
		break; // stick to defaults
	case MOUNT_TYPE_BIND_FILE:
		mountflags |= MS_RDONLY; // Fallthrough
	case MOUNT_TYPE_BIND_FILE_RW:
		if (container_has_userns(vol->container)) // skip
			goto final;
		mountflags |= MS_BIND; // use bind mount
		IF_TRUE_GOTO(-1 == c_vol_mount_file_bind(img, dir, mountflags), error);
		goto final;
	case MOUNT_TYPE_COPY: // deprecated
		//WARN("Found deprecated MOUNT_TYPE_COPY");
		shiftids = true;
		break;
	case MOUNT_TYPE_FLASH:
		DEBUG("Skipping mounting of FLASH type image %s", mount_entry_get_img(mntent));
		goto final;
	case MOUNT_TYPE_BIND_DIR:
		mountflags |= MS_RDONLY; // Fallthrough
	case MOUNT_TYPE_BIND_DIR_RW:
		mountflags |= MS_BIND; // use bind mount
		shiftids = true;
		IF_TRUE_GOTO(-1 == c_vol_mount_dir_bind(img, dir, mountflags), error);
		goto final;
	default:
		ERROR("Unsupported operating system mount type %d for %s",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		goto error;
	}

	// try to create mount point before mount, usually not necessary...
	if (dir_mkdir_p(dir, 0777) < 0)
		DEBUG_ERRNO("Could not mkdir %s", dir);

	if (strcmp(mount_entry_get_fs(mntent), "tmpfs") == 0) {
		const char *mount_data = mount_entry_get_mount_data(mntent);
		if (mount(mount_entry_get_fs(mntent), dir, mount_entry_get_fs(mntent), mountflags,
			  mount_data) >= 0) {
			DEBUG("Sucessfully mounted %s to %s", mount_entry_get_fs(mntent), dir);

			if (chmod(dir, 0755) < 0) {
				ERROR_ERRNO(
					"Could not set permissions of overlayfs mount point at %s",
					dir);
				goto error;
			}
			DEBUG("Changed permissions of %s to 0755", dir);

			if (is_root && setup_mode && c_vol_setup_busybox_copy(dir) < 0)
				WARN("Cannot copy busybox for setup mode!");
			goto final;
		} else {
			ERROR_ERRNO("Cannot mount %s to %s", mount_entry_get_fs(mntent), dir);
			goto error;
		}
	}

	if (c_vol_check_image(vol, img) < 0) {
		new_image = true;
		if (c_vol_create_image(vol, img, mntent) < 0) {
			goto error;
		}
	}

	if (verity) {
		TRACE("Creating dm-verity device");
		char *label = mem_printf("%s-%s", uuid_string(container_get_uuid(vol->container)),
					 mount_entry_get_img(mntent));
		char *verity_dev = verity_get_device_path_new(label);
		if (file_is_blk(verity_dev) || file_links_to_blk(verity_dev)) {
			INFO("Using existing mapper device: %s", verity_dev);
		} else {
			const char *root_hash = mount_entry_get_verity_sha256(mntent);
			img_hash = c_vol_hash_image_path_new(vol, mntent);
			IF_NULL_GOTO(img_hash, error);

			if (verity_create_blk_dev(label, img, img_hash, root_hash,
						  !cmld_is_hostedmode_active())) {
				ERROR("Failed to open %s from %s as dm-verity device with hash-dev %s and hash %s",
				      label, img, img_hash, root_hash);
				mem_free0(label);
				mem_free0(verity_dev);
				goto error;
			}

			int control_fd = -1;
			if ((control_fd = dm_open_control()) < 0) {
				ERROR("Failed to open /dev/mapper/control\n");
				mem_free0(label);
				mem_free0(verity_dev);
				goto error;
			}

			char *type = dm_get_target_type_new(control_fd, label);
			if (!type) {
				ERROR("Failed to get target type of %s\n", label);
				mem_free0(label);
				mem_free0(verity_dev);
				goto error;
			}
			INFO("Type of %s is %s\n", label, type);
			dm_close_control(control_fd);

			// TODO audit_log_event?
		}

		dev = verity_dev;
		mem_free0(label);

		// TODO timeout?
		while (access(dev, F_OK) < 0) {
			NANOSLEEP(0, 100000000);
			DEBUG("Waiting for %s", dev);
		}
		DEBUG("Device %s is now available\n", dev);

	} else {
		TRACE("Creating loopdev");
		dev = loopdev_create_new(&fd, img, 0, 0);
		IF_NULL_GOTO(dev, error);
	}

	if (encrypted) {
		TRACE("Creating encrypted image");
		char *label, *crypt;

		label = mem_printf("%s-%s", uuid_string(container_get_uuid(vol->container)),
				   mount_entry_get_img(mntent));

		if (!container_get_key(vol->container)) {
			audit_log_event(container_get_uuid(vol->container), FSA, CMLD,
					CONTAINER_MGMT, "setup-crypted-volume-no-key",
					uuid_string(container_get_uuid(vol->container)), 2, "label",
					label);
			ERROR("Trying to mount encrypted volume without key...");
			mem_free0(label);
			goto error;
		}

		crypt = cryptfs_get_device_path_new(label);
		if (file_is_blk(crypt) || file_links_to_blk(crypt)) {
			INFO("Using existing mapper device: %s", crypt);
		} else {
			DEBUG("Setting up cryptfs volume %s for %s", label, dev);

			img_meta = c_vol_meta_image_path_new(vol, mntent);
			dev_meta = loopdev_create_new(&fd_meta, img_meta, 0, 0);

			IF_NULL_GOTO(dev_meta, error);

			mem_free0(crypt);
			crypt = cryptfs_setup_volume_new(
				label, dev, container_get_key(vol->container), dev_meta);

			// release loopdev fd (crypt device should keep it open now)
			close(fd_meta);
			mem_free0(img_meta);

			if (!crypt) {
				audit_log_event(container_get_uuid(vol->container), FSA, CMLD,
						CONTAINER_MGMT, "setup-crypted-volume",
						uuid_string(container_get_uuid(vol->container)), 2,
						"label", label);
				ERROR("Setting up cryptfs volume %s for %s failed", label, dev);
				mem_free0(label);
				goto error;
			}
			audit_log_event(container_get_uuid(vol->container), SSA, CMLD,
					CONTAINER_MGMT, "setup-crypted-volume",
					uuid_string(container_get_uuid(vol->container)), 2, "label",
					label);
		}

		mem_free0(label);
		mem_free0(dev);
		dev = crypt;

		// TODO: timeout?
		while (access(dev, F_OK) < 0) {
			NANOSLEEP(0, 10000000)
			DEBUG("Waiting for %s", dev);
		}
	}

	if (overlay) {
		TRACE("Device to be mounted is an overlay device\n");
		const char *upper_fstype = NULL;
		const char *lower_fstype = NULL;
		char *upper_dev = NULL;
		char *lower_dev = NULL;
		const char *mount_data = mount_entry_get_mount_data(mntent);

		switch (mount_entry_get_type(mntent)) {
		case MOUNT_TYPE_OVERLAY_RW: {
			TRACE("Preparing MOUNT_TYPE_OVERLAY_RW");
			upper_dev = dev;
			upper_fstype = mount_entry_get_fs(mntent);
			if (new_image) {
				if (c_vol_format_image(dev, upper_fstype) < 0) {
					ERROR("Could not format image %s using %s", img, dev);
					goto error;
				}
				DEBUG("Successfully formatted new image %s using %s", img, dev);
			}
			if (!strcmp("btrfs", upper_fstype) && mount_data &&
			    !strncmp("subvol", mount_data, 6)) {
				c_vol_btrfs_create_subvol(dev, mount_data);
			}
		} break;

		case MOUNT_TYPE_OVERLAY_RO: {
			TRACE("Preparing MOUNT_TYPE_OVERLAY_RO");
			upper_dev = dev;
			upper_fstype = mount_entry_get_fs(mntent);
			mountflags |= MS_RDONLY;
		} break;

		case MOUNT_TYPE_SHARED_RW: {
			upper_fstype = "tmpfs";
			lower_fstype = mount_entry_get_fs(mntent);
			lower_dev = dev;
			TRACE("Preparing MOUNT_TYPE_SHARED_RW with upper fstype %s and lower fstype %s",
			      upper_fstype, lower_fstype);
		} break;

		default:
			ERROR_ERRNO("Mounttype does not support overlay mounting!");
			goto error;
		}

		char *overlayfs_mount_dir =
			mem_printf("/tmp/overlayfs/%s/%d",
				   uuid_string(container_get_uuid(vol->container)),
				   ++vol->overlay_count);

		if (c_vol_mount_overlay(vol, dir, upper_fstype, lower_fstype, mountflags,
					mount_data, upper_dev, lower_dev,
					overlayfs_mount_dir) < 0) {
			ERROR_ERRNO("Could not mount %s to %s", img, dir);
			mem_free0(overlayfs_mount_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s using overlay to %s", img, dir);
		mem_free0(overlayfs_mount_dir);

		// c_vol_mount_overlay allready does idmapping thus skip this after final mount
		goto final_noshift;
	}

	DEBUG("Mounting image %s %s using %s to %s", img, mountflags & MS_RDONLY ? "ro" : "rw", dev,
	      dir);

	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags,
		  mount_entry_get_mount_data(mntent)) >= 0) {
		DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);
		goto final;
	}

	// retry with default options
	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags, NULL) >= 0) {
		DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);
		goto final;
	}

	if (errno != EINVAL) {
		ERROR_ERRNO("Could not mount image %s using %s to %s", img, dev, dir);
		goto error;
	}

	INFO("Could not mount image %s using %s to %s because an invalid "
	     "superblock was detected.",
	     img, dev, dir);

	if (mount_entry_get_type(mntent) != MOUNT_TYPE_EMPTY)
		goto error;

	/* TODO better password handling before in order to remove this condition. */
	if (encrypted && !new_image) {
		DEBUG("Possibly the wrong password was specified. Abort container start.");
		goto error;
	}

	INFO("Formating image %s using %s as %s", img, dev, mount_entry_get_fs(mntent));

	if (c_vol_format_image(dev, mount_entry_get_fs(mntent)) < 0) {
		ERROR("Could not format image %s using %s", img, dev);
		goto error;
	}

	DEBUG("Mounting image %s using %s to %s (2nd try)", img, dev, dir);

	// 2nd try to mount image...
	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags,
		  mount_entry_get_mount_data(mntent)) < 0) {
		ERROR("Could not mount image %s using %s to %s", img, dev, dir);
		goto error;
	}

	DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);

final:
	if (mount(NULL, dir, NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
		ERROR_ERRNO("Could not mount '%s' MS_PRIVATE", dir);
		goto error;
	}

	if (shiftids) {
		if (container_shift_ids(vol->container, dir, dir, NULL) < 0) {
			ERROR_ERRNO("Shifting user and gids for '%s' failed!", dir);
			goto error;
		}
	}

final_noshift:

	if (dev)
		loopdev_free(dev);
	if (dev_meta)
		loopdev_free(dev_meta);
	if (img)
		mem_free0(img);
	if (img_meta)
		mem_free0(img_meta);
	if (dir)
		mem_free0(dir);
	if (fd)
		close(fd);
	if (fd_meta)
		close(fd_meta);
	if (img_hash)
		mem_free0(img_hash);
	return 0;

error:
	if (dev)
		loopdev_free(dev);
	if (dev_meta)
		loopdev_free(dev_meta);
	if (img)
		mem_free0(img);
	if (img_meta)
		mem_free0(img_meta);
	if (dir)
		mem_free0(dir);
	if (fd)
		close(fd);
	if (fd_meta)
		close(fd_meta);
	return -1;
}

static int
c_vol_cleanup_dm(c_vol_t *vol)
{
	ssize_t i, n;
	int fd;

	IF_TRUE_RETVAL(((fd = dm_open_control()) < 0), -1);

	n = mount_get_count(vol->mnt);
	for (i = n - 1; i >= 0; i--) {
		const mount_entry_t *mntent;
		char *label;

		mntent = mount_get_entry(vol->mnt, i);

		label = mem_printf("%s-%s", uuid_string(container_get_uuid(vol->container)),
				   mount_entry_get_img(mntent));

		DEBUG("Cleanup: Checking target type of %s\n", label);

		char *type = dm_get_target_type_new(fd, label);
		if (type == NULL) {
			WARN("Failed to get target type of %s\n", label);
			continue;
		}

		DEBUG("Cleanup: removing block device %s of type %s\n", label, type);

		if (!strcmp(type, "crypt")) {
			if (cryptfs_delete_blk_dev(fd, label) < 0)
				DEBUG("Could not delete dm-crypt dev %s", label);
		} else if (!strcmp(type, "verity")) {
			if (verity_delete_blk_dev(label) < 0)
				DEBUG("Could not delete dm-verity dev %s", label);
		}
		mem_free0(label);
		mem_free0(type);
	}
	dm_close_control(fd);

	return 0;
}

static int
c_vol_umount_dir(const char *mount_dir)
{
	IF_NULL_RETVAL(mount_dir, -1);

	while (file_is_mountpoint(mount_dir)) {
		if (umount(mount_dir) < 0) {
			if (umount2(mount_dir, MNT_DETACH) < 0) {
				ERROR_ERRNO("Could not umount '%s'", mount_dir);
				return -1;
			}
		}
	}
	return 0;
}

static int
c_vol_cleanup_overlays_cb(const char *path, const char *file, UNUSED void *data)
{
	char *overlay = mem_printf("%s/%s", path, file);
	int ret = c_vol_umount_dir(overlay);
	if (rmdir(overlay) < 0)
		TRACE("Unable to remove %s", overlay);

	mem_free0(overlay);
	return ret;
}

/**
 * Umount all image files.
 * This function is called in the rootns, to cleanup stopped container.
 */
static int
c_vol_umount_all(c_vol_t *vol)
{
	int i, n;
	char *c_root = mem_printf("%s%s", vol->root, "/setup");
	bool setup_mode = container_has_setup_mode(vol->container);

	// umount /dev
	char *mount_dir = mem_printf("%s/dev", vol->root);
	if (c_vol_umount_dir(mount_dir) < 0)
		goto error;
	mem_free0(mount_dir);

	if (setup_mode) {
		// umount setup in revers order
		n = mount_get_count(vol->mnt_setup);
		TRACE("n setup: %d", n);
		for (i = n - 1; i >= 0; i--) {
			const mount_entry_t *mntent;
			TRACE("i setup: %d", i);
			mntent = mount_get_entry(vol->mnt_setup, i);
			mount_dir = mem_printf("%s/%s", c_root, mount_entry_get_dir(mntent));
			if (c_vol_umount_dir(mount_dir) < 0)
				goto error;
			mem_free0(mount_dir);
		}
	}

	// umount root in revers order
	n = mount_get_count(vol->mnt);
	TRACE("n rootfs: %d", n);
	for (i = n - 1; i >= 0; i--) {
		const mount_entry_t *mntent;
		TRACE("i rootfs: %d", i);
		mntent = mount_get_entry(vol->mnt, i);
		mount_dir = mem_printf("%s/%s", vol->root, mount_entry_get_dir(mntent));
		if (c_vol_umount_dir(mount_dir) < 0)
			goto error;
		mem_free0(mount_dir);
	}
	if (rmdir(vol->root) < 0)
		TRACE("Unable to remove %s", vol->root);

	// cleanup left-over overlay mounts in main cmld process
	mount_dir =
		mem_printf("/tmp/overlayfs/%s", uuid_string(container_get_uuid(vol->container)));
	if (dir_foreach(mount_dir, &c_vol_cleanup_overlays_cb, NULL) < 0)
		WARN("Could not release overlays in '%s'", mount_dir);
	if (rmdir(mount_dir) < 0)
		TRACE("Unable to remove %s", mount_dir);
	mem_free0(mount_dir);

	mem_free0(c_root);
	return 0;
error:
	mem_free0(mount_dir);
	mem_free0(c_root);
	return -1;
}

/**
 * Mount all image files.
 * This function is called in the rootns.
 */
static int
c_vol_mount_images(c_vol_t *vol)
{
	size_t i, n;

	ASSERT(vol);

	bool setup_mode = container_has_setup_mode(vol->container);

	// in setup mode mount container images under {root}/setup subfolder
	char *c_root = mem_printf("%s%s", vol->root, (setup_mode) ? "/setup" : "");

	if (setup_mode) {
		n = mount_get_count(vol->mnt_setup);
		for (i = 0; i < n; i++) {
			const mount_entry_t *mntent;

			mntent = mount_get_entry(vol->mnt_setup, i);

			if (c_vol_mount_image(vol, vol->root, mntent) < 0) {
				goto err;
			}
		}

		// create mount point for setup
		if (dir_mkdir_p(c_root, 0755) < 0)
			DEBUG_ERRNO("Could not mkdir %s", c_root);
	}

	n = mount_get_count(vol->mnt);
	for (i = 0; i < n; i++) {
		const mount_entry_t *mntent;

		mntent = mount_get_entry(vol->mnt, i);

		if (c_vol_mount_image(vol, c_root, mntent) < 0) {
			goto err;
		}
	}
	mem_free0(c_root);
	return 0;
err:
	c_vol_umount_all(vol);
	c_vol_cleanup_dm(vol);
	mem_free0(c_root);
	return -1;
}

static bool
c_vol_populate_dev_filter_cb(const char *dev_node, void *data)
{
	c_vol_t *vol = data;
	ASSERT(vol);

	// filter out mount points, to avoid copying private stuff, e.g, /dev/pts
	if (file_is_mountpoint(dev_node)) {
		TRACE("filter mountpoint '%s'", dev_node);
		return false;
	}

	struct stat s;
	IF_TRUE_RETVAL(stat(dev_node, &s), true);

	char type;
	switch (s.st_mode & S_IFMT) {
	case S_IFBLK:
		type = 'b';
		break;
	case S_IFCHR:
		type = 'c';
		break;
	default:
		return true;
	}

	if (!container_is_device_allowed(vol->container, type, major(s.st_rdev),
					 minor(s.st_rdev))) {
		TRACE("filter device %s (%c %d:%d)", dev_node, type, major(s.st_rdev),
		      minor(s.st_rdev));
		return false;
	}
	return true;
}

static int
c_vol_mount_dev(c_vol_t *vol)
{
	ASSERT(vol);

	int ret = -1;
	char *dev_mnt = mem_printf("%s/%s", vol->root, "dev");
	char *pts_mnt = mem_printf("%s/%s", dev_mnt, "pts");

	if ((ret = mkdir(dev_mnt, 0755)) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /dev");
		goto error;
	}
	if ((ret = mount("tmpfs", dev_mnt, "tmpfs", MS_RELATIME | MS_NOSUID, NULL)) < 0) {
		ERROR_ERRNO("Could not mount /dev");
		goto error;
	}

	if ((ret = mount(NULL, dev_mnt, NULL, MS_SHARED, NULL)) < 0) {
		ERROR_ERRNO("Could not apply MS_SHARED to %s", dev_mnt);
	} else {
		DEBUG("Applied MS_SHARED to %s", dev_mnt);
	}

	if (container_shift_ids(vol->container, dev_mnt, dev_mnt, NULL)) {
		ERROR_ERRNO("Could not shift ids for dev on '%s'", dev_mnt);
		goto error;
	}

	DEBUG("Creating directory %s", pts_mnt);
	if (mkdir(pts_mnt, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s", pts_mnt);
		goto error;
	}

	if (chmod(dev_mnt, 0755) < 0) {
		ERROR_ERRNO("Could not set permissions of overlayfs mount point at %s", dev_mnt);
		goto error;
	}
	DEBUG("Changed permissions of %s to 0755", dev_mnt);

	ret = 0;
error:
	mem_free0(pts_mnt);
	mem_free0(dev_mnt);
	return ret;
}

/**
 * This Function verifies integrity of base images as part of
 * TSF.CML.SecureCompartmentInit.
 */
static bool
c_vol_verify_mount_entries(const c_vol_t *vol)
{
	ASSERT(vol);

	int n = mount_get_count(vol->mnt);
	for (int i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		mntent = mount_get_entry(vol->mnt, i);
		if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_RW ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RO) {
			if (mount_entry_get_verity_sha256(mntent)) {
				// skip, handled in c_vol_verify_mount_entries_bg()
				continue;
			}
			if (guestos_check_mount_image_block(vol->os, mntent, true) !=
			    CHECK_IMAGE_GOOD) {
				ERROR("Cannot verify image %s: image file is corrupted",
				      mount_entry_get_img(mntent));
				return false;
			}
		}
	}
	return true;
}

/**
 * This Function verifies integrity of base images in background as part of
 * TSF.CML.SecureCompartmentInit.
 */
static bool
c_vol_verify_mount_entries_bg(const c_vol_t *vol)
{
	ASSERT(vol);

	int n = mount_get_count(vol->mnt);
	for (int i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		mntent = mount_get_entry(vol->mnt, i);
		if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_RW ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RO) {
			if (mount_entry_get_verity_sha256(mntent)) {
				/* let dm-verity do the integrity checks on
			         * block access, and check the whole image in
				 * background
				 */
				pid_t pid = fork();
				if (pid < 0) {
					ERROR_ERRNO("Can not fork child for integrity check!");
					return false;
				} else if (pid == 0) { // child do check
					event_reset();
					if (guestos_check_mount_image_block(
						    vol->os, mntent, true) != CHECK_IMAGE_GOOD) {
						ERROR("Cannot verify image %s: "
						      "image file is corrupted",
						      mount_entry_get_img(mntent));

						audit_log_event(
							container_get_uuid(vol->container), FSA,
							CMLD, CONTAINER_MGMT, "verify-image",
							uuid_string(
								container_get_uuid(vol->container)),
							2, "name", mount_entry_get_img(mntent));
						_exit(-1);
					}
					audit_log_event(
						container_get_uuid(vol->container), SSA, CMLD,
						CONTAINER_MGMT, "verify-image",
						uuid_string(container_get_uuid(vol->container)), 2,
						"name", mount_entry_get_img(mntent));
					_exit(0);
				} else { // parent
					INFO("dm-verity active for image %s, "
					     "start thorough image check in "
					     "background.",
					     mount_entry_get_img(mntent));
					container_wait_for_child(vol->container, "vol-bg-check",
								 pid);
					continue;
				}
			}
		}
	}
	return true;
}

/******************************************************************************/

static void *
c_vol_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_vol_t *vol = mem_new0(c_vol_t, 1);
	vol->container = compartment_get_extension_data(compartment);

	vol->root = mem_printf("/tmp/%s", uuid_string(container_get_uuid(vol->container)));
	vol->overlay_count = 0;

	vol->mnt = mount_new();

	vol->os = container_get_guestos(vol->container);
	if (vol->os) {
		guestos_fill_mount(vol->os, vol->mnt);

		vol->mnt_setup = mount_new();
		guestos_fill_mount_setup(vol->os, vol->mnt_setup);

		// prepend container init env with guestos specific values
		container_init_env_prepend(vol->container, guestos_get_init_env(vol->os),
					   guestos_get_init_env_len(vol->os));
	}

	// mount modules inside container
	if (compartment_get_flags(compartment) & COMPARTMENT_FLAG_MODULE_LOAD)
		mount_add_entry(vol->mnt, MOUNT_TYPE_BIND_DIR, "/lib/modules", "/lib/modules",
				"none", 0);

	return vol;
}

static void
c_vol_free(void *volp)
{
	c_vol_t *vol = volp;
	ASSERT(vol);

	if (vol->mnt)
		mount_free(vol->mnt);
	if (vol->mnt_setup)
		mount_free(vol->mnt_setup);

	if (vol->root)
		mem_free0(vol->root);

	mem_free0(vol);
}

static int
c_vol_do_shared_bind_mounts(const c_vol_t *vol)
{
	ASSERT(vol);
	char *bind_img_path = NULL;
	char *bind_dev = NULL;
	int loop_fd = 0;
	bool contains_bind = false;

	int n = mount_get_count(vol->mnt);
	for (int i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		mntent = mount_get_entry(vol->mnt, i);
		if (mount_entry_get_type(mntent) == MOUNT_TYPE_BIND_FILE_RW ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_BIND_FILE) {
			contains_bind = true;
		}
	}
	// if no bind mount nothing to do
	IF_FALSE_RETVAL(contains_bind, 0);

	if (!file_is_dir(SHARED_FILES_PATH)) {
		if (dir_mkdir_p(SHARED_FILES_PATH, 0755) < 0) {
			DEBUG_ERRNO("Could not mkdir %s", SHARED_FILES_PATH);
			return -1;
		}
	}
	// if already mounted nothing to be done
	IF_TRUE_RETVAL(file_is_mountpoint(SHARED_FILES_PATH), 0);

	// setup persitent image as date store for shared objects
	bind_img_path = mem_printf("%s/_store.img", SHARED_FILES_PATH);
	if (!file_exists(bind_img_path)) {
		if (c_vol_create_image_empty(bind_img_path, NULL, SHARED_FILES_STORE_SIZE) < 0) {
			goto err;
		}
		if (c_vol_format_image(bind_img_path, "ext4") < 0) {
			goto err;
		}
		INFO("Succesfully created image for %s", SHARED_FILES_PATH);
	}
	bind_dev = loopdev_create_new(&loop_fd, bind_img_path, 0, 0);
	IF_NULL_GOTO(bind_dev, err);
	if (mount(bind_dev, SHARED_FILES_PATH, "ext4", MS_NOATIME | MS_NODEV | MS_NOEXEC, NULL) <
	    0) {
		ERROR_ERRNO("Failed to mount %s to %s", bind_img_path, SHARED_FILES_PATH);
		goto err;
	}

	close(loop_fd);
	mem_free0(bind_img_path);
	mem_free0(bind_dev);
	return 0;
err:
	if (loop_fd)
		close(loop_fd);
	if (bind_img_path)
		mem_free0(bind_img_path);
	if (bind_dev)
		mem_free0(bind_dev);
	return -1;
}

static char *
c_vol_get_rootdir(void *volp)
{
	c_vol_t *vol = volp;
	ASSERT(vol);
	return vol->root;
}

static int
c_vol_start_child_early(void *volp)
{
	c_vol_t *vol = volp;
	ASSERT(vol);

	// check image integrity (this is blocking that is why we do this
	// in the early_child and not in the host process
	IF_FALSE_GOTO(c_vol_verify_mount_entries(vol), error);

	INFO("Mounting rootfs to %s", vol->root);

	if (mkdir(container_get_images_dir(vol->container), 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Cound not mkdir container directory %s",
			    container_get_images_dir(vol->container));
		goto error;
	}

	if (mkdir("/tmp", 0700) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /tmp dir for container start");
		goto error;
	}

	if (mkdir(vol->root, 0700) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir root dir %s for container start", vol->root);
		goto error;
	}

	DEBUG("Mounting images");
	if (c_vol_mount_images(vol) < 0) {
		ERROR("Could not mount images for container start");
		goto error;
	}

	//FIXME should be before mounting images, because it sets up storage for bound files!
	if (c_vol_do_shared_bind_mounts(vol) < 0) {
		ERROR("Could not do shared bind mounts for container start");
		goto error;
	}

	DEBUG("Mounting /dev");
	IF_TRUE_GOTO_ERROR(c_vol_mount_dev(vol) < 0, error);

	return 0;
error:
	ERROR("Failed to execute start child early hook for c_vol");
	return -COMPARTMENT_ERROR_VOL;
}

static int
c_vol_start_post_clone(void *volp)
{
	c_vol_t *vol = volp;
	ASSERT(vol);

	// check image integrity lazy in background for verity enabled images
	if (c_vol_verify_mount_entries_bg(vol))
		return 0;

	ERROR("Failed to execute post clone hook for c_vol");
	return -COMPARTMENT_ERROR_VOL;
}

struct tty_cb_data {
	bool found;
	char *name;
};

static int
c_vol_dev_get_tty_cb(UNUSED const char *path, const char *file, void *data)
{
	struct tty_cb_data *tty_data = data;

	if (!tty_data->found && strlen(file) >= 4 && strstr(file, "tty")) {
		tty_data->name = mem_strdup(file);
		INFO("Found tty: %s", tty_data->name);
		tty_data->found = true;
	}
	return 0;
}

static int
c_vol_start_pre_exec(void *volp)
{
	c_vol_t *vol = volp;
	ASSERT(vol);

	INFO("Populating container's /dev.");
	char *dev_mnt = mem_printf("%s/%s", vol->root, "dev");
	if (dir_copy_folder("/dev", dev_mnt, &c_vol_populate_dev_filter_cb, vol) < 0) {
		ERROR_ERRNO("Could not populate /dev!");
		mem_free0(dev_mnt);
		return -COMPARTMENT_ERROR_VOL;
	}

	/* link first /dev/tty* to /dev/console for systemd containers */
	struct tty_cb_data tty_data = { .found = false, .name = NULL };
	dir_foreach(dev_mnt, c_vol_dev_get_tty_cb, &tty_data);
	if (tty_data.name != NULL) {
		char *lnk_path = mem_printf("%s/console", dev_mnt);
		if (symlink(tty_data.name, lnk_path))
			WARN_ERRNO("Could not link %s to /dev/console in container", tty_data.name);
		mem_free0(lnk_path);
		mem_free0(tty_data.name);
	}

	if (container_shift_ids(vol->container, dev_mnt, dev_mnt, NULL) < 0)
		WARN("Failed to setup ids for %s in user namespace!", dev_mnt);

	mem_free0(dev_mnt);
	return 0;
}
static int
c_vol_mount_proc_and_sys(const c_vol_t *vol, const char *dir)
{
	char *mnt_proc = mem_printf("%s/proc", dir);
	char *mnt_sys = mem_printf("%s/sys", dir);

	DEBUG("Mounting proc on %s", mnt_proc);
	if (mkdir(mnt_proc, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s", mnt_proc);
		goto error;
	}
	if (mount("proc", mnt_proc, "proc", 0, NULL) < 0) {
		ERROR_ERRNO("Could not mount %s", mnt_proc);
		goto error;
	}

	if (lxcfs_is_supported()) {
		if (lxcfs_mount_proc_overlay(mnt_proc) == -1) {
			ERROR_ERRNO("Could not apply lxcfs overlay on mount %s", mnt_proc);
			goto error;
		}
		INFO("lxcfs overlay mounted successfully.");
	} else {
		INFO("lxcfs not supported - not mounting overlay");
	}

	DEBUG("Mounting sys on %s", mnt_sys);
	unsigned long sysopts = MS_RELATIME | MS_NOSUID;
	if (container_has_userns(vol->container) && !container_has_netns(vol->container)) {
		sysopts |= MS_RDONLY;
	}
	if (mkdir(mnt_sys, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s", mnt_sys);
		goto error;
	}
	if (mount("sysfs", mnt_sys, "sysfs", sysopts, NULL) < 0) {
		ERROR_ERRNO("Could not mount %s", mnt_sys);
		goto error;
	}

	mem_free0(mnt_proc);
	mem_free0(mnt_sys);
	return 0;
error:
	mem_free0(mnt_proc);
	mem_free0(mnt_sys);
	return -1;
}

static int
c_vol_move_root(const c_vol_t *vol)
{
	if (chdir(vol->root) < 0) {
		ERROR_ERRNO("Could not chdir to root dir %s for container start", vol->root);
		goto error;
	}

	// mount namespace handles chroot jail breaks
	if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
		ERROR_ERRNO("Could not move mount for container start");
		goto error;
	}

	if (chroot(".") < 0) {
		ERROR_ERRNO("Could not chroot to . for container start");
		goto error;
	}

	if (chdir("/") < 0) {
		ERROR_ERRNO("Could not chdir to / for container start");
		goto error;
	}

	INFO("Sucessfully switched (move mount) to new root %s", vol->root);
	return 0;
error:
	return -1;
}

static int
pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

static int
c_vol_pivot_root(const c_vol_t *vol)
{
	int old_root = -1, new_root = -1;

	if ((old_root = open("/", O_DIRECTORY | O_PATH)) < 0) {
		ERROR_ERRNO("Could not open '/' directory of the old filesystem");
		goto error;
	}

	if ((new_root = open(vol->root, O_DIRECTORY | O_PATH)) < 0) {
		ERROR_ERRNO("Could not open the root dir '%s' for container start", vol->root);
		goto error;
	}

	if (fchdir(new_root)) {
		ERROR_ERRNO("Could not fchdir to new root dir %s for container start", vol->root);
		goto error;
	}

	if (pivot_root(".", ".") == -1) {
		ERROR_ERRNO("Could not pivot root for container start");
		goto error;
	}

	if (fchdir(old_root) < 0) {
		ERROR_ERRNO("Could not fchdir to the root directory of the old filesystem");
		goto error;
	}

	if (umount2(".", MNT_DETACH) < 0) {
		ERROR_ERRNO("Could not unmount the old root filesystem");
		goto error;
	}

	if (fchdir(new_root) < 0) {
		ERROR_ERRNO("Could not switch back to the root directory of the new filesystem");
		goto error;
	}

	INFO("Sucessfully switched (pivot_root) to new root %s", vol->root);

	close(old_root);
	close(new_root);
	return 0;
error:
	if (old_root >= 0)
		close(old_root);
	if (new_root >= 0)
		close(new_root);
	return -1;
}

static int
c_vol_start_child(void *volp)
{
	c_vol_t *vol = volp;
	ASSERT(vol);

	// remount proc to reflect namespace change
	if (!container_has_userns(vol->container)) {
		if (umount("/proc") < 0 && errno != ENOENT) {
			if (umount2("/proc", MNT_DETACH) < 0) {
				ERROR_ERRNO("Could not umount /proc");
				goto error;
			}
		}
	}
	if (mount("proc", "/proc", "proc", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not remount /proc");
		goto error;
	}

	if (container_get_type(vol->container) == CONTAINER_TYPE_KVM)
		return 0;

	INFO("Switching to new rootfs in '%s'", vol->root);

	if (c_vol_mount_proc_and_sys(vol, vol->root) == -1) {
		ERROR_ERRNO("Could not mount proc and sys");
		goto error;
	}

	/*
	 * copy cml-service-container binary to target as defined in CSERVICE_TARGET
	 * Remeber, This will only succeed if targetfs is writable
	 */
	char *cservice_bin = mem_printf("%s/%s", vol->root, CSERVICE_TARGET);
	char *cservice_dir = mem_strdup(cservice_bin);
	char *cservice_dir_p = dirname(cservice_dir);
	if (dir_mkdir_p(cservice_dir_p, 0755) < 0) {
		WARN_ERRNO("Could not mkdir '%s' dir", cservice_dir_p);
	} else if (file_exists("/sbin/cml-service-container-static")) {
		file_copy_zero("/sbin/cml-service-container-static", cservice_bin, -1, 0);
		INFO("Copied %s to container", cservice_bin);
	} else if (file_exists("/usr/sbin/cml-service-container-static")) {
		file_copy_zero("/usr/sbin/cml-service-container-static", cservice_bin, -1, 0);
		INFO("Copied %s to container", cservice_bin);
	} else {
		WARN_ERRNO("Could not copy %s to container", cservice_bin);
	}

	if (chmod(cservice_bin, 0755))
		WARN_ERRNO("Could not set %s executable", cservice_bin);

	mem_free0(cservice_bin);
	mem_free0(cservice_dir);

	if (cmld_is_hostedmode_active())
		IF_TRUE_GOTO(c_vol_pivot_root(vol) < 0, error);
	else
		IF_TRUE_GOTO(c_vol_move_root(vol) < 0, error);

	if (!container_has_userns(vol->container) && file_exists("/proc/sysrq-trigger")) {
		if (mount("/proc/sysrq-trigger", "/proc/sysrq-trigger", NULL, MS_BIND, NULL) < 0) {
			ERROR_ERRNO("Could not bind mount /proc/sysrq-trigger protection");
			goto error;
		}
		if (mount(NULL, "/proc/sysrq-trigger", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT,
			  NULL) < 0) {
			ERROR_ERRNO("Could not ro remount /proc/sysrq-trigger protection");
			goto error;
		}
	}

	DEBUG("Mounting /dev/pts");
	if (mount("devpts", "/dev/pts", "devpts", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount /dev/pts");
		goto error;
	}

	DEBUG("Mounting /run");
	if (mkdir("/run", 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /run");
		goto error;
	}
	if (mount("tmpfs", "/run", "tmpfs", MS_RELATIME | MS_NOSUID | MS_NODEV, NULL) < 0) {
		ERROR_ERRNO("Could not mount /run");
		goto error;
	}

	if (chmod("/run", 0755) < 0) {
		ERROR_ERRNO("Could not set permissions of overlayfs mount point at %s", "/run");
		goto error;
	}
	DEBUG("Changed permissions of %s to 0755", "/run");

	if (chmod("/run", 0755) < 0) {
		ERROR_ERRNO("Could not set permissions of overlayfs mount point at %s", "/run");
		goto error;
	}
	DEBUG("Changed permissions of %s to 0755", "/run");

	DEBUG("Mounting " CMLD_SOCKET_DIR);
	if (mkdir(CMLD_SOCKET_DIR, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir " CMLD_SOCKET_DIR);
		goto error;
	}
	if (mount("tmpfs", CMLD_SOCKET_DIR, "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount " CMLD_SOCKET_DIR);
		goto error;
	}

	if (chmod(CMLD_SOCKET_DIR, 0755) < 0) {
		ERROR_ERRNO("Could not set permissions of overlayfs mount point at %s",
			    CMLD_SOCKET_DIR);
		goto error;
	}
	DEBUG("Changed permissions of %s to 0755", CMLD_SOCKET_DIR);

	if (container_has_setup_mode(vol->container) && c_vol_setup_busybox_install() < 0)
		WARN("Cannot install busybox symlinks for setup mode!");

	char *mount_output = file_read_new("/proc/self/mounts", 2048);
	INFO("Mounted filesystems:");
	INFO("%s", mount_output);
	mem_free0(mount_output);

	return 0;

error:
	return -COMPARTMENT_ERROR_VOL;
}

static void *
c_vol_get_mnt(void *volp)
{
	c_vol_t *vol = volp;
	ASSERT(vol);

	return vol->mnt;
}

static bool
c_vol_is_encrypted(void *volp)
{
	size_t i, n;
	c_vol_t *vol = volp;

	ASSERT(vol);
	ASSERT(vol->container);

	n = mount_get_count(vol->mnt);
	for (i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		mntent = mount_get_entry(vol->mnt, i);
		if (mount_entry_is_encrypted(mntent))
			return true;
	}
	return false;
}

static void
c_vol_cleanup(void *volp, bool is_rebooting)
{
	c_vol_t *vol = volp;
	ASSERT(vol);

	if (c_vol_umount_all(vol))
		WARN("Could not umount all images properly");

	// keep dm crypt/integrity device up for reboot
	if (!is_rebooting && c_vol_cleanup_dm(vol))
		WARN("Could not remove mounts properly");
}

static compartment_module_t c_vol_module = {
	.name = MOD_NAME,
	.compartment_new = c_vol_new,
	.compartment_free = c_vol_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = c_vol_start_child_early,
	.start_pre_clone = NULL,
	.start_post_clone = c_vol_start_post_clone,
	.start_pre_exec = c_vol_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = c_vol_start_child,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_vol_cleanup,
	.join_ns = NULL,
	.flags = COMPARTMENT_MODULE_F_CLEANUP_LATE,
};

static void INIT
c_vol_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_vol_module);

	// register relevant handlers implemented by this module
	container_register_get_rootdir_handler(MOD_NAME, c_vol_get_rootdir);
	container_register_get_mnt_handler(MOD_NAME, c_vol_get_mnt);
	container_register_is_encrypted_handler(MOD_NAME, c_vol_is_encrypted);
}
