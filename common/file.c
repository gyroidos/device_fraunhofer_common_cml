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

#define _GNU_SOURCE // for syncfs()

#include <string.h>
#include <unistd.h>

#include "file.h"

#include "macro.h"
#include "logf.h"
#include "mem.h"
#include "fd.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <alloca.h>

/******************************************************************************/

bool
file_exists(const char *file)
{
	struct stat s;

	return !stat(file, &s);
}

bool
file_is_regular(const char *file)
{
	struct stat s;

	return !lstat(file, &s) && S_ISREG(s.st_mode);
}

bool
file_is_link(const char *file)
{
	struct stat s;

	return !lstat(file, &s) && S_ISLNK(s.st_mode);
}

bool
file_is_dir(const char *file)
{
	struct stat s;

	return !lstat(file, &s) && S_ISDIR(s.st_mode);
}

bool
file_is_blk(const char *file)
{
	struct stat s;

	return !lstat(file, &s) && S_ISBLK(s.st_mode);
}

bool
file_links_to_blk(const char *file)
{
	struct stat s;

	if (file_is_link(file))
		return !stat(file, &s) && S_ISBLK(s.st_mode);

	return !lstat(file, &s) && S_ISBLK(s.st_mode);
}

bool
file_is_mountpoint(const char *file)
{
	bool ret;
	struct stat s, s_parent;
	char *parent = mem_printf("%s/..", file);

	ret = !lstat(file, &s);
	ret &= !lstat(parent, &s_parent);
	ret &= (s.st_dev != s_parent.st_dev);

	mem_free0(parent);
	return ret;
}

bool
file_is_socket(const char *file)
{
	struct stat s;

	return !lstat(file, &s) && S_ISSOCK(s.st_mode);
}

bool
file_is_fifo(const char *file)
{
	struct stat s;

	return !lstat(file, &s) && S_ISFIFO(s.st_mode);
}

int
file_copy(const char *in_file, const char *out_file, ssize_t count, size_t bs, off_t seek)
{
	int in_fd, out_fd, ret = 0;
	ssize_t i;
	unsigned char *buf;

	IF_NULL_RETVAL(in_file, -1);
	IF_NULL_RETVAL(out_file, -1);
	IF_FALSE_RETVAL(bs, -1);

	in_fd = open(in_file, O_RDONLY);
	if (in_fd < 0) {
		DEBUG_ERRNO("Could not open input file %s", in_file);
		return -1;
	}

	out_fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 00666);
	if (out_fd < 0) {
		DEBUG_ERRNO("Could not open output file %s", out_file);
		close(in_fd);
		return -1;
	}

	buf = mem_alloc0(bs);

	ret = lseek(out_fd, seek * bs, SEEK_SET);
	if (ret < 0) {
		DEBUG_ERRNO("Could not lseek in output file %s", out_file);
		goto out;
	}

	for (i = 0; i != count; i++) {
		ssize_t len;

		len = read(in_fd, buf, bs);

		if (0 == (i % 1024))
			TRACE("Copied %ld bytes from %s to %s", MUL_WITH_OVERFLOW_CHECK(bs, i),
			      in_file, out_file);

		if (len == 0) {
			goto out;
		} else if (len < 0) {
			DEBUG_ERRNO("Could not read from input file %s", in_file);
			ret = -1;
			goto out;
		} else /* if (len > 0) */ {
			if (write(out_fd, buf, len) < 0) {
				DEBUG_ERRNO("Could not write to output file %s", out_file);
				ret = -1;
				goto out;
			}
		}
	}

out:
	close(out_fd);
	close(in_fd);
	mem_free(buf);

	return ret;
}

int
file_move(const char *src, const char *dst, size_t bs)
{
	if (rename(src, dst) == 0)
		return 0;
	if (bs == 0)
		return -1;
	if (file_is_dir(src)) {
		WARN("Cannot move directory by copying");
		return -1;
	}
	if (file_copy(src, dst, -1, bs, 0) < 0)
		return -1;
	return unlink(src);
}

static int
file_write_internal(const char *file, const char *buf, ssize_t len, int oflags)
{
	int fd;

	IF_NULL_RETVAL(file, -1);
	IF_NULL_RETVAL(buf, -1);

	fd = open(file, oflags, 00666);
	if (fd < 0) {
		DEBUG_ERRNO("Could not open output file %s", file);
		return -1;
	}

	if (len < 0)
		len = strlen(buf);

	int bytes_written = fd_write(fd, buf, len);
	if (bytes_written < 0) {
		DEBUG("Could not write to output file %s", file);
		close(fd);
		return -1;
	}

	close(fd);
	return bytes_written;
}

int
file_write(const char *file, const char *buf, ssize_t len)
{
	return file_write_internal(file, buf, len, O_WRONLY | O_CREAT | O_TRUNC);
}

int
file_write_append(const char *file, const char *buf, ssize_t len)
{
	int oflags = O_WRONLY;
	oflags |= file_exists(file) ? O_APPEND : (O_CREAT | O_TRUNC);

	return file_write_internal(file, buf, len, oflags);
}

int
file_printf(const char *file, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int ret;

	IF_NULL_RETVAL(file, -1);

	va_start(ap, fmt);
	buf = mem_vprintf(fmt, ap);
	va_end(ap);

	ret = file_write(file, buf, -1);
	mem_free0(buf);
	return ret;
}

int
file_printf_append(const char *file, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int ret;

	IF_NULL_RETVAL(file, -1);

	va_start(ap, fmt);
	buf = mem_vprintf(fmt, ap);
	va_end(ap);

	ret = file_write_append(file, buf, -1);
	mem_free0(buf);
	return ret;
}

int
file_read(const char *file, char *buf, size_t len)
{
	int fd;

	IF_NULL_RETVAL(file, -1);
	IF_NULL_RETVAL(buf, -1);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		DEBUG("Could not open input file %s", file);
		return -1;
	}

	int bytes_read;

	if ((bytes_read = fd_read(fd, buf, len)) < 0) {
		DEBUG("Could not read from input file %s", file);
		close(fd);
		return -1;
	}

	close(fd);
	return bytes_read;
}

char *
file_read_new(const char *file, size_t maxlen)
{
	char *maxbuf, *buf;

	IF_NULL_RETVAL(file, NULL);

	maxbuf = mem_new(char, maxlen);

	int bytes_read;

	if ((bytes_read = file_read(file, maxbuf, maxlen - 1)) < 0) {
		mem_free0(maxbuf);
		return NULL;
	}

	// Make sure the buffer returned is nul terminated
	maxbuf[bytes_read] = '\0';

	buf = mem_strdup(maxbuf);
	mem_free0(maxbuf);
	return buf;
}

off_t
file_size(const char *file)
{
	struct stat s;
	if (stat(file, &s) < 0)
		return -1;
	return s.st_size;
}

char *
file_get_extension(const char *file)
{
	ASSERT(file);

	char *ext = strrchr(file, '.');
	if (!ext)
		return "";
	return ext;
}

int
file_touch(const char *file)
{
	IF_NULL_RETVAL(file, -1);

	if (file_exists(file)) {
		int fd = open(file, O_WRONLY | O_CREAT, 00666);
		if (fd < 0) {
			DEBUG_ERRNO("Could not touch output file %s", file);
			return -1;
		}

		close(fd);
	} else {
		if (-1 == mknod(file, S_IFREG | 00666, 0)) {
			DEBUG_ERRNO("Could not create file %s", file);
			return -1;
		}
	}

	return 0;
}

void
file_syncfs(const char *file)
{
	IF_NULL_RETURN(file);

	int fd = open(file, O_WRONLY);
	if (syncfs(fd))
		WARN_ERRNO("Failed to sync fs for '%s'", file);

	close(fd);
}

bool
file_on_same_fs(const char *path1, const char *path2)
{
	IF_NULL_RETVAL(path1, false);
	IF_NULL_RETVAL(path2, false);

	struct stat s1, s2;

	if (lstat(path1, &s1) < 0 || lstat(path2, &s2) < 0)
		return false;

	return s1.st_dev == s2.st_dev;
}

off_t
file_disk_space(const char *path)
{
	IF_NULL_RETVAL(path, -1);
	struct statvfs s;

	if (statvfs(path, &s) < 0)
		return -1;

	return s.f_blocks * s.f_frsize;
}

off_t
file_disk_space_free(const char *path)
{
	IF_NULL_RETVAL(path, -1);
	struct statvfs s;

	if (statvfs(path, &s) < 0)
		return -1;

	return s.f_bfree * s.f_frsize;
}

off_t
file_disk_space_used(const char *path)
{
	IF_NULL_RETVAL(path, -1);
	struct statvfs s;

	if (statvfs(path, &s) < 0)
		return -1;

	return (s.f_blocks - s.f_bfree) * s.f_frsize;
}

bool
file_disk_space_available(const char *path, off_t required, float threshold)
{
	ASSERT(path);
	IF_TRUE_RETVAL_ERROR((threshold < 0 || threshold > 1), false);

	off_t available = file_disk_space_free(path);
	IF_TRUE_RETVAL_ERROR(available < 0, false);

	off_t min_free_space = file_disk_space(path);
	IF_TRUE_RETVAL_ERROR(min_free_space < 0, false);

	min_free_space *= threshold;

	if (required > available || (available - required) < min_free_space) {
		ERROR("Not enough disk space left");
		return false;
	}

	return true;
}
