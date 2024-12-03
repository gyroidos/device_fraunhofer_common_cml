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
 * @file.h
 * This module serves as a library to simplify the handling of files, such as writing, reading
 * to/from a file specified by its path.
 */

#ifndef FILE_H
#define FILE_H

#include <stdbool.h>
#include <sys/types.h>

bool
file_exists(const char *file);

bool
file_is_regular(const char *file);

bool
file_is_link(const char *file);

bool
file_is_dir(const char *file);

bool
file_is_blk(const char *file);

bool
file_links_to_blk(const char *file);

bool
file_is_mountpoint(const char *file);

bool
file_is_socket(const char *file);

bool
file_is_fifo(const char *file);

/**
 * Copy a file.
 * @param in_file The file to be read.
 * @param out_file The file to be written.
 * @param count Copy count input blocks, may be -1 to copy until end of file.
 * @param bs Read and write up to bs bytes at a time.
 * @param seek Skip seek blocks at start of output.
 * @return -1 on error else 0.
 */
int
file_copy(const char *in_file, const char *out_file, ssize_t count, size_t bs, off_t seek);

/**
 * Copy a regular file with zero copy.
 * @param in_file The file to be read.
 * @param out_file The file to be written.
 * @param len
 * @param seek Skip seek blocks at start of output.
 * @return -1 on error else 0.
 */
int
file_copy_zero(const char *in_file, const char *out_file, size_t len, off_t seek);

/**
 * Move a file.
 * @param src The source file name.
 * @param dst The destination file name.
 * @param bs Fallback blocksize for copying and unlinking the file (across file system boundaries).
 * @return -1 on error else 0.
 */
int
file_move(const char *src, const char *dst, size_t bs);

/**
 * Write a string to a file.
 * @param file The file name.
 * @param buf The buffer to be written.
 * @param len The length of buffer, maybe -1 to determine buffer length with strlen().
 * @return -1 on error else the number of bytes written.
 */
int
file_write(const char *file, const char *buf, ssize_t len);

/**
 * Append  a string to the end of a file.
 * @param file The file name.
 * @param buf The buffer to be written.
 * @param len The length of buffer, maybe -1 to determine buffer length with strlen().
 * @return -1 on error else the number of bytes written.
 */
int
file_write_append(const char *file, const char *buf, ssize_t len);

/**
 * Write a string to a file using printf.
 * @param file The file name.
 * @param fmt The format string.
 * @return -1 on error else the number of bytes written.
 */
int
file_printf(const char *file, const char *fmt, ...);

/**
 * Append a string to the end of a file using printf.
 * @param file The file name.
 * @param fmt The format string.
 * @return -1 on error else the number of bytes written.
 */
int
file_printf_append(const char *file, const char *fmt, ...);

/**
 * Read a string from a file.
 * @param file The file name.
 * @param buf A buffer to read the file data into.
 * @param len The length of buffer.
 * @return -1 on error else the number of bytes read.
 */
int
file_read(const char *file, char *buf, size_t len);

/**
 * Read a string from a file and allocate memory for it.
 * @param file The file name.
 * @param maxlen The maximum length to read.
 * @return A newly allocated buffer with the string read from file and NULL in case of an error.
 */
char *
file_read_new(const char *file, size_t maxlen);

/**
 * Return the size of the given file or -1 on error.
 * @param file The file name.
 * @return The size of the given file or -1 on error.
 */
off_t
file_size(const char *file);

/**
 * Return file extension of a given file including '.'.
 * Note: fails if path contains a '.' and file has no ending
 * @ param file The file name
 */
char *
file_get_extension(const char *file);

/**
 * creates an empty file
 * @param file The file name
 * @return -1 on error else 0
 */
int
file_touch(const char *file);

/**
 * syncs filesystem containg the corresponig file
 * @param file The file name
 */
void
file_syncfs(const char *file);

/**
 * Check whether to files/dirs are on the same file system
 * @param path1 path to first file or directory
 * @param path2 path to second file or directory
 * @return true if on same fs, false otherwise.
 */
bool
file_on_same_fs(const char *path1, const char *path2);

/**
 * get disk space of underlying file system of the corresponding
 * file or directory at path.
 * @param path The file name or directory name
 * @return The size of the file system on the given path or -1 on error.
 */
off_t
file_disk_space(const char *path);

/**
 * get free disk space of underlying file system of the corresponding
 * file or directory at path.
 * @param path The file name or directory name
 * @return The free space in the file system for the given path or -1 on error.
 */
off_t
file_disk_space_free(const char *path);

/**
 * get used disk space of underlying file system of the corresponding
 * file or directory at path.
 * @param path The file name or directory name
 * @return The used disk space of the file system for the given path or -1 on error.
 */
off_t
file_disk_space_used(const char *path);

/**
 * check if enough disk space is available on underlying file system of the corresponding
 * file or directory at path.
 * @param path The file name or directory name
 * @param required The required disk space
 * @param threshold Percentage of space which should be keept free; value in the range [0,1]
 * @return true if enough space is available, false otherwise
 */
bool
file_disk_space_available(const char *path, off_t required, float threshold);

#endif /* FILE_H */
