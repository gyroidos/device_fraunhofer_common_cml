/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2024 Fraunhofer AISEC
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

#ifndef P11TOKEN_H
#define P11TOKEN_H

#include <stdbool.h>
#include <stddef.h>

typedef struct p11token p11token_t;

/**
 * Create new PKCS1#11 token.
 * @param module_path path to PKCS1#11 module library (e.g. libsofthsm2)
 * @param so_pin pin which should be used by the SO (only required for initialisation)
 * @param user_pin pin which should be used for day to day usage
 * @param label name of the new PKCS#11 token
 * @return Success: pointer to the newly created token, Error: NULL
*/
p11token_t *
p11token_create_p11(const char *module_path, const char *so_pin, const char *user_pin,
		    const char *label);

/**
 * Get token by label.
 * @param module_path path to PKCS1#11 module library (e.g. libsofthsm2)
 * @param label label of the desired token
 * @return Success: pointer to token; Error: NULL
*/
p11token_t *
p11token_token_by_label(const char *module_path, const char *label);

/**
 * Lock token and cleanup data structure.
 * @param token
 * @return Success: 0, Error: -1
*/
int
p11token_free(p11token_t *token);

/**
 * Unlock token with pin
 * @param token
 * @param user_pin
 * @return Success: 0, Error: -1
*/
int
p11token_unlock(p11token_t *token, const char *user_pin);

/**
 * Lock token.
 * @param token
 * @return Success: 0, Error: -1
*/
int
p11token_lock(p11token_t *token);

/**
 * Check whether token is locked.
 * @param token
 * @return True if Token is locked, False otherwise
*/
bool
p11token_is_locked(p11token_t *token);

/**
 * Check whether token is locked until reboot.
 * @param token
 * @return True if Token is locked, False otherwise
*/
bool
p11token_is_locked_till_reboot(p11token_t *token);

/**
 * Wrap given key with token
 * @param token
 * @param plain_key raw key-data
 * @param plain_key_len size of the key-buffer
 * @param wrapped_key pointer to buffer which should contain wrapped key
 * @param wrapped_key_len size of the buffer pointed to by wrapped_key
*/
int
p11token_wrap_key(p11token_t *token, unsigned char *plain_key, size_t plain_key_len,
		  unsigned char **wrapped_key, unsigned long *wrapped_key_len);

/**
 * Wrap given key with token
 * @param token
 * @param wrapped_key wrapped key
 * @param wrapped_key_len size of the buffer pointed to by wrapped_key
 * @param plain_key pointer to buffer which should contain plaintext key
 * @param plain_key_len size of the key-buffer
 * @return Success: 0, Error: -1
*/
int
p11token_unwrap_key(p11token_t *token, unsigned char *wrapped_key, size_t wrapped_key_len,
		    unsigned char **plain_key, unsigned long *plain_key_len);

/**
 * Change pin of token.
 * @param token
 * @param old_pin
 * @param new_pin
 * @return Success: 0, Error: -1
*/
int
p11token_change_pin(p11token_t *token, const char *old_pin, const char *new_pin);

#endif // P11TOKEN_H
