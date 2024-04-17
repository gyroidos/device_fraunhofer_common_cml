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

#ifndef TOKEN_H
#define TOKEN_H

#include "softtoken.h"
#include "usbtoken.h"
#include "p11token.h"

#include "common/uuid.h"

#include <stdbool.h>
#include <stddef.h>

#define STOKEN_DEFAULT_PASS "trustme"

//has to be kept in sync with smartcard.h
// clang-format off
#define SCD_TOKENCONTROL_SOCKET SOCK_PATH(tokencontrol)
// clang-format on

/**
 *  Generic token type
 */
typedef struct scd_token scd_token_t;

/**
 * Internal data of the generic scd token.
 */
typedef struct scd_token_data scd_token_data_t;

/**
 * Choice of supported token types.
 * Must be kept in sync with scd.proto
 */
typedef enum scd_tokentype { NONE, SOFT, USB, PKCS11 } scd_tokentype_t;

/**
 * Data used by the constructor scd_token_new
 */
typedef struct token_constr_data {
	scd_tokentype_t type;
	char *uuid;

	union {
		const char *softtoken_dir;
		const char *usbtoken_serial;
		const char *pkcs11_module;
	} init_str;
} token_constr_data_t;

/**
 *  generic scd_token.
 */
struct scd_token {
	scd_token_data_t *token_data;

	int (*lock)(scd_token_t *token);
	int (*unlock)(scd_token_t *token, char *passwd, unsigned char *pairing_secret,
		      size_t pairing_sec_len);

	bool (*is_locked)(scd_token_t *token);
	bool (*is_locked_till_reboot)(scd_token_t *token);

	int (*wrap_key)(scd_token_t *token, char *label, unsigned char *plain_key,
			size_t plain_key_len, unsigned char **wrapped_key, int *wrapped_key_len);

	int (*unwrap_key)(scd_token_t *token, char *label, unsigned char *wrapped_key,
			  size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len);

	int (*change_passphrase)(scd_token_t *token, const char *oldpass, const char *newpass,
				 unsigned char *pairing_secret, size_t pairing_sec_len,
				 bool is_provisioning);
	int (*send_apdu)(scd_token_t *token, unsigned char *apdu, size_t apdu_len,
			 unsigned char *brsp, size_t brsp_len);
	int (*reset_auth)(scd_token_t *token, unsigned char *brsp, size_t brsp_len);
	int (*get_atr)(scd_token_t *token, unsigned char *brsp, size_t brsp_len);
};

/**
 * returns the token's type.
 * @param token the token to operate on
 *
 * @return the type of the scd token
 */
scd_tokentype_t
token_get_type(scd_token_t *token);

/**
 * returns the token's uuid.
 * @param token the token to operate on
 *
 * @return pointer to the uuid of the token on success or else NULL
 */
uuid_t *
token_get_uuid(scd_token_t *token);

/**
 * checks if the int_token is the internal token of the corresponding token.
 * @param token the token to operate on
 * @param int_token the token to checked
 *
 * @return true if int_token is internal token of token, false otherwise
 */
bool
token_has_internal_token(scd_token_t *token, const void *int_token);

/**
 * creates a new generic token
 * calls the respective create function for the selected type of token and
 * sets the function pointer appropriately
 * @param constr_data data used by the constructor
 *
 * @return pointer to the newly created generic token on success or else NULL
 */
scd_token_t *
token_new(const token_constr_data_t *constr_data);

/**
 * frees a generic scd token
 * @param token the token to be freed
 *
 * @return void
 */
void
token_free(scd_token_t *token);

#endif /* TOKEN_H */
