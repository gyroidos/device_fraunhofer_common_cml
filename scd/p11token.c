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

// pkcs11 helper for token interface

#include "p11token.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/str.h"
#include "uuid.h"
#include "pkcs11-lib/libpkcs11.h"
#include <string.h>
#include <stdbool.h>

#define P11TOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3
#define P11_LABEL_MAX_LEN 32

#define P11_CHECK_RV_RETURN(expr)                                                                  \
	do {                                                                                       \
		ck_rv_t rv = expr;                                                                 \
		if (rv != CKR_OK) {                                                                \
			ERROR("Pkcs11 operation '%s' returned Errorcode %lu\n", #expr, rv);        \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

#define P11_CHECK_RV_GOTO(expr, label)                                                             \
	do {                                                                                       \
		ck_rv_t rv = expr;                                                                 \
		if (rv != CKR_OK) {                                                                \
			fprintf(stderr, "Pkcs11 operation '%s' returned Errorcode %lu\n", #expr,   \
				rv);                                                               \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

struct p11token {
	char *module_path;
	unsigned char label[P11_LABEL_MAX_LEN];
	unsigned int wrong_unlock_attempts;
	struct ck_function_list *ctx;
	ck_session_handle_t *sh;
	void *module;
};

// Helper Functions
ck_slot_id_t *
int_get_free_slot_id_new(struct ck_function_list *ctx);

ck_slot_id_t *
int_get_token_slot_id_new(struct ck_function_list *ctx, const unsigned char *label);

unsigned char *
int_p11_token_label_new(const char *label);

/**
 * create a new pkcs11 token
*/
p11token_t *
p11token_create_p11(const char *module_path, const char *so_pin, const char *user_pin,
		    const char *label)
{
	ASSERT(module_path);
	ASSERT(so_pin);
	ASSERT(user_pin);
	ASSERT(label);

	struct ck_function_list *ctx = NULL;
	ck_slot_id_t *slot = NULL;
	unsigned char *token_label = NULL;
	// load pkcs11-module (load dll at runtime)
	void *module = C_LoadModule(module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
	}

	// init library
	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// get free slot
	slot = int_get_free_slot_id_new(ctx);
	IF_TRUE_GOTO_ERROR(slot == NULL, error);

	// sanitize label
	token_label = int_p11_token_label_new(label);

	// initialize token on free slot
	P11_CHECK_RV_GOTO(ctx->C_InitToken(*slot, (unsigned char *)so_pin, strlen(so_pin),
					   (unsigned char *)token_label),
			  error);

	// connect to token
	ck_session_handle_t sh;
	P11_CHECK_RV_GOTO(ctx->C_OpenSession(*slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL,
					     &sh),
			  error);

	// login as SO
	P11_CHECK_RV_GOTO(ctx->C_Login(sh, CKU_SO, (unsigned char *)so_pin, strlen(so_pin)),
			  error_session);

	// set user pin
	P11_CHECK_RV_GOTO(ctx->C_InitPIN(sh, (unsigned char *)user_pin, strlen(user_pin)),
			  error_session);

	// logout SO
	P11_CHECK_RV_GOTO(ctx->C_Logout(sh), error_session);

	// login as user
	P11_CHECK_RV_GOTO(ctx->C_Login(sh, CKU_USER, (unsigned char *)user_pin, strlen(user_pin)),
			  error_session);

	// create symmetric key
	ck_object_handle_t h_key;
	struct ck_mechanism mechanism = { CKM_AES_KEY_GEN, NULL, 0 };
	ck_key_type_t aes_type = CKK_AES;
	unsigned long length = 32; // size in bytes -> 256bit key
	bool y = true;
	bool n = false;
	struct ck_attribute aes_key_template[] = {
		{ CKA_KEY_TYPE, &aes_type, sizeof(aes_type) },
		{ CKA_TOKEN, &y, sizeof(y) },	    // persistently store key on token
		{ CKA_EXTRACTABLE, &n, sizeof(n) }, // key should not be extractable
		{ CKA_LABEL, &label, strlen(label) },
		{ CKA_VALUE_LEN, &length, sizeof(length) },
	};
	P11_CHECK_RV_GOTO(ctx->C_GenerateKey(sh, &mechanism, aes_key_template,
					     ELEMENTSOF(aes_key_template), &h_key),
			  error_session);

	// logout user
	P11_CHECK_RV_GOTO(ctx->C_Logout(sh), error_session);

	// terminate token-session
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);

	// free slot id ptr
	mem_free(slot);

	// Unload Module
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
	C_UnloadModule(module);

	// return new token data
	p11token_t *token = (p11token_t *)mem_new0(p11token_t, 1);
	token->module_path = mem_strdup(module_path);
	memcpy(token->label, token_label, P11_LABEL_MAX_LEN);
	// free label
	mem_free0(token_label);
	token->wrong_unlock_attempts = 0;
	token->ctx = NULL;
	token->sh = NULL;
	token->module = NULL;
	return token;
error_session:
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);
error:
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
error_init:
	if (slot) {
		mem_free(slot);
	}
	if (token_label) {
		mem_free(token_label);
	}
	C_UnloadModule(module);
	return NULL;
}

p11token_t *
p11token_token_by_label(const char *module_path, const char *label)
{
	ASSERT(module_path);
	ASSERT(label);

	struct ck_function_list *ctx = NULL;
	unsigned char *token_label = NULL;
	ck_slot_id_t *slot = NULL;
	// load module
	void *module = C_LoadModule(module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
	}

	// init library
	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// check if token exists
	token_label = int_p11_token_label_new(label);
	slot = int_get_token_slot_id_new(ctx, token_label);
	if (slot == NULL) {
		INFO("token for %s not found", label);
		goto error; // cleanup and return null
	}

	// cleanup
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
	C_UnloadModule(module);

	// if token exists create new token-object
	p11token_t *token = (p11token_t *)mem_new0(p11token_t, 1);
	token->module_path = mem_strdup(module_path);
	memcpy(token->label, token_label, P11_LABEL_MAX_LEN);
	// free label
	mem_free0(token_label);
	token->wrong_unlock_attempts = 0;
	token->ctx = NULL;
	token->sh = NULL;
	token->module = NULL;
	return token;
error:
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
error_init:
	if (token_label) {
		mem_free(token_label);
	}
	if (slot) {
		mem_free(slot);
	}
	C_UnloadModule(module);
	return NULL;
}

/**
 * lock token and cleanup data structure
*/
int
p11token_free(p11token_t *token)
{
	ASSERT(token);
	ASSERT(token->module_path);

	if (!p11token_is_locked(token)) {
		ERROR("token is not locked");
		return -1;
	}

	mem_free(token->module_path);
	mem_free(token);
	return 0;
}

int
p11token_unlock(p11token_t *token, const char *user_pin)
{
	ASSERT(token);
	ASSERT(user_pin);

	ck_slot_id_t *slot_id = NULL;

	if (p11token_is_locked_till_reboot(token)) {
		WARN("PKCS11 token: too many failed unlock attempts");
		return -1;
	}

	if (!p11token_is_locked(token)) {
		WARN("Pkcs11 token is already unlocked");
		return 0;
	}
	// load library and connect to token
	token->module = C_LoadModule(token->module_path, &token->ctx);
	if (token->module == NULL) {
		ERROR("Could not load pkcs11 module");
	}

	P11_CHECK_RV_GOTO(token->ctx->C_Initialize(NULL), error_init);

	// search token
	slot_id = int_get_token_slot_id_new(token->ctx, token->label);
	IF_TRUE_GOTO_ERROR(slot_id == NULL, error);
	// create session handle
	token->sh = (ck_session_handle_t *)mem_alloc0(sizeof(ck_session_handle_t));

	// connect to token
	P11_CHECK_RV_GOTO(token->ctx->C_OpenSession(*slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION,
						    NULL, NULL, token->sh),
			  error);
	mem_free(slot_id);
	slot_id = NULL;

	// login
	switch (token->ctx->C_Login(*token->sh, CKU_USER, (unsigned char *)user_pin,
				    strlen(user_pin))) {
	case CKR_OK:
		token->wrong_unlock_attempts = 0;
		return 0;
	case CKR_PIN_INCORRECT:
		token->wrong_unlock_attempts += 1;
	default:
		goto error_session;
	}
error_session:
	P11_CHECK_RV_GOTO(token->ctx->C_CloseSession(*token->sh), error);
error:
	if (token->sh) {
		mem_free(token->sh);
		token->sh = NULL;
	}
	if (slot_id) {
		mem_free(slot_id);
	}
	P11_CHECK_RV_GOTO(token->ctx->C_Finalize(NULL), error_init);
	token->ctx = NULL;
error_init:

	C_UnloadModule(token->module);
	return -1;
}

int
p11token_lock(p11token_t *token)
{
	ASSERT(token);

	P11_CHECK_RV_RETURN(token->ctx->C_Logout(*token->sh));

	P11_CHECK_RV_RETURN(token->ctx->C_CloseSession(*token->sh));
	free(token->sh);
	token->sh = NULL;

	P11_CHECK_RV_RETURN(token->ctx->C_Finalize(NULL));
	token->ctx = NULL;

	C_UnloadModule(token->module);

	return 0;
}

bool
p11token_is_locked(p11token_t *token)
{
	ASSERT(token);

	return (token->ctx == NULL && token->sh == NULL);
}

bool
p11token_is_locked_till_reboot(p11token_t *token)
{
	ASSERT(token);

	return token->wrong_unlock_attempts >= P11TOKEN_MAX_WRONG_UNLOCK_ATTEMPTS;
}

int
p11token_wrap_key(p11token_t *token, unsigned char *plain_key, size_t plain_key_len,
		  unsigned char **wrapped_key, unsigned long *wrapped_key_len)
{
	ASSERT(token);
	ASSERT(plain_key);
	ASSERT(wrapped_key);
	ASSERT(wrapped_key_len);

	unsigned char *ptr = NULL;

	if (p11token_is_locked(token)) {
		ERROR("p11token_wrap_key: token is locked");
		goto error;
	}

	// get wrapping key handle
	// currently there is only one, therefore we can keep the search template simple
	ck_key_type_t aes_key_type = CKK_AES;
	struct ck_attribute search_template[] = {
		{ CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
	};
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsInit(*token->sh, search_template,
							ELEMENTSOF(search_template)),
			  error);
	ck_object_handle_t h_key;
	unsigned long num_objects_found;
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjects(*token->sh, &h_key, 1, &num_objects_found),
			  error);
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsFinal(*token->sh), error);
	if (0 == num_objects_found) {
		ERROR("\nwrapping key not found\n");
		goto error;
	}

	// wrap key
	/**
	 * static default IV as defined in RFC 3394
	 * TODO: investigate whether a random IV which is passed along with the
	 * 			wrapped key is possible and desirable
	 */
	unsigned char iv[] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
			       0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
	struct ck_mechanism wrap_mechanism = {
		CKM_AES_CBC_PAD,
		iv,
		ELEMENTSOF(iv),
	};
	P11_CHECK_RV_GOTO(token->ctx->C_EncryptInit(*token->sh, &wrap_mechanism, h_key), error);
	// retrieve buffer size
	P11_CHECK_RV_GOTO(token->ctx->C_Encrypt(*token->sh, plain_key, plain_key_len, NULL,
						wrapped_key_len),
			  error);
	ptr = (unsigned char *)mem_alloc0(*wrapped_key_len);
	IF_TRUE_GOTO_DEBUG(NULL == ptr, error);
	P11_CHECK_RV_GOTO(token->ctx->C_Encrypt(*token->sh, plain_key, plain_key_len, ptr,
						wrapped_key_len),
			  error);
	*wrapped_key = ptr;
	return 0;
error:
	if (ptr) {
		mem_free0(ptr);
	}
	return -1;
}

int
p11token_unwrap_key(p11token_t *token, unsigned char *wrapped_key, size_t wrapped_key_len,
		    unsigned char **plain_key, unsigned long *plain_key_len)
{
	ASSERT(token);
	ASSERT(wrapped_key);
	ASSERT(plain_key);
	ASSERT(plain_key_len);

	unsigned char *ptr = NULL;

	if (p11token_is_locked(token)) {
		ERROR("p11token_wrap_key: token is locked");
		goto error;
	}

	// get wrapping key handle
	// currently there is only one, therefore we can keep the template simple
	ck_key_type_t aes_key_type = CKK_AES;
	struct ck_attribute search_template[] = {
		{ CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
	};
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsInit(*token->sh, search_template,
							ELEMENTSOF(search_template)),
			  error);
	ck_object_handle_t h_key;
	unsigned long num_objects_found;
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjects(*token->sh, &h_key, 1, &num_objects_found),
			  error);
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsFinal(*token->sh), error);
	if (0 == num_objects_found) {
		goto error;
	}
	// unwrap key
	/**
	 * static default IV as defined in RFC 3394
	 * TODO: investigate whether a random IV which is passed along with the
	 * 			wrapped key is possible and desirable
	 */
	unsigned char iv[] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
			       0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
	struct ck_mechanism wrap_mechanism = {
		CKM_AES_CBC_PAD,
		iv,
		ELEMENTSOF(iv),
	};
	P11_CHECK_RV_GOTO(token->ctx->C_DecryptInit(*token->sh, &wrap_mechanism, h_key), error);
	P11_CHECK_RV_GOTO(token->ctx->C_Decrypt(*token->sh, wrapped_key, wrapped_key_len, NULL,
						plain_key_len),
			  error);
	ptr = (unsigned char *)mem_alloc0(*plain_key_len);
	IF_TRUE_GOTO_DEBUG(NULL == ptr, error);
	P11_CHECK_RV_GOTO(token->ctx->C_Decrypt(*token->sh, wrapped_key, wrapped_key_len, ptr,
						plain_key_len),
			  error);
	*plain_key = ptr;

	return 0;
error:
	if (ptr) {
		mem_free0(ptr);
	}
	return -1;
}

int
p11token_change_pin(p11token_t *token, const char *old_pin, const char *new_pin)
{
	ASSERT(token);
	ASSERT(old_pin);
	ASSERT(new_pin);

	if (-1 == p11token_unlock(token, old_pin)) {
		goto error;
	}

	P11_CHECK_RV_GOTO(token->ctx->C_SetPIN(*token->sh, (unsigned char *)old_pin,
					       strlen(old_pin), (unsigned char *)new_pin,
					       strlen(new_pin)),
			  error);

	return p11token_lock(token);
error:
	return -1;
}

// internal helper functions

/**
 * get next free slot id
*/
ck_slot_id_t *
int_get_free_slot_id_new(struct ck_function_list *ctx)
{
	ASSERT(ctx);

	unsigned long slot_count = 0;
	ck_slot_id_t *p_slots = NULL;

	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(false, NULL, &slot_count), error);
	p_slots = (ck_slot_id_t *)mem_alloc(slot_count * sizeof(ck_slot_id_t));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(false, p_slots, &slot_count), error);

	for (unsigned long i = 0; i < slot_count; i++) {
		ck_rv_t rv = CKR_OK;
		struct ck_slot_info slot_info;
		if ((rv = ctx->C_GetSlotInfo(p_slots[i], &slot_info)) == CKR_OK) {
			if ((i == p_slots[i])) {
				ck_slot_id_t *free_slot = mem_alloc(sizeof(ck_slot_id_t));
				*free_slot = p_slots[i];

				mem_free(p_slots);
				return free_slot;
			}
		} else {
			WARN("Retrieving Info for slot %lu failed with %lu", p_slots[i], rv);
		}
	}

error:
	if (p_slots) {
		mem_free(p_slots);
	}
	return NULL;
}

/**
 * find token by label
*/
ck_slot_id_t *
int_get_token_slot_id_new(struct ck_function_list *ctx, const unsigned char *label)
{
	ASSERT(ctx);
	ASSERT(label);

	// get slot list
	ck_slot_id_t *p_slots = NULL;
	unsigned long slot_count = 0;
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(true, NULL, &slot_count), error);
	p_slots = (ck_slot_id_t *)mem_alloc(slot_count * sizeof(ck_slot_id_t));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(false, p_slots, &slot_count), error);

	for (unsigned long i = 0; i < slot_count; i++) {
		ck_rv_t rv = CKR_OK;
		struct ck_token_info token_info;
		if ((rv = ctx->C_GetTokenInfo(p_slots[i], &token_info)) == CKR_OK) {
			if (0 ==
			    strncmp((char *)token_info.label, (char *)label, P11_LABEL_MAX_LEN)) {
				ck_slot_id_t *slot_id =
					(ck_slot_id_t *)mem_alloc(sizeof(ck_slot_id_t));
				*slot_id = p_slots[i];

				mem_free(p_slots);
				return slot_id;
			}
		} else {
			WARN("Retrieving Info for slot %lu failed with %lu", p_slots[i], rv);
		}
	}
error:
	if (p_slots) {
		mem_free(p_slots);
	}
	return NULL;
}

/**
 * Converts a string into a token label: must not be null-terminated according to spec
*/
unsigned char *
int_p11_token_label_new(const char *label)
{
	ASSERT(label);

	size_t len_label = strlen(label);
	unsigned char *token_label = mem_alloc0(P11_LABEL_MAX_LEN);
	if (len_label <= P11_LABEL_MAX_LEN) {
		memcpy(token_label, label, len_label);

		// pad remaining space
		for (size_t i = len_label + 1; i < P11_LABEL_MAX_LEN; i++) {
			token_label[i] = ' ';
		}
	} else {
		// label is too long: truncate
		memcpy(token_label, label, P11_LABEL_MAX_LEN);
	}

	return token_label;
}
