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
#include "string.h"

#define P11TOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3

#define P11_CHECK_RV_RETURN(expr)                                                                  \
	do {                                                                                       \
		CK_RV rv = expr;                                                                   \
		if (rv != CKR_OK) {                                                                \
			ERROR("Pkcs11 operation '%s' returned Errorcode %lu\n", #expr, rv);        \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

#define P11_CHECK_RV_GOTO(expr, label)                                                             \
	do {                                                                                       \
		CK_RV rv = expr;                                                                   \
		if (rv != CKR_OK) {                                                                \
			fprintf(stderr, "Pkcs11 operation '%s' returned Errorcode %lu\n", #expr,   \
				rv);                                                               \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

struct p11token {
	char *module_path;
	CK_UTF8CHAR label[32];
	unsigned int wrong_unlock_attempts;
	CK_FUNCTION_LIST_PTR ctx;
	CK_SESSION_HANDLE_PTR sh;
	void *module;
};

// Helper Functions
CK_SLOT_ID_PTR
internal_find_free_slot(CK_FUNCTION_LIST_PTR ctx);

CK_SLOT_ID_PTR
internal_find_token(CK_FUNCTION_LIST_PTR ctx, const CK_UTF8CHAR *label);

CK_UTF8CHAR *
internal_sanitize_label(const char *label);

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

	// load pkcs11-module (load dll at runtime)
	CK_FUNCTION_LIST_PTR ctx = NULL;
	void *module = C_LoadModule(module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
	}

	// init library
	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// get free slot
	CK_SLOT_ID_PTR slot = internal_find_free_slot(ctx);
	IF_TRUE_GOTO_ERROR(slot == NULL_PTR, error);
	//fprintf(stderr, "\nslot id: %lx\n", *slot);
	// sanitize label
	CK_UTF8CHAR *token_label = internal_sanitize_label(label);

	// initialize token on free slot
	P11_CHECK_RV_GOTO(ctx->C_InitToken(*slot, (CK_CHAR_PTR)so_pin, strlen(so_pin),
					   (CK_CHAR_PTR)token_label),
			  error);

	// connect to token
	CK_SESSION_HANDLE sh;
	P11_CHECK_RV_GOTO(ctx->C_OpenSession(*slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL_PTR,
					     NULL_PTR, &sh),
			  error);
	// login as SO
	P11_CHECK_RV_GOTO(ctx->C_Login(sh, CKU_SO, (CK_CHAR_PTR)so_pin, strlen(so_pin)),
			  error_session);
	// set user pin
	P11_CHECK_RV_GOTO(ctx->C_InitPIN(sh, (CK_CHAR_PTR)user_pin, strlen(user_pin)),
			  error_session);
	// logout SO
	P11_CHECK_RV_GOTO(ctx->C_Logout(sh), error_session);
	// login as user
	P11_CHECK_RV_GOTO(ctx->C_Login(sh, CKU_USER, (CK_CHAR_PTR)user_pin, strlen(user_pin)),
			  error_session);

	// create symmetric key
	CK_OBJECT_HANDLE h_key;
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE aes_type = CKK_AES;
	CK_ULONG length = 32; // size in bytes
	//CK_BYTE id[] = { 123 };
	CK_BBOOL y = CK_TRUE;
	// CK_BBOOL no = CK_FALSE;

	CK_ATTRIBUTE aesKeyTemplate[4] = {
		{ CKA_KEY_TYPE, &aes_type, sizeof(aes_type) },
		{ CKA_TOKEN, &y, sizeof(y) },
		{ CKA_LABEL, &label, sizeof(label) - 1 },
		{ CKA_VALUE_LEN, &length, sizeof(length) },
	};
	P11_CHECK_RV_GOTO(ctx->C_GenerateKey(sh, &mechanism, aesKeyTemplate, 4, &h_key),
			  error_session);

	// logout user
	P11_CHECK_RV_GOTO(ctx->C_Logout(sh), error_session);

	// terminate token-session
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);

	// free slot id ptr
	free(slot);

	// Unload Module
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL_PTR), error_init);
	C_UnloadModule(module);

	// return new token data
	p11token_t *token = (p11token_t *)mem_new0(p11token_t, 1);
	token->module_path = mem_strdup(module_path);
	memcpy(token->label, token_label, 32);
	// free label
	mem_free0(token_label);
	token->wrong_unlock_attempts = 0;
	token->ctx = NULL_PTR;
	token->sh = NULL_PTR;
	token->module = NULL;
	return token;
error_session:
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);
error:
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL_PTR), error_init);
error_init:
	C_UnloadModule(module);
	return NULL;
}

/**
 * find token object by label
*/
p11token_t *
p11token_token_by_label(const char *module_path, const char *label)
{
	ASSERT(module_path);
	ASSERT(label);

	CK_FUNCTION_LIST_PTR ctx = NULL;
	void *module = C_LoadModule(module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
	}

	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// search for token
	CK_UTF8CHAR *token_label = internal_sanitize_label(label);

	CK_SLOT_ID_PTR slot = internal_find_token(ctx, token_label);
	if (slot == NULL) {
		INFO("token for %s not found", label);
		goto error; // cleanup and return null
	}

	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL_PTR), error_init);
	C_UnloadModule(module);

	// return new token
	p11token_t *token = (p11token_t *)mem_new0(p11token_t, 1);
	token->module_path = mem_strdup(module_path);
	memcpy(token->label, token_label, 32);
	// free label
	mem_free0(token_label);
	token->wrong_unlock_attempts = 0;
	token->ctx = NULL_PTR;
	token->sh = NULL_PTR;
	token->module = NULL;
	return token;
error:
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL_PTR), error_init);
error_init:
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

	if (!p11token_is_locked(token)) {
		ERROR("token is not locked");
		return -1;
	}

	free(token->module_path);
	free(token);
	return 0;
}

int
p11token_unlock(p11token_t *token, const char *user_pin)
{
	ASSERT(token);
	ASSERT(user_pin);

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
	CK_SLOT_ID_PTR slot_id = internal_find_token(token->ctx, token->label);
	IF_TRUE_GOTO_ERROR(slot_id == NULL_PTR, error);
	// create session handle
	token->sh = (CK_SESSION_HANDLE_PTR)mem_alloc0(sizeof(CK_SESSION_HANDLE));

	// connect to token
	P11_CHECK_RV_GOTO(token->ctx->C_OpenSession(*slot_id, CKF_RW_SESSION | CKF_SERIAL_SESSION,
						    NULL_PTR, NULL_PTR, token->sh),
			  error);
	free(slot_id);

	// login
	switch (token->ctx->C_Login(*token->sh, CKU_USER, (CK_CHAR_PTR)user_pin,
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
	token->sh = NULL_PTR;
error:
	P11_CHECK_RV_GOTO(token->ctx->C_Finalize(NULL_PTR), error_init);
	token->ctx = NULL_PTR;
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
	token->sh = NULL_PTR;

	P11_CHECK_RV_RETURN(token->ctx->C_Finalize(NULL_PTR));
	token->ctx = NULL_PTR;

	C_UnloadModule(token->module);

	return 0;
}

bool
p11token_is_locked(p11token_t *token)
{
	ASSERT(token);

	return (token->ctx == NULL_PTR && token->sh == NULL_PTR);
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

	if (p11token_is_locked(token)) {
		ERROR("p11token_wrap_key: token is locked");
		fprintf(stderr, "\ntoken is locked\n");
		goto error;
	}

	// CK_BBOOL y = CK_TRUE;

	// get wrapping key handle
	CK_KEY_TYPE aes_key_type = CKK_AES;
	CK_ATTRIBUTE aesKeyTemplate[1] = {
		{ CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
		// todo { CKA_LABEL, &label, sizeof(label) - 1 },
	};
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsInit(*token->sh, aesKeyTemplate, 1), error);
	CK_OBJECT_HANDLE h_key;
	CK_ULONG num_objects_found;
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjects(*token->sh, &h_key, 1, &num_objects_found),
			  error);
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsFinal(*token->sh), error);
	if (0 == num_objects_found) {
		fprintf(stderr, "\nwrapping key not found\n");
		goto error;
	}

	// wrap key
	CK_MECHANISM wrap_mechanism = {
		CKM_AES_ECB,
		NULL,
		0,
	};
	P11_CHECK_RV_GOTO(token->ctx->C_EncryptInit(*token->sh, &wrap_mechanism, h_key), error);
	// retrieve buffer size
	P11_CHECK_RV_GOTO(token->ctx->C_Encrypt(*token->sh, plain_key, plain_key_len, NULL_PTR,
						wrapped_key_len),
			  error);
	*wrapped_key = mem_alloc0(*wrapped_key_len);
	P11_CHECK_RV_GOTO(token->ctx->C_Encrypt(*token->sh, plain_key, plain_key_len, *wrapped_key,
						wrapped_key_len),
			  error);
	ASSERT(*wrapped_key);
	return 0;
error:
	return -1;
}

int
p11token_unwrap_key(p11token_t *token, unsigned char *wrapped_key, size_t wrapped_key_len,
		    unsigned char **plain_key, unsigned long *plain_key_len)
{
	ASSERT(token);
	ASSERT(wrapped_key);
	ASSERT(plain_key);

	if (p11token_is_locked(token)) {
		ERROR("p11token_wrap_key: token is locked");
		goto error;
	}

	CK_BBOOL y = CK_TRUE;
	// get wrapping key handle
	CK_KEY_TYPE aes_key_type = CKK_AES;
	CK_ATTRIBUTE aesKeyTemplate[6] = {
		{ CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) }, { CKA_WRAP, &y, sizeof(y) },
		// todo { CKA_LABEL, &label, sizeof(label) - 1 },
	};
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsInit(*token->sh, aesKeyTemplate, 1), error);
	CK_OBJECT_HANDLE h_key;
	CK_ULONG num_objects_found;
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjects(*token->sh, &h_key, 1, &num_objects_found),
			  error);
	P11_CHECK_RV_GOTO(token->ctx->C_FindObjectsFinal(*token->sh), error);
	if (0 == num_objects_found) {
		goto error;
	}
	// unwrap key
	CK_MECHANISM wrap_mechanism = {
		CKM_AES_ECB,
		NULL,
		0,
	};
	P11_CHECK_RV_GOTO(token->ctx->C_DecryptInit(*token->sh, &wrap_mechanism, h_key), error);
	P11_CHECK_RV_GOTO(token->ctx->C_Decrypt(*token->sh, wrapped_key, wrapped_key_len, NULL_PTR,
						plain_key_len),
			  error);
	*plain_key = (unsigned char *)mem_alloc0(*plain_key_len * sizeof(unsigned char));
	P11_CHECK_RV_GOTO(token->ctx->C_Decrypt(*token->sh, wrapped_key, wrapped_key_len,
						*plain_key, plain_key_len),
			  error);
	return 0;
error:
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
CK_SLOT_ID_PTR
internal_find_free_slot(CK_FUNCTION_LIST_PTR ctx)
{
	CK_ULONG slot_count = 0;

	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count), error);
	CK_SLOT_ID_PTR p_slots = (CK_SLOT_ID_PTR)mem_alloc0(slot_count * sizeof(CK_SLOT_ID));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(CK_FALSE, p_slots, &slot_count), error);

	for (CK_ULONG i = 0; i < slot_count; i++) {
		CK_RV rv = CKR_OK;
		CK_SLOT_INFO slot_info;
		if ((rv = ctx->C_GetSlotInfo(p_slots[i], &slot_info)) == CKR_OK) {
			if ((i == p_slots[i])) {
				CK_SLOT_ID_PTR free_slot = mem_alloc(sizeof(CK_SLOT_ID));
				*free_slot = p_slots[i];
				// free array
				free(p_slots);
				return free_slot;
			}
		} else {
			WARN("Retrieving Info for slot %lu failed with %lu", p_slots[i], rv);
		}
	}

error:
	return NULL_PTR;
}

/**
 * find token by label
*/
CK_SLOT_ID_PTR
internal_find_token(CK_FUNCTION_LIST_PTR ctx, const CK_UTF8CHAR *label)
{
	// get slot list
	CK_ULONG slot_count = 0;
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(CK_TRUE, NULL_PTR, &slot_count), error);
	CK_SLOT_ID_PTR p_slots = (CK_SLOT_ID_PTR)mem_alloc0(slot_count * sizeof(CK_SLOT_ID));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(CK_FALSE, p_slots, &slot_count), error);

	// debug helper
	char *label_str = mem_alloc0(sizeof(char) * 33);
	for (CK_ULONG i = 0; i < slot_count; i++) {
		CK_RV rv = CKR_OK;
		CK_TOKEN_INFO token_info;
		if ((rv = ctx->C_GetTokenInfo(p_slots[i], &token_info)) == CKR_OK) {
			memcpy(label_str, token_info.label, 32);
			//fprintf(stderr, "Found token %s\n", label_str);
			if (0 == strncmp((char *)token_info.label, (char *)label, 32)) {
				CK_SLOT_ID_PTR slot_id =
					(CK_SLOT_ID_PTR)mem_alloc(sizeof(CK_SLOT_ID));
				*slot_id = p_slots[i];
				free(label_str);
				return slot_id;
			}
		} else {
			WARN("Retrieving Info for slot %lu failed with %lu", p_slots[i], rv);
		}
	}
error:
	return NULL_PTR;
}

/**
 * Converts a string into a token label: must not be null-terminated according to spec
*/
CK_UTF8CHAR *
internal_sanitize_label(const char *label)
{
	size_t len_label = strlen(label);
	CK_UTF8CHAR *token_label = mem_alloc0(32); // must be 32 bytes according to spec
	if (len_label <= 32) {
		memcpy(token_label, label, len_label);

		// pad remaining space
		for (size_t i = len_label + 1; i < 32; i++) {
			token_label[i] = ' ';
		}
	} else {
		// label is too long: truncate
		memcpy(token_label, label, 32);
	}

	return token_label;
}
