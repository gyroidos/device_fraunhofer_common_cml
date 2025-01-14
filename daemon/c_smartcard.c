/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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

#define MOD_NAME "c_smartcard"

#include "scd.pb-c.h"

#include "cmld.h"
#include "audit.h"
#include "hotplug.h"
#include "scd_shared.h"
#include "crypto.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/hex.h"
#include "common/sock.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"
#include "common/proc.h"

#include <google/protobuf-c/protobuf-c-text.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>

// clang-format off
#define SCD_TOKENCONTROL_SOCKET SOCK_PATH(tokencontrol)
// clang-format on

#ifndef SCD_BINARY_NAME
#define SCD_BINARY_NAME "scd"
#endif

// TODO: centrally define key length in container or other module?
#define TOKEN_KEY_LEN 96 // actual encryption key + hmac key
#define TOKEN_MAX_WRAPPED_KEY_LEN 4096

#define MAX_PAIR_SEC_LEN 8
#define PAIR_SEC_FILE_NAME "device_pairing_secret"

#define TOKEN_IS_PAIRED_FILE_NAME "token_is_paired"

#define USB_TOKEN_ATTACH_TIMEOUT 500

extern char *scd_sock_path; // defined in scd.c

typedef struct c_smartcard {
	int sock;
	const char *path;
	container_t *container;

	// the token's type
	container_token_type_t token_type;
	// the iSerial of the usbtoken reader
	char *token_serial;
	// the path to the usbtoken APDU relay socket inside the container
	char *token_relay_path;

	// indicates whether the scd has succesfully initialized the token structure
	bool is_init;
	// indicates whether the token has already been provisioned with a platform-bound authentication code
	bool is_paired_with_device;

	void (*err_cb)(int error_code, void *data);
	void *err_cbdata;
	int (*success_cb)(container_t *container);
} c_smartcard_t;

static TokenType
c_smartcard_tokentype_to_proto(container_token_type_t tokentype)
{
	switch (tokentype) {
	case CONTAINER_TOKEN_TYPE_NONE:
		return TOKEN_TYPE__NONE;
	case CONTAINER_TOKEN_TYPE_SOFT:
		return TOKEN_TYPE__SOFT;
	case CONTAINER_TOKEN_TYPE_USB:
		return TOKEN_TYPE__USB;
	default:
		FATAL("Invalid container_token_type_t value : %d", tokentype);
	}
}

/**
 * Gets the device pairing secret.
 * TODO: the secret should be protected inside a TPM
 */
static int
c_smartcard_get_pairing_secret(c_smartcard_t *smartcard, unsigned char *buf, int buf_len)
{
	ASSERT(smartcard);
	ASSERT(buf);

	TRACE("Retrieving pairing secret");

	int bytes_read, bytes_written;
	char *pair_sec_file = mem_printf("%s/%s", smartcard->path, PAIR_SEC_FILE_NAME);

	if (file_exists(pair_sec_file)) {
		bytes_read = file_read(pair_sec_file, (char *)buf, buf_len);
	} else {
		DEBUG("No pairing secret has been persisted yet. Creating new one");
		bytes_read = crypto_random_get_bytes(buf, buf_len);
		if (bytes_read != buf_len) {
			ERROR("Failed to get random pairing secret");
			bytes_read = -1;
			goto out;
		} else {
			if (mkdir(smartcard->path, 0755) < 0 && errno != EEXIST) {
				ERROR_ERRNO("Could not mkdir %s", smartcard->path);
				bytes_read = -1;
				goto out;
			}

			bytes_written = file_write(pair_sec_file, (char *)buf, buf_len);

			if (bytes_written != bytes_read) {
				ERROR("Failed to write paring secret to file, bytes written: %d",
				      bytes_written);
				bytes_read = -1;
				goto out;
			}
		}
	}

out:
	mem_free0(pair_sec_file);
	return bytes_read;
}

static TokenToDaemon *
c_smartcard_send_recv_block(const DaemonToToken *out)
{
	ASSERT(out);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET, scd_sock_path);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s", scd_sock_path);
		return NULL;
	}

	DEBUG("c_smartcard_send_recv_block: connected to sock %d", sock);

	if (protobuf_send_message(sock, (ProtobufCMessage *)out) < 0) {
		ERROR("Failed to send message to scd on sock %d", sock);
		close(sock);
		return NULL;
	}

	TokenToDaemon *msg = NULL;
	msg = (TokenToDaemon *)protobuf_recv_message(sock, &token_to_daemon__descriptor);
	close(sock);
	return msg;
}

/**
 * Returns the path to a container specific flag file, that indicates, that the
 * token has been provisioned with a platform bound authentication code
 */
static char *
c_smartcard_token_paired_file_new(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);
	return mem_printf("%s/%s", container_get_images_dir(smartcard->container),
			  TOKEN_IS_PAIRED_FILE_NAME);
}

/**
 * checks whether the token associated to @param container has been provisioned
 * with a device bound authentication code yet.
 * TODO: this should actually query the SCD. Functionality in SCD not yet implemented.
 */
static bool
c_smartcard_container_token_is_provisioned(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	bool ret;

	char *token_init_file = c_smartcard_token_paired_file_new(smartcard);

	ret = file_exists(token_init_file);

	mem_free0(token_init_file);
	return ret;
}

static int
c_smartcard_set_error_cb(void *smartcardp, void (*cb)(int error_code, void *data), void *cbdata)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	smartcard->err_cb = cb;
	smartcard->err_cbdata = cbdata;

	return 0;
}

static void
c_smartcard_error(c_smartcard_t *smartcard, int error_code)
{
	ASSERT(smartcard);
	IF_NULL_RETURN(smartcard->err_cb);
	smartcard->err_cb(error_code, smartcard->err_cbdata);
}

void
c_smartcard_send_token_lock_cmd(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__LOCK;

	out.has_token_type = true;
	out.token_type = c_smartcard_tokentype_to_proto(smartcard->token_type);

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

	protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
	mem_free0(out.token_uuid);
}

static void
c_smartcard_cb_ctrl_container(int fd, unsigned events, event_io_t *io, void *data)
{
	c_smartcard_t *smartcard = data;
	ASSERT(smartcard);

	bool done = false;

	if (events & EVENT_IO_EXCEPT) {
		ERROR("Container start failed");

		event_remove_io(io);
		event_io_free(io);
		return;
	} else if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);

		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting container start.");

			event_remove_io(io);
			event_io_free(io);
			return;
		}

		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__LOCK_FAILED: {
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "lock",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			WARN("Locking the token failed.");
			c_smartcard_error(smartcard, CONTAINER_SMARTCARD_LOCK_FAILED);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL: {
			/* after token has sucesfully locked again we can execute the corresponding
			 * start, stop function */
			if (smartcard->success_cb) {
				if (-1 == smartcard->success_cb(smartcard->container))
					c_smartcard_error(smartcard, CONTAINER_SMARTCARD_CB_FAILED);
				else
					c_smartcard_error(smartcard, CONTAINER_SMARTCARD_CB_OK);
			}
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED: {
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "unlock",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			WARN("Unlocking the token failed.");
			c_smartcard_error(smartcard, CONTAINER_SMARTCARD_UNLOCK_FAILED);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__PASSWD_WRONG: {
			WARN("Unlocking the token failed (wrong PIN/passphrase).");
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "unlock-wrong-pin",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			c_smartcard_error(smartcard, CONTAINER_SMARTCARD_PASSWD_WRONG);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT: {
			WARN("Unlocking the token failed (locked till reboot).");
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "locked-until-reboot",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			c_smartcard_error(smartcard, CONTAINER_SMARTCARD_LOCKED_TILL_REBOOT);
			done = true;
		} break;

		/*
		 * This case handles key unwrapping as part of TSF.CML.CompartmentDataStorage.
		 */
		case TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL: {
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "unlock-successful",
					uuid_string(container_get_uuid(smartcard->container)), 0);

			if (container_get_state(smartcard->container) ==
			    COMPARTMENT_STATE_RUNNING) {
				/* in this case the token was checked to authorize container stop */
				// just lock token again which triggers success_cb
				c_smartcard_send_token_lock_cmd(smartcard);
				break;
			}

			char *keyfile =
				mem_printf("%s/%s.key", smartcard->path,
					   uuid_string(container_get_uuid(smartcard->container)));
			if (file_exists(keyfile)) {
				DEBUG("Using key for container %s from existing key file %s",
				      container_get_name(smartcard->container), keyfile);
				unsigned char key[TOKEN_MAX_WRAPPED_KEY_LEN];
				int keylen = file_read(keyfile, (char *)key, sizeof(key));
				TRACE("Length of existing key: %d", keylen);
				if (keylen < TOKEN_KEY_LEN) {
					audit_log_event(container_get_uuid(smartcard->container),
							FSA, CMLD, TOKEN_MGMT, "read-wrapped-key",
							uuid_string(container_get_uuid(
								smartcard->container)),
							0);
					ERROR("Failed to read key from file for container!");
					break;
				}

				audit_log_event(
					container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "read-wrapped-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				// unwrap via scd
				DaemonToToken out = DAEMON_TO_TOKEN__INIT;
				out.code = DAEMON_TO_TOKEN__CODE__UNWRAP_KEY;
				out.has_wrapped_key = true;
				out.wrapped_key.len = keylen;
				out.wrapped_key.data = key;
				out.container_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				out.has_token_type = true;
				out.token_type =
					c_smartcard_tokentype_to_proto(smartcard->token_type);

				out.token_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);

				//delete wrapped key from RAM
				mem_memset0(key, sizeof(key));
				mem_free0(out.container_uuid);
				mem_free0(out.token_uuid);
			} else {
				DEBUG("No previous key found for container %s. Generating new key.",
				      container_get_name(smartcard->container));
				if (!file_is_dir(smartcard->path) &&
				    mkdir(smartcard->path, 00755) < 0) {
					DEBUG_ERRNO("Could not mkdir %s", smartcard->path);
					done = true;
					break;
				}
				unsigned char key[TOKEN_KEY_LEN];
				int keylen = crypto_random_get_bytes(key, sizeof(key));
				DEBUG("SCD: keylen=%d, sizeof(key)=%zu", keylen, sizeof(key));
				if (keylen != sizeof(key)) {
					audit_log_event(container_get_uuid(smartcard->container),
							FSA, CMLD, TOKEN_MGMT,
							"gen-container-key-rng-error",
							uuid_string(container_get_uuid(
								smartcard->container)),
							0);
					ERROR("Failed to generate key for container, due to RNG Error!");
					break;
				}
				audit_log_event(
					container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "gen-container-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				// set the key
				char *ascii_key = convert_bin_to_hex_new(key, keylen);
				container_set_key(smartcard->container, ascii_key);
				// delete key from RAM
				mem_memset0(ascii_key, strlen(ascii_key));
				mem_free0(ascii_key);
				// wrap key via scd
				DaemonToToken out = DAEMON_TO_TOKEN__INIT;
				out.code = DAEMON_TO_TOKEN__CODE__WRAP_KEY;
				out.has_unwrapped_key = true;
				out.unwrapped_key.len = keylen;
				out.unwrapped_key.data = key;
				out.container_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				out.has_token_type = true;
				out.token_type =
					c_smartcard_tokentype_to_proto(smartcard->token_type);

				out.token_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);

				// delete key from RAM
				mem_memset0(key, sizeof(key));
				mem_free0(out.container_uuid);
				mem_free0(out.token_uuid);
			}
			mem_free0(keyfile);
		} break;
		/*
		 * This case handles key unwrapping as part of TSF.CML.CompartmentDataStorage.
		 */
		case TOKEN_TO_DAEMON__CODE__UNWRAPPED_KEY: {
			if (!msg->has_unwrapped_key) {
				ERROR("Expected derived key, but none was returned!");
				audit_log_event(
					container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "unwrap-container-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				c_smartcard_error(smartcard, CONTAINER_SMARTCARD_WRAPPING_ERROR);
				// lock token via scd and unregister io callback to avoid to trigger success_cb
				c_smartcard_send_token_lock_cmd(smartcard);
				done = true;
				break;
			}
			// set the key
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "unwrap-container-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			TRACE("Successfully retrieved unwrapped key from SCD");
			char *ascii_key = convert_bin_to_hex_new(msg->unwrapped_key.data,
								 msg->unwrapped_key.len);
			container_set_key(smartcard->container, ascii_key);
			//delete key from RAM
			mem_memset0(ascii_key, strlen(ascii_key));
			mem_memset0(msg->unwrapped_key.data, msg->unwrapped_key.len);
			mem_free0(ascii_key);

			// lock token via scd which will trigger success_cb
			c_smartcard_send_token_lock_cmd(smartcard);
		} break;
		case TOKEN_TO_DAEMON__CODE__WRAPPED_KEY: {
			// lock token via scd
			DaemonToToken out = DAEMON_TO_TOKEN__INIT;
			out.code = DAEMON_TO_TOKEN__CODE__LOCK;

			out.has_token_type = true;
			out.token_type = c_smartcard_tokentype_to_proto(smartcard->token_type);

			out.token_uuid =
				mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

			protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
			mem_free0(out.token_uuid);
			// save wrapped key
			if (!msg->has_wrapped_key) {
				audit_log_event(
					container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "wrap-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				ERROR("Expected wrapped key, but none was returned!");
				c_smartcard_error(smartcard, CONTAINER_SMARTCARD_WRAPPING_ERROR);
				done = true;
				break;
			}
			ASSERT(msg->wrapped_key.len < TOKEN_MAX_WRAPPED_KEY_LEN);
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "wrap-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			char *keyfile =
				mem_printf("%s/%s.key", smartcard->path,
					   uuid_string(container_get_uuid(smartcard->container)));
			// save wrapped key to file
			int bytes_written = file_write(keyfile, (char *)msg->wrapped_key.data,
						       msg->wrapped_key.len);
			if (bytes_written != (int)msg->wrapped_key.len) {
				audit_log_event(
					container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "store-wrapped-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				ERROR("Failed to store key for container %s to %s!",
				      container_get_name(smartcard->container), keyfile);
			}
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "store-wrapped-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			TRACE("Stored wrapped key on disk successfully");
			// delete wrapped key from RAM
			mem_memset0(msg->wrapped_key.data, msg->wrapped_key.len);
			mem_free0(keyfile);
		} break;
		default:
			ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
			done = true;
			break;
		}
		protobuf_free_message((ProtobufCMessage *)msg);

		if (done) {
			event_remove_io(io);
			event_io_free(io);
		}
	}
}

static int
c_smartcard_token_unlock_handler(c_smartcard_t *smartcard, const char *passwd,
				 void (*cb)(int fd, unsigned events, event_io_t *io, void *data))
{
	ASSERT(smartcard);
	ASSERT(passwd);

	int pair_sec_len;

	if (!smartcard->is_init) {
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"token-uninitialized",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		ERROR("The token that is associated with the container has not been initialized!");
		c_smartcard_error(smartcard, CONTAINER_SMARTCARD_TOKEN_UNINITIALIZED);
		return -1;
	}

	if (!smartcard->is_paired_with_device) {
		ERROR("The token that is associated with this container must be paired to the device first");
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"token-not-paired",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		c_smartcard_error(smartcard, CONTAINER_SMARTCARD_TOKEN_UNPAIRED);
		return -1;
	}

	unsigned char pair_sec[MAX_PAIR_SEC_LEN];
	pair_sec_len = c_smartcard_get_pairing_secret(smartcard, pair_sec, sizeof(pair_sec));
	if (pair_sec_len < 0) {
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"read-pairing-secret",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		ERROR("Could not retrieve pairing secret");
		c_smartcard_error(smartcard, CONTAINER_SMARTCARD_PAIRING_SECRET_FAILED);
		return -1;
	}
	audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD, TOKEN_MGMT,
			"read-pairing-secret",
			uuid_string(container_get_uuid(smartcard->container)), 0);

	// TODO register timer if socket does not respond
	event_io_t *event = event_io_new(smartcard->sock, EVENT_IO_READ, cb, smartcard);

	event_add_io(event);
	DEBUG("SCD: Registered control container callback for key from scd");
	// unlock token
	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__UNLOCK;
	out.token_pin = mem_strdup(passwd);
	out.has_pairing_secret = true;
	out.pairing_secret.len = pair_sec_len;
	out.pairing_secret.data = mem_memcpy(pair_sec, sizeof(pair_sec));
	out.has_token_type = true;
	out.token_type = c_smartcard_tokentype_to_proto(smartcard->token_type);

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text;

		size_t msg_len =
			protobuf_string_from_message(&msg_text, (ProtobufCMessage *)&out, NULL);

		TRACE("Sending DaemonToToken message:\n%s", msg_len > 0 ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
	mem_memset0(out.token_pin, strlen(out.token_pin));
	mem_free0(out.token_pin);
	mem_free0(out.pairing_secret.data);
	mem_free0(out.token_uuid);

	return 0;
}

static void
c_smartcard_cb_container_change_pin(int fd, unsigned events, event_io_t *io, void *data)
{
	c_smartcard_t *smartcard = data;
	ASSERT(smartcard);

	int rc = -1;
	bool command_state = false;

	if (events & EVENT_IO_READ) {
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting smartcard change_pin callback.");
			event_remove_io(io);
			event_io_free(io);
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					CONTAINER_MGMT, "container-change-pin",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			c_smartcard_error(smartcard, CONTAINER_SMARTCARD_CHANGE_PIN_FAILED);
			return;
		}
		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__CHANGE_PIN_SUCCESSFUL: {
			command_state = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__CHANGE_PIN_FAILED: {
			command_state = false;
		} break;
		case TOKEN_TO_DAEMON__CODE__PROVISION_PIN_SUCCESSFUL: {
			char *path = c_smartcard_token_paired_file_new(smartcard);
			rc = file_touch(path);
			if (rc != 0) { //should never happen
				ERROR("Could not write file %s to flag that container %s's token has been initialized\n \
						This may leave the system in an inconsistent state!",
				      path, uuid_string(container_get_uuid(smartcard->container)));
				smartcard->is_paired_with_device = false;
				command_state = false;
			} else {
				smartcard->is_paired_with_device = true;
				command_state = true;
			}
			mem_free0(path);
		} break;
		case TOKEN_TO_DAEMON__CODE__PROVISION_PIN_FAILED: {
			smartcard->is_paired_with_device = false;
			command_state = false;
		} break;
		default:
			ERROR("TokenToDaemon command %d not expected as answer to change_pin",
			      msg->code);
			command_state = false;
		}

		audit_log_event(container_get_uuid(smartcard->container), command_state ? SSA : FSA,
				CMLD, CONTAINER_MGMT, "container-change-pin",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		c_smartcard_error(smartcard, command_state ?
						     CONTAINER_SMARTCARD_CHANGE_PIN_SUCCESSFUL :
						     CONTAINER_SMARTCARD_CHANGE_PIN_FAILED);

		protobuf_free_message((ProtobufCMessage *)msg);
		event_remove_io(io);
		event_io_free(io);
	} else {
		ERROR("Failed to receive message: EVENT_IO_EXCEPT. Aborting smartcard change_pin.");
		event_remove_io(io);
		event_io_free(io);
	}
}

static int
c_smartcard_change_pin(void *smartcardp, const char *passwd, const char *newpasswd)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);
	ASSERT(passwd);
	ASSERT(newpasswd);

	int ret = -1;
	unsigned char pair_sec[MAX_PAIR_SEC_LEN];
	bool is_provisioning;

	DEBUG("SCD: Received new password from UI");

	ret = c_smartcard_get_pairing_secret(smartcard, pair_sec, sizeof(pair_sec));
	if (ret < 0) {
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"read-pairing-secret",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		ERROR("Could not retrieve pairing secret, ret code : %d", ret);
		c_smartcard_error(smartcard, CONTAINER_SMARTCARD_PAIRING_SECRET_FAILED);
		return -1;
	}

	is_provisioning = !c_smartcard_container_token_is_provisioned(smartcard);

	event_io_t *event = event_io_new(smartcard->sock, EVENT_IO_READ,
					 c_smartcard_cb_container_change_pin, smartcard);
	event_add_io(event);
	DEBUG("SCD: Registered smartcard_cb_container_change_pin container callback for scd");

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = is_provisioning ? DAEMON_TO_TOKEN__CODE__PROVISION_PIN :
				     DAEMON_TO_TOKEN__CODE__CHANGE_PIN;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

	out.has_token_type = true;
	out.token_type = c_smartcard_tokentype_to_proto(smartcard->token_type);

	out.token_pin = mem_strdup(passwd);
	out.token_newpin = mem_strdup(newpasswd);

	out.has_pairing_secret = true;
	out.pairing_secret.len = sizeof(pair_sec);
	out.pairing_secret.data = mem_memcpy(pair_sec, sizeof(pair_sec));

	ret = protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
	mem_memset0(out.token_pin, strlen(out.token_pin));
	mem_memset0(out.token_newpin, strlen(out.token_newpin));
	mem_memset0(pair_sec, sizeof(pair_sec));
	mem_free0(out.token_pin);
	mem_free0(out.token_newpin);
	mem_free0(out.pairing_secret.data);
	mem_free0(out.token_uuid);

	return (ret > 0) ? 0 : -1;
}

static int
c_smartcard_update_token_state(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	/* TODO: query SCD whether a token has been initialized.
	 * requires modifications to SCD
	 */
	// container_set_token_is_init(container, smartcard_container_token_is_init(container));

	smartcard->is_paired_with_device = c_smartcard_container_token_is_provisioned(smartcard);

	DEBUG("Updated Token state: %d", smartcard->is_paired_with_device);

	return 0;
}

/**
 * we cannot queue several events with the same fd.
 * therefore, we use a blocking method to query the scd to initialize a token.
 */
static int
c_smartcard_scd_token_add_block(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);
	container_t *container = smartcard->container;

	TRACE("CML: request SCD to add the token associated to %s to its list",
	      uuid_string(container_get_uuid(container)));
	ASSERT(container);

	int rc = -1;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__TOKEN_ADD;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(container)));

	out.has_token_type = true;
	out.token_type = c_smartcard_tokentype_to_proto(smartcard->token_type);

	if (out.token_type == TOKEN_TYPE__USB) {
		if (NULL == smartcard->token_serial) {
			ERROR("Could not retrive serial of usbtoken reader. Abort token init...");
			goto err;
		}
		out.usbtoken_serial = smartcard->token_serial;
	}

	TokenToDaemon *msg = c_smartcard_send_recv_block(&out);
	if (!msg) {
		ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting smartcard_scd_token_block_new.");
		goto err;
	}

	switch (msg->code) {
	case TOKEN_TO_DAEMON__CODE__TOKEN_ADD_SUCCESSFUL: {
		TRACE("CMLD: smartcard_scd_token_block_new: token in scd created successfully");
		smartcard->is_init = true;
		rc = 0;
	} break;
	case TOKEN_TO_DAEMON__CODE__TOKEN_ADD_FAILED: {
		smartcard->is_init = false;
		ERROR("Creating scd token structure failed");
	} break;
	default:
		smartcard->is_init = false;
		ERROR("TokenToDaemon command %d not expected as answer to change_pin", msg->code);
	}

	protobuf_free_message((ProtobufCMessage *)msg);

err:
	mem_free0(out.token_uuid);
	return rc;
}

static int
c_smartcard_scd_token_remove_block(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);
	container_t *container = smartcard->container;

	TRACE("CML: request scd to remove the token associated to %s from its list",
	      uuid_string(container_get_uuid(container)));
	ASSERT(container);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__TOKEN_REMOVE;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(container)));

	out.has_token_type = true;
	out.token_type = c_smartcard_tokentype_to_proto(smartcard->token_type);

	TokenToDaemon *msg = c_smartcard_send_recv_block(&out);
	if (!msg) {
		ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting smartcard_scd_token_block_new.");
		mem_free0(out.token_uuid);
		return -1;
	}

	switch (msg->code) {
	case TOKEN_TO_DAEMON__CODE__TOKEN_REMOVE_SUCCESSFUL: {
		TRACE("CMLD: smartcard_scd_token_block_remove: token in scd removed successfully");
		smartcard->is_init = false;
	} break;
	case TOKEN_TO_DAEMON__CODE__TOKEN_REMOVE_FAILED: {
		ERROR("Removing scd token structure failed");
	} break;
	default:
		ERROR("TokenToDaemon command %d not expected as answer to change_pin", msg->code);
	}

	mem_free0(out.token_uuid);
	protobuf_free_message((ProtobufCMessage *)msg);
	return 0;
}

/**
 * Requests the SCD to initialize a token associated to a container and queries whether that
 * token has been provisioned with a platform-bound authentication code.
 */
static int
c_smartcard_token_init(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	// container is configured to not use a token at all
	if (CONTAINER_TOKEN_TYPE_NONE == smartcard->token_type) {
		smartcard->is_init = false;
		DEBUG("Container %s is configured to use no token to hold encryption keys",
		      uuid_string(container_get_uuid(smartcard->container)));
		return 0;
	}

	DEBUG("Invoking container_scd_token_add_block() for container %s",
	      container_get_name(smartcard->container));
	if (c_smartcard_scd_token_add_block(smartcard) != 0) {
		ERROR("Requesting SCD to init token failed");
		return -1;
	}

	DEBUG("Initialized token for container %s", container_get_name(smartcard->container));

	c_smartcard_update_token_state(smartcard);

	return 0;
}

static void
c_smartcard_token_attach_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);
	c_smartcard_t *smartcard = data;

	// initialize the USB token
	int block_return = c_smartcard_token_init(smartcard);

	if (block_return) {
		ERROR("Failed to initialize token (might already be initialized)");
	}

	event_remove_timer(timer);
	event_timer_free(timer);
}

static int
c_smartcard_token_attach(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	TRACE("Registering callback to handle attachment of token with serial %s",
	      smartcard->token_serial);

	// give usb device some time to register
	event_timer_t *e = event_timer_new(USB_TOKEN_ATTACH_TIMEOUT, 1, c_smartcard_token_attach_cb,
					   smartcard);
	event_add_timer(e);

	return 0;
}

static int
c_smartcard_token_detach(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	// try to stop the container
	if (cmld_container_stop(smartcard->container)) {
		ERROR("Could not stop container after token detachment.");
	}

	if (c_smartcard_scd_token_remove_block(smartcard)) {
		ERROR("Failed to notify scd about token detachment");
	}

	return 0;
}

static bool
c_smartcard_has_token_changed(void *smartcardp, container_token_type_t ttype, const char *serial)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	if (ttype != smartcard->token_type) {
		TRACE("Container token type changed: %d -> %d", smartcard->token_type, ttype);
		return true;
	}

	if (smartcard->token_type != CONTAINER_TOKEN_TYPE_USB) {
		TRACE("Token did not change: Container is not a USB token container");
		return false;
	}

	if (!serial) {
		ERROR("No serial for USB token");
		return true;
	}

	if (!smartcard->token_serial) {
		ERROR("Serial currently not set for USB token");
		return true;
	}

	if (strcmp(serial, smartcard->token_serial)) {
		TRACE("Container USB token serial changed");
		return true;
	}

	TRACE("Container USB token serial did not change");
	return false;
}

static int
c_smartcard_remove_keyfile(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	int rc = -1;

	char *keyfile = mem_printf("%s/%s.key", smartcard->path,
				   uuid_string(container_get_uuid(smartcard->container)));

	if (!file_exists(keyfile)) {
		DEBUG("No keyfile found for container %s (uuid=%s).",
		      container_get_name(smartcard->container),
		      uuid_string(container_get_uuid(smartcard->container)));
		rc = 0;
		goto out;
	}

	if (0 != remove(keyfile)) {
		ERROR_ERRNO("Failed to remove keyfile");
		goto out;
	}

	rc = 0;

out:
	mem_free0(keyfile);
	return rc;
}

static int
c_smartcard_container_ctrl(void *smartcardp, int (*success_cb)(container_t *container),
			   const char *passwd)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	smartcard->success_cb = success_cb;
	return c_smartcard_token_unlock_handler(smartcard, passwd, c_smartcard_cb_ctrl_container);
}

static int
c_smartcard_scd_release_pairing(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	int ret = 0;
	char *path = c_smartcard_token_paired_file_new(smartcard);
	if (file_exists(path)) {
		ret = unlink(path);
		if (ret != 0) {
			ERROR_ERRNO("Failed to remove file %s", path);
		}
	}

	return ret;
}

static void *
c_smartcard_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_smartcard_t *smartcard = mem_new0(c_smartcard_t, 1);
	smartcard->container = compartment_get_extension_data(compartment);

	smartcard->path = cmld_get_wrapped_keys_dir();

	smartcard->token_type = container_get_token_type(smartcard->container);

	// Check configuration for a valid usb device of type TOKEN
	if (smartcard->token_type == CONTAINER_TOKEN_TYPE_USB) {
		for (list_t *l = container_get_usbdev_list(smartcard->container); l; l = l->next) {
			container_usbdev_t *ud = (container_usbdev_t *)l->data;
			if (container_usbdev_get_type(ud) == CONTAINER_USBDEV_TYPE_TOKEN) {
				smartcard->token_serial =
					mem_strdup(container_usbdev_get_i_serial(ud));
				DEBUG("container %s configured to use usb token reader with serial %s",
				      container_get_name(smartcard->container),
				      smartcard->token_serial);
				break; // TODO: handle misconfiguration with several usbtoken?
			}
		}
		if (NULL == smartcard->token_serial) {
			ERROR("Usbtoken reader serial missing in container config. Abort creation of container");
			mem_free0(smartcard);
			return NULL;
		}
	}

	smartcard->success_cb = NULL;
	smartcard->err_cb = NULL;
	smartcard->err_cbdata = NULL;

	smartcard->sock = sock_unix_create_and_connect(SOCK_SEQPACKET, scd_sock_path);
	if (smartcard->sock < 0) {
		mem_free0(smartcard);
		ERROR("Failed to connect to scd");
		return NULL;
	}

	if (0 != c_smartcard_token_init(smartcard)) {
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, CONTAINER_MGMT,
				"container-create-token-uninit",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		WARN("Could not initialize token associated with container %s (uuid=%s).",
		     container_get_name(smartcard->container),
		     uuid_string(container_get_uuid(smartcard->container)));
	}

	smartcard->token_relay_path = NULL;

	return smartcard;
}

static void
c_smartcard_free(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	IF_NULL_RETURN(smartcard);

	/* release scd connection */
	close(smartcard->sock);

	if (smartcard->token_serial)
		mem_free0(smartcard->token_serial);

	if (smartcard->token_relay_path)
		mem_free0(smartcard->token_relay_path);

	mem_free0(smartcard);
}

static void
c_smartcard_destroy(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	IF_TRUE_RETURN(CONTAINER_TOKEN_TYPE_NONE == smartcard->token_type);

	int ret = 0;
	char *path = c_smartcard_token_paired_file_new(smartcard);
	if (file_exists(path)) {
		ret = unlink(path);
		if (ret != 0) {
			ERROR_ERRNO("Failed to remove file %s", path);
		}
	}

	if (c_smartcard_scd_release_pairing(smartcard)) {
		WARN("Can't remove token paired file!");
	}

	if (smartcard->is_init) {
		if (c_smartcard_scd_token_remove_block(smartcard))
			WARN("Cannot remove token for container %s",
			     container_get_name(smartcard->container));
	}

	/* remove keyfile */
	if (0 != c_smartcard_remove_keyfile(smartcard)) {
		ERROR("Failed to remove keyfile. Continuing to remove container anyway.");
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, CONTAINER_MGMT,
				"container-remove-keyfile",
				uuid_string(container_get_uuid(smartcard->container)), 0);
	} else {
		audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD, CONTAINER_MGMT,
				"container-remove-keyfile",
				uuid_string(container_get_uuid(smartcard->container)), 0);
	}

	mem_free0(path);
}

static int
c_smartcard_bind_token(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	if (CONTAINER_TOKEN_TYPE_USB != smartcard->token_type) {
		DEBUG("Token type is not USB, not binding relay socket");
		return 0;
	}

	int ret = -1;
	uid_t uid = container_get_uid(smartcard->container);

	char *src_path = mem_printf("%s/%s.sock", SCD_TOKENCONTROL_SOCKET,
				    uuid_string(container_get_uuid(smartcard->container)));
	char *dest_dir = mem_printf("%s/dev/tokens", container_get_rootdir(smartcard->container));

	if (NULL == smartcard->token_relay_path)
		smartcard->token_relay_path = mem_printf("%s/token.sock", dest_dir);

	DEBUG("Binding token socket to %s", smartcard->token_relay_path);

	if (!file_exists(dest_dir)) {
		if (dir_mkdir_p(dest_dir, 0755)) {
			ERROR_ERRNO("Failed to create containing directory for %s",
				    smartcard->token_relay_path);
			goto err;
		}

		if (chown(dest_dir, uid, uid)) {
			ERROR("Failed to chown token directory at %s to %d",
			      smartcard->token_relay_path, uid);
			goto err;
		} else {
			DEBUG("Successfully chowned token directory at %s to %d",
			      smartcard->token_relay_path, uid);
		}
	} else if (!file_is_dir(dest_dir)) {
		ERROR("Token path %s exists and is no directory", dest_dir);
		goto err;
	}

	if (file_touch(smartcard->token_relay_path)) {
		ERROR_ERRNO("Failed to prepare target file for bind mount at %s",
			    smartcard->token_relay_path);
		goto err;
	}

	DEBUG("Binding token socket from %s to %s", src_path, smartcard->token_relay_path);
	if (mount(src_path, smartcard->token_relay_path, NULL, MS_BIND, NULL)) {
		ERROR_ERRNO("Failed to bind socket from %s to %s", src_path,
			    smartcard->token_relay_path);
		goto err;
	} else {
		DEBUG("Successfully bound token socket to %s", smartcard->token_relay_path);
	}

	if (chown(smartcard->token_relay_path, uid, uid)) {
		ERROR("Failed to chown token socket at %s to %d", smartcard->token_relay_path, uid);
		goto err;
	} else {
		DEBUG("Successfully chowned token socket at %s to %d", smartcard->token_relay_path,
		      uid);
	}

	ret = 0;

err:
	mem_free0(src_path);
	mem_free0(dest_dir);

	return ret;
}

static int
c_smartcard_unbind_token(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	IF_NULL_RETVAL(smartcard->token_relay_path, 0);

	int ret = -1;

	DEBUG("Unbinding token socket from %s.", smartcard->token_relay_path);
	if ((ret = umount2(smartcard->token_relay_path, MNT_DETACH)) == -1) {
		ERROR_ERRNO("Failed to unbind socket from %s", smartcard->token_relay_path);
	} else {
		DEBUG("Successfully unbound token socket from %s", smartcard->token_relay_path);
	}

	return ret;
}

/**
 * Start-pre-exec hook.
 *
 * @param smartcardp The generic smartcard object of the associated container.
 * @return 0 on success, -COMPARTMENT_ERROR_SMARTCARD on error.
 */
static int
c_smartcard_start_pre_exec(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	if (c_smartcard_bind_token(smartcard) < 0) {
		ERROR("Failed to bind token to container");
		return -COMPARTMENT_ERROR_SERVICE;
	}

	return 0;
}

/**
 * Cleanup hook.
 *
 * @param smartcardp The generic smartcard object of the associated container.
 */
static void
c_smartcard_cleanup(void *smartcardp, UNUSED bool is_rebooting)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	if (c_smartcard_unbind_token(smartcard) < 0)
		WARN("Failed to unbind token to container");
}

static compartment_module_t c_smartcard_module = {
	.name = MOD_NAME,
	.compartment_new = c_smartcard_new,
	.compartment_free = c_smartcard_free,
	.compartment_destroy = c_smartcard_destroy,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = c_smartcard_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_smartcard_cleanup,
	.join_ns = NULL,
};

static void INIT
c_smartcard_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_smartcard_module);

	// register relevant handlers implemented by this module
	container_register_ctrl_with_smartcard_handler(MOD_NAME, c_smartcard_container_ctrl);
	container_register_set_smartcard_error_cb_handler(MOD_NAME, c_smartcard_set_error_cb);
	container_register_change_pin_handler(MOD_NAME, c_smartcard_change_pin);
	container_register_scd_release_pairing_handler(MOD_NAME, c_smartcard_scd_release_pairing);
	container_register_token_attach_handler(MOD_NAME, c_smartcard_token_attach);
	container_register_token_detach_handler(MOD_NAME, c_smartcard_token_detach);
	container_register_has_token_changed_handler(MOD_NAME, c_smartcard_has_token_changed);
}
