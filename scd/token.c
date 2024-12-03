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

#include "token.h"

#include "tokencontrol.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/uuid.h"
#include "common/protobuf.h"
#include "common/list.h"
#include "common/str.h"
#include "common/fd.h"
#include "file.h"
#include "unistd.h"

#define SCD_TOKENCONTROL_SOCK_LISTEN_BACKLOG 1

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

typedef struct scd_tokencontrol {
	int cfd;
	int lsock;
	char *lsock_path;
	list_t *events;
} tctrl_t;

struct scd_token_data {
	union {
		softtoken_t *softtoken;
		usbtoken_t *usbtoken;
		p11token_t *p11token;
	} int_token;

	scd_tokentype_t type;
	uuid_t *token_uuid;
	tctrl_t *tctrl;
};

#ifdef ENABLESCHSM // tokencontrol socket only relevant for usbtoken
static void
wrapped_remove_event_io(void *elem)
{
	TRACE("Remove tokencontrol event from event_loop");
	ASSERT(elem);
	event_io_t *e = elem;
	event_remove_io(e);
	event_io_free(e);
}

static void
scd_tokencontrol_cb_accept(int fd, unsigned events, UNUSED event_io_t *io, void *data);

static void
scd_tokencontrol_handle_message(const ContainerToToken *msg, int fd, void *data)
{
	ASSERT(msg);
	ASSERT(data);

	DEBUG("scd_tokencontrol_handle_message");

	scd_token_t *t = (scd_token_t *)(data);
	tctrl_t *tctrl = t->token_data->tctrl;
	int len = 0;
	unsigned char *brsp = NULL;

	IF_NULL_GOTO_WARN(msg, err);
	IF_NULL_GOTO_ERROR(tctrl, err);

	TokenToContainer out = TOKEN_TO_CONTAINER__INIT;
	brsp = mem_alloc0(MAX_APDU_BUF_LEN);

	switch (msg->command) {
	case CONTAINER_TO_TOKEN__COMMAND__GET_ATR:
		DEBUG("Handle CONTAINER_TO_TOKEN__COMMAND__GET_ATR msg");
		len = t->get_atr(t, brsp, MAX_APDU_BUF_LEN);
		if (len < 0) {
			WARN("GET_ATR failed wit code %d", len);
			goto err;
		}
		goto out;
		break;

	case CONTAINER_TO_TOKEN__COMMAND__UNLOCK_TOKEN:
		DEBUG("Handle CONTAINER_TO_TOKEN__COMMAND__UNLOCK_TOKEN");
		len = t->reset_auth(t, brsp, MAX_APDU_BUF_LEN);
		if (len < 0) {
			WARN("GET_ATR failed wit code %d", len);
			goto err;
		}
		goto out;
		break;

	case CONTAINER_TO_TOKEN__COMMAND__SEND_APDU:
		DEBUG("Handle CONTAINER_TO_TOKEN__COMMAND__SEND_APDU msg");
#ifdef DEBUG_BUILD
		str_t *dump = str_hexdump_new(msg->apdu.data, msg->apdu.len);
		TRACE("Got APDU with with len: %zu, data: %s", msg->apdu.len, str_buffer(dump));
		str_free(dump, true);
#endif
		len = t->send_apdu(t, msg->apdu.data, msg->apdu.len, brsp, MAX_APDU_BUF_LEN);
		if (len < 0) {
			WARN("SEND_APDU failed wit code %d", len);
			goto err;
		}
		goto out;
		break;

	default:
		WARN("ContainerToToken command %d unknown or not implemented yet", msg->command);
	}

err:
	/* TODO: distinguish error soruces and set return code accordingly */
	out.return_code = TOKEN_TO_CONTAINER__CODE__ERR_INVALID;
	if ((protobuf_send_message(fd, (ProtobufCMessage *)&out)) < 0) {
		ERROR("Could not send protobuf response on socker %d", fd);
	}
	goto close_fd;

close_fd:
	mem_free0(brsp);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");
	return;

out:
	out.return_code = TOKEN_TO_CONTAINER__CODE__OK;
	out.has_response = true;
	out.response.len = len;
	out.response.data = brsp;

#ifdef DEBUG_BUILD
	str_t *dump = str_hexdump_new(brsp, len);
	TRACE("Returning apdu with len: %zu, data: %s", out.response.len, str_buffer(dump));
	str_free(dump, true);
#endif

	if ((protobuf_send_message(fd, (ProtobufCMessage *)&out)) < 0) {
		ERROR("Could not send protobuf response on socket %d", fd);
	}
	mem_free0(brsp);
}

/**
 * Event callback for incoming data that a ContainerToToken message.
 *
 * The handle_message function will be called to handle the received message.
 *
 * @param fd	    file descriptor of the client connection
 *		    from which the incoming message is read
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this scd_control_t struct
 */
static void
scd_tokencontrol_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	scd_token_t *token = (scd_token_t *)(data);

	DEBUG("scd_tokencontrol_cb_recv_message");

	if (events & EVENT_IO_READ) {
		ContainerToToken *msg = (ContainerToToken *)protobuf_recv_message(
			fd, &container_to_token__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);

		scd_tokencontrol_handle_message(msg, fd, data);
		protobuf_free_message((ProtobufCMessage *)msg);
		DEBUG("Handled control connection %d", fd);
	} else if (events & EVENT_IO_EXCEPT) {
		INFO("TokenControl client closed connection; disconnecting socket.");
		goto connection_err;
	} else {
		ERROR("Unexpected event");
		goto connection_err;
	}

	return;

connection_err:
	token->token_data->tctrl->events = list_remove(token->token_data->tctrl->events, io);
	event_remove_io(io);
	event_io_free(io);

	token->token_data->tctrl->cfd = -1;
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");

	// accept new connection for respective token
	event_io_t *event = event_io_new(token->token_data->tctrl->lsock, EVENT_IO_READ,
					 scd_tokencontrol_cb_accept, token);
	token->token_data->tctrl->events = list_append(token->token_data->tctrl->events, event);
	event_add_io(event);

	return;
}

/**
 * Event callback for accepting incoming connections on the listening socket.
 *
 * @param fd	    file descriptor of the listening socket
 *		    from which incoming connectionis should be accepted
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this scd_control_t struct
  */
static void
scd_tokencontrol_cb_accept(int fd, unsigned events, UNUSED event_io_t *io, void *data)
{
	scd_token_t *token = (scd_token_t *)data;

	if (events & EVENT_IO_READ) {
		token->token_data->tctrl->cfd = accept(fd, NULL, 0);
		if (-1 == token->token_data->tctrl->cfd) {
			WARN("Could not accept tokencontrol connection");
			return;
		}
		DEBUG("Accepted tokencontrol connection %d", token->token_data->tctrl->cfd);

		fd_make_non_blocking(token->token_data->tctrl->cfd);

		DEBUG("Made tokenctrl_cfd non-blocking");

		// only accept one connection per socket at a time
		token->token_data->tctrl->events =
			list_remove(token->token_data->tctrl->events, io);

		wrapped_remove_event_io(io);

		event_io_t *event = event_io_new(token->token_data->tctrl->cfd, EVENT_IO_READ,
						 scd_tokencontrol_cb_recv_message, data);

		token->token_data->tctrl->events =
			list_append(token->token_data->tctrl->events, event);

		event_add_io(event);
	} else if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
	} else {
		ERROR("Unexpected event");
	}
	return;
}

static int UNUSED
scd_tokencontrol_new(scd_token_t *token)
{
	ASSERT(token && token->token_data);

	TRACE("scd_tokencontrol_new");

	token->token_data->tctrl = mem_new0(tctrl_t, 1);
	IF_NULL_GOTO_ERROR(token->token_data->tctrl, err);
	token->token_data->tctrl->cfd = -1; // preset to signal unconnected client

	token->token_data->tctrl->lsock_path = mem_printf(
		"%s/%s.sock", SCD_TOKENCONTROL_SOCKET, uuid_string(token->token_data->token_uuid));
	IF_NULL_GOTO_ERROR(token->token_data->tctrl->lsock_path, err);

	token->token_data->tctrl->lsock = sock_unix_create_and_bind(
		SOCK_STREAM | SOCK_NONBLOCK, token->token_data->tctrl->lsock_path);
	if (token->token_data->tctrl->lsock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		goto err;
	}
	if (listen(token->token_data->tctrl->lsock, SCD_TOKENCONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		close(token->token_data->tctrl->lsock);
		goto err;
	}

	event_io_t *event = event_io_new(token->token_data->tctrl->lsock, EVENT_IO_READ,
					 scd_tokencontrol_cb_accept, token);
	token->token_data->tctrl->events = list_append(token->token_data->tctrl->events, event);
	event_add_io(event);

	return 0;

err:
	mem_free0(token->token_data->tctrl);
	mem_free0(token->token_data->tctrl->lsock_path);
	return -1;
}

static void
scd_tokencontrol_free(scd_token_t *token)
{
	ASSERT(token);

	list_foreach(token->token_data->tctrl->events, wrapped_remove_event_io);

	if (token->token_data->tctrl->cfd != -1) {
		TRACE("Closing accepted tokencontrol socket for token %s",
		      uuid_string(token->token_data->token_uuid));
		TRACE("Closing tokencontrol fd: %d", token->token_data->tctrl->cfd);
		if (sock_unix_close(token->token_data->tctrl->cfd) != 0) {
			WARN("Could not close accepted tokencontrol socket");
		}
	}
	TRACE("Closing listening tokencontrol socket");
	if (sock_unix_close_and_unlink(token->token_data->tctrl->lsock,
				       token->token_data->tctrl->lsock_path) != 0) {
		WARN_ERRNO("Could not close listening tokencontrol socket for token %s",
			   uuid_string(token->token_data->token_uuid));
	}
	mem_free0(token->token_data->tctrl->lsock_path);

	mem_free0(token->token_data->tctrl);
}
#endif // ENABLESCHSM

/*** internal helper functions ***/

int
int_lock_st(scd_token_t *token)
{
	return softtoken_lock(token->token_data->int_token.softtoken);
}

int
int_unlock_st(scd_token_t *token, char *passwd, UNUSED unsigned char *pairing_secret,
	      UNUSED size_t pairing_sec_len)
{
	return softtoken_unlock(token->token_data->int_token.softtoken, passwd);
}

bool
int_is_locked_st(scd_token_t *token)
{
	return softtoken_is_locked(token->token_data->int_token.softtoken);
}

bool
int_is_locked_till_reboot_st(scd_token_t *token)
{
	return softtoken_is_locked_till_reboot(token->token_data->int_token.softtoken);
}

int
int_wrap_st(scd_token_t *token, UNUSED char *label, unsigned char *plain_key, size_t plain_key_len,
	    unsigned char **wrapped_key, int *wrapped_key_len)
{
	return softtoken_wrap_key(token->token_data->int_token.softtoken, plain_key, plain_key_len,
				  wrapped_key, wrapped_key_len);
}

int
int_unwrap_st(scd_token_t *token, UNUSED char *label, unsigned char *wrapped_key,
	      size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	return softtoken_unwrap_key(token->token_data->int_token.softtoken, wrapped_key,
				    wrapped_key_len, plain_key, plain_key_len);
}

int
int_change_pw_st(scd_token_t *token, const char *oldpass, const char *newpass,
		 UNUSED unsigned char *pairing_secret, UNUSED size_t pairing_sec_len,
		 UNUSED bool is_provisioning)
{
	return softtoken_change_passphrase(token->token_data->int_token.softtoken, oldpass,
					   newpass);
}

int
int_send_apdu_st(UNUSED scd_token_t *token, UNUSED unsigned char *apdu, UNUSED size_t apdu_len,
		 UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("send_apdu() not meaningful to softtoken. Aborting ...");
	return -1;
}

int
int_reset_auth_st(UNUSED scd_token_t *token, UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("reset_auth() not meaningful to softtoken. Aborting ...");
	return -1;
}

int
int_get_atr_st(UNUSED scd_token_t *token, UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("get_atr() not meaningful to softtoken. Aborting ...");
	return -1;
}

#ifdef ENABLESCHSM

int
int_lock_usb(scd_token_t *token)
{
	return usbtoken_lock(token->token_data->int_token.usbtoken);
}

int
int_unlock_usb(scd_token_t *token, char *passwd, unsigned char *pairing_secret,
	       size_t pairing_sec_len)
{
	TRACE("SCD: int_usb_unlock");
	return usbtoken_unlock(token->token_data->int_token.usbtoken, passwd, pairing_secret,
			       pairing_sec_len);
}

bool
int_is_locked_usb(scd_token_t *token)
{
	return usbtoken_is_locked(token->token_data->int_token.usbtoken);
}

bool
int_is_locked_till_reboot_usb(scd_token_t *token)
{
	return usbtoken_is_locked_till_reboot(token->token_data->int_token.usbtoken);
}

int
int_wrap_usb(scd_token_t *token, char *label, unsigned char *plain_key, size_t plain_key_len,
	     unsigned char **wrapped_key, int *wrapped_key_len)
{
	return usbtoken_wrap_key(token->token_data->int_token.usbtoken, (unsigned char *)label,
				 strlen(label), plain_key, plain_key_len, wrapped_key,
				 wrapped_key_len);
}

int
int_unwrap_usb(scd_token_t *token, char *label, unsigned char *wrapped_key, size_t wrapped_key_len,
	       unsigned char **plain_key, int *plain_key_len)
{
	return usbtoken_unwrap_key(token->token_data->int_token.usbtoken, (unsigned char *)label,
				   strlen(label), wrapped_key, wrapped_key_len, plain_key,
				   plain_key_len);
}

int
int_change_pw_usb(scd_token_t *token, const char *oldpass, const char *newpass,
		  unsigned char *pairing_secret, size_t pairing_sec_len, bool is_provisioning)
{
	return usbtoken_change_passphrase(token->token_data->int_token.usbtoken, oldpass, newpass,
					  pairing_secret, pairing_sec_len, is_provisioning);
}

int
int_send_apdu_usb(scd_token_t *token, unsigned char *apdu, size_t apdu_len, unsigned char *brsp,
		  size_t brsp_len)
{
	return usbtoken_send_apdu(token->token_data->int_token.usbtoken, apdu, apdu_len, brsp,
				  brsp_len);
}

int
int_reset_auth_usb(scd_token_t *token, unsigned char *brsp, size_t brsp_len)
{
	return usbtoken_reset_auth(token->token_data->int_token.usbtoken, brsp, brsp_len);
}

int
int_get_atr_usb(scd_token_t *token, unsigned char *brsp, size_t brsp_len)
{
	return usbtoken_get_atr(token->token_data->int_token.usbtoken, brsp, brsp_len);
}
#endif // ENABLESCHSM

#ifdef ENABLEPKCS11
int
int_lock_p11(scd_token_t *token)
{
	return p11token_lock(token->token_data->int_token.p11token);
}

int
int_unlock_p11(scd_token_t *token, char *passwd, UNUSED unsigned char *pairing_secret,
	       UNUSED size_t pairing_sec_len)
{
	return p11token_unlock(token->token_data->int_token.p11token, passwd);
}

bool
int_is_locked_p11(scd_token_t *token)
{
	return p11token_is_locked(token->token_data->int_token.p11token);
}

bool
int_is_locked_till_reboot_p11(scd_token_t *token)
{
	return p11token_is_locked_till_reboot(token->token_data->int_token.p11token);
}

int
int_wrap_key_p11(scd_token_t *token, UNUSED char *label, unsigned char *plain_key,
		 size_t plain_key_len, unsigned char **wrapped_key, int *wrapped_key_len)
{
	return p11token_wrap_key(token->token_data->int_token.p11token, plain_key, plain_key_len,
				 wrapped_key, (unsigned long *)wrapped_key_len);
}

int
int_unwrap_key_p11(scd_token_t *token, UNUSED char *label, unsigned char *wrapped_key,
		   size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	return p11token_unwrap_key(token->token_data->int_token.p11token, wrapped_key,
				   wrapped_key_len, plain_key, (unsigned long *)plain_key_len);
}

int
int_change_passphrase_p11(scd_token_t *token, const char *oldpass, const char *newpass,
			  UNUSED unsigned char *pairing_secret, UNUSED size_t pairing_sec_len,
			  UNUSED bool is_provisioning)
{
	return p11token_change_pin(token->token_data->int_token.p11token, oldpass, newpass);
}

int
int_send_apdu_p11(UNUSED scd_token_t *token, UNUSED unsigned char *adpu, UNUSED size_t apdu_len,
		  UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("send_adpu() not meaningful to p11token. Aborting ...");
	return -1;
}

int
int_reset_auth_p11(UNUSED scd_token_t *token, UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("reset_auth() not meaningful to p11token. Aborting ...");
	return -1;
}

int
int_get_atr_p11(UNUSED scd_token_t *token, UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("get_atr() not meaningful to p11token. Aborting ...");
	return -1;
}
#endif // ENABLEPKCS11

scd_token_t *
token_new(const token_constr_data_t *constr_data)
{
	ASSERT(constr_data);

	scd_token_t *new_token;
	char *token_file = NULL;

	new_token = mem_new0(scd_token_t, 1);
	if (!new_token) {
		ERROR("Could not allocate new scd_token_t");
		return NULL;
	}

	new_token->token_data = mem_new(scd_token_data_t, 1);
	if (!new_token->token_data) {
		ERROR("Could not allocate memory for token_data_t");
		goto err;
	}

	new_token->token_data->token_uuid = uuid_new(constr_data->uuid);
	if (!new_token->token_data->token_uuid) {
		ERROR("Could not allocate memory for token_uuid");
		goto err;
	}

	switch (constr_data->type) {
	case (NONE): {
		WARN("Create scd_token with internal type 'NONE' selected. No token will be created.");
		goto err;
	}
	case (SOFT): {
		DEBUG("Create scd_token with internal type 'SOFT'");

		ASSERT(constr_data->uuid);
		ASSERT(constr_data->init_str.softtoken_dir);

		token_file = mem_printf("%s/%s%s", constr_data->init_str.softtoken_dir,
					constr_data->uuid, STOKEN_DEFAULT_EXT);
		if (!file_exists(token_file)) {
			if (softtoken_create_p12(token_file, STOKEN_DEFAULT_PASS,
						 constr_data->uuid) != 0) {
				ERROR("Could not create new softtoken file");
				mem_free0(token_file);
				goto err;
			}
		}
		new_token->token_data->int_token.softtoken = softtoken_new_from_p12(token_file);
		if (!new_token->token_data->int_token.softtoken) {
			ERROR("Creation of softtoken failed");
			mem_free0(token_file);
			goto err;
		}
		mem_free0(token_file);

		new_token->token_data->type = SOFT;
		new_token->lock = int_lock_st;
		new_token->unlock = int_unlock_st;
		new_token->is_locked = int_is_locked_st;
		new_token->is_locked_till_reboot = int_is_locked_till_reboot_st;
		new_token->wrap_key = int_wrap_st;
		new_token->unwrap_key = int_unwrap_st;
		new_token->change_passphrase = int_change_pw_st;
		new_token->reset_auth = int_reset_auth_st;
		new_token->get_atr = int_get_atr_st;
		new_token->send_apdu = int_send_apdu_st;
		break;
	}
#ifdef ENABLESCHSM
	case (USB): {
		DEBUG("Create scd_token with internal type 'USB'");

		ASSERT(constr_data->uuid);
		ASSERT(constr_data->init_str.usbtoken_serial);

		new_token->token_data->int_token.usbtoken =
			usbtoken_new(constr_data->init_str.usbtoken_serial);
		if (!new_token->token_data->int_token.usbtoken) {
			ERROR("Creation of usbtoken failed");
			goto err;
		}

		if (0 != scd_tokencontrol_new(new_token)) {
			ERROR("Could not create tokencontrol socket for token %s",
			      constr_data->uuid);
		}

		new_token->token_data->type = USB;
		new_token->lock = int_lock_usb;
		new_token->unlock = int_unlock_usb;
		new_token->is_locked = int_is_locked_usb;
		new_token->is_locked_till_reboot = int_is_locked_till_reboot_usb;
		new_token->wrap_key = int_wrap_usb;
		new_token->unwrap_key = int_unwrap_usb;
		new_token->change_passphrase = int_change_pw_usb;
		new_token->reset_auth = int_reset_auth_usb;
		new_token->get_atr = int_get_atr_usb;
		new_token->send_apdu = int_send_apdu_usb;
		break;
	}
#endif // ENABLESCHSM
#ifdef ENABLEPKCS11
	case (PKCS11): {
		DEBUG("Create scd_token with internal type 'PKCS11'");

		ASSERT(constr_data->uuid);
		ASSERT(constr_data->init_str.pkcs11_module);
		p11token_t *token;
		token = p11token_token_by_label(constr_data->init_str.pkcs11_module,
						constr_data->uuid);

		// create new token if not found
		if (token == NULL) {
			// create random so_pin
			unsigned char *random_mem =
				(unsigned char *)file_read_new("/dev/urandom", 32);
			ASSERT(random_mem);
			str_t *so_pin = str_hexdump_new(random_mem, 32);
			free(random_mem);
			token = p11token_create_p11(constr_data->init_str.pkcs11_module,
						    str_buffer(so_pin), STOKEN_DEFAULT_PASS,
						    constr_data->uuid);
			if (!token) {
				ERROR("Creation of softtoken failed");
				goto err;
			}
			str_free(so_pin, true);
		}

		new_token->token_data->int_token.p11token = token;

		new_token->token_data->type = PKCS11;
		new_token->lock = int_lock_p11;
		new_token->unlock = int_unlock_p11;
		new_token->is_locked = int_is_locked_p11;
		new_token->is_locked_till_reboot = int_is_locked_till_reboot_p11;
		new_token->wrap_key = int_wrap_key_p11;
		new_token->unwrap_key = int_unwrap_key_p11;
		new_token->change_passphrase = int_change_passphrase_p11;
		new_token->reset_auth = int_reset_auth_p11;
		new_token->get_atr = int_get_atr_p11;
		new_token->send_apdu = int_send_apdu_p11;
		break;
	}
#endif // ENABLEPKCS11
	default:
		ERROR("Unrecognized token type");
		goto err;
	}

	return new_token;

err:
	if (new_token->token_data->token_uuid)
		uuid_free(new_token->token_data->token_uuid);
	if (new_token->token_data)
		mem_free0(new_token->token_data);
	if (new_token)
		mem_free0(new_token);

	return NULL;
}

scd_tokentype_t
token_get_type(scd_token_t *token)
{
	ASSERT(token);
	ASSERT(token->token_data);
	return token->token_data->type;
}

uuid_t *
token_get_uuid(scd_token_t *token)
{
	ASSERT(token);
	ASSERT(token->token_data);
	return token->token_data->token_uuid;
}

bool
token_has_internal_token(scd_token_t *token, const void *int_token)
{
	ASSERT(token);
	ASSERT(token->token_data);

	if (token->token_data->int_token.usbtoken == int_token)
		return true;

	if (token->token_data->int_token.softtoken == int_token)
		return true;

	return false;
}

void
token_free(scd_token_t *token)
{
	IF_NULL_RETURN(token);

	if (token->token_data) {
		switch (token->token_data->type) {
		case (NONE):
			break;
		case (SOFT):
			TRACE("Removing softtoken %s", uuid_string(token->token_data->token_uuid));
			softtoken_remove_p12(token->token_data->int_token.softtoken);
			softtoken_free(token->token_data->int_token.softtoken);
			break;
#ifdef ENABLESCHSM
		case (USB):
			scd_tokencontrol_free(token);
			usbtoken_free(token->token_data->int_token.usbtoken);
			break;
#endif // ENABLESCHSM
#ifdef ENABLEPKCS11
		case (PKCS11):
			TRACE("Removing p11token %s", uuid_string(token->token_data->token_uuid));
			p11token_free(token->token_data->int_token.p11token);
			break;
#endif // ENABLEPKCS11
		default:
			ERROR("Failed to determine token type. Cannot clean up");
			return;
		}

		if (token->token_data->token_uuid)
			uuid_free(token->token_data->token_uuid);
		mem_free0(token->token_data);
	}
	mem_free0(token);
}
