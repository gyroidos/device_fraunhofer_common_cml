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

#ifdef ANDROID
#include "device/fraunhofer/common/cml/service/c_service.pb-c.h"
#else
#include "c_service.pb-c.h"
#endif
#include <google/protobuf-c/protobuf-c-text.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/logf.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/dir.h"
#include "common/str.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <inttypes.h>

#include "dumb_init.h"

// clang-format off
#define SERVICE_SOCKET SOCK_PATH(service)
// clang-format on

#define LOGFILE_DIR "/tmp/log/"
#define AUDIT_LOGDIR "/var/log/cmld_audit/"

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

char *LAST_AUDIT_HASH;

static logf_handler_t *service_logfile_handler = NULL;
static FILE *service_logfile = NULL;

#ifndef BOOT_COMPLETE_ONLY
static int
service_set_hostname(int fd)
{
	int rc = 0;
	char *name = NULL;
	char *line = NULL;

	CmldToServiceMessage *resp = NULL;
	ServiceToCmldMessage msg = SERVICE_TO_CMLD_MESSAGE__INIT;
	msg.code = SERVICE_TO_CMLD_MESSAGE__CODE__CONTAINER_CFG_NAME_REQ;

	ssize_t msg_size = protobuf_send_message(fd, (ProtobufCMessage *)&msg);
	if (msg_size < 0)
		WARN("Could not send request for hostname!, error: %zd\n", msg_size);

	resp = (CmldToServiceMessage *)protobuf_recv_message(fd,
							     &cmld_to_service_message__descriptor);

	//protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *) resp);
	if (!resp || (resp->code != CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_NAME)) {
		name = "localhost";
		WARN("Wrong Response Message received! Falling back to default hostname: %s", name);
	} else
		name = resp->container_cfg_name;

	// write hostname to /etc/hosts
	line = mem_printf("127.0.1.1\t %s\n", name);
	if (file_exists("/etc/hosts")) { // save and restore stock file
		if (!file_exists("/etc/hosts.stock"))
			rc = file_copy_zero("/etc/hosts", "/etc/hosts.stock",
					    file_size("/etc/hosts"), 0);
		else
			rc = file_copy_zero("/etc/hosts.stock", "/etc/hosts",
					    file_size("/etc/hosts.stock"), 0);
	}
	rc += file_write_append("/etc/hosts", line, strlen(line));

	// write hostname to kernel
	if (sethostname(name, strlen(name)) == -1)
		WARN_ERRNO("Failed to set '%s' as hostname in kernel", name);

	mem_free0(line);
	if (resp)
		protobuf_free_message((ProtobufCMessage *)resp);

	return rc;
}

static int
service_set_dnsserver(int fd)
{
	int rc;
	char *dns_addr = NULL;
	char *line = NULL;

	CmldToServiceMessage *resp = NULL;
	ServiceToCmldMessage msg = SERVICE_TO_CMLD_MESSAGE__INIT;
	msg.code = SERVICE_TO_CMLD_MESSAGE__CODE__CONTAINER_CFG_DNS_REQ;

	ssize_t msg_size = protobuf_send_message(fd, (ProtobufCMessage *)&msg);
	if (msg_size < 0)
		WARN("Could not send request for dns_server!, error: %zd\n", msg_size);

	resp = (CmldToServiceMessage *)protobuf_recv_message(fd,
							     &cmld_to_service_message__descriptor);

	if (!resp || (resp->code != CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_DNS)) {
		dns_addr = "8.8.8.8";
		WARN("Wrong response message received! Falling back to default dns: %s", dns_addr);
	} else
		dns_addr = resp->container_cfg_dns;

	line = mem_printf("nameserver %s\n", dns_addr);
	rc = file_write("/etc/resolv.conf", line, strlen(line));

	mem_free0(line);
	if (resp)
		protobuf_free_message((ProtobufCMessage *)resp);

	return rc;
}
#endif /* ndef BOOT_COMPLETE_ONLY */

static int
service_fork_execvp(char *prog, char **argv)
{
	pid_t child_pid = fork();
	if (child_pid < 0) {
		ERROR_ERRNO("fork failed!");
		return -1;
	}
	if (0 == child_pid) { //child
		if (-1 == setsid()) {
			ERROR_ERRNO("child process setsid failed!");
			return -1;
		}
		if (-1 == execvp(prog, (char **)argv)) {
			ERROR_ERRNO("child process execve failed!");
			return -1;
		}
	}
	// parent
	dumb_init_set_child_pid(child_pid);
	INFO("Started child '%s' in background.", prog);
	return 0;
}

static int
process_audit_record(CmldToServiceMessage *msg, uint8_t *buf, uint32_t buf_len)
{
	ASSERT(msg);

	int ret = -1;

	char tmpfile[] = "/tmp/audit_XXXXXX";
	if (-1 == mkstemp(tmpfile)) {
		ERROR_ERRNO("Failed to generate temporary filename");
		return -1;
	}

	//TODO find reason why received buffer contains trailing null byte
	if (0 > file_write(tmpfile, (char *)buf, buf_len)) {
		ERROR("Failed to write file");

		if (unlink(tmpfile))
			ERROR_ERRNO("Failed to unlink %s", tmpfile);

		return ret;
	}

	char *cmd = mem_printf("sha512sum /%s", tmpfile);
	FILE *hash_file = popen(cmd, "r");
	char *hash_buf = mem_alloc0(129);

	if (!fgets(hash_buf, 129, hash_file)) {
		ERROR("Hash length was smaller than 64 bytes");
		pclose(hash_file);
		mem_free0(hash_buf);
		goto out;
	}
	pclose(hash_file);

	if (!file_is_dir(AUDIT_LOGDIR) && dir_mkdir_p(AUDIT_LOGDIR, 0600)) {
		ERROR("Failed to create audit log directory");
	} else if (msg->audit_record) {
		char *record;
		size_t msg_len = protobuf_string_from_message(
			&record, (ProtobufCMessage *)msg->audit_record, NULL);
		TRACE("Storing audit record %s", record);
		file_write_append(AUDIT_LOGDIR "/audit.log", record, msg_len);

		mem_free0(LAST_AUDIT_HASH);
		LAST_AUDIT_HASH = hash_buf;
		ret = 0;
	} else {
		WARN("Got empty audit message from cmld");
	}

out:
	if (unlink(tmpfile))
		ERROR_ERRNO("Failed to unlink %s", tmpfile);

	return ret;
}

static int
audit_send_ack(int sock, const char *hash)
{
	ServiceToCmldMessage auditmsg = SERVICE_TO_CMLD_MESSAGE__INIT;
	auditmsg.code = SERVICE_TO_CMLD_MESSAGE__CODE__AUDIT_ACK;

	if (hash) {
		auditmsg.audit_ack = mem_strdup((char *)hash);
	}

	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)&auditmsg);
	if (msg_size < 0)
		WARN("Could not request audit event delivery, error: %zd\n", msg_size);

	mem_free0(auditmsg.audit_ack);

	return 0;
}

static void
service_cb_recv_message(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	DEBUG("Received message from cmld");
	static bool awaiting_record = false;

	uint8_t *buf = NULL;
	CmldToServiceMessage *msg = NULL;

	if (events & EVENT_IO_READ) {
		ssize_t buf_len = 0;
		buf = protobuf_recv_message_packed_new(fd, &buf_len);

		if (!buf) {
			ERROR("Failed to receive message from cmld");
			return;
		}

		msg = (CmldToServiceMessage *)protobuf_unpack_message(
			&cmld_to_service_message__descriptor, buf, buf_len);

		if (!msg) {
			ERROR("Failed to decode protobuf message");
			goto out;
		}

		if (CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_NOTIFY == msg->code) {
			if (awaiting_record) {
				TRACE("Got AUDIT_NOTIFY but already awaiting a record, ignoring...");
			} else {
				TRACE("New audit records available, remaining storage: %" PRIu64
				      ", start fetching...",
				      msg->audit_remaining_storage);

				if (0 != audit_send_ack(fd, LAST_AUDIT_HASH)) {
					ERROR("Failed to send ack to cmld");
				} else {
					awaiting_record = true;
				}
			}
		} else if (CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_RECORD == msg->code) {
			TRACE("Got audit record from cmld");

			awaiting_record = false;
			if (0 != process_audit_record(msg, buf, buf_len)) {
				ERROR("Failed to process audit record");
			}

			// if processing of the last record failed,
			// send ACK with old hash to trigger delivery again
			if (0 != audit_send_ack(fd, LAST_AUDIT_HASH)) {
				ERROR("Failed to send ack to cmld");
			} else {
				awaiting_record = true;
			}

			goto out;
		} else if (CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_COMPLETE == msg->code) {
			TRACE("Fetched all available audit records");
			awaiting_record = false;

			goto out;
		} else {
			ERROR_ERRNO("Received message with unknown code from cmld");
		}
	}

	if (events & EVENT_IO_EXCEPT) {
		WARN("CML connection Error");
		event_remove_io(io);
		event_io_free(io);
		close(fd);

		return;
	}

out:
	if (buf)
		mem_free0(buf);
	if (msg)
		protobuf_free_message((ProtobufCMessage *)msg);

	return;
}

static int
open_service_socket()
{
	const char *socket_file = SERVICE_SOCKET;
	if (!file_exists(socket_file)) {
		ERROR("Could not find socket file %s.", socket_file);
		return -1;
	}

	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0) {
		ERROR("Could not connect to service on socket file %s.", socket_file);
		return -1;
	}

	return sock;
}

static int
container_close_all_fds_cb(UNUSED const char *path, const char *file, UNUSED void *data)
{
	int fd = atoi(file);

	DEBUG("Closing file descriptor %d", fd);

	if (close(fd) < 0)
		WARN_ERRNO("Could not close file descriptor %d", fd);

	return 0;
}

static int
service_close_all_fds()
{
	if (dir_foreach("/proc/self/fd", &container_close_all_fds_cb, NULL) < 0) {
		WARN("Could not open /proc/self/fd directory, /proc not mounted?");
		return -1;
	}

	return 0;
}

static void
fork_service_message_handler()
{
	int pid = fork();

	if (-1 == pid) {
		ERROR("Failed to fork service handler");
	} else if (0 == pid) {
		logf_unregister(service_logfile_handler);
		if (service_logfile) {
			logf_file_close(service_logfile);
		}

		if (service_close_all_fds()) {
			ERROR("Failed to close parent fds.");
		}

		service_logfile = logf_file_new(LOGFILE_DIR "service-handler");
		service_logfile_handler = logf_register(&logf_file_write, service_logfile);
		logf_handler_set_prio(service_logfile_handler, LOGF_PRIO_TRACE);

		int sock;
		if (-1 == (sock = open_service_socket())) {
			FATAL("Failed to open service socket. Aborting.");
		}

		LAST_AUDIT_HASH = mem_strdup(
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

		int *sock_ptr = mem_alloc(sizeof(int));
		*sock_ptr = sock;

		WARN("Registering logf handler");

		/* register socket for receiving data */
		fd_make_non_blocking(sock);

		event_io_t *event =
			event_io_new(*sock_ptr, EVENT_IO_READ, service_cb_recv_message, NULL);
		event_add_io(event);

		if (0 != audit_send_ack(*sock_ptr, LAST_AUDIT_HASH)) {
			ERROR("Failed to send ack to cmld");
		}

		event_loop();

		// this should never be reached
		ERROR("Failed to enter event loop");
		exit(EXIT_FAILURE);
	}
}

int
main(int argc, char **argv)
{
	bool do_init;
	int sock;

	if (dir_mkdir_p(LOGFILE_DIR, 0755)) {
		ERROR("Failed to create logging directoy");
	}

	event_init();

	DEBUG("Registering file logger");
	service_logfile = logf_file_new(LOGFILE_DIR "service-init");
	service_logfile_handler = logf_register(&logf_file_write, service_logfile);
	logf_handler_set_prio(service_logfile_handler, LOGF_PRIO_TRACE);

	if (-1 == (sock = open_service_socket())) {
		FATAL("Failed to open service socket. Aborting...");
	}

#ifndef BOOT_COMPLETE_ONLY
	// set hostname received from cmld
	if (service_set_hostname(sock) < 0)
		WARN("Failed to set hostname");
	else
		DEBUG("Successfully setup hostname");

	// set dns server received from cmld
	if (service_set_dnsserver(sock) < 0)
		WARN("Failed to set DNS server");
	else
		DEBUG("Successfully setup DNS server");

	INFO("Minimal init done, going to start child, %s ...", argv[1]);
#endif

	ServiceToCmldMessage msg = SERVICE_TO_CMLD_MESSAGE__INIT;
	msg.code = SERVICE_TO_CMLD_MESSAGE__CODE__BOOT_COMPLETED;

	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)&msg);
	if (msg_size < 0)
		WARN("Could not send boot complete msg!, error: %zd\n", msg_size);

	// closing socket to cmld
	if (-1 == close(sock)) {
		ERROR_ERRNO("Failed to close service socket");
	}

	// if we are not running as init, just open the cml-service socket and handle messages
	if (!(do_init = (getpid() == 1))) {
		DEBUG("Not running as init, launching service message handler");
		fork_service_message_handler();

		exit(EXIT_SUCCESS);
	}

	if (argc < 2) {
		INFO("Running as init, not starting any child!");
	} else if (!strcmp(argv[1], "init")) {
		argv[1] = "/sbin/init";
		execvp(argv[1], &argv[1]);
		WARN("Error starting container init!");
	} else if (service_fork_execvp(argv[1], &argv[1])) {
		WARN("Error starting child!");
	}

	fork_service_message_handler();

	INFO("Going to handle signals ...");
	dumb_init_signal_handler();

	return 0;
}
