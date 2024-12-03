/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

#include "download.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/file.h"

#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#define WGET_PATH "wget"
#define DL_COPY_BUF_SIZE sysconf(_SC_PAGESIZE)

struct download {
	char *url;
	char *file;
	download_callback_t on_complete;
	void *data;
	pid_t wget_pid;
};

download_t *
download_new(const char *url, const char *file, download_callback_t on_complete, void *data)
{
	download_t *dl = mem_new(download_t, 1);
	dl->url = mem_strdup(url);
	dl->file = mem_strdup(file);
	dl->on_complete = on_complete;
	dl->data = data;
	return dl;
}

void
download_free(download_t *dl)
{
	IF_NULL_RETURN(dl);
	mem_free0(dl->url);
	mem_free0(dl->file);
	mem_free0(dl);
}

static void
download_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	download_t *dl = data;
	ASSERT(dl);
	pid_t wget_pid = dl->wget_pid;
	pid_t pid = 0;
	int status = 0;
	DEBUG("SIGCHLD handler called for wget (PID=%d)", wget_pid);
	if (wget_pid <= 0) {
		DEBUG("wget PID not yet set; returning");
		return;
	}
	bool remove = false;
	while ((pid = waitpid(wget_pid, &status, WNOHANG))) {
		if (pid == wget_pid) {
			bool success = false;
			if (WIFEXITED(status)) {
				DEBUG("wget terminated with status=%d", WEXITSTATUS(status));
				success = !WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				DEBUG("wget killed by signal %d", WTERMSIG(status));
			} else {
				continue;
			}
			remove = true;
			dl->on_complete(dl, success, dl->data);
		} else if (pid == 0) {
			DEBUG("waitpid child(ren) (PID %d) exist without state change", wget_pid);
			break;
		} else if (pid == -1) {
			if (errno == ECHILD)
				DEBUG("Process group of wget terminated completely");
			else
				WARN_ERRNO("waitpid failed for wget");
			remove = true;
			break;
		} else {
			DEBUG("Reaped a child with PID %d for wget", pid);
		}
	}
	if (remove) {
		event_remove_signal(sig);
		event_signal_free(sig);
	}
}

int
download_start(download_t *dl)
{
	ASSERT(dl);
	pid_t pid = fork();

	char *const argv[] = { WGET_PATH, "-O", dl->file, dl->url, NULL };
	bool do_file_copy = strlen(dl->url) > 7 && !strncmp(dl->url, "file://", 7);

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork to download (%s) image %s", dl->file,
			    do_file_copy ? "file_copy" : "wget");
		return -1;
	case 0: {
		if (do_file_copy) {
			char *local_dl_src = dl->url + 7;
			INFO("Copying file from %s -> %s", local_dl_src, dl->file);
			int ret = file_copy_zero(local_dl_src, dl->file, -1, 0);
			if (ret < 0)
				ERROR("Failed retrieving '%s'!", dl->url);
			_exit(ret);
		} else {
			execvp(argv[0], argv);
			ERROR_ERRNO("Could not exec %s", argv[0]);
			_exit(-1);
		}
	}
	default:
		DEBUG("Started download helper (%s) with PID %d",
		      do_file_copy ? "file_copy" : "wget", pid);
		dl->wget_pid = pid;
		event_signal_t *sig = event_signal_new(SIGCHLD, download_sigchld_cb, dl);
		event_add_signal(sig);
		return 0;
	}
}

const char *
download_get_url(const download_t *dl)
{
	ASSERT(dl);
	return dl->url;
}

const char *
download_get_file(const download_t *dl)
{
	ASSERT(dl);
	return dl->file;
}
