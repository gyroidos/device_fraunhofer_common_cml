/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2022 Fraunhofer AISEC
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

#define _GNU_SOURCE
#include <linux/sched.h>
#include <sched.h>

#include "compartment.h"

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/list.h"
#include "common/nl.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/proc.h"
#include "common/ns.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/wait.h>
#include <pty.h>
#include <sys/mman.h>

extern logf_handler_t *cml_daemon_logfile_handler;

/* Timeout for a compartment boot. If the compartment does not come up in that time frame
 * it is killed forcefully */
/* TODO is that enough time for all benign starts? */
#define COMPARTMENT_START_TIMEOUT 800000
/* Timeout until a compartment to be stopped gets killed if not yet down */
#define COMPARTMENT_STOP_TIMEOUT 45000

struct compartment {
	void *extension_data; /* useful for submodule implementation of compartment_new */
	compartment_state_t state;
	compartment_state_t prev_state;
	uuid_t *uuid;
	char *name;
	uint64_t flags;
	char *key;
	char *description;

	list_t *csock_list; /* List of sockets bound inside the compartment */
	pid_t pid;	    /* PID of the corresponding /init */
	pid_t pid_early;    /* PID of the corresponding early start child */
	int exit_status;    /* if the compartment's init exited, here we store its exit status */

	char *init;	     /* init to be execed in compartment */
	char **init_argv;    /* command line parameters for init */
	char **init_env;     /* environment variables passed to init */
	size_t init_env_len; /* len of init_env array */

	char *debug_log_dir; /* log for output of compartment child */

	list_t *observer_list; /* list of function callbacks to be called when the state changes */
	event_timer_t *stop_timer;  /* timer to handle compartment stop timeout */
	event_timer_t *start_timer; /* timer to handle a compartment start timeout */

	/* TODO maybe we should try to get rid of this state since it is only
	 * useful for the starting phase and only there to make it easier to pass
	 * the FD to the child via clone */
	int sync_sock_parent; /* parent sock for start synchronization */
	int sync_sock_child;  /* child sock for start synchronization */

	// Submodules
	list_t *module_instance_list;

	bool setup_mode;

	// indicate if the compartment is synced with its config
	bool is_synced;

	list_t *helper_child_list; // helper children spawned during startup
	bool is_doing_cleanup;
	bool is_rebooting;
};

struct compartment_callback {
	void (*cb)(compartment_t *, compartment_callback_t *, void *);
	void *data;
	bool todo;
};

struct compartment_extension {
	void (*set_compartment)(void *extension_data, compartment_t *compartment);
	void *data;
};

typedef struct {
	int sockfd; /* The socket FD */
	char *path; /* The path the socket should be/is (pre/post start) bound to */
} compartment_sock_t;

typedef struct {
	pid_t pid;
	char *name;
} compartment_helper_child_t;
/**
 * These are used for synchronizing the compartment start between parent
 * and child process
 */
enum compartment_start_sync_msg {
	COMPARTMENT_START_SYNC_MSG_GO = 1,
	COMPARTMENT_START_SYNC_MSG_STOP,
	COMPARTMENT_START_SYNC_MSG_SUCCESS,
	COMPARTMENT_START_SYNC_MSG_ERROR,
};

static list_t *compartment_module_list = NULL;

static int
clone3(struct clone_args *cl_args, size_t size)
{
	return syscall(SYS_clone3, cl_args, size);
}

bool
compartment_is_stoppable(compartment_t *compartment)
{
	compartment_state_t state = compartment_get_state(compartment);
	if (state == COMPARTMENT_STATE_RUNNING || state == COMPARTMENT_STATE_BOOTING ||
	    state == COMPARTMENT_STATE_SETUP) {
		DEBUG("Compartment can be stopped.");
		return true;
	}

	return false;
}

bool
compartment_is_startable(compartment_t *compartment)
{
	if ((compartment_get_state(compartment) == COMPARTMENT_STATE_STOPPED) ||
	    (compartment_get_state(compartment) == COMPARTMENT_STATE_REBOOTING)) {
		if (compartment->helper_child_list) {
			DEBUG("Helper children active, compartment can not be stopped.");
			return false;
		}

		DEBUG("Compartment can be started.");
		return true;
	}

	DEBUG("Compartment is in unstartable state.(%d)", compartment_get_state(compartment));
	return false;
}

void
compartment_register_module(compartment_module_t *mod)
{
	ASSERT(mod);

	compartment_module_list = list_append(compartment_module_list, mod);
	DEBUG("Container module %s registered, nr of hooks: %d)", mod->name,
	      list_length(compartment_module_list));
}

typedef struct {
	compartment_module_t *module;
	void *instance;
} compartment_module_instance_t;

static compartment_module_instance_t *
compartment_module_instance_new(compartment_t *compartment, compartment_module_t *module)
{
	IF_NULL_RETVAL(module->compartment_new, NULL);

	void *instance = module->compartment_new(compartment);
	IF_NULL_RETVAL(instance, NULL);

	compartment_module_instance_t *c_mod = mem_new0(compartment_module_instance_t, 1);
	c_mod->module = module;
	c_mod->instance = instance;

	return c_mod;
}

static void
compartment_module_instance_free(compartment_module_instance_t *c_mod)
{
	IF_NULL_RETURN(c_mod);

	compartment_module_t *module = c_mod->module;

	if (module->compartment_free)
		module->compartment_free(c_mod->instance);

	mem_free0(c_mod);
}

static compartment_module_instance_t *
compartment_module_get_mod_instance_by_name(const compartment_t *compartment, const char *mod_name)
{
	ASSERT(compartment);
	ASSERT(mod_name);

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (!strcmp(module->name, mod_name))
			return c_mod;
	}
	return NULL;
}

static compartment_helper_child_t *
compartment_helper_child_new(char *name, pid_t pid)
{
	compartment_helper_child_t *child = mem_new0(compartment_helper_child_t, 1);
	child->name = mem_strdup(name ? name : "generic");
	child->pid = pid;

	return child;
}

static void
compartment_helper_child_free(compartment_helper_child_t *child)
{
	IF_NULL_RETURN(child);

	if (child->name)
		mem_free0(child->name);
	mem_free0(child);
}

void *
compartment_module_get_instance_by_name(const compartment_t *compartment, const char *mod_name)
{
	ASSERT(compartment);
	ASSERT(mod_name);

	compartment_module_instance_t *c_mod =
		compartment_module_get_mod_instance_by_name(compartment, mod_name);

	return c_mod ? c_mod->instance : NULL;
}

void
compartment_free_key(compartment_t *compartment)
{
	ASSERT(compartment);

	IF_NULL_RETURN(compartment->key);

	mem_memset0(compartment->key, strlen(compartment->key));
	mem_free0(compartment->key);

	INFO("Key of compartment %s was freed", compartment->name);
}

compartment_extension_t *
compartment_extension_new(void (*set_compartment)(void *extension_data, compartment_t *compartment),
			  void *extension_data)
{
	compartment_extension_t *extension = mem_new0(compartment_extension_t, 1);

	extension->set_compartment = set_compartment;
	extension->data = extension_data;

	return extension;
}

void
compartment_extension_free(compartment_extension_t *extension)
{
	mem_free0(extension);
}

static bool
compartment_is_module_sig_enforced(void)
{
	char *sig_enforce = file_read_new("/sys/module/module/parameters/sig_enforce", 2);
	if (!sig_enforce)
		return false;

	int ret = sig_enforce[0] == 'Y' ? true : false;

	mem_free0(sig_enforce);
	return ret;
}

compartment_t *
compartment_new(const uuid_t *uuid, const char *name, uint64_t flags, const char *init,
		char **init_argv, char **init_env, size_t init_env_len,
		const compartment_extension_t *extension)
{
	compartment_t *compartment = mem_new0(compartment_t, 1);

	if (extension) {
		compartment->extension_data = extension->data;
		/* register compartment in extension data early */
		if (extension->set_compartment)
			extension->set_compartment(extension->data, compartment);
	}

	compartment->state = COMPARTMENT_STATE_STOPPED;
	compartment->prev_state = COMPARTMENT_STATE_STOPPED;

	compartment->uuid = uuid_new(uuid_string(uuid));
	compartment->name = mem_strdup(name);
	compartment->flags = flags;

	/* strip out COMPARTMENT_FLAG_MODULE_LOAD if signatures are not enforced */
	if (!compartment_is_module_sig_enforced()) {
		compartment->flags &= ~COMPARTMENT_FLAG_MODULE_LOAD;
		INFO("striped COMPARTMENT_FLAG_MODULE_LOAD since module signatures are not enforced!");
	}

	/* do not forget to update compartment->description in the setters of uuid and name */
	compartment->description =
		mem_printf("%s (%s)", compartment->name, uuid_string(compartment->uuid));

	/* initialize pid to a value indicating it is invalid */
	compartment->pid = -1;
	compartment->pid_early = -1;

	/* initialize exit_status to 0 */
	compartment->exit_status = 0;

	if (file_exists("/proc/self/ns/ipc"))
		compartment->flags |= COMPARTMENT_FLAG_NS_IPC;

	compartment->csock_list = NULL;
	compartment->observer_list = NULL;
	compartment->stop_timer = NULL;
	compartment->start_timer = NULL;

	// construct an argv buffer for execve
	compartment->init_argv = init_argv;

	compartment->init = mem_strdup(init);
	// allocate and set init_env
	compartment->init_env_len = 0;
	compartment_init_env_prepend(compartment, init_env, init_env_len);
	if (!compartment->init_env)
		compartment->init_env = mem_new0(char *, 1);

	compartment->setup_mode = false;

	compartment->is_synced = true;

	compartment->helper_child_list = NULL;

	/* Create submodules */
	for (list_t *l = compartment_module_list; l; l = l->next) {
		compartment_module_t *module = l->data;
		if (module->compartment_new) {
			compartment_module_instance_t *c_mod =
				compartment_module_instance_new(compartment, module);
			if (!c_mod) {
				WARN("Could not initialize %s subsystem for compartment %s (UUID: %s)",
				     module->name, compartment->name,
				     uuid_string(compartment->uuid));
				goto error;
			}
			compartment->module_instance_list =
				list_append(compartment->module_instance_list, c_mod);

			INFO("Initialized %s subsystem for compartment %s (UUID: %s)", module->name,
			     compartment->name, uuid_string(compartment->uuid));
		}
	}

	return compartment;

error:
	compartment_free(compartment);
	return NULL;
}

void
compartment_free(compartment_t *compartment)
{
	ASSERT(compartment);

	/* free module instances */
	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_instance_free(c_mod);
	}
	list_delete(compartment->module_instance_list);

	compartment_free_key(compartment);

	uuid_free(compartment->uuid);
	mem_free0(compartment->name);

	for (list_t *l = compartment->csock_list; l; l = l->next) {
		compartment_sock_t *cs = l->data;
		mem_free0(cs->path);
		mem_free0(cs);
	}
	list_delete(compartment->csock_list);

	mem_free0(compartment->init);
	if (compartment->init_argv) {
		for (char **arg = compartment->init_argv; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(compartment->init_argv);
	}
	if (compartment->init_env) {
		for (char **arg = compartment->init_env; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(compartment->init_env);
	}

	if (compartment->debug_log_dir)
		mem_free0(compartment->debug_log_dir);

	mem_free0(compartment);
}

void *
compartment_get_extension_data(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->extension_data;
}

bool
compartment_uuid_is_c0id(const uuid_t *uuid)
{
	ASSERT(uuid);
	uuid_t *uuid_c0 = uuid_new("00000000-0000-0000-0000-000000000000");
	bool ret = uuid_equals(uuid, uuid_c0);
	uuid_free(uuid_c0);
	return ret;
}

void
compartment_init_env_prepend(compartment_t *compartment, char **init_env, size_t init_env_len)
{
	IF_TRUE_RETURN(init_env == NULL || init_env_len <= 0);

	// construct a NULL terminated env buffer for execve
	size_t total_len;
	if (__builtin_add_overflow(compartment->init_env_len, init_env_len, &total_len)) {
		WARN("Overflow detected when calculating buffer size for compartment's env");
		return;
	}
	if (__builtin_add_overflow(total_len, 1, &total_len)) {
		WARN("Overflow detected when calculating buffer size for compartment's env");
		return;
	}
	char **init_env_old = compartment->init_env;
	compartment->init_env = mem_new0(char *, total_len);

	size_t i = 0;
	for (; i < init_env_len; i++)
		compartment->init_env[i] = mem_strdup(init_env[i]);
	for (size_t j = 0; j < compartment->init_env_len; ++j)
		compartment->init_env[i + j] = mem_strdup(init_env_old[j]);

	if (init_env_old) {
		for (char **arg = init_env_old; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(init_env_old);
	}
	compartment->init_env_len = total_len;
}

const uuid_t *
compartment_get_uuid(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->uuid;
}

const char *
compartment_get_name(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->name;
}

/* TODO think about setters for name etc.
 * Old references retrieved with the getter should not become
 * invalid! */

const char *
compartment_get_description(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->description;
}

pid_t
compartment_get_pid(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->pid;
}

pid_t
compartment_get_service_pid(const compartment_t *compartment)
{
	/* Determine PID of compartment's init */
	pid_t init = compartment_get_pid(compartment);
	if (init <= 0) {
		DEBUG("Could not determine PID of compartment's init");
		return -1;
	}

	/* Determine PID of compartment's zygote */
	pid_t zygote = proc_find(init, "main");
	if (zygote <= 0) {
		DEBUG("Could not determine PID of compartment's zygote");
		return -1;
	}

	/* Determine PID of compartment's trustme service */
	pid_t service = proc_find(zygote, "trustme.service");
	if (service <= 0) {
		DEBUG("Could not determine PID of compartment's service");
		return -1;
	}

	return service;
}

void
compartment_oom_protect_service(const compartment_t *compartment)
{
	ASSERT(compartment);

	pid_t service_pid = compartment_get_service_pid(compartment);
	if (service_pid < 0) {
		WARN("Could not determine PID of compartment's service to protect against low memory killer. Ignoring...");
		return;
	}

	DEBUG("Setting oom_adj of trustme service (PID %d) in compartment %s to -17", service_pid,
	      compartment_get_description(compartment));
	char *path = mem_printf("/proc/%d/oom_adj", service_pid);
	int ret = file_write(path, "-17", -1);
	if (ret < 0)
		ERROR_ERRNO("Failed to write to %s", path);
	mem_free0(path);
}

bool
compartment_get_sync_state(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->is_synced;
}

void
compartment_set_sync_state(compartment_t *compartment, bool state)
{
	ASSERT(compartment);
	compartment->is_synced = state;
}

int
compartment_get_exit_status(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->exit_status;
}

bool
compartment_is_privileged(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment_uuid_is_c0id(compartment->uuid);
}

/**
 * This function should be called only on a (physically) not-running compartment and
 * should make sure that the compartment and all its submodules are in the same
 * state they had immediately after their creation with _new().
 * Return values are not gathered, as the cleanup should just work as the system allows.
 */
static void
compartment_cleanup(compartment_t *compartment, bool is_rebooting)
{
	/* timer can be removed here, because compartment is on the transition to the stopped state */
	if (compartment->stop_timer) {
		DEBUG("Remove compartment stop timer for %s",
		      compartment_get_description(compartment));
		event_remove_timer(compartment->stop_timer);
		event_timer_free(compartment->stop_timer);
		compartment->stop_timer = NULL;
	}
	if (compartment->start_timer) {
		DEBUG("Remove compartment start timer for %s",
		      compartment_get_description(compartment));
		event_remove_timer(compartment->start_timer);
		event_timer_free(compartment->start_timer);
		compartment->start_timer = NULL;
	}

	list_t *do_late_list = NULL;

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->cleanup)
			continue;

		if (module->flags & COMPARTMENT_MODULE_F_CLEANUP_LATE) {
			do_late_list = list_append(do_late_list, c_mod);
			continue;
		}

		module->cleanup(c_mod->instance, is_rebooting);
	}

	/* cleanup modules with flag COMPARTMENT_MODULE_F_CLEANUP_LATE set.
	 * NULL check and check for flag already made in loop above */
	for (list_t *l = do_late_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		module->cleanup(c_mod->instance, is_rebooting);
	}

	list_delete(do_late_list);

	compartment->pid = -1;
	compartment->pid_early = -1;
}

void
compartment_sigchld_handle_helpers(compartment_t *compartment, event_signal_t *sig)
{
	int status = 0;

	for (list_t *l = compartment->helper_child_list; l;) {
		list_t *next = l->next;
		compartment_helper_child_t *child = l->data;
		if (proc_waitpid(child->pid, &status, WNOHANG) == child->pid) {
			DEBUG("Reaped helper child %s (pid=%d) for compartment %s", child->name,
			      child->pid, compartment_get_description(compartment));
			compartment->helper_child_list =
				list_unlink(compartment->helper_child_list, l);
			compartment_helper_child_free(child);
		}
		l = next;
	}

	if (!compartment->helper_child_list && compartment->is_doing_cleanup) {
		DEBUG("CLEANUP DONE, all pending helpers reaped!");
		/* remove the sigchld callback for this compartment from the event loop */
		event_remove_signal(sig);
		event_signal_free(sig);
		compartment->is_doing_cleanup = false;
		compartment_state_t state = compartment->is_rebooting ?
						    COMPARTMENT_STATE_REBOOTING :
						    COMPARTMENT_STATE_STOPPED;
		compartment_set_state(compartment, state);
		compartment->is_rebooting = false;
	}
}

void
compartment_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	ASSERT(data);

	compartment_t *compartment = data;

	TRACE("SIGCHLD handler called for compartment %s with PID %d",
	      compartment_get_description(compartment), compartment->pid);

	if (compartment->pid == -1) {
		TRACE("All processes of container %s already reaped, check for remaining helpers.",
		      compartment_get_description(compartment));

		compartment_sigchld_handle_helpers(compartment, sig);
		return;
	}

	/* In the start function the childs init process gets set a process group which has
	 * the same pgid as its pid. We wait for all processes belonging to our compartment's
	 * process group, but only change the compartments state to stopped if the init exited */
	pid_t pid = 0;
	int status = 0;
	if ((pid = proc_waitpid(-(compartment->pid), &status, WNOHANG)) != 0) {
		if (pid == compartment->pid) {
			if (WIFEXITED(status)) {
				INFO("Container %s terminated (init process exited with status=%d)",
				     compartment_get_description(compartment), WEXITSTATUS(status));
				compartment->exit_status = WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				INFO("Container %s killed by signal %d",
				     compartment_get_description(compartment), WTERMSIG(status));
				/* Since Kernel 3.4 reboot inside pid namspaces
				 * are signaled by SIGHUP (see manpage REBOOT(2)) */
				if (WTERMSIG(status) == SIGHUP) {
					compartment->is_rebooting = true;
				}
			} else {
				return;
			}
			/* cleanup and set states accordingly to notify observers */
			compartment_cleanup(compartment, compartment->is_rebooting);
			compartment->is_doing_cleanup = true;

		} else if (pid == -1) {
			if (errno == ECHILD) {
				DEBUG("Process group of compartment %s terminated completely",
				      compartment_get_description(compartment));
			} else {
				WARN_ERRNO("waitpid failed for compartment %s",
					   compartment_get_description(compartment));
			}
		} else {
			DEBUG("Reaped a child with PID %d for compartment %s", pid,
			      compartment_get_description(compartment));
		}
	}

	// check for compartment itself again, e.g., before execv
	if (compartment->pid > 0 &&
	    compartment->pid == proc_waitpid(compartment->pid, &status, WNOHANG)) {
		INFO("Compartment %s reaped before beeing part of pg",
		     compartment_get_description(compartment));
		if (WIFEXITED(status)) {
			INFO("Early Container %s terminated (init process exited with status=%d)",
			     compartment_get_description(compartment), WEXITSTATUS(status));
			compartment->exit_status = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			INFO("Early Container %s killed by signal %d",
			     compartment_get_description(compartment), WTERMSIG(status));
		} else {
			return;
		}
		compartment_cleanup(compartment, false);
		compartment->is_doing_cleanup = true;
	}

	// reap any open helper child and set state accordingly
	compartment_sigchld_handle_helpers(compartment, sig);

	TRACE("No more children to reap. Callback exiting...");
}

void
compartment_sigchld_early_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	compartment_t *compartment = data;
	ASSERT(compartment);

	pid_t pid = 0;
	int status = 0;

	TRACE("SIGCHLD handler called for compartment %s early start child with PID %d",
	      compartment_get_description(compartment), compartment->pid_early);

	if (compartment->pid_early &&
	    (pid = proc_waitpid(compartment->pid_early, &status, WNOHANG)) > 0) {
		TRACE("Reaped early compartment child process: %d", pid);
		/* remove the sigchld callback for this early child from the event loop */
		event_remove_signal(sig);
		event_signal_free(sig);
		// cleanup if early child returned with an error
		if ((WIFEXITED(status) && WEXITSTATUS(status)) || WIFSIGNALED(status)) {
			if (compartment->pid == -1)
				compartment_cleanup(compartment, false);

			compartment_set_state(compartment, COMPARTMENT_STATE_STOPPED);
		}
		compartment->pid_early = -1;
	}

	// reap any open helper child and set state accordingly
	compartment_sigchld_handle_helpers(compartment, sig);
}

static int
compartment_close_all_fds_cb(UNUSED const char *path, const char *file, UNUSED void *data)
{
	int fd = atoi(file);

	close(fd);

	return 0;
}

static int
compartment_close_all_fds()
{
	DEBUG("Closing all fds");
	logf_unregister(cml_daemon_logfile_handler);

	if (dir_foreach("/proc/self/fd", &compartment_close_all_fds_cb, NULL) < 0) {
		return -1;
	}

	return 0;
}

static int
compartment_start_child(compartment_t *compartment)
{
	ASSERT(compartment);

	int ret = 0;

	char *kvm_root = mem_printf("/tmp/%s", uuid_string(compartment->uuid));

	/*******************************************************************/
	// wait on synchronization socket for start message code from parent
	// check if everything went ok in the parent (else goto error)
	char msg;
	if (read(compartment->sync_sock_child, &msg, 1) != 1) {
		WARN_ERRNO("Could not read from sync socket");
		goto error;
	}

	DEBUG("Received message from parent %d", msg);
	if (msg == COMPARTMENT_START_SYNC_MSG_STOP) {
		DEBUG("Received stop message, exiting...");
		return 0;
	}

	/* Reset umask and sigmask for /init */
	sigset_t sigset;
	umask(0);
	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);

	/* Make sure /init in node doesn`t kill CMLD daemon */
	if (setpgid(0, 0) < 0) {
		WARN("Could not move process group of compartment %s", compartment->name);
		goto error;
	}

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_child)
			continue;

		if ((ret = module->start_child(c_mod->instance)) < 0) {
			goto error;
		}
	}

	char *root = (compartment->flags & COMPARTMENT_FLAG_TYPE_KVM) ? kvm_root : "/";
	if (chdir(root) < 0) {
		WARN_ERRNO("Could not chdir to \"%s\" in compartment %s", root,
			   uuid_string(compartment->uuid));
		goto error;
	}

	// bind sockets in csock_list
	// make sure this is done *after* the c_vol hook, which brings the childs mounts into place
	for (list_t *l = compartment->csock_list; l; l = l->next) {
		compartment_sock_t *cs = l->data;
		sock_unix_bind(cs->sockfd, cs->path);
	}

	// send success message to parent
	DEBUG("Sending COMPARTMENT_START_SYNC_MSG_SUCCESS to parent");
	char msg_success = COMPARTMENT_START_SYNC_MSG_SUCCESS;
	if (write(compartment->sync_sock_child, &msg_success, 1) < 0) {
		WARN_ERRNO("Could not write to sync socket");
		goto error;
	}

	DEBUG("Executing start_pre_exec_child_early hooks");
	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_pre_exec_child_early)
			continue;

		if ((ret = module->start_pre_exec_child_early(c_mod->instance)) < 0) {
			goto error;
		}
	}

	/* Block on socket until the next sync message is sent by the parent */
	if (read(compartment->sync_sock_child, &msg, 1) != 1) {
		WARN_ERRNO("Could not read from sync socket");
		goto error;
	}

	DEBUG("Received message from parent %d", msg);

	if (msg == COMPARTMENT_START_SYNC_MSG_STOP) {
		DEBUG("Received stop message, exiting...");
		return 0;
	}

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_pre_exec_child)
			continue;

		if ((ret = module->start_pre_exec_child(c_mod->instance)) < 0) {
			goto error;
		}
	}

	DEBUG("Will start %s after closing filedescriptors of %s", compartment->init,
	      compartment_get_description(compartment));

	DEBUG("init_argv:");
	for (char **arg = compartment->init_argv; *arg; arg++) {
		DEBUG("\t%s", *arg);
	}
	DEBUG("init_env:");
	for (char **arg = compartment->init_env; *arg; arg++) {
		DEBUG("\t%s", *arg);
	}

	if (compartment->flags & COMPARTMENT_FLAG_TYPE_KVM) {
		int fd_master;
		int pid = forkpty(&fd_master, NULL, NULL, NULL);

		if (pid == -1) {
			ERROR_ERRNO("Forkpty() failed!");
			goto error;
		}
		if (pid == 0) { // child
			char *const argv[] = { "/usr/bin/lkvm", "run", "-d", kvm_root, NULL };
			execv(argv[0], argv);
			WARN("Could not run exec for kvm compartment %s",
			     uuid_string(compartment->uuid));
		} else { // parent
			char buffer[128];
			ssize_t read_bytes;
			char *kvm_log = mem_printf("%s.kvm.log", compartment->debug_log_dir);
			read_bytes = read(fd_master, buffer, 128);
			file_write(kvm_log, buffer, read_bytes);
			while ((read_bytes = read(fd_master, buffer, 128))) {
				file_write_append(kvm_log, buffer, read_bytes);
			}
			return COMPARTMENT_ERROR;
		}
	}

	if (compartment_get_state(compartment) != COMPARTMENT_STATE_SETUP) {
		DEBUG("After closing all file descriptors no further debugging info can be printed");
		if (compartment_close_all_fds()) {
			WARN("Closing all file descriptors failed, continuing anyway...");
		}
	}

	execve(compartment->init, compartment->init_argv, compartment->init_env);

	/* handle possibly empty rootfs in setup_mode */
	if (compartment_get_state(compartment) == COMPARTMENT_STATE_SETUP) {
		// fallback: if there is still no init, just idle to keep namespaces open
		event_reset();
		WARN("No init found for compartment '%s', just loop forever!",
		     uuid_string(compartment->uuid));
		event_loop();
	}

	WARN_ERRNO("Could not run exec for compartment %s", uuid_string(compartment->uuid));

	return COMPARTMENT_ERROR;

error:
	if (ret == 0) {
		ret = COMPARTMENT_ERROR;
	}

	// send error message to parent
	char msg_error = COMPARTMENT_START_SYNC_MSG_ERROR;
	if (write(compartment->sync_sock_child, &msg_error, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}

	// TODO call c_<module>_cleanup_child() hooks

	if (compartment_close_all_fds()) {
		WARN("Closing all file descriptors in compartment start error failed");
	}
	return ret; // exit the child process
}

static int
compartment_start_child_early(compartment_t *compartment)
{
	ASSERT(compartment);

	int ret = 0;

	event_reset();
	close(compartment->sync_sock_parent);

	/* Make sure /init in node doesn`t kill CMLD daemon */
	if (setpgid(0, 0) < 0) {
		WARN("Could not move process group of compartment %s", compartment->name);
		goto error;
	}

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_child_early)
			continue;

		if ((ret = module->start_child_early(c_mod->instance)) < 0) {
			goto error;
		}
	}

	struct clone_args args = { 0 };
	args.exit_signal = SIGCHLD;

	/* Set namespaces for node */
	/* set some basic and non-configurable namespaces */
	args.flags |= CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID;
	if (compartment_has_ipcns(compartment))
		args.flags |= CLONE_NEWIPC;

	compartment_module_instance_t *c_user =
		compartment_module_get_mod_instance_by_name(compartment, "c_user");
	compartment_module_instance_t *c_net =
		compartment_module_get_mod_instance_by_name(compartment, "c_net");
	// on reboots of c0 rejoin existing userns and netns
	if (compartment_uuid_is_c0id(compartment_get_uuid(compartment)) &&
	    compartment->prev_state == COMPARTMENT_STATE_REBOOTING) {
		if (c_user && c_user->module && c_user->module->join_ns) {
			IF_TRUE_GOTO((ret = c_user->module->join_ns(c_user->instance)) < 0, error);
		}
		if (c_net && c_net->module && c_net->module->join_ns) {
			IF_TRUE_GOTO((ret = c_net->module->join_ns(c_net->instance)) < 0, error);
		}
	} else {
		if (c_user && compartment_has_userns(compartment))
			args.flags |= CLONE_NEWUSER;
		if (c_net && compartment_has_netns(compartment))
			args.flags |= CLONE_NEWNET;
	}

	compartment->pid = clone3(&args, sizeof(struct clone_args));
	if (compartment->pid == 0) { // child
		int ret = compartment_start_child(compartment);
		_exit(ret);
	} else if (compartment->pid < 0) {
		ERROR_ERRNO("Double clone compartment failed");
		goto error;
	}

	char *msg_pid = mem_printf("%d", compartment->pid);
	if (write(compartment->sync_sock_child, msg_pid, strlen(msg_pid)) < 0) {
		ERROR_ERRNO("write pid '%s' to sync socket failed", msg_pid);
		goto error;
	}
	mem_free0(msg_pid);
	return 0;

error:
	if (ret == 0) {
		ret = COMPARTMENT_ERROR;
	}

	// send error message to parent
	char msg_error = COMPARTMENT_START_SYNC_MSG_ERROR;
	if (write(compartment->sync_sock_child, &msg_error, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}

	if (compartment_close_all_fds()) {
		WARN("Closing all file descriptors in compartment start error failed");
	}
	return ret; // exit the child process
}

static void
compartment_start_timeout_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);

	compartment_t *compartment = data;

	/* Only kill the compartment in case it is still in the booting state.
	 * If this is not the case then simply remove the timer and do nothing
	 * Note that we do NOT have a problem with repeated compartment starts
	 * and overlapping start timeouts since the start_timer is cleared in
	 * compartment_cleanup which is called by the SIGCHLD handler as soon
	 * as the compartment goes down. */
	if (compartment_get_state(compartment) == COMPARTMENT_STATE_BOOTING) {
		WARN("Reached compartment start timeout for compartment %s and the compartment is still booting."
		     " Killing it...",
		     compartment_get_description(compartment));
		/* kill compartment. SIGCHLD cb handles the cleanup and state change */
		compartment_kill(compartment);
	}

	DEBUG("Freeing compartment start timeout timer");
	event_timer_free(timer);
	compartment->start_timer = NULL;

	return;
}

void
compartment_kill_early_child(compartment_t *compartment)
{
	// killing process group of early child if running
	if (compartment->pid_early > 1) {
		kill(-(compartment->pid_early), SIGKILL);
	}
}

static void
compartment_start_post_clone_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);

	char msg;
	compartment_t *compartment = data;

	DEBUG("Received event from child process %u", events);

	if (events == EVENT_IO_EXCEPT) {
		WARN("Received exception from child process");
		msg = COMPARTMENT_START_SYNC_MSG_ERROR;
	} else {
		// receive success or error message from started child
		if (read(fd, &msg, 1) != 1) {
			WARN_ERRNO("Could not read from sync socket");
			event_remove_io(io);
			event_io_free(io);
			close(fd);
			return;
		}
	}

	DEBUG("Received message %d from child", msg);

	if (msg == COMPARTMENT_START_SYNC_MSG_ERROR) {
		WARN("Received error message from child process");
		return; // the child exits on its own and we cleanup in the sigchld handler
	}

	/********************************************************/
	/* on success call all c_<module>_start_pre_exec hooks */

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_pre_exec)
			continue;

		IF_TRUE_GOTO_WARN((module->start_pre_exec(c_mod->instance) < 0), error_pre_exec);
	}

	// skip setup of start timer and maintain SETUP state if in SETUP mode
	if (compartment_get_state(compartment) != COMPARTMENT_STATE_SETUP) {
		compartment_set_state(compartment, COMPARTMENT_STATE_BOOTING);

		/* register a timer to kill the compartment if it does not come up in time */
		compartment->start_timer = event_timer_new(
			COMPARTMENT_START_TIMEOUT, 1, &compartment_start_timeout_cb, compartment);
		event_add_timer(compartment->start_timer);
	}

	DEBUG("Freeing key of compartment %s", compartment_get_name(compartment));
	compartment_free_key(compartment);

	/* Notify child to do its exec */
	char msg_go = COMPARTMENT_START_SYNC_MSG_GO;
	if (write(fd, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error;
	}

	/* Call all c_<module>_start_post_exec hooks */

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_post_exec)
			continue;

		IF_TRUE_GOTO_WARN(module->start_post_exec(c_mod->instance) < 0, error);
	}

	// if no service module is registered diretcly switch to state running
	compartment_module_instance_t *c_service =
		compartment_module_get_mod_instance_by_name(compartment, "c_service");
	if (!c_service)
		compartment_set_state(compartment, COMPARTMENT_STATE_RUNNING);

	event_remove_io(io);
	event_io_free(io);
	close(fd);

	return;

error_pre_exec:
	DEBUG("A pre-exec compartment start error occured, stopping compartment");
	char msg_stop = COMPARTMENT_START_SYNC_MSG_STOP;
	if (write(fd, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error;
	}

	// kill running helper children
	for (list_t *l = compartment->helper_child_list; l; l = l->next) {
		compartment_helper_child_t *child = l->data;
		if (child->pid <= 1) {
			WARN("Helper child with pid=%d, in list, do not kill anything", child->pid);
			continue;
		}
		if (kill(child->pid, SIGKILL)) {
			TRACE_ERRNO("Could not send kill to helper %s (pid=%d).", child->name,
				    child->pid);
		}
	}

	event_remove_io(io);
	event_io_free(io);
	close(fd);
	return;
error:
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	compartment_kill(compartment);
}

static void
compartment_start_post_clone_early_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	int ret = 0;

	compartment_t *compartment = data;

	DEBUG("Received event from child process %u", events);

	if (events == EVENT_IO_EXCEPT) {
		ERROR("Received exception from child process");
		goto error_pre_clone;
	}

	// receive success or error message from started child
	char *pid_msg = mem_alloc0(34);
	if (read(compartment->sync_sock_parent, pid_msg, 33) <= 0) {
		WARN_ERRNO("Could not read from sync socket");
		mem_free0(pid_msg);
		goto error_pre_clone;
	}

	if (pid_msg[0] == COMPARTMENT_START_SYNC_MSG_ERROR) {
		WARN("Early child died with error!");
		mem_free0(pid_msg);
		goto error_pre_clone;
	}

	// release post_clone_early io handler
	event_remove_io(io);
	event_io_free(io);

	DEBUG("Received pid message from child %s", pid_msg);
	compartment->pid = atoi(pid_msg);
	mem_free0(pid_msg);

	/*********************************************************/
	/* REGISTER SOCKET TO RECEIVE STATUS MESSAGES FROM CHILD */
	event_io_t *sync_sock_parent_event =
		event_io_new(fd, EVENT_IO_READ, &compartment_start_post_clone_cb, compartment);
	event_add_io(sync_sock_parent_event);

	/* register SIGCHILD handler which sets the state and
	 * calls the appropriate cleanup functions if the child
	 * dies */
	event_signal_t *sig = event_signal_new(SIGCHLD, compartment_sigchld_cb, compartment);
	event_add_signal(sig);

	/*********************************************************/
	/* POST CLONE HOOKS */
	// execute all necessary c_<module>_start_post_clone hooks
	// goto error_post_clone on an error

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_post_clone)
			continue;

		if ((ret = module->start_post_clone(c_mod->instance)) < 0) {
			goto error_post_clone;
		}
	}

	/*********************************************************/
	/* NOTIFY CHILD TO START */
	char msg_go = COMPARTMENT_START_SYNC_MSG_GO;
	if (write(compartment->sync_sock_parent, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error_post_clone;
	}

	return;

error_pre_clone:
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	compartment_kill_early_child(compartment);
	return;

error_post_clone:
	if (ret == 0)
		ret = COMPARTMENT_ERROR;
	char msg_stop = COMPARTMENT_START_SYNC_MSG_STOP;
	if (write(compartment->sync_sock_parent, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		compartment_kill(compartment);
	}
	return;
}

int
compartment_start(compartment_t *compartment)
{
	ASSERT(compartment);

	int ret = 0;

	compartment_set_state(compartment, COMPARTMENT_STATE_STARTING);

	/*********************************************************/
	/* PRE CLONE HOOKS */

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_pre_clone)
			continue;

		if ((ret = module->start_pre_clone(c_mod->instance)) < 0) {
			goto error_pre_clone;
		}
	}

	/*********************************************************/
	/* PREPARE CLONE */

	struct clone_args args = { 0 };
	args.exit_signal = SIGCHLD;

	/* Create a socketpair for synchronization and save it in the compartment structure to be able to
	 * pass it around */
	int fd[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		WARN("Could not create socketpair for synchronization with child!");
		goto error_pre_clone;
	}
	compartment->sync_sock_parent = fd[0];
	compartment->sync_sock_child = fd[1];

	/*********************************************************/
	/* CLONE */

	// activate setup mode in perent and child
	if (compartment->setup_mode) {
		compartment_set_state(compartment, COMPARTMENT_STATE_SETUP);
		INFO("Container in setup mode!");
	}

	pid_t compartment_pid = clone3(&args, sizeof(struct clone_args));
	if (compartment_pid == 0) { // child
		int ret = compartment_start_child_early(compartment);
		_exit(ret);
	} else if (compartment_pid < 0) {
		WARN_ERRNO("Clone compartment failed");
		goto error_pre_clone;
	}
	compartment->pid_early = compartment_pid;

	/* close the childs end of the sync sockets */
	close(compartment->sync_sock_child);

	/*********************************************************/
	/* REGISTER SOCKET TO RECEIVE STATUS MESSAGES FROM CHILD */
	event_io_t *sync_sock_parent_event =
		event_io_new(compartment->sync_sock_parent, EVENT_IO_READ,
			     &compartment_start_post_clone_early_cb, compartment);
	event_add_io(sync_sock_parent_event);

	// handler for early start child process which dies after double fork
	event_signal_t *sig = event_signal_new(SIGCHLD, compartment_sigchld_early_cb, compartment);
	event_add_signal(sig);

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->start_post_clone_early)
			continue;

		if ((ret = module->start_post_clone_early(c_mod->instance)) < 0) {
			goto error_post_clone;
		}
	}

	return 0;

error_pre_clone:
	compartment_cleanup(compartment, false);
	compartment_set_state(compartment, COMPARTMENT_STATE_STOPPED);
	return ret;

error_post_clone:
	if (ret == 0)
		ret = COMPARTMENT_ERROR;
	char msg_stop = COMPARTMENT_START_SYNC_MSG_STOP;
	if (write(compartment->sync_sock_parent, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		compartment_kill(compartment);
	}
	return ret;
}

void
compartment_kill(compartment_t *compartment)
{
	ASSERT(compartment);

	if (compartment_get_state(compartment) == COMPARTMENT_STATE_STOPPED) {
		DEBUG("Trying to kill stopped compartment... doing nothing.");
		return;
	}

	// killing process group of early child if running
	compartment_kill_early_child(compartment);

	if (compartment_get_pid(compartment) < 0) {
		ERROR("No pid (%d) for container %s -> state mismatch, do not kill anything!",
		      compartment_get_pid(compartment), compartment_get_description(compartment));
		return;
	}

	// TODO kill compartment (possibly register callback and wait non-blocking)
	DEBUG("Killing compartment %s with pid: %d", compartment_get_description(compartment),
	      compartment_get_pid(compartment));

	if (kill(compartment_get_pid(compartment), SIGKILL)) {
		ERROR_ERRNO("Failed to kill compartment %s",
			    compartment_get_description(compartment));
	}
}

/* This callback determines the compartment's state and forces its shutdown,
 * when a compartment could not be stopped in time*/
static void
compartment_stop_timeout_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);

	compartment_t *compartment = data;
	DEBUG("Reached compartment stop timeout for compartment %s. Doing the kill now",
	      compartment_get_description(compartment));

	// kill compartment. sichld cb handles the cleanup and state change
	compartment_kill(compartment);

	event_timer_free(timer);
	compartment->stop_timer = NULL;

	return;
}

int
compartment_stop(compartment_t *compartment)
{
	ASSERT(compartment);

	int ret = 0;

	/* register timer with callback doing the kill, if stop fails */
	event_timer_t *compartment_stop_timer = event_timer_new(
		COMPARTMENT_STOP_TIMEOUT, 1, &compartment_stop_timeout_cb, compartment);
	event_add_timer(compartment_stop_timer);
	compartment->stop_timer = compartment_stop_timer;

	/* remove setup_mode for next run */
	if (compartment_get_state(compartment) == COMPARTMENT_STATE_SETUP)
		compartment_set_setup_mode(compartment, false);

	/* set state to shutting down (notifies observers) */
	compartment_set_state(compartment, COMPARTMENT_STATE_SHUTTING_DOWN);

	/* call stop hooks for c_* modules */
	DEBUG("Call stop hooks for modules");

	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->stop)
			continue;

		if (module->stop(c_mod->instance) < 0) {
			DEBUG("Module '%s' could not be stopped successfully", module->name);
			ret = -1;
		}
	}

	// When the stop command was emitted, the TrustmeService tries to shut down the compartment
	// i.g. to terminate the compartment's init process.
	// we need to wait for the SIGCHLD signal for which we have a callback registered, which
	// does the cleanup and sets the state of the compartment to stopped.
	if (ret == 0)
		DEBUG("Stop compartment successfully emitted. Wait for child process to terminate (SICHLD)");

	return ret;
}

int
compartment_bind_socket_before_start(compartment_t *compartment, const char *path)
{
	ASSERT(compartment);

	compartment_sock_t *cs = mem_new0(compartment_sock_t, 1);
	if ((cs->sockfd = sock_unix_create(SOCK_STREAM)) < 0) {
		mem_free0(cs);
		return -1;
	}
	cs->path = mem_strdup(path);
	compartment->csock_list = list_append(compartment->csock_list, cs);

	return cs->sockfd;
}

int
compartment_bind_socket_after_start(UNUSED compartment_t *compartment, UNUSED const char *path)
{
	//	int sock = compartment_bind_socket_before_start(compartment, socket_type, path);
	//	// TODO find out what works and implement me
	//	// EITHER:
	//	char *bind_path = mem_printf("/proc/%s/root/%s", atoi(compartment->pid), path);
	//	sock_unix_bind(sock, path_into_ns);
	//
	//	// OR:
	//	// create a socketpair for synchronization
	//	int fd[2];
	//    pid_t pid;
	//    socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	//    pid = fork();
	//	if (pid == -1) {
	//		WARN_ERRNO("Fork failed");
	//		return -1;
	//	}
	//    if (pid == 0) {
	//		// TODO synchronization
	//		/* executed in child */
	//        close(fd[0]);
	//		char *mnt_ns_path = mem_printf("/proc/%s/ns/mnt", atoi(compartment->pid));
	//		ns_fd = open(mnt_ns_path, O_RDONLY);
	//		setns(ns_fd, 0); // switch into mount namespace of compartment
	//		sock_unix_bind(sock, path);
	//		exit(0);
	//    } else {
	//		/* executed in parent */
	//        close(fd[1]);
	//    }
	return 0;
}

int
compartment_snapshot(compartment_t *compartment)
{
	ASSERT(compartment);
	// TODO implement
	return 0;
}

void
compartment_destroy(compartment_t *compartment)
{
	ASSERT(compartment);

	INFO("Destroying compartment %s with uuid=%s", compartment_get_name(compartment),
	     uuid_string(compartment_get_uuid(compartment)));

	/* call module hooks for destroy */
	for (list_t *l = compartment->module_instance_list; l; l = l->next) {
		compartment_module_instance_t *c_mod = l->data;
		compartment_module_t *module = c_mod->module;
		if (NULL == module->compartment_destroy)
			continue;

		module->compartment_destroy(c_mod->instance);
	}
}

static void
compartment_notify_observers(compartment_t *compartment)
{
	for (list_t *l = compartment->observer_list; l; l = l->next) {
		compartment_callback_t *ccb = l->data;
		ccb->todo = true;
	}
	// call all observer callbacks
	for (list_t *l = compartment->observer_list; l;) {
		compartment_callback_t *ccb = l->data;
		if (ccb->todo) {
			ccb->todo = false;
			(ccb->cb)(compartment, ccb, ccb->data);

			if (compartment->observer_list)
				l = compartment->observer_list;
			else
				break;
		} else {
			l = l->next;
		}
	}
}

void
compartment_set_state(compartment_t *compartment, compartment_state_t state)
{
	ASSERT(compartment);

	if (compartment->state == state)
		return;

	// maintaining SETUP state in following cases
	if (compartment->state == COMPARTMENT_STATE_SETUP) {
		switch (state) {
		case COMPARTMENT_STATE_BOOTING:
		case COMPARTMENT_STATE_RUNNING:
			return;
		default:
			break;
		}
	}

	// save previous state
	compartment->prev_state = compartment->state;

	DEBUG("Setting compartment state: %d", state);
	compartment->state = state;

	compartment_notify_observers(compartment);
}

compartment_state_t
compartment_get_state(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->state;
}

compartment_state_t
compartment_get_prev_state(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->prev_state;
}

uint64_t
compartment_get_flags(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->flags;
}

compartment_callback_t *
compartment_register_observer(compartment_t *compartment,
			      void (*cb)(compartment_t *, compartment_callback_t *, void *),
			      void *data)
{
	ASSERT(compartment);
	ASSERT(cb);

	compartment_callback_t *ccb = mem_new0(compartment_callback_t, 1);
	ccb->cb = cb;
	ccb->data = data;
	compartment->observer_list = list_prepend(compartment->observer_list, ccb);
	return ccb;
}

void
compartment_unregister_observer(compartment_t *compartment, compartment_callback_t *cb)
{
	ASSERT(compartment);
	ASSERT(cb);

	if (list_find(compartment->observer_list, cb)) {
		compartment->observer_list = list_remove(compartment->observer_list, cb);
		DEBUG("Container %s: callback %p unregistered (nr of observers: %d)",
		      compartment_get_description(compartment), CAST_FUNCPTR_VOIDPTR(cb),
		      list_length(compartment->observer_list));
		mem_free0(cb);
	}
}

const char *
compartment_get_key(const compartment_t *compartment)
{
	ASSERT(compartment);

	return compartment->key;
}

void
compartment_set_key(compartment_t *compartment, const char *key)
{
	ASSERT(compartment);
	ASSERT(key);

	if (compartment->key && !strcmp(compartment->key, key))
		return;

	compartment_free_key(compartment);

	compartment->key = strdup(key);

	compartment_notify_observers(compartment);
}

bool
compartment_has_netns(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->flags & COMPARTMENT_FLAG_NS_NET;
}

bool
compartment_has_userns(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->flags & COMPARTMENT_FLAG_NS_USER;
}

bool
compartment_has_ipcns(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->flags & COMPARTMENT_FLAG_NS_IPC;
}

void
compartment_set_setup_mode(compartment_t *compartment, bool setup)
{
	ASSERT(compartment);
	if (compartment->setup_mode == setup)
		return;

	compartment->setup_mode = setup;
}

bool
compartment_has_setup_mode(const compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->setup_mode;
}

void
compartment_set_debug_log_dir(compartment_t *compartment, const char *dir)
{
	ASSERT(compartment);
	compartment->debug_log_dir = mem_strdup(dir);
}

bool
compartment_contains_pid(const compartment_t *compartment, pid_t pid)
{
	ASSERT(compartment);

	/* Determine PID of compartment's init */
	pid_t init = compartment_get_pid(compartment);

	IF_TRUE_RETVAL_TRACE(init <= 0, false);

	// check if pidns of pid and the pidns of init are the same
	return ns_cmp_pidns_by_pid(init, pid);
}

int
compartment_get_sync_sock_parent(compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->sync_sock_parent;
}

int
compartment_get_sync_sock_child(compartment_t *compartment)
{
	ASSERT(compartment);
	return compartment->sync_sock_child;
}

void
compartment_wait_for_child(compartment_t *compartment, char *name, pid_t pid)
{
	ASSERT(compartment);

	compartment_helper_child_t *child = compartment_helper_child_new(name, pid);
	compartment->helper_child_list = list_append(compartment->helper_child_list, child);

	DEBUG("Helpers registered:");
	for (list_t *l = compartment->helper_child_list; l; l = l->next) {
		compartment_helper_child_t *child = l->data;
		DEBUG("\t Helper child '%s' (%d)", child->name, child->pid);
	}
}
