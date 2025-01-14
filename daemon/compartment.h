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

/**
 * @file compartment.h
 *
 * The compartment module represents a single compartment and offers an interface for managing it,
 * e.g. starting and stopping, suspending and resuming, etc.
 * Container instances can be created using a low-level constructor with all
 * specific parameters.
 * It furthermore provides the possibility to register observer functions as callbacks
 * which are called when the compartment's state changes. Compartment sub-modules
 * are called at certain key events during the execution of a compartment.
 */

#ifndef COMPARTMENT_H
#define COMPARTMENT_H

#include "common/uuid.h"
#include "common/list.h"

#include <sys/types.h>
#include <stdint.h>
#include <errno.h>

/**
 * Opaque compartment type.
 * (only used as pointer outside of the compartment module)
 */
typedef struct compartment compartment_t;

/**
 * Opaque compartment observer callback type.
 * (only used as pointer outside of the compartment module)
 */
typedef struct compartment_callback compartment_callback_t;

/**
 * Opaque compartment extension type.
 * (only used as pointer outside of the compartment module)
 */
typedef struct compartment_extension compartment_extension_t;

/**
 * FLAGS for configuring a compartment
 */
#define COMPARTMENT_FLAG_TYPE_CONTAINER 0x0000000000000001
#define COMPARTMENT_FLAG_TYPE_KVM 0x0000000000000002
#define COMPARTMENT_FLAG_NS_USER 0x0000000000000004
#define COMPARTMENT_FLAG_NS_NET 0x0000000000000008
#define COMPARTMENT_FLAG_NS_IPC 0x0000000000000010
#define COMPARTMENT_FLAG_SYSTEM_TIME 0x0000000000000020
#define COMPARTMENT_FLAG_MODULE_LOAD 0x0000000000000040
#define COMPARTMENT_FLAG_XORG_COMPAT 0x0000000000000080

/**
 * Represents the current compartment state.
 */
typedef enum {
	COMPARTMENT_STATE_STOPPED = 1,
	COMPARTMENT_STATE_STARTING,
	COMPARTMENT_STATE_BOOTING,
	COMPARTMENT_STATE_RUNNING,
	COMPARTMENT_STATE_FREEZING,
	COMPARTMENT_STATE_FROZEN,
	COMPARTMENT_STATE_ZOMBIE,
	COMPARTMENT_STATE_SHUTTING_DOWN,
	COMPARTMENT_STATE_SETUP,
	COMPARTMENT_STATE_REBOOTING
} compartment_state_t;

/**
 * Represents an error that happened during the start of a compartment.
 */
enum compartment_error {
	COMPARTMENT_ERROR = 1,
	COMPARTMENT_ERROR_VOL,
	COMPARTMENT_ERROR_INPUT,
	COMPARTMENT_ERROR_UEVENT,
	COMPARTMENT_ERROR_CGROUPS,
	COMPARTMENT_ERROR_NET,
	COMPARTMENT_ERROR_SERVICE,
	COMPARTMENT_ERROR_DEVNS,
	COMPARTMENT_ERROR_USER,
	COMPARTMENT_ERROR_FIFO,
	COMPARTMENT_ERROR_TIME,
	COMPARTMENT_ERROR_AUDIT,
	COMPARTMENT_ERROR_SMARTCARD
};

typedef struct compartment_module {
	const char *name;
	void *(*compartment_new)(compartment_t *compartment);
	void (*compartment_free)(void *data);
	void (*compartment_destroy)(void *data);
	int (*start_post_clone_early)(void *data);
	int (*start_child_early)(void *data);
	int (*start_pre_clone)(void *data);
	int (*start_post_clone)(void *data);
	int (*start_pre_exec)(void *data);
	int (*start_post_exec)(void *data);
	int (*start_child)(void *data);
	int (*start_pre_exec_child_early)(void *data);
	int (*start_pre_exec_child)(void *data);
	int (*stop)(void *data);
	void (*cleanup)(void *data, bool rebooting);
	int (*join_ns)(void *data);
	int flags;
} compartment_module_t;

/* If COMPARTMENT_MODULE_F_CLEANUP_LATE is used, the call to
 * module cleanup() is postponed to after all modules without
 * that flag. Remember if more than one module has this flag set,
 * the order in which the modules are registered also applies to
 * the late cleanup.
 */
#define COMPARTMENT_MODULE_F_CLEANUP_LATE (1U << 0)

void
compartment_register_module(compartment_module_t *mod);

void *
compartment_module_get_instance_by_name(const compartment_t *compartment, const char *mod_name);

/**
 * Low-level constructor that creates a new compartment instance
 * with the given parameters.
 *
 * TODO: Document parameters.
 * @return The new compartment instance.
 */
compartment_t *
compartment_new(const uuid_t *uuid, const char *name, uint64_t flags, const char *init,
		char **init_argv, char **init_env, size_t init_env_len,
		const compartment_extension_t *extension);

/**
 * Creates a new compartment_extension object,
 * which gets an callback to set internal compartment pointer inside an extension, e.g.,
 * a wrapping container object.
 */
compartment_extension_t *
compartment_extension_new(void (*set_compartment)(void *extension_data, compartment_t *compartment),
			  void *extension_data);

/**
 * Free a compartment_extension data structure.
 */
void
compartment_extension_free(compartment_extension_t *extension);

/**
 * Returns pointer to extension_data, e.g. usfull to store the pointer of a wrapping
 * container object which can be used for submodule implementations
 */
void *
compartment_get_extension_data(const compartment_t *compartment);

/**
 * Free the compartment's key
*/
void
compartment_free_key(compartment_t *compartment);

/**
 * Free a compartment data structure.
 */
void
compartment_free(compartment_t *compartment);

/**
 * Returns the name of the compartment.
 */
const char *
compartment_get_name(const compartment_t *compartment);

/**
 * Returns the uuid of the compartment.
 */
const uuid_t *
compartment_get_uuid(const compartment_t *compartment);

/**
 * Returns a string describing the compartment.
 */
const char *
compartment_get_description(const compartment_t *compartment);

/**
 * Gets the PID of the compartment's init process.
 */
pid_t
compartment_get_pid(const compartment_t *compartment);

/**
 * Returns the PID of the compartment's trustme service process
 * or -1 if the PID could not be determined.
 */
pid_t
compartment_get_service_pid(const compartment_t *compartment);

/*
 * Prevents Android's low memory killer (OOM killer) from
 * killing the trustme service running in this compartment.
 */
void
compartment_oom_protect_service(const compartment_t *compartment);

/**
 * Gets the last exit_status of the compartment's init process.
 * Only valid if the compartment is stopped...
 */
int
compartment_get_exit_status(const compartment_t *compartment);

/**
 * Call destroy hooks of modules in case a compartment should persistently be removed from disk
 * This does not free the compartment object, this must be done
 * seperately by the module that called compartment_new in the first place.
 *
 * @param compartment The compartment to be destroyed.
 */
void
compartment_destroy(compartment_t *compartment);

/**
 * Get the information if the compartment should be privileged. This affects how the compartment
 * is handled by the trustme-lsm and which capabilities are dropped.
 */
bool
compartment_is_privileged(const compartment_t *compartment);

/**
 * Suspends the compartment before moving it into background
 */
int
compartment_suspend(compartment_t *compartment);

/**
 * Resumes the compartment.
 */
int
compartment_resume(compartment_t *compartment);

/**
 * Start the given compartment using the given key to decrypt its filesystem
 * image(s).
 * This is the main function which sets up isolation mechnsims as part of
 * TSF.CML.Isolation
 *
 * @param compartment The compartment to be started.
 * @param key The key used for filesystem image decryption. Can be NULL.
 * @return 0 if the compartment start was successful. An negative integer to
 * indicate an error. The error is a negative compartment_error (e.g. COMPARTMENT_ERROR_VOL).
 * Note that the return value only gives information regarding the first
 * stage of the compartment start, i.e. before the child process begins with
 * its initialization. For information if the start was completely successful,
 * one should register a callback on the compartment state and check if the
 * compartment passes over to the state CONTAINER_STATE_BOOTING, which means
 * that all initialization done in the compartment module were successful and
 * the boot is now up to the guest OS.
 */
int
compartment_start(compartment_t *compartment); //, const char *key);

/**
 * Gracefully terminate the execution of a compartment. Gives the compartment the
 * chance to do a normal shutdown. May take some time to complete and sets the
 * compartment state to CONTAINER_STATE_SHUTTING_DOWN. Should be used in combination
 * with registering a callback on compartment state changes.
 */
int
compartment_stop(compartment_t *compartment);

/**
 * Forcefully terminate the execution of a compartment.
 */
void
compartment_kill(compartment_t *compartment);

/**
 * Register a unix socket which is bound into the compartment at the given path during
 * compartment start. The function **must** be called before starting the compartment
 * and the returned socket is guaranteed to be bound after the compartment is
 * started, i.e. listen/accept can be called on it.
 *
 *            \-._,, /"/
 *             "-/  l-'
 *               \  /\_
 *               | /\  \
 *              (_/  \  %----.__
 *                    \/ ___    \
 *                  ,'  /   '-.__|_
 *                  |   \'-.___    \
 *                   \__ '/   _/\_  '-.
 *                      \/   /-.  \_   \
 *                      /   |   \_  \   |
 *                     /   / \_   '-'   /
 *                    |    |   '-.___,-'
 *                  ,-'     \
 *                 /         "-._
 *                 |             '-._
 *                  \                \
 *                  | \               |-.
 *                  \  | /'-._,-|    /   \
 *                   | \ |      \    |    $
 *                   \ | /       |  /
 *                    | /         \ |
 *                    |/           |/
 *
 * @param compartment The compartment in which the socket will be bound.
 * @param path The path to which the socket will be bound inside the compartment.
 * @return On success, the newly created socket which will be bound into the
 * compartment during compartment start and which will be available to listen/accept
 * after that start. On error, -1 is returned.
 */
int
compartment_bind_socket_before_start(compartment_t *compartment, const char *path);

/**
 * Bind a unix socket into the **already started** compartment at the given path. The
 * function **must** be called **after** starting the compartment and the returned
 * socket is guaranteed to be bound when the function returns, i.e. listen/accept
 * can be called on it.
 *
 * @param compartment The compartment in which the socket is bound.
 * @param path The path to which the socket is bound inside the compartment.
 * @return The newly created and bound into the compartment socket which is immediately
 * ready to call listen+accept on.
 */
int
compartment_bind_socket_after_start(compartment_t *compartment, const char *path);

/**
 * TODO Document 'snapshot' function.
 */
int
compartment_snapshot(compartment_t *compartment);

/**
 * Update the state of the compartment and notify observers.
 *
 * @param compartment The compartment object.
 * @param state The updated state to set.
 */
void
compartment_set_state(compartment_t *compartment, compartment_state_t state);

/**
 * Returns the current state of the compartment.
 */
compartment_state_t
compartment_get_state(const compartment_t *compartment);

/**
 * Returns the previous state of the compartment.
 */
compartment_state_t
compartment_get_prev_state(const compartment_t *compartment);

/**
 * Returns the the flags of the compartment.
 */
uint64_t
compartment_get_flags(const compartment_t *compartment);

/**
 * Register a callback function which is always called when the compartment's
 * state changes.
 */
compartment_callback_t *
compartment_register_observer(compartment_t *compartment,
			      void (*cb)(compartment_t *, compartment_callback_t *, void *),
			      void *data);

/**
 * Unregister observer callback.
 */
void
compartment_unregister_observer(compartment_t *compartment, compartment_callback_t *cb);

/**
 * Set observer finishiner callback.
 */
void
compartment_finish_observers(compartment_t *compartment, void (*cb)(void *), void *data);

/**
 * Gets the compartment's key previously set by compartment_set_key or NULL if no key
 * has been set.
 */
const char *
compartment_get_key(const compartment_t *compartment);

/**
 * Sets the key for encrypted storage of the contaier.
 */
void
compartment_set_key(compartment_t *compartment, const char *key);

void
compartment_init_env_prepend(compartment_t *compartment, char **init_env, size_t init_env_len);

bool
compartment_has_netns(const compartment_t *compartment);

bool
compartment_has_userns(const compartment_t *compartment);

bool
compartment_has_ipcns(const compartment_t *compartment);

void
compartment_set_setup_mode(compartment_t *compartment, bool setup);

bool
compartment_has_setup_mode(const compartment_t *compartment);

bool
compartment_get_sync_state(const compartment_t *compartment);

void
compartment_set_sync_state(compartment_t *compartment, bool state);

/**
 * Checks if the compartments uuid is the all zero uuid which
 * is assigned to c0.
 *
 * This function can be used to check if the compartment is c0
 * even if the compartment is not yet fulle created.
 */
bool
compartment_uuid_is_c0id(const uuid_t *uuid);

/**
 * Set directory for log output of compartment
 *
 * This function set a directory where a logfile for the stdout of the
 * child process of the compartment is logged. (only effective for
 * compartments with COMPARTMENT_FLAG_TYPE_KVM)
 */
void
compartment_set_debug_log_dir(compartment_t *compartment, const char *dir);

/**
 * Check if a specific pid is part of the compartment
 *
 * This function checks if a pid is contained in this compartment.
 * This is done by comparing the pidns references of the compartment's
 * init and the pidns reference of the provided pid.
 */
bool
compartment_contains_pid(const compartment_t *compartment, pid_t pid);

/**
 * Checks if a given compartment is stoppable
 */
bool
compartment_is_stoppable(compartment_t *compartment);

/**
 * Checks if a given compartment is startable
 */
bool
compartment_is_startable(compartment_t *compartment);

int
compartment_get_sync_sock_parent(compartment_t *compartment);

int
compartment_get_sync_sock_child(compartment_t *compartment);

bool
compartment_get_allow_system_time(compartment_t *compartment);

/**
 * Registers child at compartments sigchld handler
 *
 * If spawning any helper process during startup of a compartment, use
 * this function to assure that the spawned helper is reaped properly.
 * Caution: Do do not spawn helper children in early child hooks. This
 * function does not propagate the child correctly to the main process.
 */
void
compartment_wait_for_child(compartment_t *compartment, char *name, pid_t pid);

#endif /* COMPARTMENT_H */
