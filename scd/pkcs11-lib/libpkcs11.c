/*
 * Convenience pkcs11 library that can be linked into an application,
 * and will bind to a specific pkcs11 module.
 *
 * Copyright (C) 2002  Olaf Kirch <okir@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <dlfcn.h>

#include "libpkcs11.h"
#include "../common/macro.h"

#define MAGIC 0xd00bed00

struct sc_pkcs11_module {
	unsigned int _magic;
	void *handle;
};
typedef struct sc_pkcs11_module sc_pkcs11_module_t;

/*
 * Load a module - this will load the shared object, call
 * C_Initialize, and get the list of function pointers
 */
void *
C_LoadModule(const char *mspec, struct ck_function_list **funcs)
{
	sc_pkcs11_module_t *mod;
	ck_rv_t rv, (*c_get_function_list)(struct ck_function_list **);
	ck_rv_t (*c_get_interface)(unsigned char *, struct ck_version *, struct ck_interface **,
				   ck_flags_t);
	mod = calloc(1, sizeof(*mod));
	if (mod == NULL) {
		return NULL;
	}
	mod->_magic = MAGIC;

	if (mspec == NULL) {
		free(mod);
		return NULL;
	}
	mod->handle = dlopen(mspec, RTLD_LAZY);
	if (mod->handle == NULL) {
		fprintf(stderr, "dlopen failed: %s\n", dlerror());
		goto failed;
	}

	c_get_interface =
		CAST(ck_rv_t(*)(unsigned char *, struct ck_version *, struct ck_interface **,
				ck_flags_t)) dlsym(mod->handle, "C_GetInterface");
	if (c_get_interface) {
		struct ck_interface *interface = NULL;

		/* Get default PKCS #11 interface */
		rv = c_get_interface((unsigned char *)"PKCS 11", NULL, &interface, 0);
		if (rv == CKR_OK) {
			/* this is actually 3.0 function list, but it starts
			 * with the same fields. Only for new functions, it
			 * needs to be casted to new structure */
			*funcs = interface->function_list_ptr;
			return (void *)mod;
		} else {
			fprintf(stderr, "C_GetInterface failed %lx, retry 2.x way", rv);
		}
	}

	/* Get the list of function pointers */
	c_get_function_list = CAST(ck_rv_t(*)(struct ck_function_list **))
		dlsym(mod->handle, "C_GetFunctionList");
	if (!c_get_function_list)
		goto failed;
	rv = c_get_function_list(funcs);
	if (rv == CKR_OK)
		return (void *)mod;
	else {
		fprintf(stderr, "C_GetFunctionList failed %lx", rv);
		rv = C_UnloadModule((void *)mod);
		if (rv == CKR_OK)
			mod = NULL; /* already freed */
	}
failed:
	free(mod);
	return NULL;
}

/*
 * Unload a pkcs11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize
 */
ck_rv_t
C_UnloadModule(void *module)
{
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *)module;

	if (!mod || mod->_magic != MAGIC)
		return CKR_ARGUMENTS_BAD;

	if (mod->handle != NULL && dlclose(mod->handle) < 0)
		return CKR_FUNCTION_FAILED;

	free(mod);
	return CKR_OK;
}