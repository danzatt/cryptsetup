/*
 * cli tokens plugins helpers
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef USE_EXTERNAL_CLI_TOKENS
#include <assert.h>
#include <dlfcn.h>
#endif

#include "cryptsetup.h"

#ifdef USE_EXTERNAL_CLI_TOKENS
static int tools_plugin_load_symbol(const char *symbol, void *handle, bool quiet, void **ret_symbol)
{
	char *error;
	void *sym = dlsym(handle, symbol);

	error = dlerror();
	if (error) {
		if (!quiet)
			log_err(_("Failed to load mandatory plugin symbol %s (%s)."), symbol, error);
		return -EINVAL;
	}

	*ret_symbol = sym;

	return 0;
}

static void tools_plugin_load_optional_symbol(const char *symbol, void *handle, void **ret_symbol)
{
	char *error;
	void *sym = dlsym(handle, symbol);

	error = dlerror();
	if (error) {
		log_dbg("Failed to load optional plugin symbol %s (%s).", symbol, error);
		return;
	}

	*ret_symbol = sym;
}

static int dlopen_plugin(const char *type, struct tools_token_handler *th, bool quiet)
{
	char plugin[64];
	void *h;
	int r = snprintf(plugin, sizeof(plugin), "libcryptsetup-token-%s.so", type);

	log_dbg("Loading plugin %s.", plugin);

	if (r < 0 || (size_t)r >= sizeof(plugin))
		return -EINVAL;

	r = -EINVAL;
	h = dlopen(plugin, RTLD_LAZY);
	if (!h) {
		if (!quiet)
			log_err("Failed to load cryptsetup plugin: %s.", dlerror());
		return r;
	}
	dlerror();

	r = tools_plugin_load_symbol("crypt_token_handle_init", h, quiet, (void **)&th->init);
	if (r)
		goto out;

	r = tools_plugin_load_symbol("crypt_token_handle_free", h, quiet, (void **)&th->free);
	if (r)
		goto out;

	r = tools_plugin_load_symbol("crypt_token_params", h, quiet, (void **)&th->params);
	if (r)
		goto out;

	tools_plugin_load_optional_symbol("crypt_token_validate_create_params", h, (void **)&th->validate_create_params);

	tools_plugin_load_optional_symbol("crypt_token_create", h, (void **)&th->create);

	tools_plugin_load_optional_symbol("crypt_token_validate_remove_params", h, (void **)&th->validate_remove_params);

	tools_plugin_load_optional_symbol("crypt_token_remove", h, (void **)&th->remove);

	th->loaded = true;
	th->dlhandle = h;
	r = 0;
out:
	if (r)
		dlclose(h);
	return r;
}

static int plugin_add_options(struct tools_token_handler *thandle,
		struct tools_arg *core_args,
		size_t core_args_len,
		struct poptOption *popt_basic_options,
		void *plugin_cb)

{
	const crypt_token_arg_item *item;
	int j;
	size_t cc = 0, pc = 0;
	const struct poptOption tend = POPT_TABLEEND;
	struct tools_arg *arg = NULL;
	struct poptOption *tmp = NULL;

	//tool_ctx.plugin_args.name = thandle->type;

	if (!thandle->args_count)
		return 0;

	assert(thandle->args_count >= thandle->private_args_count);

	/* poptOption table has 2 extra rows (callback helper row and table end row) */
	if (thandle->args_count < SIZE_MAX / sizeof(*tmp) - 2)
		tmp = calloc(thandle->args_count + 2, sizeof(*tmp));

	if (!tmp)
		return -ENOMEM;

	/* allocate structures for plugin private arguments */
	if (thandle->private_args_count) {
		if (thandle->private_args_count < SIZE_MAX / sizeof(*arg))
			arg = calloc(thandle->private_args_count, sizeof(*arg));

		if (!arg) {
			free(tmp);
			return -ENOMEM;
		}
	}

	item = thandle->params();

	tmp[0].shortName = '\0';
	tmp[0].argInfo = POPT_ARG_CALLBACK;
	tmp[0].arg = plugin_cb;
	tmp[0].descrip = (const char *)thandle;

	while (item && (cc + pc < thandle->args_count)) {
		if (strncmp(item->name, "plugin-", 7)) {
			assert(thandle->private_args_count+cc < thandle->args_count);
			/* just link core utility argument for poptHelp() output in plugins section */
			j = tools_find_arg_id_in_args(item->name, core_args, core_args_len);
			if (j > 0) {
				tmp[thandle->private_args_count+cc+1] = popt_basic_options[j];
				cc++;
			}
			item = item->next;
			continue;
		}

		assert(pc < thandle->private_args_count);

		tmp[pc+1].longName = item->name;
		arg[pc].name = item->name + strlen(thandle->type) + 8; // plugin-<type>-<name>
		arg[pc].type = item->arg_type;
		switch (item->arg_type) {
		case CRYPT_ARG_BOOL:
			tmp[pc+1].argInfo = POPT_ARG_NONE;
			break;
		case CRYPT_ARG_STRING:
		case CRYPT_ARG_INT32:
		case CRYPT_ARG_UINT32:
		case CRYPT_ARG_INT64:
		case CRYPT_ARG_UINT64:
			tmp[pc+1].argInfo = POPT_ARG_STRING;
			break;
		}
		tmp[pc+1].descrip = item->desc;
		pc++;
		item = item->next;
	}

	tmp[thandle->args_count + 1] = tend;

	thandle->popt_plugin = tmp;
	thandle->args_plugin = arg;

	/*
	tool_ctx.plugin_args.name = thandle->type;
	tool_ctx.plugin_args.args = arg;
	tool_ctx.plugin_args.count = thandle->private_args_count;
	*/

	return 0;
}

static int plugin_validate_args(struct tools_token_handler *thandle,
		struct tools_arg *core_args,
		size_t core_args_len)
{
	size_t n;
	const crypt_token_arg_item *item = thandle->params();

	while (item) {
		if (!item->name || item->arg_type > CRYPT_ARG_UINT64)
			return -EINVAL;
		log_dbg("Validating plugin parameter %s (type %d).", item->name, item->arg_type);
		if (!strncmp(item->name, "plugin-", 7)) {
			/* plugin specific argument must be prefixed with "plugin-<type>-" */
			n = strlen(thandle->type);
			if (strncmp(item->name + 7, thandle->type, n)) {
				log_dbg("Invalid argument %s name (expected: plugin-%s-<name>).", item->name, thandle->type);
				return -EINVAL;
			}
			if ((*(item->name + n + 7) != '-') || !*(item->name + n + 8)) {
				log_dbg("Invalid argument %s name (expected: plugin-%s-<name>).", item->name, thandle->type);
				return -EINVAL;
			}
			thandle->private_args_count++;
		} else {
			if (tools_find_arg_id_in_args(item->name, core_args, core_args_len) < 0) {
				log_dbg("Plugin requests access to undefined core argument %s.", item->name);
				return -EINVAL;
			}
		}

		thandle->args_count++;
		item = item->next;
	}

	return 0;
}

int tools_plugin_load(const char *type,
		struct poptOption *plugin_options,
		struct tools_token_handler *token_handler,
		struct tools_arg *core_args,
		size_t core_args_len,
		struct poptOption *popt_core_options,
		void *plugin_cb,
		bool quiet)
{
	int r;

	r = dlopen_plugin(type, token_handler, quiet);
	if (r)
		return r;

	r = plugin_validate_args(token_handler, core_args, core_args_len);
	if (r && !quiet)
		log_err(_("Plugin %s has invalid parameters."), type);

	if (!r)
		r = plugin_add_options(token_handler, core_args, core_args_len, popt_core_options, plugin_cb);

	if (r)
		tools_plugin_unload(token_handler);
	else {
		plugin_options->longName = NULL;
		plugin_options->shortName = '\0';
		plugin_options->argInfo = POPT_ARG_INCLUDE_TABLE;
		plugin_options->arg = token_handler->popt_plugin;
		plugin_options->val = 0;
		plugin_options->descrip = N_("Plugins options:");
		plugin_options->argDescrip = NULL;
	}

	return r;
}

void tools_plugin_unload(struct tools_token_handler *th)
{
	if (!th || !th->type)
		return;

	if (th->loaded)
		dlclose(th->dlhandle);
	free(CONST_CAST(void *)th->type);
	free(th->popt_plugin);
	free(th->args_plugin);
	memset(th, 0, sizeof(*th));
}
#else
int tools_plugin_load(const char *type,
		struct poptOption *plugin_options,
		struct tools_token_handler *token_handler,
		struct tools_arg *core_args,
		size_t core_args_len,
		struct poptOption *popt_core_options,
		void *plugin_cb,
		bool quiet)
{
	return -ENOTSUP;
}

void tools_plugin_unload(struct tools_token_handler *th)
{
}
#endif //USE_EXTERNAL_CLI_TOKENS
