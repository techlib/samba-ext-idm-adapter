/*
 * Copyright (C)  Jan Hamal Dvořák <mordae@anilinux.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ldb.h>
#include <ldb_module.h>
#include <ldb_errors.h>
#include <talloc.h>

#include <sys/types.h>
#include <string.h>
#include <error.h>
#include <errno.h>

#include "samba.h"

static int _ldb_init_done = 0;

struct ldb_context *samba_init(void *t, const char *url)
{
	if (!_ldb_init_done) {
		_ldb_init_done = 1;

		if (0 != ldb_global_init())
			error(1, errno, "LDB global initialization failed");
	}

	struct ldb_context *ldb = ldb_init(t, NULL);

	if (0 != ldb_modules_hook(ldb, LDB_MODULE_HOOK_CMDLINE_PRECONNECT))
		error(1, errno, "failed to run module preconnect hooks");

	if (0 != ldb_connect(ldb, url, 0, NULL))
		error(1, errno, "failed to open LDB");

	if (0 != ldb_modules_hook(ldb, LDB_MODULE_HOOK_CMDLINE_POSTCONNECT))
		error(1, errno, "failed to run module postconnect hooks");

	return ldb;
}

static const char *const attrs[] = {
	"cn",
	"unicodePwd",
	NULL
};

inline static const char *el_value(struct ldb_message_element *el)
{
	return (char *)(el->values[0].data);
}

int samba_list_users(struct ldb_context *ldb, void *t,
                     struct samba_user ***users,
                     const char *base, unsigned long cn)
{
	void *tt = talloc_new(NULL);
	struct ldb_result *res = NULL;
	struct ldb_dn *basedn;
	int r;
	size_t m, e;

	basedn = ldb_dn_new(t, ldb, base);

	if (cn > 0) {
		r = ldb_search(ldb, tt, &res, basedn, LDB_SCOPE_SUBTREE, attrs,
		               "(&(objectClass=user)(uidNumber=*)(cn=%lu))", cn);
	} else {
		r = ldb_search(ldb, tt, &res, basedn, LDB_SCOPE_SUBTREE, attrs,
		               "(objectClass=user)(uidNumber=*)");
	}

	if (0 != r)
		return -1;

	*users = talloc_zero_array(t, struct samba_user *, res->count + 1);

	for (m = 0; m < res->count; m++) {
		struct samba_user *user = talloc_zero(t, struct samba_user);
		struct ldb_message *msg = res->msgs[m];

		for (e = 0; e < msg->num_elements; e++) {
			struct ldb_message_element *el = msg->elements + e;

			if (0 == strcmp(el->name, "cn"))
				user->cn = atol(el_value(el));

			if (0 == strcmp(el->name, "unicodePwd")) {
				user->pwd = talloc(user, struct ldb_val);
				user->pwd->length = el->values[0].length;
				user->pwd->data = talloc_steal(user, el->values[0].data);
			}
		}

		(*users)[m] = user;
	}

	talloc_free(tt);
	return 0;
}

int samba_set_password(struct ldb_context *ldb,
                       const char *base, unsigned long cn,
                       struct ldb_val *pwd)
{
	struct ldb_message *msg = talloc_zero(NULL, struct ldb_message);

	msg->dn = ldb_dn_new_fmt(msg, ldb, "CN=%lu,%s", cn, base);
	msg->num_elements = 1;
	msg->elements = talloc_zero_array(msg, struct ldb_message_element,
	                                  msg->num_elements);

	msg->elements[0].flags = LDB_FLAG_MOD_REPLACE;
	msg->elements[0].name = talloc_strdup(msg, "unicodePwd");
	msg->elements[0].num_values = 1;
	msg->elements[0].values = talloc_steal(msg, pwd);

	int r = ldb_modify(ldb, msg);

	talloc_free(msg);
	return r;
}
