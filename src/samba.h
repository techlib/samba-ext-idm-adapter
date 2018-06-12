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

#ifndef _SAMBA_H
#define _SAMBA_H 1

#include <ldb.h>


/**
 * User search result structure.
 */
struct samba_user {
	unsigned long   cn;
	char           *name;
	struct ldb_val *pwd;
};


/**
 * Initialize LDB context.
 *
 * \param t       talloc memory context
 * \param url     a LDB file url
 *
 * \returns the LDB context
 */
struct ldb_context *samba_init(void *t, const char *url);


/**
 * Find samba users with given cn (all if cn=0).
 *
 * \param ldb     a LDB context
 * \param t       talloc memory context
 * \param base    base DN of the users subtree
 * \param users   pointer to an array of users to be allocated under the t
 * \param cn      user identifier to filter by (or 0 for all)
 *
 * \returns 0 on success, -1 on failure
 */
int samba_list_users(struct ldb_context *ldb, void *t,
                     struct samba_user ***users,
                     const char *base, unsigned long cn);


/**
 * Change password of users with given cn (that must be > 0).
 *
 * \param ldb     a LDB context
 * \param base    base DN of the users subtree
 * \param cn      user identifier to filter by
 * \param pwd     new password value
 *
 * \returns 0 on success, -1 on failure
 */
int samba_set_password(struct ldb_context *ldb,
                       const char *base, unsigned long cn,
                       struct ldb_val *pwd);


#endif				/* !_SAMBA_H */
