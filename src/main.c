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
#include <talloc.h>

#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#define DEFAULT_LDB "/var/lib/samba/private/sam.ldb"

/* Long command-line options. */
static const struct option longopts[] = {
	{"help",     0, 0, 'h'},
	{"version",  0, 0, 'V'},

	{"ldb-url",  1, 0, 'H'},
	{"basedn",   0, 0, 'b'},

	{"homedir",  1, 0, 'd'},
	{"linkdir",  1, 0, 'l'},

	{0, 0, 0, 0},
};

/* Short command-line options that should correspond to those above. */
static const char optstring[] = "hVH:b:d:l:";

/* LDB database file to operate on. */
static char *opt_ldb_url = NULL;

/* Base DN to update user accounts under. */
static char *opt_ldb_basedn = NULL;

/* Directory to maintain homes under. */
static char *opt_homedir = NULL;

/* Directory to maintain links to home directories under. */
static char *opt_linkdir = NULL;

static int do_version(int argc, char **argv)
{
	printf("samba-ext-idm-adapter %s\n", VERSION);
	return 0;
}

static int do_help(int argc, char **argv)
{
	puts("Usage: samba-ext-idm-adapter [ACTION] OPTION...");
	puts("Create home and change Samba password hash from env.");
	puts("");
	puts("ACTIONS:");
	puts("  --help, -h          Display this help.");
	puts("  --version, -V       Display version information.");
	puts("");
	puts("OPTIONS:");
	puts("  --ldb-url, -H URL   LDB database file to operate on.");
	puts("                      Can also be given as LDB_URL variable.");
	puts("                      Defaults to " DEFAULT_LDB ".");
	puts("  --basedn, -b DN     Base DN to update user accounts under.");
	puts("  --homedir, -d PATH  Directory to maintain home directories under.");
	puts("  --linkdir, -l PATH  Directory to maintain links to homes under.");
	puts("");
	puts("ENVIRONMENT:");
	puts("  LDB_URL             An alternative way to specify LDB file.");
	puts("  __NAME__            Both CN and uid of the user account.");
	puts("  __UID__             Used if the __NAME__ is not specified.");
	puts("  unicodePwd          Hex-encoded Samba password hash.");
	puts("  sAMAccountName      Login name of the user account.");
	puts("");
	puts("Report bugs to <http://github.org/techlib/samba-ext-idm-adapter>.");
	return 0;
}

static int do_apply(int argc, char **argv)
{
	fputs("Not yet implemented.\n", stderr);
	return 1;
}

int main(int argc, char **argv)
{
	int result, c, idx = 0;
	int (*action)(int argc, char **argv) = do_apply;
	void *t = talloc_init("samba-ext-idm-adapter");

	while (-1 != (c = getopt_long(argc, argv, optstring, longopts, &idx)))
		switch (c) {
			case 'h':
				action = do_help;
				break;

			case 'V':
				action = do_version;
				break;

			case 'H':
				if (opt_ldb_url)
					talloc_free(opt_ldb_url);

				opt_ldb_url = talloc_strdup(t, optarg);
				break;

			case 'b':
				if (opt_ldb_basedn)
					talloc_free(opt_ldb_basedn);

				opt_ldb_basedn = talloc_strdup(t, optarg);
				break;

			case 'd':
				if (opt_homedir)
					talloc_free(opt_homedir);

				opt_homedir = talloc_strdup(t, optarg);
				break;

			case 'l':
				if (opt_linkdir)
					talloc_free(opt_linkdir);

				opt_linkdir = talloc_strdup(t, optarg);
				break;
		}

	if (NULL == opt_ldb_url)
		opt_ldb_url = talloc_strdup(t, DEFAULT_LDB);

	result = action(argc - optind, argv + optind);

	talloc_free(t);
	return result;
}
