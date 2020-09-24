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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <attr/xattr.h>
#include <attr/attributes.h>

#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "samba.h"

/* Long command-line options. */
static const struct option longopts[] = {
	{"help",     0, 0, 'h'},
	{"version",  0, 0, 'V'},
	{"update",   0, 0, 'u'},
	{"list",     0, 0, 'l'},
	{"delete",   0, 0, 'd'},

	{"ldb-url",  1, 0, 'H'},
	{"basedn",   1, 0, 'b'},

	{"homedir",  1, 0, 'D'},
	{"setup",    1, 0, 's'},
	{"linkdir",  1, 0, 'L'},
	{"trashdir", 1, 0, 'T'},
	{"group",    1, 0, 'G'},

	{0, 0, 0, 0},
};

/* Short command-line options that should correspond to those above. */
static const char optstring[] = "hVuldvH:b:D:L:T:G:s:";

/* LDB database file to operate on. */
static char *opt_ldb_url = NULL;

/* Base DN to update user accounts under. */
static char *opt_basedn = NULL;

/* Directory to maintain homes under. */
static char *opt_homedir = NULL;

/* Command to set up the home. */
static char *opt_setup = NULL;

/* Directory to move deleted homes under. */
static char *opt_trashdir = NULL;

/* Directory to maintain links to home directories under. */
static char *opt_linkdir = NULL;

/* Environment variables with user information. */
unsigned long uid = 0;
unsigned long gid = 100;
const char *password = NULL;
const char *username = NULL;

static void load_env(int require_uid)
{
	const char *env_UID = getenv("__UID__");
	const char *env_NAME = getenv("__NAME__");
	const char *env_unicodePwd = getenv("unicodePwd");
	const char *env_sAMAccountName = getenv("sAMAccountName");

	if (env_UID && 0 == strlen(env_UID))
		error(1, 0, "__UID__ specified, but empty.");

	if (env_NAME && 0 == strlen(env_NAME))
		error(1, 0, "__NAME__ specified, but empty.");

	if (env_UID)
		uid = atol(env_UID);
	else if (env_NAME)
		uid = atol(env_NAME);
	else if (require_uid)
		error(1, 0, "Neither __NAME__ nor __UID__ variable set.");

	if (require_uid && 0 == uid)
		error(1, 0, "Non-positive user identifier specified.");

	if (env_unicodePwd && 0 == strlen(env_unicodePwd))
		error(1, 0, "unicodePwd specified, but empty.");

	password = env_unicodePwd;

	if (env_sAMAccountName && 0 == strlen(env_sAMAccountName))
		error(1, 0, "sAMAccountName specified, but empty.");

	username = env_sAMAccountName;
}

static int do_version(void *t, int argc, char **argv)
{
	printf("samba-ext-idm-adapter %s\n", VERSION);
	return 0;
}

static int do_help(void *t, int argc, char **argv)
{
	puts("Usage: samba-ext-idm-adapter [ACTION] OPTION...");
	puts("Create home and change Samba password hash from env.");
	puts("");
	puts("ACTIONS:");
	puts("  --help, -h          Display this help.");
	puts("  --version, -V       Display version information.");
	puts("  --update, -u        Apply changes.");
	puts("  --list, -l          List known users.");
	puts("  --delete, -d        Delete the homedir.");
	puts("");
	puts("OPTIONS:");
	puts("  --ldb-url, -H URL   LDB database file to operate on.");
	puts("                      Can also be given as LDB_URL variable.");
	puts("  --basedn, -b DN     Base DN to update user accounts under.");
	puts("  --homedir, -D PATH  Directory to maintain home directories under.");
	puts("  --linkdir, -L PATH  Directory to maintain links to homes under.");
	puts("  --trashdir, -T PATH Directory to move deleted homes under.");
	puts("  --group, -G GID     Numeric group identifier for homes.");
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

static void mark(const char *path, const char *name, const char *value)
{
	char fullname[PATH_MAX] = "user.";

	strcat(fullname, name);

	if (0 != setxattr(path, fullname, value, strlen(value), 0))
		error(1, errno, "%s: %s=%s", path, fullname, value);
}

static void unmark(const char *path, const char *name)
{
	char fullname[PATH_MAX] = "user.";

	strcat(fullname, name);

	if (0 != removexattr(path, fullname)) {
		if (errno != ENOATTR)
			error(1, errno, "%s (remove %s)", path, fullname);
	}
}

static int checkmark(const char *path, const char *name)
{
	char fullname[PATH_MAX] = "user.";

	strcat(fullname, name);

	return getxattr(path, fullname, NULL, 0) >= 0;
}

static char *getmark(void *t, const char *path, const char *name)
{
	char *value = NULL;
	char fullname[PATH_MAX] = "user.";

	strcat(fullname, name);

	ssize_t size = getxattr(path, fullname, NULL, 0);

	if (size >= 0)
		value = talloc_zero_array(t, char, size + 1);

	if (-1 == getxattr(path, fullname, value, size))
		error(1, errno, "%s (get %s)", path, fullname);

	return value;
}

static int touch(const char *path)
{
	struct timeval tv[2];
	struct stat st;

	if (0 != stat(path, &st))
		return -1;

	TIMESPEC_TO_TIMEVAL(&tv[0], &st.st_atim);
	TIMESPEC_TO_TIMEVAL(&tv[1], &st.st_mtim);

	if (0 != gettimeofday(&tv[1], NULL))
		return -1;

	if (0 != utimes(path, tv))
		return -1;

	return 0;
}

static void make_home(void *t)
{
	char *path = talloc_asprintf(t, "%s/%lu", opt_homedir, uid);

	if (0 != mkdir(path, 0700)) {
		if (errno != EEXIST)
			error(1, errno, "%s", path);
	}

	if (0 != chown(path, uid, gid))
		error(0, errno, "%s (chown %lu:%lu)", path, uid, gid);

	if (opt_setup) {
		pid_t pid;
		char *uidstr = talloc_asprintf(t, "%lu", uid);
		char *argv[] = {opt_setup, uidstr, path, NULL};

		int r = posix_spawn(&pid, opt_setup, NULL, NULL, argv, environ);

		if (-1 == r)
			error(1, errno, "%s", opt_setup);

		return;
	}
}

static void trash_home(void *t)
{
	char *path = talloc_asprintf(t, "%s/%lu", opt_homedir, uid);
	char *dest = NULL;
	int i;

	if (0 != access(path, F_OK)) {
		if (ENOENT != errno)
			error(1, errno, "%s", path);

		return;
	}

	for (i = 0; /**/; i++) {
		if (dest)
			talloc_free(dest);

		dest = talloc_asprintf(t, "%s/%lu.%i", opt_trashdir, uid, i);

		if (0 != rename(path, dest)) {
			if (EEXIST == errno)
				continue;

			error(1, errno, "%s -> %s", path, dest);
		}

		if (0 != touch(dest))
			error(0, errno, "%s (touch)", dest);

		break;
	}
}

static void update_link(void *t, int del)
{
	char *home = talloc_asprintf(t, "%s/%lu", opt_homedir, uid);

	/* Remove the old link. */
	if ((del || username) && checkmark(home, "name")) {
		char *oldname = getmark(t, home, "name");
		char *oldpath = talloc_asprintf(t, "%s/%s", opt_linkdir, oldname);

		if (del || strcmp(oldname, username)) {
			if (0 != unlink(oldpath))
				error(1, errno, "%s (unlink)", oldpath);

			unmark(home, "name");
		}
	}

	/* Create a new link. */
	if (!del && username) {
		char *path = talloc_asprintf(t, "%s/%s", opt_linkdir, username);
		char *rhome = talloc_array(t, char, PATH_MAX);

		if (NULL == realpath(home, rhome))
			error(1, errno, "%s", home);

		if (0 != symlink(rhome, path)) {
			if (EEXIST != errno)
				error(1, errno, "%s -> %s", path, rhome);
		}

		mark(rhome, "name", username);
	}
}

static void update_password(void *t)
{
	struct ldb_context *ldb = samba_init(t, opt_ldb_url);
	struct ldb_val *pwd = talloc_zero(t, struct ldb_val);
	size_t b;

	if (strlen(password) % 2)
		error(1, 0, "invalid password hash length");

	pwd->length = strlen(password) / 2;
	pwd->data = talloc_zero_array(pwd, uint8_t, pwd->length + 1);

	for (b = 0; b < pwd->length; b++)
		if (1 != sscanf(password + (2 * b), "%2hhx", pwd->data + b))
			error(1, errno, "invalid password hash");

	if (0 != samba_set_password(ldb, opt_basedn, uid, pwd))
		error(1, errno, "failed to set password");
}

static int do_update(void *t, int argc, char **argv)
{
	if (argc > 0)
		error(1, 0, "Too many arguments.");

	load_env(1);

	if (NULL == opt_homedir)
		error(1, 0, "Please specify the --homedir option.");

	if (NULL == opt_linkdir)
		error(1, 0, "Please specify the --linkdir option.");

	if (NULL == opt_trashdir)
		error(1, 0, "Please specify the --trashdir option.");

	if (password) {
		if (NULL == opt_ldb_url)
			error(1, 0, "Please specify the --ldb-url option.");

		if (NULL == opt_basedn)
			error(1, 0, "Please specify the --basedn option.");

		update_password(t);
	}

	if (username) {
		make_home(t);
		update_link(t, 0);
	}

	return 0;
}

static int list_ldb_users(void *t)
{
	struct ldb_context *ldb = samba_init(t, opt_ldb_url);
	struct samba_user **users = NULL;
	size_t b;
	int i;

	if (0 != samba_list_users(ldb, t, &users, opt_basedn, uid))
		error(1, errno, "LDB user search failed");

	for (i = 0; users[i]; i++) {
		if (0 == users[i]->cn)
			continue;

		char *path = talloc_asprintf(t, "%s/%lu", opt_homedir, users[i]->cn);

		printf("--- NEW SEARCH RESULT ITEM ---\n");
		printf("__UID__=%lu\n", users[i]->cn);
		printf("__NAME__=%lu\n", users[i]->cn);

		if (users[i]->pwd) {
			printf("unicodePwd=");

			for (b = 0; b < users[i]->pwd->length; b++)
				printf("%02x", users[i]->pwd->data[b]);

			printf("\n");
		}

		if (checkmark(path, "name")) {
			char *name = getmark(t, path, "name");
			printf("sAMAccountName=%s\n", name);
		}

		printf("\n");
	}

	talloc_free(ldb);
	return 0;
}

static int list_homedir_users(void *t)
{
	DIR *dp = opendir(opt_homedir);
	struct dirent *de;

	if (NULL == dp)
		error(1, errno, "%s (opendir)", opt_homedir);

	while (NULL != (de = readdir(dp))) {
		/* Skip hidden files and directories. */
		if ('.' == de->d_name[0])
			continue;

		/* Skip non-directories. */
		if (de->d_type && !(DT_DIR & de->d_type))
			continue;

		/* Apply uid filter, if specified. */
		if (uid && atol(de->d_name) != (long)(uid))
			continue;

		char *path = talloc_asprintf(t, "%s/%s", opt_homedir, de->d_name);

		printf("--- NEW SEARCH RESULT ITEM ---\n");
		printf("__UID__=%s\n", de->d_name);
		printf("__NAME__=%s\n", de->d_name);

		if (checkmark(path, "name")) {
			char *name = getmark(t, path, "name");
			printf("sAMAccountName=%s\n", name);
		}

		printf("\n");
	}

	closedir(dp);

	return 0;
}

static int do_list(void *t, int argc, char **argv)
{
	if (argc > 0)
		error(1, 0, "Too many arguments.");

	load_env(0);

	if (!opt_homedir)
		error(1, 0, "Please specify the --homedir option.");

	if (opt_basedn && !opt_ldb_url)
		error(1, 0, "Please specify the --ldb-url option as well.");

	if (opt_ldb_url && !opt_basedn)
		error(1, 0, "Please specify the --basedn option as well.");

	if (opt_basedn && opt_ldb_url)
		return list_ldb_users(t);

	return list_homedir_users(t);
}

int do_delete(void *t, int argc, char **argv)
{
	if (argc > 0)
		error(1, 0, "Too many arguments.");

	load_env(1);

	if (NULL == opt_homedir)
		error(1, 0, "Please specify the --homedir option.");

	if (NULL == opt_linkdir)
		error(1, 0, "Please specify the --linkdir option.");

	if (NULL == opt_trashdir)
		error(1, 0, "Please specify the --trashdir option.");

	update_link(t, 1);
	trash_home(t);

	return 0;
}

int main(int argc, char **argv)
{
	int result, c, idx = 0;
	int (*action)(void *t, int argc, char **argv) = do_update;
	void *t = talloc_init("samba-ext-idm-adapter");

	while (-1 != (c = getopt_long(argc, argv, optstring, longopts, &idx)))
		switch (c) {
			case 'h':
				action = do_help;
				break;

			case 'V':
				action = do_version;
				break;

			case 'u':
				action = do_update;
				break;

			case 'd':
				action = do_delete;
				break;

			case 'l':
				action = do_list;
				break;

			case 'H':
				if (opt_ldb_url)
					talloc_free(opt_ldb_url);

				opt_ldb_url = talloc_strdup(t, optarg);
				break;

			case 'b':
				if (opt_basedn)
					talloc_free(opt_basedn);

				opt_basedn = talloc_strdup(t, optarg);
				break;

			case 'D':
				if (0 == strcmp(optarg, ""))
					error(1, 0, "Empty --homedir given.");

				if (opt_homedir)
					talloc_free(opt_homedir);

				opt_homedir = talloc_strdup(t, optarg);
				break;

			case 's':
				if (0 == strcmp(optarg, ""))
					error(1, 0, "Empty --setup given.");

				if (opt_setup)
					talloc_free(opt_setup);

				opt_setup = talloc_strdup(t, optarg);
				break;

			case 'L':
				if (0 == strcmp(optarg, ""))
					error(1, 0, "Empty --linkdir given.");

				if (opt_linkdir)
					talloc_free(opt_linkdir);

				opt_linkdir = talloc_strdup(t, optarg);
				break;

			case 'T':
				if (0 == strcmp(optarg, ""))
					error(1, 0, "Empty --trashdir given.");

				if (opt_trashdir)
					talloc_free(opt_trashdir);

				opt_trashdir = talloc_strdup(t, optarg);
				break;

			case 'G':
				gid = atol(optarg);

				if (0 == gid)
					error(1, 0, "Invalid GID.");

				break;
		}

	result = action(t, argc - optind, argv + optind);

	talloc_free(t);
	return result;
}
