// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#define _GNU_SOURCE
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <syscall.h>
#include <limits.h>
#include <unistd.h>

#include "../kselftest.h"
#include "helpers.h"

/*
 * Construct a test directory with the following structure:
 *
 * root/
 * |-- procexe -> /proc/self/exe
 * |-- procroot -> /proc/self/root
 * |-- root/
 * |-- mnt/ [mountpoint]
 * |   |-- self -> ../mnt/
 * |   `-- absself -> /mnt/
 * |-- etc/
 * |   `-- passwd
 * |-- relsym -> etc/passwd
 * |-- abssym -> /etc/passwd
 * |-- abscheeky -> /cheeky
 * |-- abscheeky -> /cheeky
 * `-- cheeky/
 *     |-- absself -> /
 *     |-- self -> ../../root/
 *     |-- garbageself -> /../../root/
 *     |-- passwd -> ../cheeky/../cheeky/../etc/../etc/passwd
 *     |-- abspasswd -> /../cheeky/../cheeky/../etc/../etc/passwd
 *     |-- dotdotlink -> ../../../../../../../../../../../../../../etc/passwd
 *     `-- garbagelink -> /../../../../../../../../../../../../../../etc/passwd
 */
int setup_testdir(void)
{
	int dfd, tmpfd;
	char dirname[] = "/tmp/resolveat-testdir.XXXXXX";

	/* Unshare and make /tmp a new directory. */
	E_unshare(CLONE_NEWNS);
	E_mount("", "/tmp", "", MS_PRIVATE, "");

	/* Make the top-level directory. */
	if (!mkdtemp(dirname))
		ksft_exit_fail_msg("setup_testdir: failed to create tmpdir\n");
	dfd = open(dirname, O_PATH | O_DIRECTORY);
	if (dfd < 0)
		ksft_exit_fail_msg("setup_testdir: failed to open tmpdir\n");

	/* A sub-directory which is actually used for tests. */
	E_mkdirat(dfd, "root", 0755);
	tmpfd = openat(dfd, "root", O_PATH | O_DIRECTORY);
	if (tmpfd < 0)
		ksft_exit_fail_msg("setup_testdir: failed to open tmpdir\n");
	close(dfd);
	dfd = tmpfd;

	E_symlinkat("/proc/self/exe", dfd, "procexe");
	E_symlinkat("/proc/self/root", dfd, "procroot");
	E_mkdirat(dfd, "root", 0755);

	/* There is no mountat(2), so use chdir. */
	E_mkdirat(dfd, "mnt", 0755);
	E_fchdir(dfd);
	E_mount("tmpfs", "./mnt", "tmpfs", MS_NOSUID | MS_NODEV, "");
	E_symlinkat("../mnt/", dfd, "mnt/self");
	E_symlinkat("/mnt/", dfd, "mnt/absself");

	E_mkdirat(dfd, "etc", 0755);
	E_touchat(dfd, "etc/passwd");

	E_symlinkat("etc/passwd", dfd, "relsym");
	E_symlinkat("/etc/passwd", dfd, "abssym");
	E_symlinkat("/cheeky", dfd, "abscheeky");

	E_mkdirat(dfd, "cheeky", 0755);

	E_symlinkat("/", dfd, "cheeky/absself");
	E_symlinkat("../../root/", dfd, "cheeky/self");
	E_symlinkat("/../../root/", dfd, "cheeky/garbageself");

	E_symlinkat("../cheeky/../etc/../etc/passwd", dfd, "cheeky/passwd");
	E_symlinkat("/../cheeky/../etc/../etc/passwd", dfd, "cheeky/abspasswd");

	E_symlinkat("../../../../../../../../../../../../../../etc/passwd",
		    dfd, "cheeky/dotdotlink");
	E_symlinkat("/../../../../../../../../../../../../../../etc/passwd",
		    dfd, "cheeky/garbagelink");

	return dfd;
}

struct basic_test {
	const char *dir;
	const char *path;
	unsigned int flags;
	bool pass;
	union {
		int err;
		const char *path;
	} out;
};

void test_resolveat_basic_tests(void)
{
	int rootfd;
	char *procselfexe;

	E_asprintf(&procselfexe, "/proc/%d/exe", getpid());
	rootfd = setup_testdir();

	struct basic_test tests[] = {
		/** RESOLVE_BENEATH **/
		/* Attempts to cross dirfd should be blocked. */
		{ .path = "/",			.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/absself",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/absself",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "..",			.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "../root/",		.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/self",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/self",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/garbageself",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/garbageself", .flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		/* Only relative paths that stay inside dirfd should work. */
		{ .path = "root",		.flags = RESOLVE_BENEATH,
		  .out.path = "root",		.pass = true },
		{ .path = "etc",		.flags = RESOLVE_BENEATH,
		  .out.path = "etc",		.pass = true },
		{ .path = "etc/passwd",		.flags = RESOLVE_BENEATH,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "relsym",		.flags = RESOLVE_BENEATH,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/passwd",	.flags = RESOLVE_BENEATH,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/passwd",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abssym",		.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "/etc/passwd",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/abspasswd",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/abspasswd", .flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		/* Tricky paths should fail. */
		{ .path = "cheeky/dotdotlink",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/dotdotlink", .flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/garbagelink",	.flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/garbagelink", .flags = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },

		/** RESOLVE_IN_ROOT **/
		/* All attempts to cross the dirfd will be scoped-to-root. */
		{ .path = "/",			.flags = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "cheeky/absself",	.flags = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "abscheeky/absself",	.flags = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "..",			.flags = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "../root/",		.flags = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "../root/",		.flags = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "cheeky/self",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "cheeky/garbageself",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "abscheeky/garbageself", .flags = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "root",		.flags = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "etc",		.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc",		.pass = true },
		{ .path = "etc/passwd",		.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "relsym",		.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/passwd",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/passwd",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abssym",		.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "/etc/passwd",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/abspasswd",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/abspasswd",.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/dotdotlink",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/dotdotlink", .flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "/../../../../abscheeky/dotdotlink", .flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/garbagelink",	.flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/garbagelink", .flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "/../../../../abscheeky/garbagelink", .flags = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },

		/** RESOLVE_XDEV **/
		/* Crossing *down* into a mountpoint is disallowed. */
		{ .path = "mnt",		.flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "mnt/",		.flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "mnt/.",		.flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		/* Crossing *up* out of a mountpoint is disallowed. */
		{ .dir = "mnt", .path = ".",	.flags = RESOLVE_XDEV,
		  .out.path = "mnt",		.pass = true },
		{ .dir = "mnt", .path = "..",	.flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .dir = "mnt", .path = "../mnt", .flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .dir = "mnt", .path = "self",	.flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .dir = "mnt", .path = "absself", .flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		/* Jumping to "/" is ok, but later components cannot cross. */
		{ .dir = "mnt", .path = "/",	.flags = RESOLVE_XDEV,
		  .out.path = "/",		.pass = true },
		{ .dir = "/", .path = "/",	.flags = RESOLVE_XDEV,
		  .out.path = "/",		.pass = true },
		{ .path = "/proc/1",		.flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "/tmp",		.flags = RESOLVE_XDEV,
		  .out.err = -EXDEV,		.pass = false },

		/** RESOLVE_NO_MAGICLINKS **/
		/* Regular symlinks should work. */
		{ .path = "relsym",		.flags = RESOLVE_NO_MAGICLINKS,
		  .out.path = "etc/passwd",	.pass = true },
		/* Magic-links should not work. */
		{ .path = "procexe",		.flags = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/exe",	.flags = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "procroot/etc",	.flags = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/root/etc", .flags = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/root/etc", .flags = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_FOLLOW,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/exe",	.flags = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_FOLLOW,
		  .out.path = procselfexe,	.pass = true },

		/** RESOLVE_NO_SYMLINKS **/
		/* Normal paths should work. */
		{ .path = ".",			.flags = RESOLVE_NO_SYMLINKS,
		  .out.path = NULL,		.pass = true },
		{ .path = "root",		.flags = RESOLVE_NO_SYMLINKS,
		  .out.path = "root",		.pass = true },
		{ .path = "etc",		.flags = RESOLVE_NO_SYMLINKS,
		  .out.path = "etc",		.pass = true },
		{ .path = "etc/passwd",		.flags = RESOLVE_NO_SYMLINKS,
		  .out.path = "etc/passwd",	.pass = true },
		/* Regular symlinks are blocked. */
		{ .path = "relsym",		.flags = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abssym",		.flags = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "cheeky/garbagelink",	.flags = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abscheeky/garbagelink", .flags = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abscheeky/absself",	.flags = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		/* Trailing symlinks with NO_FOLLOW. */
		{ .path = "relsym",		.flags = RESOLVE_NO_SYMLINKS | RESOLVE_NO_FOLLOW,
		  .out.path = "relsym",		.pass = true },
		{ .path = "abssym",		.flags = RESOLVE_NO_SYMLINKS | RESOLVE_NO_FOLLOW,
		  .out.path = "abssym",		.pass = true },
		{ .path = "cheeky/garbagelink",	.flags = RESOLVE_NO_SYMLINKS | RESOLVE_NO_FOLLOW,
		  .out.path = "cheeky/garbagelink", .pass = true },
		{ .path = "abscheeky/garbagelink", .flags = RESOLVE_NO_SYMLINKS | RESOLVE_NO_FOLLOW,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abscheeky/absself",	.flags = RESOLVE_NO_SYMLINKS | RESOLVE_NO_FOLLOW,
		  .out.err = -ELOOP,		.pass = false },
	};

	for (int i = 0; i < ARRAY_LEN(tests); i++) {
		int dfd, fd;
		bool failed;
		void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;

		struct basic_test *test = &tests[i];
		char *flagstr = resolveat_flags(test->flags);

		if (test->dir)
			dfd = openat(rootfd, test->dir, O_PATH | O_DIRECTORY);
		else
			dfd = dup(rootfd);
		if (dfd < 0) {
			resultfn = ksft_test_result_error;
			goto next;
		}

		fd = sys_resolveat(dfd, test->path, test->flags);
		if (test->pass)
			failed = (fd < 0 || !fdequal(fd, rootfd, test->out.path));
		else
			failed = (fd != test->out.err);
		if (fd >= 0)
			close(fd);
		close(dfd);

		if (failed)
			resultfn = ksft_test_result_fail;

next:
		if (test->pass)
			resultfn("resolveat(root[%s], %s, %s) ==> %s\n",
				 test->dir ?: ".", test->path, flagstr,
				 test->out.path ?: ".");
		else
			resultfn("resolveat(root[%s], %s, %s) ==> %d (%s)\n",
				 test->dir ?: ".", test->path, flagstr,
				 test->out.err, strerror(-test->out.err));
		free(flagstr);
	}

	free(procselfexe);
	close(rootfd);
}


static int proc_exec(int fd)
{
	int err, saved_errno;
	char *procpath;
	char *argv[] = {"foo", NULL};
	char *envp[] = {"bar", NULL};

	E_asprintf(&procpath, "/proc/self/fd/%d", fd);
	err = execve(procpath, argv, envp);
	saved_errno = errno;
	free(procpath);

	return err >= 0 ? err : -saved_errno;
}

static int fd_exec(int fd)
{
	char *argv[] = {"foo", NULL};
	char *envp[] = {"bar", NULL};

	return sys_execveat(fd, "", argv, envp, AT_EMPTY_PATH);
}

int main(int argc, char **argv)
{
	ksft_print_header();
	test_resolveat_supported();

	/* NOTE: We should be checking for CAP_SYS_ADMIN here... */
	if (geteuid() != 0)
		ksft_exit_skip("resolveat(2) tests require euid == 0\n");

	test_resolveat_basic_tests();

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
