// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

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
 * |-- creatlink -> /newfile3
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
	char dirname[] = "/tmp/ksft-openat2-testdir.XXXXXX";

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

	E_symlinkat("/newfile3", dfd, "creatlink");
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
	struct open_how how;
	bool pass;
	union {
		int err;
		const char *path;
	} out;
};

void test_openat2_opath_tests(void)
{
	int rootfd;
	char *procselfexe;

	E_asprintf(&procselfexe, "/proc/%d/exe", getpid());
	rootfd = setup_testdir();

	struct basic_test tests[] = {
		/** RESOLVE_BENEATH **/
		/* Attempts to cross dirfd should be blocked. */
		{ .path = "/",			.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/absself",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/absself",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "..",			.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "../root/",		.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/self",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/self",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/garbageself",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/garbageself", .how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		/* Only relative paths that stay inside dirfd should work. */
		{ .path = "root",		.how.resolve = RESOLVE_BENEATH,
		  .out.path = "root",		.pass = true },
		{ .path = "etc",		.how.resolve = RESOLVE_BENEATH,
		  .out.path = "etc",		.pass = true },
		{ .path = "etc/passwd",		.how.resolve = RESOLVE_BENEATH,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "relsym",		.how.resolve = RESOLVE_BENEATH,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/passwd",	.how.resolve = RESOLVE_BENEATH,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/passwd",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abssym",		.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "/etc/passwd",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/abspasswd",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/abspasswd", .how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		/* Tricky paths should fail. */
		{ .path = "cheeky/dotdotlink",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/dotdotlink", .how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "cheeky/garbagelink",	.how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "abscheeky/garbagelink", .how.resolve = RESOLVE_BENEATH,
		  .out.err = -EXDEV,		.pass = false },

		/** RESOLVE_IN_ROOT **/
		/* All attempts to cross the dirfd will be scoped-to-root. */
		{ .path = "/",			.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "cheeky/absself",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "abscheeky/absself",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "..",			.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = NULL,		.pass = true },
		{ .path = "../root/",		.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "../root/",		.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "cheeky/self",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "cheeky/garbageself",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "abscheeky/garbageself", .how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "root",		.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "root",		.pass = true },
		{ .path = "etc",		.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc",		.pass = true },
		{ .path = "etc/passwd",		.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "relsym",		.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/passwd",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/passwd",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abssym",		.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "/etc/passwd",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/abspasswd",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/abspasswd",.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/dotdotlink",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/dotdotlink", .how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "/../../../../abscheeky/dotdotlink", .how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "cheeky/garbagelink",	.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "abscheeky/garbagelink", .how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		{ .path = "/../../../../abscheeky/garbagelink", .how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "etc/passwd",	.pass = true },
		/* O_CREAT should handle trailing symlinks correctly. */
		{ .path = "newfile1",		.how.flags = O_CREAT,
						.how.mode = 0700,
						.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "newfile1",	.pass = true },
		{ .path = "/newfile2",		.how.flags = O_CREAT,
						.how.mode = 0700,
						.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "newfile2",	.pass = true },
		{ .path = "/creatlink",		.how.flags = O_CREAT,
						.how.mode = 0700,
						.how.resolve = RESOLVE_IN_ROOT,
		  .out.path = "newfile3",	.pass = true },

		/** RESOLVE_NO_XDEV **/
		/* Crossing *down* into a mountpoint is disallowed. */
		{ .path = "mnt",		.how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "mnt/",		.how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "mnt/.",		.how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		/* Crossing *up* out of a mountpoint is disallowed. */
		{ .dir = "mnt", .path = ".",	.how.resolve = RESOLVE_NO_XDEV,
		  .out.path = "mnt",		.pass = true },
		{ .dir = "mnt", .path = "..",	.how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .dir = "mnt", .path = "../mnt", .how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .dir = "mnt", .path = "self",	.how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .dir = "mnt", .path = "absself", .how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		/* Jumping to "/" is ok, but later components cannot cross. */
		{ .dir = "mnt", .path = "/",	.how.resolve = RESOLVE_NO_XDEV,
		  .out.path = "/",		.pass = true },
		{ .dir = "/", .path = "/",	.how.resolve = RESOLVE_NO_XDEV,
		  .out.path = "/",		.pass = true },
		{ .path = "/proc/1",		.how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },
		{ .path = "/tmp",		.how.resolve = RESOLVE_NO_XDEV,
		  .out.err = -EXDEV,		.pass = false },

		/** RESOLVE_NO_MAGICLINKS **/
		/* Regular symlinks should work. */
		{ .path = "relsym",		.how.resolve = RESOLVE_NO_MAGICLINKS,
		  .out.path = "etc/passwd",	.pass = true },
		/* Magic-links should not work. */
		{ .path = "procexe",		.how.resolve = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/exe",	.how.resolve = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "procroot/etc",	.how.resolve = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/root/etc", .how.resolve = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/root/etc", .how.flags = O_NOFOLLOW,
						 .how.resolve = RESOLVE_NO_MAGICLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "/proc/self/exe",	.how.flags = O_NOFOLLOW,
						.how.resolve = RESOLVE_NO_MAGICLINKS,
		  .out.path = procselfexe,	.pass = true },

		/** RESOLVE_NO_SYMLINKS **/
		/* Normal paths should work. */
		{ .path = ".",			.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.path = NULL,		.pass = true },
		{ .path = "root",		.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.path = "root",		.pass = true },
		{ .path = "etc",		.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.path = "etc",		.pass = true },
		{ .path = "etc/passwd",		.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.path = "etc/passwd",	.pass = true },
		/* Regular symlinks are blocked. */
		{ .path = "relsym",		.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abssym",		.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "cheeky/garbagelink",	.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abscheeky/garbagelink", .how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abscheeky/absself",	.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		/* Trailing symlinks with NO_FOLLOW. */
		{ .path = "relsym",		.how.flags = O_NOFOLLOW,
						.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.path = "relsym",		.pass = true },
		{ .path = "abssym",		.how.flags = O_NOFOLLOW,
						.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.path = "abssym",		.pass = true },
		{ .path = "cheeky/garbagelink",	.how.flags = O_NOFOLLOW,
						.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.path = "cheeky/garbagelink", .pass = true },
		{ .path = "abscheeky/garbagelink", .how.flags = O_NOFOLLOW,
						   .how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
		{ .path = "abscheeky/absself",	.how.flags = O_NOFOLLOW,
						.how.resolve = RESOLVE_NO_SYMLINKS,
		  .out.err = -ELOOP,		.pass = false },
	};

	for (int i = 0; i < ARRAY_LEN(tests); i++) {
		int dfd, fd;
		bool failed;
		void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;
		struct basic_test *test = &tests[i];
		char *flagstr;

		/* Auto-set O_PATH. */
		if (!(test->how.flags & O_CREAT))
			test->how.flags |= O_PATH;
		flagstr = openat2_flags(&test->how);

		if (test->dir)
			dfd = openat(rootfd, test->dir, O_PATH | O_DIRECTORY);
		else
			dfd = dup(rootfd);
		if (dfd < 0) {
			resultfn = ksft_test_result_error;
			goto next;
		}

		fd = sys_openat2(dfd, test->path, &test->how);
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
			resultfn("openat2(root[%s], %s, %s) ==> %s\n",
				 test->dir ?: ".", test->path, flagstr,
				 test->out.path ?: ".");
		else
			resultfn("openat2(root[%s], %s, %s) ==> %d (%s)\n",
				 test->dir ?: ".", test->path, flagstr,
				 test->out.err, strerror(-test->out.err));
		free(flagstr);
	}

	free(procselfexe);
	close(rootfd);
}

int main(int argc, char **argv)
{
	ksft_print_header();
	test_openat2_supported();

	/* NOTE: We should be checking for CAP_SYS_ADMIN here... */
	if (geteuid() != 0)
		ksft_exit_skip("openat2(2) tests require euid == 0\n");

	test_openat2_opath_tests();

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
