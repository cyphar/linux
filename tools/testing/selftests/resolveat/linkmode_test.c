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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <syscall.h>
#include <limits.h>
#include <unistd.h>

#include "../kselftest.h"
#include "helpers.h"

static mode_t fdmode(int fd)
{
	char *fdpath;
	struct stat statbuf;
	mode_t mode;

	E_asprintf(&fdpath, "/proc/self/fd/%d", fd);
	E_fstatat(AT_FDCWD, fdpath, &statbuf, AT_SYMLINK_NOFOLLOW);
	mode = (statbuf.st_mode & ~S_IFMT);
	free(fdpath);

	return mode;
}

static int reopen_proc(int fd, unsigned int flags)
{
	int ret, saved_errno;
	char *fdpath;

	E_asprintf(&fdpath, "/proc/self/fd/%d", fd);
	ret = open(fdpath, flags);
	saved_errno = errno;
	free(fdpath);

	return ret >= 0 ? ret : -saved_errno;
}

static int reopen_oemptypath(int fd, unsigned int flags)
{
	int ret = openat(fd, "", O_EMPTYPATH | flags);
	return ret >= 0 ? ret : -errno;
}

struct reopen_test {
	openfunc_t open;
	mode_t chmod_mode;
	struct {
		unsigned int flags;
		mode_t mode;
		int err;
	} orig, new;
};

static bool reopen(int fd, struct reopen_test *test)
{
	int newfd;
	mode_t proc_mode;
	bool failed = false;

	/* Check that the proc mode is correct. */
	proc_mode = fdmode(fd);
	if (proc_mode != test->orig.mode) {
		ksft_print_msg("incorrect fdmode (got[%o] != want[%o])\n",
			       proc_mode, test->orig.mode);
		failed = true;
	}

	/* Re-open through /proc. */
	newfd = reopen_proc(fd, test->new.flags);
	if (newfd != test->new.err && (newfd < 0 || test->new.err < 0)) {
		ksft_print_msg("/proc failure (%d != %d [%s])\n",
			       newfd, test->new.err, strerror(-test->new.err));
		failed = true;
	}
	if (newfd >= 0) {
		proc_mode = fdmode(newfd);
		if (proc_mode != test->new.mode) {
			ksft_print_msg("/proc wrong fdmode (got[%o] != want[%o])\n",
				       proc_mode, test->new.mode);
			failed = true;
		}
		close(newfd);
	}

	/* Re-open with O_EMPTYPATH. */
	newfd = reopen_oemptypath(fd, test->new.flags);
	if (newfd != test->new.err && (newfd < 0 || test->new.err < 0)) {
		ksft_print_msg("O_EMPTYPATH failure (%d != %d [%s])\n",
			       newfd, test->new.err, strerror(-test->new.err));
		failed = true;
	}
	if (newfd >= 0) {
		proc_mode = fdmode(newfd);
		if (proc_mode != test->new.mode) {
			ksft_print_msg("O_EMPTYPATH wrong fdmode (got[%o] != want[%o])\n",
				       proc_mode, test->new.mode);
			failed = true;
		}
		close(newfd);
	}

	return failed;
}

void test_reopen_ordinary(bool privileged)
{
	int fd;
	int err_access = privileged ? 0 : -EACCES;
	char tmpfile[] = "/tmp/reopen-testfile.XXXXXX";

	fd = mkstemp(tmpfile);
	E_assert(fd >= 0, "mkstemp failed: %m\n");
	close(fd);

	struct reopen_test tests[] = {
		/* Re-opening with the same mode should succeed. */
		{ .open = sys_openat,	  .chmod_mode = 0400,
		  .orig.flags = O_RDONLY, .orig.mode  = privileged ? 0777 : 0555,
		  .new.flags  = O_RDONLY, .new.mode   = privileged ? 0777 : 0555},
		{ .open = sys_openat,	  .chmod_mode = 0200,
		  .orig.flags = O_WRONLY, .orig.mode  = privileged ? 0777 : 0333,
		  .new.flags  = O_WRONLY, .new.mode   = privileged ? 0777 : 0333 },
		{ .open = sys_openat,	  .chmod_mode = 0600,
		  .orig.flags =   O_RDWR, .orig.mode  = 0777,
		  .new.flags  =   O_RDWR, .new.mode   = 0777 },
		{ .open = sys_openat,	  .chmod_mode = 0600,
		  .orig.flags =   O_RDWR, .orig.mode  = 0777,
		  .new.flags  = O_RDONLY, .new.mode   = 0777 },
		{ .open = sys_openat,	  .chmod_mode = 0600,
		  .orig.flags =   O_RDWR, .orig.mode  = 0777,
		  .new.flags  = O_WRONLY, .new.mode   = 0777 },

		/*
		 * Upgrading the mode of a normal file works if the user had the
		 * required access at original-open time.
		 */
		{ .open = sys_openat,	  .chmod_mode = 0600,
		  .orig.flags = O_RDONLY, .orig.mode  = 0777,
		  .new.flags  = O_WRONLY, .new.mode   = 0777 },
		{ .open = sys_openat,	  .chmod_mode = 0600,
		  .orig.flags = O_WRONLY, .orig.mode  = 0777,
		  .new.flags  = O_RDONLY, .new.mode   = 0777 },
		{ .open = sys_openat,	  .chmod_mode = 0600,
		  .orig.flags = O_RDONLY, .orig.mode  = 0777,
		  .new.flags  =   O_RDWR, .new.mode   = 0777 },
		{ .open = sys_openat,	  .chmod_mode = 0600,
		  .orig.flags = O_WRONLY, .orig.mode  = 0777,
		  .new.flags  =   O_RDWR, .new.mode   = 0777 },

		/* However, re-open will be blocked given insufficient permissions. */
		{ .open = sys_openat,	  .chmod_mode = 0400,
		  .orig.flags = O_RDONLY, .orig.mode  = privileged ? 0777 : 0555,
		  .new.flags  = O_WRONLY, .new.mode   = 0777, .new.err = err_access },
		{ .open = sys_openat,	  .chmod_mode = 0200,
		  .orig.flags = O_WRONLY, .orig.mode  = privileged ? 0777 : 0333,
		  .new.flags  = O_RDONLY, .new.mode   = 0777, .new.err = err_access },
		{ .open = sys_openat,	  .chmod_mode = 0400,
		  .orig.flags = O_RDONLY, .orig.mode  = privileged ? 0777 : 0555,
		  .new.flags  =   O_RDWR, .new.mode   = 0777, .new.err = err_access },
		{ .open = sys_openat,	  .chmod_mode = 0200,
		  .orig.flags = O_WRONLY, .orig.mode  = privileged ? 0777 : 0333,
		  .new.flags  =   O_RDWR, .new.mode   = 0777, .new.err = err_access },

		/* O_PATH re-opens (of ordinary files) will always work. */
		{ .open = sys_openat,	  .chmod_mode = 0000,
		  .orig.flags =   O_PATH, .orig.mode  = 0777,
		  .new.flags  = O_WRONLY, .new.mode   = 0777 },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags =        0, .orig.mode  = 0777,
		  .new.flags  = O_WRONLY, .new.mode   = 0777 },
		{ .open = sys_openat,	  .chmod_mode = 0000,
		  .orig.flags =   O_PATH, .orig.mode  = 0777,
		  .new.flags  = O_RDONLY, .new.mode   = 0777 },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags =        0, .orig.mode  = 0777,
		  .new.flags  = O_RDONLY, .new.mode   = 0777 },
		{ .open = sys_openat,	  .chmod_mode = 0000,
		  .orig.flags =   O_PATH, .orig.mode  = 0777,
		  .new.flags  =   O_RDWR, .new.mode   = 0777 },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags =        0, .orig.mode  = 0777,
		  .new.flags  =   O_RDWR, .new.mode   = 0777 },

		/*
		 * resolveat(2) RESOLVE_UPGRADE_NO* flags. In the privileged case, the
		 * re-open will work but the mode will still be scoped to the mode
		 * (or'd with the open acc_mode).
		 */
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOREAD | RESOLVE_UPGRADE_NOWRITE,
		                          .orig.mode  = 0111,
		  .new.flags  = O_RDONLY, .new.mode   = 0555, .new.err = err_access },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOREAD | RESOLVE_UPGRADE_NOWRITE,
		                          .orig.mode  = 0111,
		  .new.flags  = O_WRONLY, .new.mode   = 0333, .new.err = err_access },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOREAD | RESOLVE_UPGRADE_NOWRITE,
		                          .orig.mode  = 0111,
		  .new.flags  =   O_RDWR, .new.mode   = 0777, .new.err = err_access },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOWRITE,
		                          .orig.mode  = 0555,
		  .new.flags  = O_RDONLY, .new.mode   = 0555 },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOREAD,
		                          .orig.mode  = 0333,
		  .new.flags  = O_WRONLY, .new.mode   = 0333 },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOWRITE,
		                          .orig.mode  = 0555,
		  .new.flags  = O_RDONLY, .new.mode   = 0555 },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOREAD,
		                          .orig.mode  = 0333,
		  .new.flags  = O_RDONLY, .new.mode   = 0777, .new.err = err_access },
		{ .open = sys_resolveat,  .chmod_mode = 0000,
		  .orig.flags = RESOLVE_UPGRADE_NOWRITE,
		                          .orig.mode  = 0555,
		  .new.flags  = O_WRONLY, .new.mode   = 0777, .new.err = err_access },
	};

	for (int i = 0; i < ARRAY_LEN(tests); i++) {
		int fd;
		char *orig_flagset, *new_flagset;
		struct reopen_test *test = &tests[i];
		void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;

		E_chmod(tmpfile, test->chmod_mode);

		fd = test->open(AT_FDCWD, tmpfile, test->orig.flags);
		E_assert(fd >= 0, "open '%s' failed: %m\n", tmpfile);

		/* Make sure that any EACCES we see is not from inode permissions. */
		E_chmod(tmpfile, 0777);

		if (reopen(fd, test))
			resultfn = ksft_test_result_fail;

		close(fd);

		new_flagset = openat_flags(test->new.flags);
		if (test->open == sys_openat)
			orig_flagset = openat_flags(test->orig.flags);
		else if (test->open == sys_resolveat)
			orig_flagset = resolveat_flags(test->orig.flags);
		else
			ksft_exit_fail_msg("unknown test->open\n");

		resultfn("%sordinary reopen of (orig[%s]=%s, new=%s) chmod=%.3o %s\n",
			 privileged ? "privileged " : "",
			 test->open == sys_openat ? "openat" : "resolveat",
			 orig_flagset, new_flagset, test->chmod_mode,
			 test->new.err < 0 ? strerror(-test->new.err) : "works");

		free(new_flagset);
		free(orig_flagset);
	}

	unlink(tmpfile);
}


int main(int argc, char **argv)
{
	bool privileged;

	ksft_print_header();
	test_resolveat_supported();

	/*
	 * Technically we should be checking CAP_DAC_OVERRIDE, but it's easier to
	 * just assume that euid=0 has the full capability set.
	 */
	privileged = (geteuid() == 0);
	if (!privileged)
		ksft_test_result_skip("privileged tests require euid == 0\n");
	else {
		test_reopen_ordinary(privileged);

		E_setresuid(65534, 65534, 65534);
		privileged = (geteuid() == 0);
	}

	test_reopen_ordinary(privileged);

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
