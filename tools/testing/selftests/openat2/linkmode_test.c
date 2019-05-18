// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sched.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>

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

static int reopen_proc(int fd, struct open_how how)
{
	int ret, saved_errno;
	char *fdpath;

	E_asprintf(&fdpath, "/proc/self/fd/%d", fd);
	ret = sys_openat2(AT_FDCWD, fdpath, &how);
	saved_errno = errno;
	free(fdpath);

	return ret >= 0 ? ret : -saved_errno;
}

static int reopen_oemptypath(int fd, struct open_how how)
{
	int ret;

	how.flags |= O_EMPTYPATH;
	ret = sys_openat2(fd, "", &how);
	return ret >= 0 ? ret : -errno;
}

struct reopen_test {
	const char *name, *srcpath;
	bool openat2_only;
	mode_t chmod_mode;
	struct {
		struct open_how how;
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
	newfd = reopen_proc(fd, test->new.how);
	if (newfd != test->new.err && (newfd < 0 || test->new.err < 0)) {
		ksft_print_msg("/proc failure (got[%d] != want[%d] [%s])\n",
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

	/* Re-open with O_EMPTYPATH -- but O_PATH is not supported. */
	if (!(test->new.how.flags & O_PATH)) {
		newfd = reopen_oemptypath(fd, test->new.how);
		if (newfd != test->new.err && (newfd < 0 || test->new.err < 0)) {
			ksft_print_msg("O_EMPTYPATH failure (got[%d] != want[%d] [%s])\n",
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
	}

	return failed;
}

#define NUM_REOPEN_ORDINARY_TESTS 44

void test_reopen_ordinary(bool privileged)
{
	int fd;
	int err_access = privileged ? 0 : -EACCES;
	char tmpfile[] = "/tmp/ksft-openat2-reopen-testfile.XXXXXX";

	fd = mkstemp(tmpfile);
	E_assert(fd >= 0, "mkstemp failed: %m\n");
	close(fd);

	struct reopen_test tests[] = {
		/* Re-opening with the same mode should succeed. */
		{ .name = "same mode (mode:r old:r new:r)",
		  .chmod_mode = 0400,
		  .orig.how.flags = O_RDONLY, .orig.mode  = 0500,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500 },
		{ .name = "same mode (mode:w old:w new:w)",
		  .chmod_mode = 0200,
		  .orig.how.flags = O_WRONLY, .orig.mode  = 0300,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300 },
		{ .name = "same mode (mode:rw old:rw new:rw)",
		  .chmod_mode = 0600,
		  .orig.how.flags =   O_RDWR, .orig.mode  = 0700,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700 },
		{ .name = "same mode (mode:rw old:rw new:r)",
		  .chmod_mode = 0600,
		  .orig.how.flags =   O_RDWR, .orig.mode  = 0700,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500 },
		{ .name = "same mode (mode:rw old:rw new:w)",
		  .chmod_mode = 0600,
		  .orig.how.flags =   O_RDWR, .orig.mode  = 0700,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300 },

		/*
		 * Re-opening with a different mode will always fail (with an obvious
		 * carve-out for privileged users).
		 */
		{ .name = "different mode (mode:rw old:r new:w)",
		  .chmod_mode = 0600,
		  .orig.how.flags = O_RDONLY, .orig.mode  = 0500,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300, .new.err = err_access },
		{ .name = "different mode (mode:rw old:w new:r)",
		  .chmod_mode = 0600,
		  .orig.how.flags = O_WRONLY, .orig.mode  = 0300,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500, .new.err = err_access },
		{ .name = "different mode (mode:rw old:r new:rw)",
		  .chmod_mode = 0600,
		  .orig.how.flags = O_RDONLY, .orig.mode  = 0500,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700, .new.err = err_access },
		{ .name = "different mode (mode:rw old:w new:rw)",
		  .chmod_mode = 0600,
		  .orig.how.flags = O_WRONLY, .orig.mode  = 0300,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700, .new.err = err_access },

		/* Doubly so if they didn't even have permissions at open-time. */
		{ .name = "different mode (mode:r old:r new:w)",
		  .chmod_mode = 0400,
		  .orig.how.flags = O_RDONLY, .orig.mode  = 0500,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300, .new.err = err_access },
		{ .name = "different mode (mode:w old:w new:r)",
		  .chmod_mode = 0200,
		  .orig.how.flags = O_WRONLY, .orig.mode  = 0300,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500, .new.err = err_access },
		{ .name = "different mode (mode:r old:r new:rw)",
		  .chmod_mode = 0400,
		  .orig.how.flags = O_RDONLY, .orig.mode  = 0500,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700, .new.err = err_access },
		{ .name = "different mode (mode:w old:w new:rw)",
		  .chmod_mode = 0200,
		  .orig.how.flags = O_WRONLY, .orig.mode  = 0300,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700, .new.err = err_access },

		/* O_PATH re-opens (of ordinary files) will always work. */
		{ .name = "O_PATH ordinary file (mode:_ old:RW new:w)",
		  .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0070,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300 },
		{ .name = "O_PATH ordinary file (mode:_ old:RW new:r)",
		  .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0070,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500 },
		{ .name = "O_PATH ordinary file (mode:_ old:RW new:rw)",
		  .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0070,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700 },

		/* O_PATH inherits the original magic-link mode. */
		{ .name = "O_PATH magic-link (mode:rw old:r new:R)",
		  .chmod_mode = 0600,
		  .orig.how.flags = O_RDONLY, .orig.mode  = 0500,
		  .new.how.flags  =   O_PATH, .new.mode   = 0050 },
		{ .name = "O_PATH magic-link (mode:rw old:w new:W)",
		  .chmod_mode = 0600,
		  .orig.how.flags = O_WRONLY, .orig.mode  = 0300,
		  .new.how.flags  =   O_PATH, .new.mode   = 0030 },
		{ .name = "O_PATH magic-link (mode:rw old:rw new:RW)",
		  .chmod_mode = 0600,
		  .orig.how.flags =   O_RDWR, .orig.mode  = 0700,
		  .new.how.flags  =   O_PATH, .new.mode   = 0070 },

		/*
		 * openat2(2) UPGRADE_NO* flags. In the privileged case, the re-open
		 * will work but the mode will still be scoped to the mode (or'd with
		 * the open acc_mode).
		 */
		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-RW] new:r)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0010,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD | UPGRADE_NOWRITE,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500, .new.err = err_access },
		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-RW] new:w)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0010,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD | UPGRADE_NOWRITE,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300, .new.err = err_access },
		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-RW] new:rw)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0010,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD | UPGRADE_NOWRITE,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700, .new.err = err_access },

		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-W] new:r)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0050,
		  .orig.how.upgrade_mask = UPGRADE_NOWRITE,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500 },

		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-R] new:w)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0030,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300 },

		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-R] new:r)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0030,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500, .new.err = err_access },
		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-W] new:w)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0050,
		  .orig.how.upgrade_mask = UPGRADE_NOWRITE,
		  .new.how.flags  = O_WRONLY, .new.mode   = 0300, .new.err = err_access },
		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-R] new:rw)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0030,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700, .new.err = err_access },
		{ .name = "O_PATH upgrade mask (mode:_ old:RW[-W] new:rw)",
		  .openat2_only = true,       .chmod_mode = 0000,
		  .orig.how.flags =   O_PATH, .orig.mode  = 0050,
		  .orig.how.upgrade_mask = UPGRADE_NOWRITE,
		  .new.how.flags  =   O_RDWR, .new.mode   = 0700, .new.err = err_access },

		/*
		 * O_PATH chained magic-links will inherit the limitations of
		 * the first magic-link.
		 *
		 * TODO: Really this should also be done with /proc/self/fd/.
		 */
		{ .name = "O_PATH chained magic-link of /proc/self/exe (old:R new:r)",
		  .srcpath = "/proc/self/exe",
		  .orig.how.flags =   O_PATH, .orig.mode  = 0050,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500 },
		{ .name = "O_PATH chained magic-link of /proc/self/exe (old:R new:R)",
		  .srcpath = "/proc/self/exe",
		  .orig.how.flags = O_PATH, .orig.mode  = 0050,
		  .new.how.flags  = O_PATH, .new.mode   = 0050 },
		{ .name = "O_PATH chained magic-link of /proc/self/exe (old:R new:w)",
		  .srcpath = "/proc/self/exe",
		  .orig.how.flags =   O_PATH, .orig.mode  = 0050,
		  .new.how.flags  = O_WRONLY, .new.err    = err_access ?: -ETXTBSY },
		{ .name = "O_PATH chained magic-link of /proc/self/exe (old:R new:rw)",
		  .srcpath = "/proc/self/exe",
		  .orig.how.flags =   O_PATH, .orig.mode  = 0050,
		  .new.how.flags  =   O_RDWR, .new.err    = err_access ?: -ETXTBSY },

		/* O_PATH chained magic-links using UPGRADE_NO* flags. */
		{ .name = "O_PATH chained magic-link of /proc/self/exe (old:R new:R[-R])",
		  .srcpath = "/proc/self/exe",
		  .orig.how.flags = O_PATH, .orig.mode  = 0050,
		  .new.how.flags  = O_PATH, .new.mode   = 0010,
		  .new.how.upgrade_mask = UPGRADE_NOREAD },
		{ .name = "O_PATH chained magic-link of /proc/self/exe (old:R[-R] new:_)",
		  .openat2_only = true,     .srcpath = "/proc/self/exe",
		  .orig.how.flags = O_PATH, .orig.mode  = 0010,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD,
		  .new.how.flags  = O_PATH, .new.mode   = 0010},
		{ .name = "O_PATH chained magic-link of /proc/self/exe (old:R[-R] new:r)",
		  .openat2_only = true,       .srcpath = "/proc/self/exe",
		  .orig.how.flags =   O_PATH, .orig.mode  = 0010,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD,
		  .new.how.flags  = O_RDONLY, .new.mode   = 0500, .new.err = err_access },

		{ .name = "O_PATH chained magic-link (mode:_ old:RW new:RW)",
		  .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0070,
		  .new.how.flags  = O_PATH, .new.mode   = 0070 },
		{ .name = "O_PATH chained magic-link (mode:_ old:RW new:RW[-RW])",
		  .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0070,
		  .new.how.flags  = O_PATH, .new.mode   = 0010,
		  .new.how.upgrade_mask = UPGRADE_NOREAD | UPGRADE_NOWRITE },
		{ .name = "O_PATH chained magic-link (mode:_ old:RW new:RW[-R])",
		  .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0070,
		  .new.how.flags  = O_PATH, .new.mode   = 0030,
		  .new.how.upgrade_mask = UPGRADE_NOREAD },
		{ .name = "O_PATH chained magic-link (mode:_ old:RW new:RW[-W])",
		  .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0070,
		  .new.how.flags  = O_PATH, .new.mode   = 0050,
		  .new.how.upgrade_mask = UPGRADE_NOWRITE },

		{ .name = "O_PATH chained magic-link (mode:_ old:RW[-RW] new:_)",
		  .openat2_only = true,     .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0010,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD | UPGRADE_NOWRITE,
		  .new.how.flags  = O_PATH, .new.mode   = 0010 },

		{ .name = "O_PATH chained magic-link (mode:_ old:RW[-R] new:W)",
		  .openat2_only = true,     .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0030,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD,
		  .new.how.flags  = O_PATH, .new.mode   = 0030 },
		{ .name = "O_PATH chained magic-link (mode:_ old:RW[-R] new:W[-W])",
		  .openat2_only = true,     .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0030,
		  .orig.how.upgrade_mask = UPGRADE_NOREAD,
		  .new.how.flags  = O_PATH, .new.mode   = 0010,
		  .new.how.upgrade_mask = UPGRADE_NOWRITE },

		{ .name = "O_PATH chained magic-link (mode:_ old:RW[-W] new:R)",
		  .openat2_only = true,     .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0050,
		  .orig.how.upgrade_mask = UPGRADE_NOWRITE,
		  .new.how.flags  = O_PATH, .new.mode   = 0050 },
		{ .name = "O_PATH chained magic-link (mode:_ old:RW[-W] new:R[-R])",
		  .openat2_only = true,     .chmod_mode = 0000,
		  .orig.how.flags = O_PATH, .orig.mode  = 0050,
		  .orig.how.upgrade_mask = UPGRADE_NOWRITE,
		  .new.how.flags  = O_PATH, .new.mode   = 0010,
		  .new.how.upgrade_mask = UPGRADE_NOREAD },
	};

	BUILD_BUG_ON(ARRAY_LEN(tests) != NUM_REOPEN_ORDINARY_TESTS);

	for (int i = 0; i < ARRAY_LEN(tests); i++) {
		int fd;
		const char *src = tmpfile;
		struct reopen_test *test = &tests[i];
		void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;

		if (test->srcpath)
			src = test->srcpath;

		if (test->openat2_only)
			goto openat2;

		if (src == tmpfile)
			E_chmod(src, test->chmod_mode);
		fd = sys_openat(AT_FDCWD, src, &test->orig.how);
		E_assert(fd >= 0, "open '%s' failed: %m\n", src);
		if (src == tmpfile)
			E_chmod(src, 0700);

		if (reopen(fd, test)) {
			resultfn = ksft_test_result_fail;
			ksft_print_msg("openat reopen failed\n");
		}
		close(fd);

openat2:
		if (src == tmpfile)
			E_chmod(src, test->chmod_mode);
		fd = sys_openat2(AT_FDCWD, src, &test->orig.how);
		E_assert(fd >= 0, "open '%s' failed: %m\n", src);
		if (src == tmpfile)
			E_chmod(src, 0700);

		if (reopen(fd, test)) {
			resultfn = ksft_test_result_fail;
			ksft_print_msg("openat2 reopen failed\n");
		}
		close(fd);

		if (!test->new.err)
			resultfn("%s%s %s succeeds\n",
				 privileged ? "privileged " : "",
				 test->openat2_only ? "openat2" : "openat(+2)",
				 test->name);
		else
			resultfn("%s%s %s fails with %d (%s)\n",
				 privileged ? "privileged " : "",
				 test->openat2_only ? "openat2" : "openat(+2)",
				 test->name, test->new.err,
				 strerror(-test->new.err));
		fflush(stdout);
	}

	unlink(tmpfile);
}

#define NUM_FLIPFLOP_RACE_TESTS 2

struct flipflop_test {
	int target_fd, dummy_fd, attacker_fd;
};

int flipflopper(void *arg)
{
	struct flipflop_test *test = arg;

	/* If the parent (the test process) dies, kill ourselves too. */
	E_prctl(PR_SET_PDEATHSIG, SIGKILL);

	for (;;) {
		dup2(test->target_fd, test->attacker_fd);
		dup2(test->dummy_fd, test->attacker_fd);
	}

	return 1;
}

#define FLIPFLOP_ROUNDS 500000
#define STACK_SIZE (1024 * 1024)
static char flipflop_stack[STACK_SIZE];

void test_reopen_flipflop(void)
{
	pid_t child;
	int procfs_failures = 0, emptypath_failures = 0;
	struct flipflop_test test = {};
	void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;

	int tmpfd;
	char tmpfile[] = "/tmp/ksft-openat2-reopen-testfile.XXXXXX";

	tmpfd = mkstemp(tmpfile);
	E_assert(tmpfd >= 0, "mkstemp failed: %m\n");
	close(tmpfd);

	test.target_fd = open(tmpfile, O_RDONLY);
	test.dummy_fd = open("/dev/null", O_RDWR);
	/* Get an fd to target for the attack. */
	test.attacker_fd = dup(test.dummy_fd);

	/* We need to share our fdtable with the flipper. */
	child = clone(flipflopper, flipflop_stack + STACK_SIZE,
		      CLONE_FILES, &test);
	E_assert(child >= 0, "clone() failed: %m\n");

	for (int i = 0; i < FLIPFLOP_ROUNDS; i++) {
		int newfd;
		struct open_how how = { .flags = O_WRONLY };

		newfd = reopen_proc(test.attacker_fd, how);
		if (newfd >= 0) {
			/* Did we open the readonly-fd as O_WRONLY? */
			if (fdequal(newfd, test.target_fd, NULL))
				procfs_failures++;
			close(newfd);
		}

		newfd = reopen_oemptypath(test.attacker_fd, how);
		if (newfd >= 0) {
			/* Did we open the readonly-fd as O_WRONLY? */
			if (fdequal(newfd, test.target_fd, NULL))
				emptypath_failures++;
			close(newfd);
		}
	}

	if (procfs_failures + emptypath_failures > 0) {
		resultfn = ksft_test_result_fail;
		ksft_print_msg("illegal re-opens: procfs=%d + O_EMPTYPATH=%d\n",
			       procfs_failures, emptypath_failures);
	}
	resultfn("flip-flop reopen attack (%d runs, got %d illegal re-opens)\n",
		 FLIPFLOP_ROUNDS, procfs_failures + emptypath_failures);

	/* Should be killed anyway, but might as well make sure. */
	E_kill(child, SIGKILL);
}

void test_xdev_flipflop(void)
{
	pid_t child;
	int procfs_failures = 0;
	struct flipflop_test test = {};
	void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;

	int tmpfd;
	char tmpfile[] = "/tmp/ksft-openat2-xdev-testfile.XXXXXX";

	tmpfd = mkstemp(tmpfile);
	E_assert(tmpfd >= 0, "mkstemp failed: %m\n");
	close(tmpfd);

	test.target_fd = open(tmpfile, O_RDONLY);
	test.dummy_fd = open("/proc", O_RDONLY);
	/* Get an fd to target for the attack. */
	test.attacker_fd = dup(test.dummy_fd);

	/* We need to share our fdtable with the flipper. */
	child = clone(flipflopper, flipflop_stack + STACK_SIZE,
		      CLONE_FILES, &test);
	E_assert(child >= 0, "clone() failed: %m\n");

	for (int i = 0; i < FLIPFLOP_ROUNDS; i++) {
		int newfd;
		struct open_how how = {
			.flags = O_RDONLY,
			.resolve = RESOLVE_NO_XDEV,
		};

		newfd = reopen_proc(test.attacker_fd, how);
		if (newfd >= 0) {
			/* Did we open the readonly-fd as O_WRONLY? */
			if (fdequal(newfd, test.target_fd, NULL))
				procfs_failures++;
			close(newfd);
		}
	}

	if (procfs_failures > 0) {
		resultfn = ksft_test_result_fail;
		ksft_print_msg("illegal opens: procfs=%d\n", procfs_failures);
	}
	resultfn("flip-flop no_xdev attack (%d runs, got %d illegal opens)\n",
		 FLIPFLOP_ROUNDS, procfs_failures);

	/* Should be killed anyway, but might as well make sure. */
	E_kill(child, SIGKILL);
}

#define NUM_TESTS (2 * NUM_REOPEN_ORDINARY_TESTS) + NUM_FLIPFLOP_RACE_TESTS

int main(int argc, char **argv)
{
	bool privileged;

	ksft_print_header();
	ksft_set_plan(NUM_TESTS);
	test_openat2_supported();

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
	test_reopen_flipflop();
	test_xdev_flipflop();

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
