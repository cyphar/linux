// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <syscall.h>
#include <limits.h>
#include <unistd.h>

#include "../kselftest.h"
#include "helpers.h"

/* Construct a test directory with the following structure:
 *
 * root/
 * |-- a/
 * |   `-- c/
 * `-- b/
 */
int setup_testdir(void)
{
	int dfd;
	char dirname[] = "/tmp/ksft-openat2-rename-attack.XXXXXX";

	/* Make the top-level directory. */
	if (!mkdtemp(dirname))
		ksft_exit_fail_msg("setup_testdir: failed to create tmpdir\n");
	dfd = open(dirname, O_PATH | O_DIRECTORY);
	if (dfd < 0)
		ksft_exit_fail_msg("setup_testdir: failed to open tmpdir\n");

	E_mkdirat(dfd, "a", 0755);
	E_mkdirat(dfd, "b", 0755);
	E_mkdirat(dfd, "a/c", 0755);

	return dfd;
}

/* Swap @dirfd/@a and @dirfd/@b constantly. Parent must kill this process. */
pid_t spawn_attack(int dirfd, char *a, char *b)
{
	pid_t child = fork();
	if (child != 0)
		return child;

	/* If the parent (the test process) dies, kill ourselves too. */
	prctl(PR_SET_PDEATHSIG, SIGKILL);

	/* Swap @a and @b. */
	for (;;)
		renameat2(dirfd, a, dirfd, b, RENAME_EXCHANGE);
	exit(1);
}

#define ROUNDS 400000
void test_rename_attack(void)
{
	int dfd, afd, escaped_count = 0;
	void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;
	pid_t child;

	dfd = setup_testdir();
	afd = openat(dfd, "a", O_PATH);
	if (afd < 0)
		ksft_exit_fail_msg("test_rename_attack: failed to open 'a'\n");

	child = spawn_attack(dfd, "a/c", "b");

	for (int i = 0; i < ROUNDS; i++) {
		int fd;
		bool failed;
		struct open_how how = {
			.flags = O_PATH,
			.resolve = RESOLVE_IN_ROOT,
		};
		char *victim_path = "c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../../c/../..";

		fd = sys_openat2(afd, victim_path, &how);
		if (fd < 0)
			failed = (fd != -EXDEV);
		else
			failed = !fdequal(fd, afd, NULL);

		escaped_count += failed;
		close(fd);
	}

	if (escaped_count > 0)
		resultfn = ksft_test_result_fail;

	resultfn("rename attack fails (expected 0 breakouts in %d runs, got %d)\n",
		 ROUNDS, escaped_count);

	/* Should be killed anyway, but might as well make sure. */
	kill(child, SIGKILL);
}

int main(int argc, char **argv)
{
	ksft_print_header();
	test_openat2_supported();

	test_rename_attack();

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
