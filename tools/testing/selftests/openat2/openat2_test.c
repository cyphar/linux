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

#define NUM_OPENAT2_TESTS 7

struct open_how_ext {
	struct open_how inner;
	uint32_t extra1;
	char pad1[128];
	uint32_t extra2;
	char pad2[128];
	uint32_t extra3;
};

struct struct_test {
	struct open_how_ext arg;
	size_t size;
	int err;
};

void test_openat2_struct(void)
{
	struct struct_test tests[] = {
		/* Normal struct. */
		{ .arg.inner.flags = O_RDONLY,
		  .size = sizeof(struct open_how) },
		/* Bigger struct, with zero padding. */
		{ .arg.inner.flags = O_RDONLY,
		  .size = sizeof(struct open_how_ext) },

		/* TODO: Once expanded, check zero-padding. */

		/* Smaller than version-0 struct. */
		{ .arg.inner.flags = O_RDONLY, .size = 0, .err = -EINVAL },
		{ .arg.inner.flags = O_RDONLY,
		  .size = OPEN_HOW_SIZE_VER0 - 1, .err = -EINVAL },
		/* Bigger struct, with non-zero trailing bytes. */
		{ .arg.inner.flags = O_RDONLY, .arg.extra1 = 0xdeadbeef,
		  .size = sizeof(struct open_how_ext), .err = -E2BIG },
		{ .arg.inner.flags = O_RDONLY, .arg.extra2 = 0xfeedcafe,
		  .size = sizeof(struct open_how_ext), .err = -E2BIG },
		{ .arg.inner.flags = O_RDONLY, .arg.extra3 = 0xabad1dea,
		  .size = sizeof(struct open_how_ext), .err = -E2BIG },
	};

	BUILD_BUG_ON(ARRAY_LEN(tests) != NUM_OPENAT2_TESTS);

	for (int i = 0; i < ARRAY_LEN(tests); i++) {
		int fd;
		bool failed;
		void (*resultfn)(const char *msg, ...) = ksft_test_result_pass;
		struct struct_test *test = &tests[i];

		fd = raw_openat2(AT_FDCWD, ".", &test->arg, test->size);
		if (test->err >= 0)
			failed = (fd < 0);
		else
			failed = (fd != test->err);
		if (fd >= 0)
			close(fd);

		if (failed)
			resultfn = ksft_test_result_fail;

		if (test->err >= 0)
			resultfn("openat2([.], [struct], %ld [kernel:%ld]) ==> [.] [got:%s]\n",
				 test->size, sizeof(struct open_how),
				 (fd >= 0) ? "." : strerror(-fd));
		else
			resultfn("openat2([.], [struct], %ld [kernel:%ld]) ==> %s [got:%s]\n",
				 test->size, sizeof(struct open_how),
				 strerror(-test->err),
				 (fd >= 0) ? "." : strerror(-fd));
		fflush(stdout);
	}
}

int main(int argc, char **argv)
{
	ksft_print_header();
	ksft_set_plan(NUM_OPENAT2_TESTS);

	test_openat2_supported();
	test_openat2_struct();

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
