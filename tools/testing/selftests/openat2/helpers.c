// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <syscall.h>
#include <limits.h>

#include "helpers.h"

int raw_openat2(int dfd, const char *path, const void *how, size_t size)
{
	int ret = syscall(__NR_openat2, dfd, path, how, size);
	return ret >= 0 ? ret : -errno;
}

int sys_openat2(int dfd, const char *path, const struct open_how *how)
{
	return raw_openat2(dfd, path, how, sizeof(*how));
}

int sys_openat(int dfd, const char *path, const struct open_how *how)
{
	int ret = openat(dfd, path, how->flags, how->mode);
	return ret >= 0 ? ret : -errno;
}

int sys_renameat2(int olddirfd, const char *oldpath,
		  int newdirfd, const char *newpath, unsigned int flags)
{
	int ret = syscall(__NR_renameat2, olddirfd, oldpath,
					  newdirfd, newpath, flags);
	return ret >= 0 ? ret : -errno;
}

int touchat(int dfd, const char *path)
{
	int fd = openat(dfd, path, O_CREAT);
	if (fd >= 0)
		close(fd);
	return fd;
}

char *fdreadlink(int fd)
{
	char *target, *tmp;

	E_asprintf(&tmp, "/proc/self/fd/%d", fd);

	target = malloc(PATH_MAX);
	if (!target)
		ksft_exit_fail_msg("fdreadlink: malloc failed\n");
	memset(target, 0, PATH_MAX);

	E_readlink(tmp, target, PATH_MAX);
	free(tmp);
	return target;
}

bool fdequal(int fd, int dfd, const char *path)
{
	char *fdpath, *dfdpath, *other;
	bool cmp;

	fdpath = fdreadlink(fd);
	dfdpath = fdreadlink(dfd);

	if (!path)
		E_asprintf(&other, "%s", dfdpath);
	else if (*path == '/')
		E_asprintf(&other, "%s", path);
	else
		E_asprintf(&other, "%s/%s", dfdpath, path);

	cmp = !strcmp(fdpath, other);

	free(fdpath);
	free(dfdpath);
	free(other);
	return cmp;
}

void test_openat2_supported(void)
{
	struct open_how how = {};
	int fd = sys_openat2(AT_FDCWD, ".", &how);
	if (fd == -ENOSYS)
		ksft_exit_skip("openat2(2) unsupported on this kernel\n");
	if (fd < 0)
		ksft_exit_fail_msg("openat2(2) supported check failed: %s\n", strerror(-fd));
	close(fd);
}
