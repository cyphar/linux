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

int sys_openat2(int dfd, const char *path, const struct open_how *how)
{
	int ret = syscall(__NR_openat2, dfd, path, how);
	return ret >= 0 ? ret : -errno;
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

char *openat_flags(unsigned int flags)
{
	char *flagset, *accmode = "(none)";

	switch (flags & 0x03) {
		case O_RDWR:
			accmode = "O_RDWR";
			break;
		case O_RDONLY:
			accmode = "O_RDONLY";
			break;
		case O_WRONLY:
			accmode = "O_WRONLY";
			break;
	}

	E_asprintf(&flagset, "%s%s%s",
		   (flags & O_PATH) ? "O_PATH|" : "",
		   (flags & O_CREAT) ? "O_CREAT|" : "",
		   accmode);

	return flagset;
}

char *openat2_flags(const struct open_how *how)
{
	char *p;
	char *flags_set, *resolve_set, *acc_set, *set;

	flags_set = openat_flags(how->flags);

	E_asprintf(&resolve_set, "%s%s%s%s%s0",
		   (how->resolve & RESOLVE_NO_XDEV) ? "RESOLVE_NO_XDEV|" : "",
		   (how->resolve & RESOLVE_NO_MAGICLINKS) ? "RESOLVE_NO_MAGICLINKS|" : "",
		   (how->resolve & RESOLVE_NO_SYMLINKS) ? "RESOLVE_NO_SYMLINKS|" : "",
		   (how->resolve & RESOLVE_BENEATH) ? "RESOLVE_BENEATH|" : "",
		   (how->resolve & RESOLVE_IN_ROOT) ? "RESOLVE_IN_ROOT|" : "");

	/* Remove trailing "|0". */
	p = strstr(resolve_set, "|0");
	if (p)
		*p = '\0';

	if (how->flags & O_PATH)
		E_asprintf(&acc_set, ", upgrade_mask=%s%s0",
			   (how->upgrade_mask & UPGRADE_NOREAD) ? "UPGRADE_NOREAD|" : "",
			   (how->upgrade_mask & UPGRADE_NOWRITE) ? "UPGRADE_NOWRITE|" : "");
	else if (how->flags & O_CREAT)
		E_asprintf(&acc_set, ", mode=0%o", how->mode);
	else
		acc_set = strdup("");

	/* Remove trailing "|0". */
	p = strstr(acc_set, "|0");
	if (p)
		*p = '\0';

	/* And now generate our flagset. */
	E_asprintf(&set, "[flags=%s, resolve=%s%s]",
		   flags_set, resolve_set, acc_set);

	free(flags_set);
	free(resolve_set);
	free(acc_set);
	return set;
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
	if (!cmp)
		ksft_print_msg("fdequal: expected '%s' but got '%s'\n", other, fdpath);

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
