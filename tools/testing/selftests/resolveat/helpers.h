// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#ifndef __RESOLVEAT_H__
#define __RESOLVEAT_H__

#define _GNU_SOURCE
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

#define ARRAY_LEN(X) (sizeof (X) / sizeof (*(X)))

#ifndef __NR_resolveat
#define __NR_resolveat 435
#define RESOLVE_UPGRADE_NOWRITE	0x002 /* Disallow re-opening for write. */
#define RESOLVE_UPGRADE_NOREAD	0x004 /* Disallow re-opening for read. */
#define RESOLVE_NO_FOLLOW	0x008 /* Don't follow trailing symlinks. */
#define RESOLVE_BENEATH		0x010 /* Block "lexical" trickery like "..", symlinks, absolute paths, etc. */
#define RESOLVE_XDEV		0x020 /* Block mount-point crossings (includes bind-mounts). */
#define RESOLVE_NO_MAGICLINKS	0x040 /* Block procfs-style "magic" symlinks. */
#define RESOLVE_NO_SYMLINKS	0x080 /* Block all symlinks (implies AT_NO_MAGICLINKS). */
#define RESOLVE_IN_ROOT		0x100 /* Scope ".." and "/" resolution to dirfd (like chroot(2)). */
#endif /* __NR_resolveat */

#ifndef O_EMPTYPATH
#define O_EMPTYPATH 040000000
#endif /* O_EMPTYPATH */

#define E_func(func, ...)						\
	do {								\
		if (func(__VA_ARGS__) < 0)				\
			ksft_exit_fail_msg("%s:%d %s failed\n", \
					   __FILE__, __LINE__, #func);\
	} while (0)

#define E_mkdirat(...)   E_func(mkdirat,   __VA_ARGS__)
#define E_symlinkat(...) E_func(symlinkat, __VA_ARGS__)
#define E_touchat(...)   E_func(touchat,   __VA_ARGS__)
#define E_readlink(...)  E_func(readlink,  __VA_ARGS__)
#define E_fstatat(...)   E_func(fstatat,   __VA_ARGS__)
#define E_asprintf(...)  E_func(asprintf,  __VA_ARGS__)
#define E_fchdir(...)    E_func(fchdir,    __VA_ARGS__)
#define E_mount(...)     E_func(mount,     __VA_ARGS__)
#define E_unshare(...)   E_func(unshare,   __VA_ARGS__)
#define E_setresuid(...) E_func(setresuid, __VA_ARGS__)
#define E_chmod(...)     E_func(chmod,     __VA_ARGS__)

#define E_assert(expr, msg, ...)					\
	do {								\
		if (!(expr))						\
			ksft_exit_fail_msg("ASSERT(%s:%d) failed (%s): " msg "\n", \
					   __FILE__, __LINE__, #expr, ##__VA_ARGS__); \
	} while (0)

typedef int (*openfunc_t)(int dfd, const char *path, unsigned int flags);

static int sys_resolveat(int dfd, const char *path, unsigned int flags)
{
	int ret = syscall(__NR_resolveat, dfd, path, flags);
	return ret >= 0 ? ret : -errno;
}

static int sys_openat(int dfd, const char *path, unsigned int flags)
{
	int ret = openat(dfd, path, flags);
	return ret >= 0 ? ret : -errno;
}

static int sys_execveat(int dfd, const char *path,
			char *const argv[], char *const envp[], int flags)
{
	int ret = syscall(SYS_execveat, dfd, path, argv, envp, flags);
	return ret >= 0 ? ret : -errno;
}

static char *resolveat_flags(unsigned int flags)
{
	char *flagset, *p;

	E_asprintf(&flagset, "%s%s%s%s%s%s%s%s0",
		   (flags & RESOLVE_UPGRADE_NOWRITE)	? "RESOLVE_UPGRADE_NOWRITE|" : "",
		   (flags & RESOLVE_UPGRADE_NOREAD)	? "RESOLVE_UPGRADE_NOREAD|" : "",
		   (flags & RESOLVE_NO_FOLLOW)		? "RESOLVE_NO_FOLLOW|" : "",
		   (flags & RESOLVE_BENEATH)		? "RESOLVE_BENEATH|" : "",
		   (flags & RESOLVE_XDEV)		? "RESOLVE_XDEV|" : "",
		   (flags & RESOLVE_NO_MAGICLINKS)	? "RESOLVE_NO_MAGICLINKS|" : "",
		   (flags & RESOLVE_NO_SYMLINKS)	? "RESOLVE_NO_SYMLINKS|" : "",
		   (flags & RESOLVE_IN_ROOT)		? "RESOLVE_IN_ROOT|" : "");

	/* Fix up the trailing |0. */
	p = strstr(flagset, "|0");
	if (p)
		*p = '\0';
	return flagset;
}

static char *openat_flags(unsigned int flags)
{
	char *flagset;
	const char *modeflag = "(none)";

	/* Handle the peculiarity of the ACC_MODE flags. */
	switch (flags & 0x03) {
		case O_RDWR:
			modeflag = "O_RDWR";
			break;
		case O_RDONLY:
			modeflag = "O_RDONLY";
			break;
		case O_WRONLY:
			modeflag = "O_WRONLY";
			break;
	}

	/* TODO: Add more open flags. */
	E_asprintf(&flagset, "%s", modeflag);
	return flagset;
}

static int touchat(int dfd, const char *path)
{
	int fd = openat(dfd, path, O_CREAT);
	if (fd >= 0)
		close(fd);
	return fd;
}

static char *fdreadlink(int fd)
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

static bool fdequal(int fd, int dfd, const char *path)
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

static void test_resolveat_supported(void)
{
	int fd = sys_resolveat(AT_FDCWD, ".", 0);
	if (fd == -ENOSYS)
		ksft_exit_skip("resolveat(2) unsupported on this kernel\n");
	if (fd < 0)
		ksft_exit_fail_msg("resolveat(2) supported check failed: %s\n", strerror(-fd));
	close(fd);
}

#endif /* __RESOLVEAT_H__ */
