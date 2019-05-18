// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2018-2019 SUSE LLC.
 */

#ifndef __RESOLVEAT_H__
#define __RESOLVEAT_H__

#define _GNU_SOURCE
#include <stdint.h>
#include "../kselftest.h"

#define ARRAY_LEN(X) (sizeof (X) / sizeof (*(X)))

#ifndef SYS_openat2
#ifndef __NR_openat2
#define __NR_openat2 434
#endif /* __NR_openat2 */
#define SYS_openat2 __NR_openat2
#endif /* SYS_openat2 */

/**
 * Arguments for how openat2(2) should open the target path. If @extra is zero,
 * then openat2 is identical to openat(2). Only one of @mode or @upgrade_mask
 * may be set at any given time.
 *
 * @flags: O_* flags (unknown flags ignored).
 * @mode: O_CREAT file mode (ignored otherwise).
 * @upgrade_mask: restrict how the O_PATH may be re-opened (ignored otherwise).
 * @resolve: RESOLVE_* flags (-EINVAL on unknown flags).
 * @reserved: reserved for future extensions, must be zeroed.
 */
struct open_how {
	uint32_t flags;
	union {
		uint16_t mode;
		uint16_t upgrade_mask;
	};
	uint16_t resolve;
	uint64_t reserved[7]; /* must be zeroed */
};

#ifndef RESOLVE_INROOT
/* how->resolve flags for openat2(2). */
#define RESOLVE_NO_XDEV		0x01 /* Block mount-point crossings
					(includes bind-mounts). */
#define RESOLVE_NO_MAGICLINKS	0x02 /* Block traversal through procfs-style
					"magic-links". */
#define RESOLVE_NO_SYMLINKS	0x04 /* Block traversal through all symlinks
					(implies OEXT_NO_MAGICLINKS) */
#define RESOLVE_BENEATH		0x08 /* Block "lexical" trickery like
					"..", symlinks, and absolute
					paths which escape the dirfd. */
#define RESOLVE_IN_ROOT		0x10 /* Make all jumps to "/" and ".."
					be scoped inside the dirfd
					(similar to chroot(2)). */
#endif /* RESOLVE_IN_ROOT */

#ifndef UPGRADE_NOREAD
/* how->upgrade flags for openat2(2). */
/* First bit is reserved for a future UPGRADE_NOEXEC flag. */
#define UPGRADE_NOREAD		0x02 /* Block re-opening with MAY_READ. */
#define UPGRADE_NOWRITE		0x04 /* Block re-opening with MAY_WRITE. */
#endif /* UPGRADE_NOREAD */

#ifndef O_EMPTYPATH
#define	O_EMPTYPATH 040000000
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

typedef int (*openfunc_t)(int dfd, const char *path, const struct open_how *how);

int sys_openat2(int dfd, const char *path, const struct open_how *how);
char *openat2_flags(const struct open_how *how);

int sys_openat(int dfd, const char *path, const struct open_how *how);
char *openat_flags(unsigned int flags);

int sys_renameat2(int olddirfd, const char *oldpath,
		  int newdirfd, const char *newpath, unsigned int flags);

int touchat(int dfd, const char *path);
char *fdreadlink(int fd);
bool fdequal(int fd, int dfd, const char *path);

void test_openat2_supported(void);

#endif /* __RESOLVEAT_H__ */
