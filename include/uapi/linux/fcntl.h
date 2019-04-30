/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_FCNTL_H
#define _UAPI_LINUX_FCNTL_H

#include <asm/fcntl.h>

#define F_SETLEASE	(F_LINUX_SPECIFIC_BASE + 0)
#define F_GETLEASE	(F_LINUX_SPECIFIC_BASE + 1)

/*
 * Cancel a blocking posix lock; internal use only until we expose an
 * asynchronous lock api to userspace:
 */
#define F_CANCELLK	(F_LINUX_SPECIFIC_BASE + 5)

/* Create a file descriptor with FD_CLOEXEC set. */
#define F_DUPFD_CLOEXEC	(F_LINUX_SPECIFIC_BASE + 6)

/*
 * Request nofications on a directory.
 * See below for events that may be notified.
 */
#define F_NOTIFY	(F_LINUX_SPECIFIC_BASE+2)

/*
 * Set and get of pipe page size array
 */
#define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#define F_GETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 8)

/*
 * Set/Get seals
 */
#define F_ADD_SEALS	(F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS	(F_LINUX_SPECIFIC_BASE + 10)

/*
 * Types of seals
 */
#define F_SEAL_SEAL	0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK	0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW	0x0004	/* prevent file from growing */
#define F_SEAL_WRITE	0x0008	/* prevent writes */
#define F_SEAL_FUTURE_WRITE	0x0010  /* prevent future writes while mapped */
/* (1U << 31) is reserved for signed error codes */

/*
 * Set/Get write life time hints. {GET,SET}_RW_HINT operate on the
 * underlying inode, while {GET,SET}_FILE_RW_HINT operate only on
 * the specific file.
 */
#define F_GET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 11)
#define F_SET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 12)
#define F_GET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 13)
#define F_SET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 14)

/*
 * Valid hint values for F_{GET,SET}_RW_HINT. 0 is "not set", or can be
 * used to clear any hints previously set.
 */
#define RWF_WRITE_LIFE_NOT_SET	0
#define RWH_WRITE_LIFE_NONE	1
#define RWH_WRITE_LIFE_SHORT	2
#define RWH_WRITE_LIFE_MEDIUM	3
#define RWH_WRITE_LIFE_LONG	4
#define RWH_WRITE_LIFE_EXTREME	5

/*
 * Types of directory notifications that may be requested.
 */
#define DN_ACCESS	0x00000001	/* File accessed */
#define DN_MODIFY	0x00000002	/* File modified */
#define DN_CREATE	0x00000004	/* File created */
#define DN_DELETE	0x00000008	/* File removed */
#define DN_RENAME	0x00000010	/* File renamed */
#define DN_ATTRIB	0x00000020	/* File changed attibutes */
#define DN_MULTISHOT	0x80000000	/* Don't remove notifier */

#define AT_FDCWD		-100    /* Special value used to indicate
                                           openat should use the current
                                           working directory. */
#define AT_SYMLINK_NOFOLLOW	0x100   /* Do not follow symbolic links.  */
#define AT_REMOVEDIR		0x200   /* Remove directory instead of
                                           unlinking file.  */
#define AT_SYMLINK_FOLLOW	0x400   /* Follow symbolic links.  */
#define AT_NO_AUTOMOUNT		0x800	/* Suppress terminal automount traversal */
#define AT_EMPTY_PATH		0x1000	/* Allow empty relative pathname */

#define AT_STATX_SYNC_TYPE	0x6000	/* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT	0x0000	/* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC	0x2000	/* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC	0x4000	/* - Don't sync attributes with the server */

#define AT_RECURSIVE		0x8000	/* Apply to the entire subtree */

/**
 * Arguments for how openat2(2) should open the target path. If @extra is zero,
 * then openat2(2) is identical to openat(2).
 *
 * @flags: O_* flags (unknown flags ignored).
 * @mode: O_CREAT file mode (ignored otherwise).
 * @upgrade_mask: restrict how the O_PATH may be re-opened (ignored otherwise).
 * @resolve: RESOLVE_* flags (-EINVAL on unknown flags).
 * @reserved: reserved for future extensions, must be zeroed.
 */
struct open_how {
	__u32 flags;
	union {
		__u16 mode;
		__u16 upgrade_mask;
	};
	__u16 resolve;
	__u64 reserved[7]; /* must be zeroed */
};

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

/* how->upgrade flags for openat2(2). */
/* First bit is reserved for a future UPGRADE_NOEXEC flag. */
#define UPGRADE_NOREAD		0x02 /* Block re-opening with MAY_READ. */
#define UPGRADE_NOWRITE		0x04 /* Block re-opening with MAY_WRITE. */

#endif /* _UAPI_LINUX_FCNTL_H */
