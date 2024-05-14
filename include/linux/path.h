/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;

typedef enum {
	PATH_RESTRICT_NONE	= 0, /* should only be used for kernel-initiated operations */
	/* Bit 1 is reserved for PATH_RESTRICT_NOEXEC / MAY_EXEC. */
	PATH_RESTRICT_NOWRITE	= 2, /* MAY_WRITE */
	PATH_RESTRICT_NOREAD	= 4, /* MAY_READ */
} path_restrict_t;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
	path_restrict_t restrict_mask;
} __randomize_layout;

extern void path_get(const struct path *);
extern void path_put(const struct path *);

static inline int path_equal(const struct path *path1, const struct path *path2)
{
	return path1->mnt == path2->mnt && path1->dentry == path2->dentry;
}

static inline void path_put_init(struct path *path)
{
	path_put(path);
	*path = (struct path) { };
}

#endif  /* _LINUX_PATH_H */
