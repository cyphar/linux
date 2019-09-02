// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2019 SUSE LLC
 * Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
 */

#include <linux/types.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/string.h>

#define BUFFER_SIZE 64

/*
 * "memset(p, 0, size)" but for user space buffers. Caller must have already
 * checked access_ok(p, size).
 */
static int __memzero_user(void __user *p, size_t s)
{
	const char zeros[BUFFER_SIZE] = {};
	while (s > 0) {
		size_t n = min(s, sizeof(zeros));

		if (__copy_to_user(p, zeros, n))
			return -EFAULT;

		p += n;
		s -= n;
	}
	return 0;
}

/**
 * copy_struct_to_user: copy a struct to user space
 * @dst:   Destination address, in user space.
 * @usize: Size of @dst struct.
 * @src:   Source address, in kernel space.
 * @ksize: Size of @src struct.
 *
 * Copies a struct from kernel space to user space, in a way that guarantees
 * backwards-compatibility for struct syscall arguments (as long as future
 * struct extensions are made such that all new fields are *appended* to the
 * old struct, and zeroed-out new fields have the same meaning as the old
 * struct).
 *
 * @ksize is just sizeof(*dst), and @usize should've been passed by user space.
 * The recommended usage is something like the following:
 *
 *   SYSCALL_DEFINE2(foobar, struct foo __user *, uarg, size_t, usize)
 *   {
 *      int err;
 *      struct foo karg = {};
 *
 *      // do something with karg
 *
 *      err = copy_struct_to_user(uarg, usize, &karg, sizeof(karg));
 *      if (err)
 *        return err;
 *
 *      // ...
 *   }
 *
 * There are three cases to consider:
 *  * If @usize == @ksize, then it's copied verbatim.
 *  * If @usize < @ksize, then kernel space is "returning" a newer struct to an
 *    older user space. In order to avoid user space getting incomplete
 *    information (new fields might be important), all trailing bytes in @src
 *    (@ksize - @usize) must be zerored, otherwise -EFBIG is returned.
 *  * If @usize > @ksize, then the kernel is "returning" an older struct to a
 *    newer user space. The trailing bytes in @dst (@usize - @ksize) will be
 *    zero-filled.
 *
 * Returns (in all cases, some data may have been copied):
 *  * -EFBIG:  (@usize < @ksize) and there are non-zero trailing bytes in @src.
 *  * -EFAULT: access to user space failed.
 */
int copy_struct_to_user(void __user *dst, size_t usize,
			const void *src, size_t ksize)
{
	size_t size = min(ksize, usize);
	size_t rest = abs(ksize - usize);

	if (unlikely(usize > PAGE_SIZE))
		return -EFAULT;
	if (unlikely(!access_ok(dst, usize)))
		return -EFAULT;

	/* Deal with trailing bytes. */
	if (usize < ksize) {
		if (memchr_inv(src + size, 0, rest))
			return -EFBIG;
	} else if (usize > ksize) {
		if (__memzero_user(dst + size, rest))
			return -EFAULT;
	}
	/* Copy the interoperable parts of the struct. */
	if (__copy_to_user(dst, src, size))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(copy_struct_to_user);

/**
 * copy_struct_from_user: copy a struct from user space
 * @dst:   Destination address, in kernel space. This buffer must be @ksize
 *         bytes long.
 * @ksize: Size of @dst struct.
 * @src:   Source address, in user space.
 * @usize: (Alleged) size of @src struct.
 *
 * Copies a struct from user space to kernel space, in a way that guarantees
 * backwards-compatibility for struct syscall arguments (as long as future
 * struct extensions are made such that all new fields are *appended* to the
 * old struct, and zeroed-out new fields have the same meaning as the old
 * struct).
 *
 * @ksize is just sizeof(*dst), and @usize should've been passed by user space.
 * The recommended usage is something like the following:
 *
 *   SYSCALL_DEFINE2(foobar, const struct foo __user *, uarg, size_t, usize)
 *   {
 *      int err;
 *      struct foo karg = {};
 *
 *      err = copy_struct_from_user(&karg, sizeof(karg), uarg, size);
 *      if (err)
 *        return err;
 *
 *      // ...
 *   }
 *
 * There are three cases to consider:
 *  * If @usize == @ksize, then it's copied verbatim.
 *  * If @usize < @ksize, then the user space has passed an old struct to a
 *    newer kernel. The rest of the trailing bytes in @dst (@ksize - @usize)
 *    are to be zero-filled.
 *  * If @usize > @ksize, then the user space has passed a new struct to an
 *    older kernel. The trailing bytes unknown to the kernel (@usize - @ksize)
 *    are checked to ensure they are zeroed, otherwise -E2BIG is returned.
 *
 * Returns (in all cases, some data may have been copied):
 *  * -E2BIG:  (@usize > @ksize) and there are non-zero trailing bytes in @src.
 *  * -E2BIG:  @usize is "too big" (at time of writing, >PAGE_SIZE).
 *  * -EFAULT: access to user space failed.
 */
int copy_struct_from_user(void *dst, size_t ksize,
			  const void __user *src, size_t usize)
{
	size_t size = min(ksize, usize);
	size_t rest = abs(ksize - usize);

	if (unlikely(usize > PAGE_SIZE))
		return -EFAULT;
	if (unlikely(!access_ok(src, usize)))
		return -EFAULT;

	/* Deal with trailing bytes. */
	if (usize < ksize)
		memset(dst + size, 0, rest);
	else if (usize > ksize) {
		const void __user *addr = src + size;
		char buffer[BUFFER_SIZE] = {};

		while (rest > 0) {
			size_t bufsize = min(rest, sizeof(buffer));

			if (__copy_from_user(buffer, addr, bufsize))
				return -EFAULT;
			if (memchr_inv(buffer, 0, bufsize))
				return -E2BIG;

			addr += bufsize;
			rest -= bufsize;
		}
	}
	/* Copy the interoperable parts of the struct. */
	if (__copy_from_user(dst, src, size))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(copy_struct_from_user);
