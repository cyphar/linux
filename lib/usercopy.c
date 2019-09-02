// SPDX-License-Identifier: GPL-2.0
#include <linux/uaccess.h>
#include <linux/bitops.h>

/* out-of-line parts */

#ifndef INLINE_COPY_FROM_USER
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;
	might_fault();
	if (likely(access_ok(from, n))) {
		kasan_check_write(to, n);
		res = raw_copy_from_user(to, from, n);
	}
	if (unlikely(res))
		memset(to + (n - res), 0, res);
	return res;
}
EXPORT_SYMBOL(_copy_from_user);
#endif

#ifndef INLINE_COPY_TO_USER
unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	might_fault();
	if (likely(access_ok(to, n))) {
		kasan_check_read(from, n);
		n = raw_copy_to_user(to, from, n);
	}
	return n;
}
EXPORT_SYMBOL(_copy_to_user);
#endif

/**
 * check_zeroed_user: check if a userspace buffer only contains zero bytes
 * @from: Source address, in userspace.
 * @size: Size of buffer.
 *
 * This is effectively shorthand for "memchr_inv(from, 0, size) == NULL" for
 * userspace addresses (and is more efficient because we don't care where the
 * first non-zero byte is).
 *
 * Returns:
 *  * 0: There were non-zero bytes present in the buffer.
 *  * 1: The buffer was full of zero bytes.
 *  * -EFAULT: access to userspace failed.
 */
int check_zeroed_user(const void __user *from, size_t size)
{
	unsigned long val;
	uintptr_t align = (uintptr_t) from % sizeof(unsigned long);

	if (unlikely(size == 0))
		return 1;

	from -= align;
	size += align;

	if (!user_access_begin(from, size))
		return -EFAULT;

	unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	if (align)
		val &= ~aligned_byte_mask(align);

	while (size > sizeof(unsigned long)) {
		if (unlikely(val))
			goto done;

		from += sizeof(unsigned long);
		size -= sizeof(unsigned long);

		unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	}

	if (size < sizeof(unsigned long))
		val &= aligned_byte_mask(size);

done:
	user_access_end();
	return (val == 0);
err_fault:
	user_access_end();
	return -EFAULT;
}
EXPORT_SYMBOL(check_zeroed_user);

/**
 * copy_struct_from_user: copy a struct from userspace
 * @dst:   Destination address, in kernel space. This buffer must be @ksize
 *         bytes long.
 * @ksize: Size of @dst struct.
 * @src:   Source address, in userspace.
 * @usize: (Alleged) size of @src struct.
 *
 * Copies a struct from userspace to kernel space, in a way that guarantees
 * backwards-compatibility for struct syscall arguments (as long as future
 * struct extensions are made such that all new fields are *appended* to the
 * old struct, and zeroed-out new fields have the same meaning as the old
 * struct).
 *
 * @ksize is just sizeof(*dst), and @usize should've been passed by userspace.
 * The recommended usage is something like the following:
 *
 *   SYSCALL_DEFINE2(foobar, const struct foo __user *, uarg, size_t, usize)
 *   {
 *      int err;
 *      struct foo karg = {};
 *
 *      if (usize > PAGE_SIZE)
 *        return -E2BIG;
 *      if (usize < FOO_SIZE_VER0)
 *        return -EINVAL;
 *
 *      err = copy_struct_from_user(&karg, sizeof(karg), uarg, usize);
 *      if (err)
 *        return err;
 *
 *      // ...
 *   }
 *
 * There are three cases to consider:
 *  * If @usize == @ksize, then it's copied verbatim.
 *  * If @usize < @ksize, then the userspace has passed an old struct to a
 *    newer kernel. The rest of the trailing bytes in @dst (@ksize - @usize)
 *    are to be zero-filled.
 *  * If @usize > @ksize, then the userspace has passed a new struct to an
 *    older kernel. The trailing bytes unknown to the kernel (@usize - @ksize)
 *    are checked to ensure they are zeroed, otherwise -E2BIG is returned.
 *
 * Returns (in all cases, some data may have been copied):
 *  * -E2BIG:  (@usize > @ksize) and there are non-zero trailing bytes in @src.
 *  * -EFAULT: access to userspace failed.
 */
int copy_struct_from_user(void *dst, size_t ksize,
			  const void __user *src, size_t usize)
{
	size_t size = min(ksize, usize);
	size_t rest = max(ksize, usize) - size;

	/* Deal with trailing bytes. */
	if (usize < ksize) {
		memset(dst + size, 0, rest);
	} else if (usize > ksize) {
		int ret = check_zeroed_user(src + size, rest);
		if (ret <= 0)
			return ret ?: -E2BIG;
	}
	/* Copy the interoperable parts of the struct. */
	if (copy_from_user(dst, src, size))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(copy_struct_from_user);
