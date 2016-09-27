/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/cprotect.h>
#include <sys/malloc.h>
#include <sys/mount_internal.h>
#include <sys/filio.h>
#include <sys/content_protection.h>
#include <libkern/crypto/sha1.h>
#include <libkern/libkern.h>

#define PTR_ADD(type, base, offset)		(type)((uintptr_t)(base) + (offset))

// -- struct cpx --

/*
 * This structure contains the unwrapped key and is passed to the lower layers.
 * It is private so users must use the accessors declared in sys/cprotect.h
 * to read/write it.
 */

// cpx_flags
typedef uint32_t cpx_flags_t;
enum {
	CPX_SEP_WRAPPEDKEY			= 0x01,
	CPX_IV_AES_CTX_INITIALIZED	= 0x02,
	CPX_USE_OFFSET_FOR_IV		= 0x04,

	// Using AES IV context generated from key
	CPX_IV_AES_CTX_VFS			= 0x08,
	CPX_SYNTHETIC_OFFSET_FOR_IV     = 0x10,
};

struct cpx {
#if DEBUG
	uint32_t		cpx_magic1;
#endif
	cpx_flags_t		cpx_flags;
	uint16_t		cpx_max_key_len;
	uint16_t		cpx_key_len;
	aes_encrypt_ctx cpx_iv_aes_ctx;		// Context used for generating the IV
	uint8_t			cpx_cached_key[];
} __attribute__((packed));

// -- cpx_t accessors --

size_t cpx_size(size_t key_size)
{
	size_t size = sizeof(struct cpx) + key_size;

#if DEBUG
	size += 4; // Extra for magic
#endif

	return size;
}

size_t cpx_sizex(const struct cpx *cpx)
{
	return cpx_size(cpx->cpx_max_key_len);
}

cpx_t cpx_alloc(size_t key_len)
{
	cpx_t cpx;

	MALLOC(cpx, cpx_t, cpx_size(key_len), M_TEMP, M_WAITOK);

	cpx_init(cpx, key_len);

	return cpx;
}

#if DEBUG
static const uint32_t cpx_magic1 = 0x7b787063;		// cpx{
static const uint32_t cpx_magic2 = 0x7870637d;		// }cpx
#endif

void cpx_free(cpx_t cpx)
{
#if DEBUG
	assert(cpx->cpx_magic1 == cpx_magic1);
	assert(*PTR_ADD(uint32_t *, cpx, cpx_sizex(cpx) - 4) == cpx_magic2);
#endif
	bzero(cpx->cpx_cached_key, cpx->cpx_max_key_len);
	FREE(cpx, M_TEMP);
}

void cpx_init(cpx_t cpx, size_t key_len)
{
#if DEBUG
	cpx->cpx_magic1 = cpx_magic1;
	*PTR_ADD(uint32_t *, cpx, cpx_size(key_len) - 4) = cpx_magic2;
#endif
	cpx->cpx_flags = 0;
	cpx->cpx_key_len = 0;
	cpx->cpx_max_key_len = key_len;
}

bool cpx_is_sep_wrapped_key(const struct cpx *cpx)
{
	return ISSET(cpx->cpx_flags, CPX_SEP_WRAPPEDKEY);
}

void cpx_set_is_sep_wrapped_key(struct cpx *cpx, bool v)
{
	if (v)
	SET(cpx->cpx_flags, CPX_SEP_WRAPPEDKEY);
	else
	CLR(cpx->cpx_flags, CPX_SEP_WRAPPEDKEY);
}

bool cpx_use_offset_for_iv(const struct cpx *cpx)
{
	return ISSET(cpx->cpx_flags, CPX_USE_OFFSET_FOR_IV);
}

void cpx_set_use_offset_for_iv(struct cpx *cpx, bool v)
{
	if (v)
	SET(cpx->cpx_flags, CPX_USE_OFFSET_FOR_IV);
	else
	CLR(cpx->cpx_flags, CPX_USE_OFFSET_FOR_IV);
}

bool cpx_synthetic_offset_for_iv(const struct cpx *cpx)
{
	return ISSET(cpx->cpx_flags, CPX_SYNTHETIC_OFFSET_FOR_IV);
}

void cpx_set_synthetic_offset_for_iv(struct cpx *cpx, bool v)
{
	if (v)
	SET(cpx->cpx_flags, CPX_SYNTHETIC_OFFSET_FOR_IV);
	else
	CLR(cpx->cpx_flags, CPX_SYNTHETIC_OFFSET_FOR_IV);
}

uint16_t cpx_max_key_len(const struct cpx *cpx)
{
	return cpx->cpx_max_key_len;
}

uint16_t cpx_key_len(const struct cpx *cpx)
{
	return cpx->cpx_key_len;
}

void cpx_set_key_len(struct cpx *cpx, uint16_t key_len)
{
	cpx->cpx_key_len = key_len;

	if (ISSET(cpx->cpx_flags, CPX_IV_AES_CTX_VFS)) {
		/*
		 * We assume that if the key length is being modified, the key
		 * has changed.  As a result, un-set any bits related to the
		 * AES context, if needed. They should be re-generated
		 * on-demand.
		 */
		CLR(cpx->cpx_flags, CPX_IV_AES_CTX_INITIALIZED | CPX_IV_AES_CTX_VFS);
	}
}

bool cpx_has_key(const struct cpx *cpx)
{
	return cpx->cpx_key_len > 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
void *cpx_key(const struct cpx *cpx)
{
	return (void *)cpx->cpx_cached_key;
}
#pragma clang diagnostic pop

void cpx_set_aes_iv_key(struct cpx *cpx, void *iv_key)
{
	aes_encrypt_key128(iv_key, &cpx->cpx_iv_aes_ctx);
	SET(cpx->cpx_flags, CPX_IV_AES_CTX_INITIALIZED | CPX_USE_OFFSET_FOR_IV);
	CLR(cpx->cpx_flags, CPX_IV_AES_CTX_VFS);
}

aes_encrypt_ctx *cpx_iv_aes_ctx(struct cpx *cpx)
{
	if (ISSET(cpx->cpx_flags, CPX_IV_AES_CTX_INITIALIZED))
	return &cpx->cpx_iv_aes_ctx;

	SHA1_CTX sha1ctxt;
	uint8_t digest[SHA_DIGEST_LENGTH]; /* Kiv */

	/* First init the cp_cache_iv_key[] */
	SHA1Init(&sha1ctxt);

	/*
	 * We can only use this when the keys are generated in the AP; As a result
	 * we only use the first 32 bytes of key length in the cache key
	 */
	SHA1Update(&sha1ctxt, cpx->cpx_cached_key, cpx->cpx_key_len);
	SHA1Final(digest, &sha1ctxt);

	cpx_set_aes_iv_key(cpx, digest);
	SET(cpx->cpx_flags, CPX_IV_AES_CTX_VFS);

	return &cpx->cpx_iv_aes_ctx;
}

void cpx_flush(cpx_t cpx)
{
	bzero(cpx->cpx_cached_key, cpx->cpx_max_key_len);
	bzero(&cpx->cpx_iv_aes_ctx, sizeof(cpx->cpx_iv_aes_ctx));
	cpx->cpx_flags = 0;
	cpx->cpx_key_len = 0;
}

bool cpx_can_copy(const struct cpx *src, const struct cpx *dst)
{
	return src->cpx_key_len <= dst->cpx_max_key_len;
}

void cpx_copy(const struct cpx *src, cpx_t dst)
{
	uint16_t key_len = cpx_key_len(src);
	cpx_set_key_len(dst, key_len);
	memcpy(cpx_key(dst), cpx_key(src), key_len);
	dst->cpx_flags = src->cpx_flags;
	if (ISSET(dst->cpx_flags, CPX_IV_AES_CTX_INITIALIZED))
	dst->cpx_iv_aes_ctx = src->cpx_iv_aes_ctx;
}

static struct cp_wrap_func g_cp_wrap_func = {};

static int
cp_lock_vfs_callback(mount_t mp, void *arg)
{
	VFS_IOCTL(mp, FIODEVICELOCKED, arg, 0, vfs_context_kernel());

	return 0;
}

int
cp_key_store_action(cp_key_store_action_t action)
{
	switch (action) {
		case CP_ACTION_LOCKED:
		case CP_ACTION_UNLOCKED:;
			cp_lock_state_t state = (action == CP_ACTION_LOCKED
									 ? CP_LOCKED_STATE : CP_UNLOCKED_STATE);
			return vfs_iterate(0, cp_lock_vfs_callback, (void *)(uintptr_t)state);
		default:
			return -1;
	}
}

int
cp_register_wraps(cp_wrap_func_t key_store_func)
{
  g_cp_wrap_func.new_key = key_store_func->new_key;
  g_cp_wrap_func.unwrapper = key_store_func->unwrapper;
  g_cp_wrap_func.rewrapper = key_store_func->rewrapper;
  /* do not use invalidater until rdar://12170050 goes in ! */
  g_cp_wrap_func.invalidater = key_store_func->invalidater;
  g_cp_wrap_func.backup_key = key_store_func->backup_key;

  return 0;
}

int cp_rewrap_key(cp_cred_t access, uint32_t dp_class,
				  const cp_wrapped_key_t wrapped_key_in,
				  cp_wrapped_key_t wrapped_key_out)
{
	if (!g_cp_wrap_func.rewrapper)
		return ENXIO;
	return g_cp_wrap_func.rewrapper(access, dp_class, wrapped_key_in,
									wrapped_key_out);
}

int cp_new_key(cp_cred_t access, uint32_t dp_class, cp_raw_key_t key_out,
               cp_wrapped_key_t wrapped_key_out)
{
	if (!g_cp_wrap_func.new_key)
		return ENXIO;
	return g_cp_wrap_func.new_key(access, dp_class, key_out, wrapped_key_out);
}

int cp_unwrap_key(cp_cred_t access, const cp_wrapped_key_t wrapped_key_in,
                  cp_raw_key_t key_out)
{
	if (!g_cp_wrap_func.unwrapper)
		return ENXIO;
	return g_cp_wrap_func.unwrapper(access, wrapped_key_in, key_out);
}

int cp_get_backup_key(cp_cred_t access, const cp_wrapped_key_t wrapped_key_in,
                      cp_wrapped_key_t wrapped_key_out)
{
	if (!g_cp_wrap_func.backup_key)
		return ENXIO;
	return g_cp_wrap_func.backup_key(access, wrapped_key_in, wrapped_key_out);
}

int
cp_is_valid_class(int isdir, int32_t protectionclass)
{
	/*
	 * The valid protection classes are from 0 -> N
	 * We use a signed argument to detect unassigned values from
	 * directory entry creation time in HFS.
	 */
	if (isdir) {
		/* Directories are not allowed to have F, but they can have "NONE" */
		return ((protectionclass >= PROTECTION_CLASS_DIR_NONE) &&
				(protectionclass <= PROTECTION_CLASS_D));
	}
	else {
		return ((protectionclass >= PROTECTION_CLASS_A) &&
				(protectionclass <= PROTECTION_CLASS_F));
	}
}

/*
 * Parses versions of the form 12A316, i.e. <major><minor><revision> and
 * returns a uint32_t in the form 0xaabbcccc where aa = <major>,
 * bb = <ASCII char>, cccc = <revision>.
 */
static cp_key_os_version_t
parse_os_version(const char *vers)
{
	const char *p = vers;

	int a = 0;
	while (*p >= '0' && *p <= '9') {
		a = a * 10 + *p - '0';
		++p;
	}

	if (!a)
		return 0;

	int b = *p++;
	if (!b)
		return 0;

	int c = 0;
	while (*p >= '0' && *p <= '9') {
		c = c * 10 + *p - '0';
		++p;
	}

	if (!c)
		return 0;

	return (a & 0xff) << 24 | b << 16 | (c & 0xffff);
}

cp_key_os_version_t
cp_os_version(void)
{
	static cp_key_os_version_t cp_os_version;

	if (cp_os_version)
		return cp_os_version;

	if (!osversion[0])
		return 0;

	cp_os_version = parse_os_version(osversion);
	if (!cp_os_version) {
		printf("cp_os_version: unable to parse osversion `%s'\n", osversion);
		cp_os_version = 1;
	}

	return cp_os_version;
}
