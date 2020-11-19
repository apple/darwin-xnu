/*
 * Copyright (c) 2015-2018 Apple Inc. All rights reserved.
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
//for write protection
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#define PTR_ADD(type, base, offset)             (type)((uintptr_t)(base) + (offset))

// -- struct cpx --

/*
 * This structure contains the unwrapped key and is passed to the lower layers.
 * It is private so users must use the accessors declared in sys/cprotect.h
 * to read/write it.
 */

// cpx_flags defined in cprotect.h
enum {
	CPX_SEP_WRAPPEDKEY                      = 0x01,
	CPX_IV_AES_CTX_INITIALIZED      = 0x02,
	CPX_USE_OFFSET_FOR_IV           = 0x04,

	// Using AES IV context generated from key
	CPX_IV_AES_CTX_VFS                      = 0x08,
	CPX_SYNTHETIC_OFFSET_FOR_IV = 0x10,
	CPX_COMPOSITEKEY            = 0x20,

	//write page protection
	CPX_WRITE_PROTECTABLE           = 0x40
};

/*
 * variable-length CPX structure. See fixed-length variant in cprotect.h
 */
struct cpx {
#if DEBUG
	uint32_t                cpx_magic1;
#endif
	aes_encrypt_ctx         *cpx_iv_aes_ctx_ptr;// Pointer to context used for generating the IV
	cpx_flags_t             cpx_flags;
	uint16_t                cpx_max_key_len;
	uint16_t                cpx_key_len;
	//fixed length up to here.  cpx_cached_key is variable-length
	uint8_t                 cpx_cached_key[];
};

/* Allows us to switch between CPX types */
typedef union cpxunion {
	struct cpx cpx_var;
	fcpx_t cpx_fixed;
} cpxunion_t;

ZONE_DECLARE(cpx_zone, "cpx",
    sizeof(struct fcpx), ZC_ZFREE_CLEARMEM);
ZONE_DECLARE(aes_ctz_zone, "AES ctx",
    sizeof(aes_encrypt_ctx), ZC_ZFREE_CLEARMEM | ZC_NOENCRYPT);

// Note: see struct fcpx defined in sys/cprotect.h

// -- cpx_t accessors --

size_t
cpx_size(size_t key_len)
{
	// This should pick up the 'magic' word in DEBUG for free.
	size_t size = sizeof(struct cpx) + key_len;

	return size;
}

size_t
cpx_sizex(const struct cpx *cpx)
{
	return cpx_size(cpx->cpx_max_key_len);
}

cpx_t
cpx_alloc(size_t key_len, bool needs_ctx)
{
	cpx_t cpx = NULL;

#if CONFIG_KEYPAGE_WP
	/*
	 * Macs only use 1 key per volume, so force it into its own page.
	 * This way, we can write-protect as needed.
	 */
	size_t cpsize = cpx_size(key_len);

	// silence warning for needs_ctx
	(void) needs_ctx;

	if (cpsize < PAGE_SIZE) {
		/*
		 * Don't use MALLOC to allocate the page-sized structure.  Instead,
		 * use kmem_alloc to bypass KASAN since we are supplying our own
		 * unilateral write protection on this page. Note that kmem_alloc
		 * can block.
		 */
		if (kmem_alloc(kernel_map, (vm_offset_t *)&cpx, PAGE_SIZE, VM_KERN_MEMORY_FILE)) {
			/*
			 * returning NULL at this point (due to failed allocation) would just
			 * result in a panic. fall back to attempting a normal MALLOC, and don't
			 * let the cpx get marked PROTECTABLE.
			 */
			MALLOC(cpx, cpx_t, cpx_size(key_len), M_TEMP, M_WAITOK);
		} else {
			//mark the page as protectable, since kmem_alloc succeeded.
			cpx->cpx_flags |= CPX_WRITE_PROTECTABLE;
		}
	} else {
		panic("cpx_size too large ! (%lu)", cpsize);
	}
#else
	/* If key page write protection disabled, just switch to zalloc */

	// error out if you try to request a key that's too big
	if (key_len > VFS_CP_MAX_CACHEBUFLEN) {
		return NULL;
	}

	// the actual key array is fixed-length, but the amount of usable content can vary, via 'key_len'
	cpx = zalloc_flags(cpx_zone, Z_WAITOK | Z_ZERO);

	// if our encryption type needs it, alloc the context
	if (needs_ctx) {
		cpx_alloc_ctx(cpx);
	}

#endif
	cpx_init(cpx, key_len);

	return cpx;
}

int
cpx_alloc_ctx(cpx_t cpx)
{
#if CONFIG_KEYPAGE_WP
	(void) cpx;
#else
	if (cpx->cpx_iv_aes_ctx_ptr) {
		// already allocated?
		return 0;
	}

	cpx->cpx_iv_aes_ctx_ptr = zalloc_flags(aes_ctz_zone, Z_WAITOK | Z_ZERO);
#endif // CONFIG_KEYPAGE_WP

	return 0;
}

void
cpx_free_ctx(cpx_t cpx)
{
#if CONFIG_KEYPAGE_WP
	(void) cpx;
# else
	if (cpx->cpx_iv_aes_ctx_ptr) {
		zfree(aes_ctz_zone, cpx->cpx_iv_aes_ctx_ptr);
	}
#endif // CONFIG_KEYPAGE_WP
}

void
cpx_writeprotect(cpx_t cpx)
{
#if CONFIG_KEYPAGE_WP
	void *cpxstart = (void*)cpx;
	void *cpxend = (void*)((uint8_t*)cpx + PAGE_SIZE);
	if (cpx->cpx_flags & CPX_WRITE_PROTECTABLE) {
		vm_map_protect(kernel_map, (vm_map_offset_t)cpxstart, (vm_map_offset_t)cpxend, (VM_PROT_READ), FALSE);
	}
#else
	(void) cpx;
#endif
	return;
}

#if DEBUG
static const uint32_t cpx_magic1 = 0x7b787063;          // cpx{
static const uint32_t cpx_magic2 = 0x7870637d;          // }cpx
#endif

void
cpx_free(cpx_t cpx)
{
#if DEBUG
	assert(cpx->cpx_magic1 == cpx_magic1);
	assert(*PTR_ADD(uint32_t *, cpx, cpx_sizex(cpx) - 4) == cpx_magic2);
#endif

#if CONFIG_KEYPAGE_WP
	/* unprotect the page before bzeroing */
	void *cpxstart = (void*)cpx;
	void *cpxend = (void*)((uint8_t*)cpx + PAGE_SIZE);
	if (cpx->cpx_flags & CPX_WRITE_PROTECTABLE) {
		vm_map_protect(kernel_map, (vm_map_offset_t)cpxstart, (vm_map_offset_t)cpxend, (VM_PROT_DEFAULT), FALSE);

		//now zero the memory after un-protecting it
		bzero(cpx->cpx_cached_key, cpx->cpx_max_key_len);

		//If we are here, then we used kmem_alloc to get the page. Must use kmem_free to drop it.
		kmem_free(kernel_map, (vm_offset_t)cpx, PAGE_SIZE);
		return;
	}
#else
	// free the context if it wasn't already freed
	cpx_free_ctx(cpx);
	zfree(cpx_zone, cpx);
	return;
#endif
}

void
cpx_init(cpx_t cpx, size_t key_len)
{
#if DEBUG
	cpx->cpx_magic1 = cpx_magic1;
	*PTR_ADD(uint32_t *, cpx, cpx_size(key_len) - 4) = cpx_magic2;
#endif
	cpx->cpx_flags = 0;
	cpx->cpx_key_len = 0;
	assert(key_len <= UINT16_MAX);
	cpx->cpx_max_key_len = (uint16_t)key_len;
}

bool
cpx_is_sep_wrapped_key(const struct cpx *cpx)
{
	return ISSET(cpx->cpx_flags, CPX_SEP_WRAPPEDKEY);
}

void
cpx_set_is_sep_wrapped_key(struct cpx *cpx, bool v)
{
	if (v) {
		SET(cpx->cpx_flags, CPX_SEP_WRAPPEDKEY);
	} else {
		CLR(cpx->cpx_flags, CPX_SEP_WRAPPEDKEY);
	}
}

bool
cpx_is_composite_key(const struct cpx *cpx)
{
	return ISSET(cpx->cpx_flags, CPX_COMPOSITEKEY);
}

void
cpx_set_is_composite_key(struct cpx *cpx, bool v)
{
	if (v) {
		SET(cpx->cpx_flags, CPX_COMPOSITEKEY);
	} else {
		CLR(cpx->cpx_flags, CPX_COMPOSITEKEY);
	}
}

bool
cpx_use_offset_for_iv(const struct cpx *cpx)
{
	return ISSET(cpx->cpx_flags, CPX_USE_OFFSET_FOR_IV);
}

void
cpx_set_use_offset_for_iv(struct cpx *cpx, bool v)
{
	if (v) {
		SET(cpx->cpx_flags, CPX_USE_OFFSET_FOR_IV);
	} else {
		CLR(cpx->cpx_flags, CPX_USE_OFFSET_FOR_IV);
	}
}

bool
cpx_synthetic_offset_for_iv(const struct cpx *cpx)
{
	return ISSET(cpx->cpx_flags, CPX_SYNTHETIC_OFFSET_FOR_IV);
}

void
cpx_set_synthetic_offset_for_iv(struct cpx *cpx, bool v)
{
	if (v) {
		SET(cpx->cpx_flags, CPX_SYNTHETIC_OFFSET_FOR_IV);
	} else {
		CLR(cpx->cpx_flags, CPX_SYNTHETIC_OFFSET_FOR_IV);
	}
}

uint16_t
cpx_max_key_len(const struct cpx *cpx)
{
	return cpx->cpx_max_key_len;
}

uint16_t
cpx_key_len(const struct cpx *cpx)
{
	return cpx->cpx_key_len;
}

void
cpx_set_key_len(struct cpx *cpx, uint16_t key_len)
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

bool
cpx_has_key(const struct cpx *cpx)
{
	return cpx->cpx_key_len > 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
void *
cpx_key(const struct cpx *cpx)
{
	return (void *)cpx->cpx_cached_key;
}
#pragma clang diagnostic pop

void
cpx_set_aes_iv_key(struct cpx *cpx, void *iv_key)
{
	if (cpx->cpx_iv_aes_ctx_ptr) {
		aes_encrypt_key128(iv_key, cpx->cpx_iv_aes_ctx_ptr);
		SET(cpx->cpx_flags, CPX_IV_AES_CTX_INITIALIZED | CPX_USE_OFFSET_FOR_IV);
		CLR(cpx->cpx_flags, CPX_IV_AES_CTX_VFS);
	}
}

aes_encrypt_ctx *
cpx_iv_aes_ctx(struct cpx *cpx)
{
	if (ISSET(cpx->cpx_flags, CPX_IV_AES_CTX_INITIALIZED)) {
		return cpx->cpx_iv_aes_ctx_ptr;
	}

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

	return cpx->cpx_iv_aes_ctx_ptr;
}

void
cpx_flush(cpx_t cpx)
{
	bzero(cpx->cpx_cached_key, cpx->cpx_max_key_len);
	if (cpx->cpx_iv_aes_ctx_ptr) {
		bzero(cpx->cpx_iv_aes_ctx_ptr, sizeof(aes_encrypt_ctx));
	}
	cpx->cpx_flags = 0;
	cpx->cpx_key_len = 0;
}

bool
cpx_can_copy(const struct cpx *src, const struct cpx *dst)
{
	return src->cpx_key_len <= dst->cpx_max_key_len;
}

void
cpx_copy(const struct cpx *src, cpx_t dst)
{
	uint16_t key_len = cpx_key_len(src);
	cpx_set_key_len(dst, key_len);
	memcpy(cpx_key(dst), cpx_key(src), key_len);
	dst->cpx_flags = src->cpx_flags;
	if (ISSET(dst->cpx_flags, CPX_IV_AES_CTX_INITIALIZED)) {
		*(dst->cpx_iv_aes_ctx_ptr) = *(src->cpx_iv_aes_ctx_ptr); // deep copy
	}
}

typedef struct {
	cp_lock_state_t state;
	int             valid_uuid;
	uuid_t          volume_uuid;
} cp_lock_vfs_callback_arg;

static int
cp_lock_vfs_callback(mount_t mp, void *arg)
{
	cp_lock_vfs_callback_arg *callback_arg = (cp_lock_vfs_callback_arg *)arg;

	if (callback_arg->valid_uuid) {
		struct vfs_attr va;
		VFSATTR_INIT(&va);
		VFSATTR_WANTED(&va, f_uuid);

		if (vfs_getattr(mp, &va, vfs_context_current())) {
			return 0;
		}

		if (!VFSATTR_IS_SUPPORTED(&va, f_uuid)) {
			return 0;
		}

		if (memcmp(va.f_uuid, callback_arg->volume_uuid, sizeof(uuid_t))) {
			return 0;
		}
	}

	VFS_IOCTL(mp, FIODEVICELOCKED, (void *)(uintptr_t)callback_arg->state, 0, vfs_context_kernel());
	return 0;
}

int
cp_key_store_action(cp_key_store_action_t action)
{
	cp_lock_vfs_callback_arg callback_arg;

	switch (action) {
	case CP_ACTION_LOCKED:
	case CP_ACTION_UNLOCKED:
		callback_arg.state = (action == CP_ACTION_LOCKED ? CP_LOCKED_STATE : CP_UNLOCKED_STATE);
		memset(callback_arg.volume_uuid, 0, sizeof(uuid_t));
		callback_arg.valid_uuid = 0;
		return vfs_iterate(0, cp_lock_vfs_callback, (void *)&callback_arg);
	default:
		return -1;
	}
}

int
cp_key_store_action_for_volume(uuid_t volume_uuid, cp_key_store_action_t action)
{
	cp_lock_vfs_callback_arg callback_arg;

	switch (action) {
	case CP_ACTION_LOCKED:
	case CP_ACTION_UNLOCKED:
		callback_arg.state = (action == CP_ACTION_LOCKED ? CP_LOCKED_STATE : CP_UNLOCKED_STATE);
		memcpy(callback_arg.volume_uuid, volume_uuid, sizeof(uuid_t));
		callback_arg.valid_uuid = 1;
		return vfs_iterate(0, cp_lock_vfs_callback, (void *)&callback_arg);
	default:
		return -1;
	}
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
		return (protectionclass >= PROTECTION_CLASS_DIR_NONE) &&
		       (protectionclass <= PROTECTION_CLASS_D);
	} else {
		return (protectionclass >= PROTECTION_CLASS_A) &&
		       (protectionclass <= PROTECTION_CLASS_F);
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

	if (!a) {
		return 0;
	}

	int b = *p++;
	if (!b) {
		return 0;
	}

	int c = 0;
	while (*p >= '0' && *p <= '9') {
		c = c * 10 + *p - '0';
		++p;
	}

	if (!c) {
		return 0;
	}

	return (a & 0xff) << 24 | b << 16 | (c & 0xffff);
}

cp_key_os_version_t
cp_os_version(void)
{
	static cp_key_os_version_t cp_os_version;

	if (cp_os_version) {
		return cp_os_version;
	}

	if (!osversion[0]) {
		return 0;
	}

	cp_os_version = parse_os_version(osversion);
	if (!cp_os_version) {
		printf("cp_os_version: unable to parse osversion `%s'\n", osversion);
		cp_os_version = 1;
	}

	return cp_os_version;
}
