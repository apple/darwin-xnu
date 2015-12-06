/*
 * Copyright (c) 2009-2015 Apple Inc. All rights reserved.
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

#ifndef HFS_CPROTECT_H_
#define	HFS_CPROTECT_H_

#if KERNEL_PRIVATE

#include <sys/cprotect.h>

#include <sys/cdefs.h>
#include <sys/content_protection.h>
#include <sys/kernel_types.h>
#include <crypto/aes.h>
#include <sys/kdebug.h>

#include "hfs.h"
#include "hfs_fsctl.h"

__BEGIN_DECLS

#define CP_IV_KEYSIZE             16	/* 16x8 = 128 */
#define CP_MAX_KEYSIZE			  32	/* 8x4 = 32, 32x8 = 256 */
#define CP_MAX_CACHEBUFLEN        64	/* Maximum size of cp cache buffer/array */

#define CP_INITIAL_WRAPPEDKEYSIZE 40
#define CP_V2_WRAPPEDKEYSIZE      40	/* Size of the wrapped key in a v2 EA */
#define CP_V4_RESERVEDBYTES       16	/* Number of reserved bytes in EA still present */

#define CP_LOCKED_KEYCHAIN        0
#define CP_UNLOCKED_KEYCHAIN      1

#define CONTENT_PROTECTION_XATTR_NAME	"com.apple.system.cprotect"
#define CONTENT_PROTECTION_XATTR_NAME_CHARS				\
	{ 'c', 'o', 'm', '.', 'a', 'p', 'p', 'l', 'e',		\
	'.', 's', 'y', 's', 't', 'e', 'm',					\
	'.', 'c', 'p', 'r', 'o', 't', 'e', 'c', 't' }
#define CP_CURRENT_VERS			CP_VERS_5
#define CP_VERS_5				5		// iOS 8.1
#define CP_VERS_4				4		// iOS 5
#define CP_VERS_2				2		// iOS 4
#define CP_MINOR_VERS           0

/* the class occupies the lowest 5 bits, so there are 32 values (0-31) */
#define CP_EFFECTIVE_CLASSMASK 0x0000001f

typedef uint32_t cp_key_class_t;
typedef uint32_t cp_key_os_version_t;

/* macros for quick access/typing to mask out the classmask */
#define CP_CLASS(x) ((cp_key_class_t)(CP_EFFECTIVE_CLASSMASK & (x)))

#define CP_CRYPTO_G1	0x00000020

typedef struct cp_xattr *cp_xattr_t;
typedef struct cnode * cnode_ptr_t;
//forward declare the struct.
struct hfsmount;

/* 
 * Flags for Key Generation Behavior 
 *
 * These are passed to cp_generate_keys() and cp_new() in the 
 * flags arguments
 */
#define CP_KEYWRAP_DIFFCLASS    0x00000001 /* wrapping with a different class bag is OK */

/*
 * off_rsrc_t: this structure represents an offset and whether or not it's
 * the resource fork.  It's done this way so that we can easily do comparisons
 * i.e.
 *
 *   { 0, data-fork } < { 100, rsrc-fork }
 */

enum {
	OFF_RSRC_BIT = 0x4000000000000000,
};

typedef int64_t off_rsrc_t;

static inline bool off_rsrc_is_rsrc(off_rsrc_t off_rsrc)
{
	return off_rsrc & OFF_RSRC_BIT;
}

static inline off_t off_rsrc_get_off(off_rsrc_t off_rsrc)
{
	return off_rsrc & (OFF_RSRC_BIT - 1);
}

static inline off_rsrc_t off_rsrc_make(off_t offset, bool is_rsrc)
{
	return offset | (is_rsrc ? OFF_RSRC_BIT : 0);
}

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
	CPX_IV_AES_CTX_HFS			= 0x08,
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

// -- struct cp_key_pair --

/*
 * This structure maintains the pair of keys; the persistent, wrapped key that
 * is written to disk, and the unwrapped key (cpx_t) that we pass to lower
 * layers.
 */

typedef struct cp_key_pair {
	uint16_t	cpkp_max_pers_key_len;
	uint16_t	cpkp_pers_key_len;
	struct cpx	cpkp_cpx;

	// cpkp_cpx is variable length so the location of the persistent key varies
	// uint8_t cpkp_persistent_key[];
} cp_key_pair_t;

// -- struct cprotect --

/*
 * Runtime-only structure containing the content protection status for
 * the given file.  This is referenced by the cnode.  It has the
 * variable length key pair at the end.
 */

typedef uint32_t cp_flags_t;
enum {
	CP_NO_XATTR				= 0x01,	/* Key info has not been saved as EA to the FS */
	CP_RELOCATION_INFLIGHT	= 0x02,	/* File with offset IVs is in the process of being relocated. */

	CP_HAS_A_KEY            = 0x08, /* File has a non-zero length key */
};

struct cprotect {
#if DEBUG
	uint32_t						cp_magic1;
#endif
	cp_flags_t						cp_flags;
	cp_key_class_t					cp_pclass;  /* persistent class stored on-disk */
	void*							cp_backing_cnode;
	cp_key_os_version_t				cp_key_os_version;
	cp_key_revision_t				cp_key_revision;
	uint16_t						cp_raw_open_count;
	cp_key_pair_t					cp_keys;	// Variable length
};

// -- On-Disk Structures --

typedef uint32_t cp_xattr_flags_t;
enum {
	/* 
	 * Be careful about using flags 0x02 to 0x20.  Older code used to write
	 * flags that were used for in-memory purposes to disk and therefore
	 * they might be used in V4 structures.  Here's what they were:
	 *
	 *	  CP_KEY_FLUSHED			0x02	Should never have made it to disk
	 *    CP_NO_XATTR				0x04	Should never have made it to disk
	 *	  CP_OFF_IV_ENABLED			0x08	Probably made it to disk
	 *	  CP_RELOCATION_INFLIGHT	0x10	Should never have made it to disk
	 *	  CP_SEP_WRAPPEDKEY			0x20	Probably made it to disk
	 *
	 */

	CP_XAF_NEEDS_KEYS			= 0x0001,	/* V4 only: file needs persistent keys */

};

/*
 * V2 structure written as the per-file EA payload
 * All on-disk multi-byte fields for the CP XATTR must be stored
 * little-endian on-disk.  This means they must be endian swapped to
 * L.E on getxattr() and converted to LE on setxattr().
 *
 * This structure is a fixed length and is tightly packed.
 * 56 bytes total.
 */
struct cp_xattr_v2 {
	u_int16_t xattr_major_version;
	u_int16_t xattr_minor_version;
	cp_xattr_flags_t flags;
	u_int32_t persistent_class;
	u_int32_t key_size;
	uint8_t   persistent_key[CP_V2_WRAPPEDKEYSIZE];
} __attribute__((aligned(2), packed));


/*
 * V4 Content Protection EA On-Disk Layout.
 *
 * This structure must be tightly packed, but the *size can vary*
 * depending on the length of the key.  At MOST, the key length will be
 * CP_MAX_WRAPPEDKEYSIZE, but the length is defined by the key_size field.
 *
 * Either way, the packing must be applied to ensure that the key data is
 * retrievable in the right location relative to the start of the struct.
 *
 * Fully packed, this structure can range from :
 * 		MIN: 36 bytes (no key -- used with directories)
 *		MAX: 164 bytes (with 128 byte key)
 *
 * During runtime we always allocate with the full 128 byte key, but only
 * use as much of the key buffer as needed. It must be tightly packed, though.
 */

struct cp_xattr_v4 {
	u_int16_t			xattr_major_version;
	u_int16_t			xattr_minor_version;
	cp_xattr_flags_t	flags;
	cp_key_class_t		persistent_class;
	u_int32_t			key_size;
	// This field will be zero on older systems
	cp_key_os_version_t	key_os_version;
	/* CP V4 Reserved Bytes == 16 */
	u_int8_t			reserved[CP_V4_RESERVEDBYTES];
	/* All above fields are fixed regardless of key length (36 bytes) */
	/* Max Wrapped Size == 128 */
	uint8_t				persistent_key[CP_MAX_WRAPPEDKEYSIZE];
} __attribute__((aligned(2), packed));

// -- Version 5 --


struct cp_xattr_v5 {
	uint16_t			xattr_major_version;
	uint16_t			xattr_minor_version;
	cp_xattr_flags_t	flags;
	cp_key_class_t		persistent_class;
	cp_key_os_version_t	key_os_version;
	cp_key_revision_t	key_revision;
	uint16_t			key_len;

	// 20 bytes to here

	// Variable length from here
	uint8_t				persistent_key[CP_MAX_WRAPPEDKEYSIZE];


	// Wouldn't be necessary if xattr routines returned just what we ask for
	uint8_t				spare[512];
} __attribute__((aligned(2), packed));

enum {
	CP_XATTR_MIN_LEN = 20,			// Minimum length for all versions
};

/*
 * The Root Directory's EA (fileid 1) is special; it defines information about
 * what capabilities the filesystem is using.
 *
 * The data is still stored little endian.
 */
struct cp_root_xattr {
 	u_int16_t major_version;
 	u_int16_t minor_version;
 	u_int64_t flags;
} __attribute__((aligned(2), packed));

enum {
	CP_ROOT_XATTR_MIN_LEN = 12,
};


// -- Function Prototypes --

int cp_entry_init(cnode_ptr_t, struct mount *);
int cpx_gentempkeys(cpx_t *pcpx, struct hfsmount *hfsmp);
void cp_entry_destroy(struct hfsmount *hfsmp, struct cprotect *entry_ptr);
void cp_replace_entry (struct hfsmount *hfsmp, struct cnode *cp, struct cprotect *newentry);
cnode_ptr_t cp_get_protected_cnode(vnode_t);
int cp_fs_protected (mount_t);
int cp_getrootxattr (struct hfsmount *hfsmp, struct cp_root_xattr *outxattr);
int cp_setrootxattr (struct hfsmount *hfsmp, struct cp_root_xattr *newxattr);
int cp_generate_keys (struct hfsmount *hfsmp, struct cnode *cp,
					  cp_key_class_t targetclass, uint32_t flags,
					  struct cprotect **newentry);
int cp_setup_newentry (struct hfsmount *hfsmp, struct cnode *dcp,
					   cp_key_class_t suppliedclass, mode_t cmode,
					   struct cprotect **tmpentry);
int cp_is_valid_class (int isdir, int32_t protectionclass);
int cp_set_trimmed(struct hfsmount*);
int cp_set_rewrapped(struct hfsmount *);
int cp_flop_generation (struct hfsmount*);
bool cp_is_supported_version(uint16_t version);


typedef struct cp_io_params {
	// The key to use
	cpx_t	cpx;

	/*
	 * The physical offset for this I/O or -1 if unknown (i.e. caller must
	 * do a regular look up).
	 */
	off_t	phys_offset;

	// The maximum length allowed for this I/O
	off_t	max_len;
} cp_io_params_t;

// Return the I/O parameters for this I/O
void cp_io_params(struct hfsmount *hfsmp, cprotect_t cpr, off_rsrc_t off_rsrc,
				  int direction, cp_io_params_t *io_params);

int cp_setxattr(struct cnode *cp, struct cprotect *entry, struct hfsmount *hfsmp,
				uint32_t fileid, int xattr_opts);

typedef void * (* cp_new_alloc_fn)(const void *old, uint16_t pers_key_len,
								   uint16_t cached_key_len,
								   cp_key_pair_t **pcpkp);

int cp_new(cp_key_class_t *newclass_eff, struct hfsmount *hfsmp,
		   struct cnode *cp, mode_t cmode, int32_t keyflags,
		   cp_key_revision_t key_revision,
		   cp_new_alloc_fn alloc_fn, void **pholder);

int cp_rewrap(struct cnode *cp, __unused struct hfsmount *hfsmp,
			  cp_key_class_t *newclass, cp_key_pair_t *cpkp, const void *old_holder,
			  cp_new_alloc_fn alloc_fn, void **pholder);

cprotect_t cp_entry_alloc(cprotect_t old, uint16_t pers_keylen,
						  uint16_t cached_key_len, cp_key_pair_t **pcpkp);

cp_key_os_version_t cp_os_version(void);

cp_key_revision_t cp_next_key_revision(cp_key_revision_t rev);

typedef uint32_t cp_getxattr_options_t;
enum {
	// Return just basic information (not the key)
	CP_GET_XATTR_BASIC_INFO     = 1,
};

int cp_read_xattr_v5(struct hfsmount *hfsmp, struct cp_xattr_v5 *xattr,
					 size_t xattr_len, cprotect_t *pcpr, cp_getxattr_options_t options);


errno_t cp_handle_strategy(buf_t bp);

// -- cp_key_pair_t functions --

size_t cpkp_size(uint16_t pers_key_len, uint16_t cached_key_len);
size_t cpkp_sizex(const cp_key_pair_t *cpkp);
void cpkp_init(cp_key_pair_t *cpkp, uint16_t max_pers_key_len,
			   uint16_t max_cached_key_len);
void cpkp_flush(cp_key_pair_t *cpkp);
void cpkp_copy(const cp_key_pair_t *src, cp_key_pair_t *dst);
uint16_t cpkp_max_pers_key_len(const cp_key_pair_t *cpkp);
uint16_t cpkp_pers_key_len(const cp_key_pair_t *cpkp);
bool cpkp_can_copy(const cp_key_pair_t *src, const cp_key_pair_t *dst);

// -- Private cpx functions --

void cpx_init(cpx_t, size_t key_len);
bool cpx_has_key(const struct cpx *cpx);
uint16_t cpx_max_key_len(const struct cpx *cpx);
cpx_t cpkp_cpx(const cp_key_pair_t *cpkp);
void cpx_copy(const struct cpx *src, cpx_t dst);

// -- Helper Functions --

static inline int cp_get_crypto_generation (cp_key_class_t protclass) {
	if (protclass & CP_CRYPTO_G1) {
		return 1;
	}
	else return 0;
}

__END_DECLS

#endif	/* KERNEL_PRIVATE */

#endif /* !HFS_CPROTECT_H_ */
