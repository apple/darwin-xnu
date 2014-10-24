/*
 * Copyright (c) 2009-2014 Apple Inc. All rights reserved.
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

#ifndef _SYS_CPROTECT_H_
#define	_SYS_CPROTECT_H_

#ifdef __cplusplus
extern "C" {
#endif

#if KERNEL_PRIVATE

#include <sys/cdefs.h>
#include <sys/content_protection.h>
#include <sys/kernel_types.h>
#include <crypto/aes.h>

#include <sys/kdebug.h>

#define CP_CODE(code) FSDBG_CODE(DBG_CONTENT_PROT, code)
/* 
 * Class DBG_FSYSTEM == 0x03
 * Subclass DBG_CONTENT_PROT == 0xCF
 * These debug codes are of the form 0x03CFzzzz
 */

enum {
	CPDBG_OFFSET_IO = CP_CODE(0),	/* 0x03CF0000 */
};

/* normally the debug events are no-ops */
#define CP_DEBUG(x,a,b,c,d,e) do {} while (0);

/* dev kernels only! */
#if !SECURE_KERNEL 

/* KDEBUG events used by content protection subsystem */
#if 0
#undef CP_DEBUG
#define CP_DEBUG KERNEL_DEBUG_CONSTANT
#endif

#endif



#define CP_IV_KEYSIZE             20	/* 16x8 = 128, but SHA1 pushes 20 bytes so keep space for that */
#define CP_MAX_KEYSIZE            32	/* 8x4 = 32, 32x8 = 256 */
#define CP_MAX_CACHEBUFLEN        64	/* Maximum size of cp cache buffer/array */

#define CP_MAX_WRAPPEDKEYSIZE     128	/* The size of the largest allowed key */
#define CP_INITIAL_WRAPPEDKEYSIZE 40
#define CP_V2_WRAPPEDKEYSIZE      40	/* Size of the wrapped key in a v2 EA */
#define CP_V4_RESERVEDBYTES       20	/* Number of reserved bytes in EA still present */

/* lock events from AppleKeyStore */
#define CP_LOCKED_STATE           0 	/* Device is locked */
#define CP_UNLOCKED_STATE         1 	/* Device is unlocked */

#define CP_MAX_STATE			  1 	/* uint8_t ; maximum # of states is 255 */

#define CP_LOCKED_KEYCHAIN        0
#define CP_UNLOCKED_KEYCHAIN      1

/* For struct cprotect: cp_flags */
#define CP_NEEDS_KEYS             0x01	/* File needs persistent keys */
#define CP_KEY_FLUSHED            0x02	/* File's unwrapped key has been purged from memory */
#define CP_NO_XATTR               0x04	/* Key info has not been saved as EA to the FS */
#define CP_OFF_IV_ENABLED         0x08	/* Only go down relative IV route if this flag is set */
#define CP_RELOCATION_INFLIGHT    0x10	/* File with offset IVs is in the process of being relocated. */
#define CP_SEP_WRAPPEDKEY		  0x20  /* Wrapped key delivered from keybag */



/* Content Protection VNOP Operation flags */
#define CP_READ_ACCESS            0x1
#define CP_WRITE_ACCESS           0x2

/*
 * Check for this version when deciding to enable features
 * For iOS 4, CP_CURRENT_MAJOR_VERS = 2.0
 * For iOS 5, CP_CURRENT_MAJOR_VERS = 4.0
 */
#define CONTENT_PROTECTION_XATTR_NAME	"com.apple.system.cprotect"
#define CP_NEW_MAJOR_VERS         4
#define CP_PREV_MAJOR_VERS        2
#define CP_MINOR_VERS             0

/* the class occupies the lowest 5 bits, so there are 32 values (0-31) */
#define CP_EFFECTIVE_CLASSMASK 0x0000001f

/* macros for quick access/typing to mask out the classmask */
#define CP_CLASS(x) ((uint32_t)(CP_EFFECTIVE_CLASSMASK & (x)))

#define CP_CRYPTO_G1	0x00000020

typedef struct cprotect *cprotect_t;
typedef struct cp_wrap_func *cp_wrap_func_t;
typedef struct cp_xattr *cp_xattr_t;

typedef struct cnode * cnode_ptr_t;
//forward declare the struct.
struct hfsmount;

/* Structures passed between HFS and AKS kext */
typedef struct {
	void     *key;
	unsigned key_len;
	void     *iv_key;
	unsigned iv_key_len;
	uint32_t flags;
} cp_raw_key_s;

typedef cp_raw_key_s* cp_raw_key_t;

typedef struct {
	void     *key;
	unsigned key_len;
	uint32_t dp_class;
} cp_wrapped_key_s;

typedef cp_wrapped_key_s* cp_wrapped_key_t;

typedef struct {
	ino64_t  inode;
	uint32_t volume;
	pid_t    pid;
	uid_t    uid;
} cp_cred_s;

typedef cp_cred_s* cp_cred_t;

/* The wrappers are invoked on the AKS kext */
typedef int unwrapper_t(cp_cred_t access, const cp_wrapped_key_t wrapped_key_in, cp_raw_key_t key_out);
typedef int rewrapper_t(cp_cred_t access, uint32_t dp_class, const cp_wrapped_key_t wrapped_key_in, cp_wrapped_key_t wrapped_key_out);
typedef int new_key_t(cp_cred_t access, uint32_t dp_class, cp_raw_key_t key_out, cp_wrapped_key_t wrapped_key_out);
typedef int invalidater_t(cp_cred_t access); /* invalidates keys */
typedef int backup_key_t(cp_cred_t access, const cp_wrapped_key_t wrapped_key_in, cp_wrapped_key_t wrapped_key_out);


/* 
 * Flags for Interaction between AKS / Kernel 
 * These are twiddled via the input/output structs in the above
 * wrapper/unwrapper functions.
 */
#define CP_RAW_KEY_WRAPPEDKEY	0x00000001


/* 
 * Flags for Key Generation Behavior 
 *
 * These are passed to cp_generate_keys() and cp_new() in the 
 * flags arguments
 */
#define CP_KEYWRAP_DIFFCLASS    0x00000001 /* wrapping with a different class bag is OK */


/*
 * Runtime-only structure containing the content protection status
 * for the given file.  This is contained within the cnode
 * This is passed down to IOStorageFamily via the bufattr struct
 *
 ******************************************************
 * Some Key calculation information for offset based IV
 ******************************************************
 * Kf  = original 256 bit per file key
 * Kiv = SHA1(Kf), use full Kf, but truncate Kiv to 128 bits
 * Kiv can be cached in the cprotect, so it only has to be calculated once for the file init
 *
 * IVb = Encrypt(Kiv, offset)
 *
 */
struct cprotect {
	uint32_t	cp_flags;
	uint32_t	cp_pclass;  /* persistent class stored on-disk */
	aes_encrypt_ctx	cp_cache_iv_ctx;
	uint32_t	cp_cache_key_len;
	uint8_t		cp_cache_key[CP_MAX_CACHEBUFLEN];
	uint32_t	cp_persistent_key_len;
	void*		cp_backing_cnode;
	uint8_t		cp_persistent_key[];
};

/* Structure to store pointers for AKS functions */
struct cp_wrap_func {
	new_key_t       *new_key;
	unwrapper_t     *unwrapper;
	rewrapper_t     *rewrapper;
	invalidater_t	*invalidater;
	backup_key_t	*backup_key;
};

/*
 * On-disk structure written as the per-file EA payload
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
	u_int32_t flags;
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
	u_int16_t xattr_major_version;
	u_int16_t xattr_minor_version;
	u_int32_t flags;
	u_int32_t persistent_class;
	u_int32_t key_size;
	/* CP V4 Reserved Bytes == 20 */
	u_int8_t reserved[CP_V4_RESERVEDBYTES];
	/* All above fields are fixed regardless of key length (36 bytes) */
	/* Max Wrapped Size == 128 */
	uint8_t   persistent_key[CP_MAX_WRAPPEDKEYSIZE];
} __attribute__((aligned(2), packed));


/*
 * The Root Directory's EA (fileid 1) is special; it defines information about
 * what capabilities the filesystem is using.
 *
 * The data is still stored little endian.
 *
 * Note that this structure is tightly packed: 28 bytes total.
 */
 struct cp_root_xattr {
 	u_int16_t major_version;
 	u_int16_t minor_version;
 	u_int64_t flags;
	u_int8_t reserved[16];
} __attribute__((aligned(2), packed));


/*
 * Functions to check the status of a CP and to query
 * the containing filesystem to see if it is supported.
 */
int cp_vnode_getclass(vnode_t, int *);
int cp_vnode_setclass(vnode_t, uint32_t);
int cp_vnode_transcode(vnode_t vp, void *key, unsigned *len);

int cp_key_store_action(int);
int cp_register_wraps(cp_wrap_func_t);

int cp_entry_init(cnode_ptr_t, struct mount *);
int cp_entry_gentempkeys(struct cprotect **entry_ptr, struct hfsmount *hfsmp);
int cp_needs_tempkeys (struct hfsmount *hfsmp, int* needs);
void cp_entry_destroy(struct cprotect *entry_ptr);
void cp_replace_entry (struct cnode *cp, struct cprotect *newentry);
cnode_ptr_t cp_get_protected_cnode(vnode_t);
int cp_handle_vnop(vnode_t, int, int);
int cp_fs_protected (mount_t);
int cp_getrootxattr (struct hfsmount *hfsmp, struct cp_root_xattr *outxattr);
int cp_setrootxattr (struct hfsmount *hfsmp, struct cp_root_xattr *newxattr);
int cp_setxattr(struct cnode *cp, struct cprotect *entry, struct hfsmount *hfsmp, uint32_t fileid, int options);
int cp_generate_keys (struct hfsmount *hfsmp, struct cnode *cp, int targetclass, 
		uint32_t flags, struct cprotect **newentry);
int cp_setup_newentry (struct hfsmount *hfsmp, struct cnode *dcp, int32_t suppliedclass, 
		mode_t cmode, struct cprotect **tmpentry);
int cp_handle_relocate (cnode_ptr_t cp, struct hfsmount *hfsmp);
int cp_handle_open(struct vnode *vp, int mode);
int cp_get_root_major_vers (struct vnode *vp, uint32_t *level);
int cp_get_default_level (struct vnode *vp, uint32_t *level);
int cp_is_valid_class (int isdir, int32_t protectionclass);
int cp_set_trimmed(struct hfsmount *hfsmp);
int cp_set_rewrapped(struct hfsmount *hfsmp);
int cp_flop_generation (struct hfsmount *hfsmp);


#endif	/* KERNEL_PRIVATE */

#ifdef __cplusplus
};
#endif

#endif /* !_SYS_CPROTECT_H_ */
