/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include <sys/kernel_types.h>

#define PROTECTION_CLASS_A 1
#define PROTECTION_CLASS_B 2
#define PROTECTION_CLASS_C 3
#define PROTECTION_CLASS_D 4
#define PROTECTION_CLASS_E 5

#define KEYSIZE 8				/* 8x4 = 32, 32x8 = 256 */
#define INTEGRITYSIZE 2			/* 2x4 = 8, 8x8 = 64 */

#define LOCKED_STATE 0
#define UNLOCKED_STATE 1

#define LOCKED_KEYCHAIN 0
#define UNLOCKED_KEYCHAIN 1

#define CONTENT_PROTECTION_XATTR_NAME	"com.apple.system.cprotect"

#define kEMBCKeyHandleSpecial	~1

/* SLIST_HEAD(cp_list, cp_entry) cp_head = LIST_HEAD_INITIALIZER(cp_head); */
/* struct cp_list *cprotect_list_headp;                 /\* List head *\/ */

typedef struct cprotect *cprotect_t;
typedef struct cp_wrap_func *cp_wrap_func_t;
typedef struct cp_global_state *cp_global_state_t;
typedef struct cp_xattr *cp_xattr_t;


typedef int wrapper_t(uint32_t properties, void *key_bytes, size_t key_length, void **wrapped_data, uint32_t *wrapped_length);
typedef	int unwrapper_t(uint32_t properties, void *wrapped_data, size_t wrapped_data_length, void **key_bytes, uint32_t *key_length);

struct cprotect {
	uint32_t cache_key[KEYSIZE];
	uint32_t special_data;
	uint32_t pclass;
	uint8_t cache_key_flushed;
	uint8_t lock_state;			/* lock_state: 0 means unlocked. 1 means locked */
};

struct cp_entry {
    SLIST_ENTRY(cp_entry) cp_list;
	struct cprotect *protected_entry;
};

struct cp_wrap_func {
	wrapper_t *wrapper;
	unwrapper_t *unwrapper;
};

struct cp_global_state {
	uint8_t lock_state;
	uint8_t wrap_functions_set;
};

struct cp_xattr {
	uint32_t persistent_class;
	uint8_t persistent_key[32];
	uint8_t persistent_integrity[8];
	uint8_t xattr_version;
};

int cp_create_init(vnode_t, vfs_context_t);
int cp_key_store_action(int);
int cp_register_wraps(cp_wrap_func_t);
struct cprotect *cp_vnode_entry_alloc(void);
void cp_vnode_entry_init(vnode_t);
int cp_vnode_entry_init_needed(vnode_t);
struct cp_xattr * cp_vn_getxattr(vnode_t, vfs_context_t);
int cp_vn_setxattr(vnode_t, uint32_t, vfs_context_t);

#endif	/* KERNEL_PRIVATE */

#ifdef __cplusplus
};
#endif

#endif /* !_SYS_CPROTECT_H_ */
