/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 * 1999 Mar 29 rsulack created.
 */

#ifndef	_MACH_KMOD_H_
#define	_MACH_KMOD_H_

#include <mach/kern_return.h>

#define KMOD_CNTL_START		1	// call kmod's start routine
#define KMOD_CNTL_STOP		2	// call kmod's stop routine
#define KMOD_CNTL_RETAIN	3	// increase a kmod's reference count
#define KMOD_CNTL_RELEASE	4	// decrease a kmod's reference count
#define KMOD_CNTL_GET_CMD	5	// get kmod load cmd from kernel

#define KMOD_PACK_IDS(from, to)	(((unsigned long)from << 16) | (unsigned long)to)
#define KMOD_UNPACK_FROM_ID(i)	((unsigned long)i >> 16)
#define KMOD_UNPACK_TO_ID(i)	((unsigned long)i & 0xffff)

#define KMOD_MAX_NAME	64

typedef int kmod_t;
typedef int kmod_control_flavor_t;
typedef void* kmod_args_t;

typedef struct kmod_reference {
	struct kmod_reference	*next;
	struct kmod_info	*info;
} kmod_reference_t;

/**************************************************************************************/
/*	 warning any changes to this structure affect the following macros.	      */	
/**************************************************************************************/

#define KMOD_RETURN_SUCCESS	KERN_SUCCESS
#define KMOD_RETURN_FAILURE	KERN_FAILURE

typedef kern_return_t kmod_start_func_t(struct kmod_info *ki, void *data);
typedef kern_return_t kmod_stop_func_t(struct kmod_info *ki, void *data);

typedef struct kmod_info {
	struct kmod_info 	*next;
	int			info_version;		// version of this structure
	int			id;
	char			name[KMOD_MAX_NAME];
	char			version[KMOD_MAX_NAME];
	int			reference_count;	// # refs to this 
	kmod_reference_t	*reference_list;	// who this refs
	vm_address_t		address;		// starting address
	vm_size_t		size;			// total size
	vm_size_t		hdr_size;		// unwired hdr size
        kmod_start_func_t	*start;
        kmod_stop_func_t	*stop;
} kmod_info_t;

typedef kmod_info_t *kmod_info_array_t;

#define KMOD_INFO_NAME 		kmod_info
#define KMOD_INFO_VERSION	1

#define KMOD_DECL(name, version)							\
	static kmod_start_func_t name ## _module_start;					\
	static kmod_stop_func_t  name ## _module_stop;					\
	kmod_info_t KMOD_INFO_NAME = { 0, KMOD_INFO_VERSION, -1,			\
				       { #name }, { version }, -1, 0, 0, 0, 0,		\
			               name ## _module_start,		\
			               name ## _module_stop };

#define KMOD_EXPLICIT_DECL(name, version, start, stop)					\
	kmod_info_t KMOD_INFO_NAME = { 0, KMOD_INFO_VERSION, -1,			\
				       { #name }, { version }, -1, 0, 0, 0, 0,		\
			               start, stop };

// the following is useful for libaries that don't need their own start and stop functions
#define KMOD_LIB_DECL(name, version)							\
	kmod_info_t KMOD_INFO_NAME = { 0, KMOD_INFO_VERSION, -1,			\
				       { #name }, { version }, -1, 0, 0, 0, 0,		\
			               kmod_default_start,				\
				       kmod_default_stop };


// *************************************************************************************
// kmod kernel to user commands
// *************************************************************************************

#define KMOD_LOAD_EXTENSION_PACKET		1
#define KMOD_LOAD_WITH_DEPENDENCIES_PACKET	2

// for generic packets
#define KMOD_IOKIT_START_RANGE_PACKET		0x1000
#define KMOD_IOKIT_END_RANGE_PACKET		0x1fff

typedef struct kmod_load_extension_cmd {
	int	type;
	char	name[KMOD_MAX_NAME];
} kmod_load_extension_cmd_t;

typedef struct kmod_load_with_dependencies_cmd {
	int	type;
	char	name[KMOD_MAX_NAME];
	char	dependencies[1][KMOD_MAX_NAME];
} kmod_load_with_dependencies_cmd_t;

typedef struct kmod_generic_cmd {
	int	type;
	char	data[1];
} kmod_generic_cmd_t;

#ifdef KERNEL_PRIVATE

extern void kmod_init();

extern kern_return_t kmod_create_fake(char *name, char *version);

extern kmod_info_t *kmod_lookupbyname(char * name);
extern kmod_info_t *kmod_lookupbyid(kmod_t id);

extern kern_return_t kmod_load_extension(char *name);
extern kern_return_t kmod_load_extension_with_dependencies(char *name, char **dependencies);
extern kern_return_t kmod_send_generic(int type, void *data, int size);

extern kmod_start_func_t kmod_default_start;
extern kmod_stop_func_t  kmod_default_stop;

extern kern_return_t kmod_initialize_cpp(kmod_info_t *info);
extern kern_return_t kmod_finalize_cpp(kmod_info_t *info);

extern void kmod_dump(vm_offset_t *addr, unsigned int cnt);

#endif /* KERNEL_PRIVATE */

#endif	/* _MACH_KMOD_H_ */
