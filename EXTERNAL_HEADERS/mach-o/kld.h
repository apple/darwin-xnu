/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _MACHO_KLD_H_
#define _MACHO_KLD_H_

#include <mach-o/loader.h>
#include <stdarg.h>

/*
 * These API's are in libkld.  Both kmodload(8) and /mach_kernel should
 * link with -lkld and then ld(1) will expand -lkld to libkld.dylib or
 * libkld.a depending on if -dynamic or -static is in effect.
 *
 * Note: we are using the __DYNAMIC__ flag to indicate user space kernel
 * linking and __STATIC__ as a synonym of KERNEL.
 */

/*
 * Note that you must supply the following function for error reporting when
 * using any of the functions listed here.
 */
extern void kld_error_vprintf(const char *format, va_list ap);

/*
 * These two are only in libkld.dylib for use by kmodload(8) (user code compiled
 * with the default -dynamic).
 */
#ifdef __DYNAMIC__
__private_extern__ long kld_load_basefile(
    const char *base_filename);

/* Note: this takes only one object file name */
__private_extern__ long kld_load(
    struct mach_header **header_addr,
    const char *object_filename,
    const char *output_filename);

__private_extern__ long kld_load_from_memory(
    struct mach_header **header_addr,
    const char *object_name,
    char *object_addr,
    long object_size,
    const char *output_filename);
#endif /* __DYNAMIC__ */

/*
 * This two are only in libkld.a use by /mach_kernel (kernel code compiled with
 * -static).
 */
#ifdef __STATIC__
/* Note: this api does not write an output file */
__private_extern__ long kld_load_from_memory(
    struct mach_header **header_addr,
    const char *object_name,
    char *object_addr,
    long object_size);
#endif /* __STATIC__ */

__private_extern__ long kld_load_basefile_from_memory(
    const char *base_filename,
    char *base_addr,
    long base_size);

__private_extern__ long kld_unload_all(
    long deallocate_sets);

__private_extern__ long kld_lookup(
    const char *symbol_name,
    unsigned long *value);

__private_extern__ long kld_forget_symbol(
    const char *symbol_name);

__private_extern__ void kld_address_func(
    unsigned long (*func)(unsigned long size, unsigned long headers_size));

#define KLD_STRIP_ALL	0x00000000
#define KLD_STRIP_NONE	0x00000001

__private_extern__ void kld_set_link_options(
    unsigned long link_options);

#endif /* _MACHO_KLD_H_ */
