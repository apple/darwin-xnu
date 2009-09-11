/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

/*
 * These kxld stubs panic if the kernel is built without kxld support but
 * something tries to use it anyway.
 */

#if !CONFIG_KXLD

#include <libkern/kxld.h>
#include <libkern/kxld_types.h>

#include <kern/debug.h>

kern_return_t
kxld_create_context(KXLDContext **_context __unused,
    KXLDAllocateCallback allocate_callback __unused,
    KXLDLoggingCallback logging_callback __unused,
    KXLDFlags flags __unused, cpu_type_t cputype __unused,
    cpu_subtype_t cpusubtype __unused)
{
    return KERN_SUCCESS;
}

void
kxld_destroy_context(KXLDContext *context __unused)
{
    /* Do nothing */
}

kern_return_t
kxld_link_file(
    KXLDContext *context __unused,
    u_char *file __unused,
    u_long size __unused,
    const char *name,
    void *callback_data __unused,
    u_char **deps __unused,
    u_int ndeps __unused,
    u_char **_linked_object __unused,
    kxld_addr_t *kmod_info_kern __unused,
    u_char **_link_state __unused,
    u_long *_link_state_size __unused,
    u_char **_symbol_file __unused,
    u_long *_symbol_file_size __unused)
{
    panic("%s (%s) called in kernel without kxld support", __PRETTY_FUNCTION__, name);
    return KERN_SUCCESS;
}

boolean_t 
kxld_validate_copyright_string(const char *str __unused)
{
    return TRUE;
}

#endif
