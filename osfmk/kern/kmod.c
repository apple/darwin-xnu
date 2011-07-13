/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * Copyright (c) 1999 Apple Inc.  All rights reserved. 
 *
 * HISTORY
 *
 * 1999 Mar 29 rsulack created.
 */

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/kern_return.h>
#include <mach/host_priv_server.h>
#include <mach/vm_map.h>

#include <kern/kern_types.h>
#include <kern/thread.h>

#include <vm/vm_kern.h>

#include <libkern/kernel_mach_header.h>

/*********************************************************************
**********************************************************************
***           KMOD INTERFACE DEPRECATED AS OF SNOWLEOPARD          ***
**********************************************************************
**********************************************************************
* Except for kmod_get_info(), which continues to work for K32 with
* 32-bit clients, all remaining functions in this module remain
* for symbol linkage or MIG support only,
* and return KERN_NOT_SUPPORTED.
*
* Some kernel-internal portions have been moved to
* libkern/OSKextLib.cpp and libkern/c++/OSKext.cpp.
**********************************************************************/

// bsd/sys/proc.h
extern void proc_selfname(char * buf, int size);

#define NOT_SUPPORTED_USER64()    \
    do { \
        char procname[64] = "unknown";  \
        proc_selfname(procname, sizeof(procname));  \
        printf("%s is not supported for 64-bit clients (called from %s)\n",  \
            __FUNCTION__, procname);  \
    } while (0)

#define NOT_SUPPORTED_KERNEL()    \
    do { \
        char procname[64] = "unknown";  \
        proc_selfname(procname, sizeof(procname));  \
        printf("%s is not supported on this kernel architecture (called from %s)\n",  \
            __FUNCTION__, procname);  \
    } while (0)

#if __i386__
// in libkern/OSKextLib.cpp
extern kern_return_t kext_get_kmod_info(
    kmod_info_array_t      * kmod_list,
    mach_msg_type_number_t * kmodCount);
#define KMOD_MIG_UNUSED
#else
#define KMOD_MIG_UNUSED __unused
#endif /* __i386__ */


/*********************************************************************
* Old MIG routines that are no longer supported.
**********************************************************************
* We have to keep these around for ppc, i386, and x86_64. A 32-bit
* user-space client might call into the 64-bit kernel. Only
* kmod_get_info() retains a functional implementation (ppc/i386).
**********************************************************************/
kern_return_t
kmod_create(
    host_priv_t   host_priv __unused,
    vm_address_t  addr __unused,
    kmod_t      * id __unused)
{
    NOT_SUPPORTED_KERNEL();
    return KERN_NOT_SUPPORTED;
}

/********************************************************************/
kern_return_t
kmod_destroy(
    host_priv_t host_priv __unused,
     kmod_t     id __unused)
{
    NOT_SUPPORTED_KERNEL();
    return KERN_NOT_SUPPORTED;
}

/********************************************************************/
kern_return_t
kmod_control(
    host_priv_t              host_priv __unused,
    kmod_t                   id __unused,
    kmod_control_flavor_t    flavor __unused,
    kmod_args_t            * data __unused,
    mach_msg_type_number_t * dataCount __unused)
{
    NOT_SUPPORTED_KERNEL();
    return KERN_NOT_SUPPORTED;
};

/********************************************************************/
kern_return_t
kmod_get_info(
    host_t host __unused,
    kmod_info_array_t * kmod_list KMOD_MIG_UNUSED,
    mach_msg_type_number_t * kmodCount KMOD_MIG_UNUSED);
kern_return_t
kmod_get_info(
    host_t host __unused,
    kmod_info_array_t * kmod_list KMOD_MIG_UNUSED,
    mach_msg_type_number_t * kmodCount KMOD_MIG_UNUSED)
{
#if __i386__
    if (current_task() != kernel_task && task_has_64BitAddr(current_task())) {
        NOT_SUPPORTED_USER64();
        return KERN_NOT_SUPPORTED;
    }
    return kext_get_kmod_info(kmod_list, kmodCount);
#else
    NOT_SUPPORTED_KERNEL();
    return KERN_NOT_SUPPORTED;
#endif /* __i386__ */
}
