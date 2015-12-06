/*
 * Copyright (c) 2012-2013, 2015 Apple Inc. All rights reserved.
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

#ifndef _TASK_CORPSE_H_
#define _TASK_CORPSE_H_

#include <stdint.h>
#include <mach/mach_types.h>
#include <kern/kern_cdata.h>

typedef struct kcdata_item	*task_crashinfo_item_t;

/*
 * NOTE: Please update libkdd/kcdata/kcdtypes.c if you make any changes
 * in TASK_CRASHINFO_* types.
 */

#define TASK_CRASHINFO_BEGIN                KCDATA_BUFFER_BEGIN_CRASHINFO
#define TASK_CRASHINFO_STRING_DESC          KCDATA_TYPE_STRING_DESC
#define TASK_CRASHINFO_UINT32_DESC          KCDATA_TYPE_UINT32_DESC
#define TASK_CRASHINFO_UINT64_DESC          KCDATA_TYPE_UINT64_DESC

#define TASK_CRASHINFO_EXTMODINFO           0x801
#define TASK_CRASHINFO_BSDINFOWITHUNIQID    0x802 /* struct proc_uniqidentifierinfo */
#define TASK_CRASHINFO_TASKDYLD_INFO        0x803
#define TASK_CRASHINFO_UUID                 0x804
#define TASK_CRASHINFO_PID                  0x805
#define TASK_CRASHINFO_PPID                 0x806
#define TASK_CRASHINFO_RUSAGE               0x807  /* struct rusage */
#define TASK_CRASHINFO_RUSAGE_INFO          0x808  /* struct rusage_info_current */
#define TASK_CRASHINFO_PROC_NAME            0x809  /* char * */
#define TASK_CRASHINFO_PROC_STARTTIME       0x80B  /* struct timeval64 */
#define TASK_CRASHINFO_USERSTACK            0x80C  /* uint64_t */
#define TASK_CRASHINFO_ARGSLEN              0x80D
#define TASK_CRASHINFO_EXCEPTION_CODES      0x80E  /* mach_exception_data_t */
#define TASK_CRASHINFO_PROC_PATH            0x80F  /* string of len MAXPATHLEN */
#define TASK_CRASHINFO_PROC_CSFLAGS         0x810  /* uint32_t */
#define TASK_CRASHINFO_PROC_STATUS          0x811  /* char */
#define TASK_CRASHINFO_UID                  0x812  /* uid_t */
#define TASK_CRASHINFO_GID                  0x813  /* gid_t */
#define TASK_CRASHINFO_PROC_ARGC            0x814  /* int */
#define TASK_CRASHINFO_PROC_FLAGS           0x815  /* unsigned int */
#define TASK_CRASHINFO_CPUTYPE              0x816  /* cpu_type_t */
#define TASK_CRASHINFO_WORKQUEUEINFO        0x817  /* struct proc_workqueueinfo */
#define TASK_CRASHINFO_RESPONSIBLE_PID      0x818  /* pid_t */
#define TASK_CRASHINFO_DIRTY_FLAGS          0x819  /* int */
#define TASK_CRASHINFO_CRASHED_THREADID     0x81A  /* uint64_t */

#define TASK_CRASHINFO_END                  KCDATA_TYPE_BUFFER_END

/* Deprecated: use the KCDATA_* macros for all future use */
#define CRASHINFO_ITEM_TYPE(item)		  KCDATA_ITEM_TYPE(item)
#define CRASHINFO_ITEM_SIZE(item)		  KCDATA_ITEM_SIZE(item)
#define CRASHINFO_ITEM_DATA_PTR(item)	  KCDATA_ITEM_DATA_PTR(item)

#define CRASHINFO_ITEM_NEXT_HEADER(item)  KCDATA_ITEM_NEXT_HEADER(item)

#define CRASHINFO_ITEM_FOREACH(head)	  KCDATA_ITEM_FOREACH(head)


#ifndef KERNEL
#define task_crashinfo_get_data_with_desc kcdata_get_data_with_desc

#endif /* KERNEL */

#ifdef XNU_KERNEL_PRIVATE

#define CORPSEINFO_ALLOCATION_SIZE (1024 * 1024 * 2)
#define TOTAL_CORPSES_ALLOWED 5



extern kern_return_t task_mark_corpse(task_t task);

extern kern_return_t task_deliver_crash_notification(task_t task);

extern kcdata_descriptor_t task_get_corpseinfo(task_t task);

extern kcdata_descriptor_t  task_crashinfo_alloc_init(
					mach_vm_address_t crash_data_p,
					unsigned size);
extern kern_return_t  task_crashinfo_destroy(kcdata_descriptor_t data);

extern void corpses_init(void);

extern boolean_t corpses_enabled(void);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _TASK_CORPSE_H_ */
