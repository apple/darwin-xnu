/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
 * Thread group support routines.
 */
#ifndef _KERN_THREAD_GROUP_H_
#define _KERN_THREAD_GROUP_H_

struct thread_group;

#include <mach/thread_status.h> /* for proc_reg.h / CONFIG_THREAD_GROUPS */

#ifndef CONFIG_THREAD_GROUPS
#error "The platform must define CONFIG_THREAD_GROUPS to 0 or 1"
#endif

#if CONFIG_THREAD_GROUPS
#include <kern/queue.h>
#include <machine/machine_routines.h>

#define THREAD_GROUP_MAX                (CONFIG_TASK_MAX + 10)
#define THREAD_GROUP_MAXNAME            (16)

#define THREAD_GROUP_SYSTEM          0       // kernel (-VM) + launchd
#define THREAD_GROUP_BACKGROUND      1       // background daemons
#define THREAD_GROUP_ADAPTIVE        2       // adaptive daemons
#define THREAD_GROUP_VM              3       // kernel VM threads
#define THREAD_GROUP_IO_STORAGE      4       // kernel io storage threads
#define THREAD_GROUP_PERF_CONTROLLER 5       // kernel CLPC threads

#define THREAD_GROUP_INVALID    UINT64_MAX

/* Thread group flags */
#define THREAD_GROUP_FLAGS_EFFICIENT    0x1
#define THREAD_GROUP_FLAGS_UI_APP       0x2
#define THREAD_GROUP_FLAGS_SMP_RESTRICT 0x4
#define THREAD_GROUP_FLAGS_VALID        (THREAD_GROUP_FLAGS_EFFICIENT | THREAD_GROUP_FLAGS_UI_APP | THREAD_GROUP_FLAGS_SMP_RESTRICT)

__BEGIN_DECLS

void            thread_group_init(void);
void            thread_group_resync(boolean_t create);
struct thread_group *thread_group_create_and_retain(void);
void            thread_group_init_thread(thread_t t, task_t task);
void            thread_group_set_name(struct thread_group *tg, const char *name);
void            thread_group_flags_update_lock(void);
void            thread_group_flags_update_unlock(void);
void            thread_group_set_flags(struct thread_group *tg, uint64_t flags);
void            thread_group_clear_flags(struct thread_group *tg, uint64_t flags);
void            thread_group_set_flags_locked(struct thread_group *tg, uint64_t flags);
void            thread_group_clear_flags_locked(struct thread_group *tg, uint64_t flags);
struct thread_group *thread_group_find_by_name_and_retain(char *name);
struct thread_group *thread_group_find_by_id_and_retain(uint64_t id);
struct thread_group *thread_group_retain(struct thread_group *tg);
void            thread_group_release(struct thread_group *tg);
struct thread_group *thread_group_get(thread_t t);
struct thread_group *thread_group_get_home_group(thread_t t);
void            thread_group_set_bank(thread_t t, struct thread_group *tg);
uint64_t        thread_group_get_id(struct thread_group *tg);
uint32_t        thread_group_count(void);
const char *    thread_group_get_name(struct thread_group *tg);
void *          thread_group_get_machine_data(struct thread_group *tg);
uint32_t        thread_group_machine_data_size(void);
cluster_type_t  thread_group_recommendation(struct thread_group *tg);

typedef         void (*thread_group_iterate_fn_t)(void*, int, struct thread_group *);
kern_return_t   thread_group_iterate_stackshot(thread_group_iterate_fn_t callout, void *arg);
uint64_t kdp_thread_group_get_flags(struct thread_group *);
boolean_t       thread_group_smp_restricted(struct thread_group *tg);
void            thread_group_update_recommendation(struct thread_group *tg, cluster_type_t new_recommendation);

void            thread_set_work_interval_thread_group(thread_t t, struct thread_group *tg, bool auto_join);

#if XNU_KERNEL_PRIVATE
void            thread_group_vm_add(void);
#endif

__END_DECLS

#endif /* CONFIG_THREAD_GROUPS */

#endif // _KERN_THREAD_GROUP_H_
