/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#ifndef __KERN_KPC_H__
#define __KERN_KPC_H__

/* Kernel interfaces to KPC PMC infrastructure. */

#include <machine/machine_kpc.h>

/* cross-platform class constants */
#define KPC_CLASS_FIXED         (0)
#define KPC_CLASS_CONFIGURABLE  (1)
#define KPC_CLASS_POWER         (2)
#define KPC_CLASS_RAWPMU        (3)

#define KPC_CLASS_FIXED_MASK         (1u << KPC_CLASS_FIXED)
#define KPC_CLASS_CONFIGURABLE_MASK  (1u << KPC_CLASS_CONFIGURABLE)
#define KPC_CLASS_POWER_MASK         (1u << KPC_CLASS_POWER)
#define KPC_CLASS_RAWPMU_MASK        (1u << KPC_CLASS_RAWPMU)

#define KPC_ALL_CPUS (1u << 31)

/* bootstrap */
extern void kpc_init(void);

/* Architecture specific initialisation */
extern void kpc_arch_init(void);

/* Get the bitmask of available classes */
extern uint32_t kpc_get_classes(void);

/* Get the bitmask of currently running counter classes  */
extern uint32_t kpc_get_running(void);

/* Set the bitmask of currently running counter classes. Specify
 * classes = 0 to stop counters
 */
extern int kpc_set_running(uint32_t classes);

/* Read CPU counters */
extern int kpc_get_cpu_counters(boolean_t all_cpus, uint32_t classes, 
                                int *curcpu, uint64_t *buf);

/* Read shadow counters */
extern int kpc_get_shadow_counters( boolean_t all_cpus, uint32_t classes,
                                    int *curcpu, uint64_t *buf );

/* Read current thread's counter accumulations */
extern int kpc_get_curthread_counters(uint32_t *inoutcount, uint64_t *buf);

/* Given a config, how many counters and config registers there are */
extern uint32_t kpc_get_counter_count(uint32_t classes);
extern uint32_t kpc_get_config_count(uint32_t classes);

/* enable/disable thread counting */
extern uint32_t kpc_get_thread_counting(void);
extern int      kpc_set_thread_counting(uint32_t classes);

/* get and set config registers */
extern int kpc_get_config(uint32_t classes, kpc_config_t *current_config);
extern int kpc_set_config(uint32_t classes, kpc_config_t *new_config);

/* get and set PMI period */
extern int kpc_get_period(uint32_t classes, uint64_t *period);
extern int kpc_set_period(uint32_t classes, uint64_t *period);

/* get and set kperf actionid */
extern int kpc_get_actionid(uint32_t classes, uint32_t *actionid);
extern int kpc_set_actionid(uint32_t classes, uint32_t *actionid);

/* hooks on thread create and delete */
extern void kpc_thread_create(thread_t thread);
extern void kpc_thread_destroy(thread_t thread);

/* allocate a buffer big enough for all counters */
extern uint64_t *kpc_counterbuf_alloc(void);
extern void      kpc_counterbuf_free(uint64_t*);

/* whether we're currently accounting into threads */
extern int kpc_threads_counting;

/* AST callback for KPC */
extern void kpc_thread_ast_handler( thread_t thread );
	
/* context switch accounting between two threads */
extern void kpc_switch_context( thread_t old, thread_t new );

/* acquire/release the counters used by the Power Manager */
extern int kpc_force_all_ctrs( task_t task, int val );
extern int kpc_get_force_all_ctrs( void );

/* arch-specific routine for acquire/release the counters used by the Power Manager */
extern int kpc_force_all_ctrs_arch( task_t task, int val );

extern int kpc_set_sw_inc( uint32_t mask );

/* disable/enable whitelist of allowed events */
extern int kpc_get_whitelist_disabled( void );
extern int kpc_disable_whitelist( int val );

/*
 * Allow the Power Manager to register for KPC notification when the counters
 * are acquired/released by a task. The argument is equal to true if the Power
 * Manager can use the counters, otherwise it is equal to false.
 */
extern boolean_t kpc_register_pm_handler(void (*handler)(boolean_t));

/*
 * Is the PMU used by both the power manager and userspace?
 *
 * This is true when the power manager has been registered. It disables certain
 * counter configurations (like RAWPMU) that are incompatible with sharing
 * counters.
 */
extern boolean_t kpc_multiple_clients(void);

/*
 * Is kpc controlling the fixed counters?
 *
 * This returns false when the power manager has requested custom configuration
 * control.
 */
extern boolean_t kpc_controls_fixed_counters(void);

extern void kpc_idle(void);
extern void kpc_idle_exit(void);


/* KPC PRIVATE */
extern uint32_t kpc_actionid[KPC_MAX_COUNTERS];
/* mp operations */
struct kpc_config_remote
{
	uint32_t classes;
	kpc_config_t *configv;
};

extern int kpc_get_fixed_counters(uint64_t *counterv);
extern int kpc_get_configurable_counters(uint64_t *counterv);
extern boolean_t kpc_is_running_fixed(void);
extern boolean_t kpc_is_running_configurable(void);
extern uint32_t kpc_fixed_count(void);
extern uint32_t kpc_configurable_count(void);
extern uint32_t kpc_fixed_config_count(void);
extern uint32_t kpc_configurable_config_count(void);
extern uint32_t kpc_rawpmu_config_count(void);
extern int kpc_get_fixed_config(kpc_config_t *configv);
extern int kpc_get_configurable_config(kpc_config_t *configv);
extern int kpc_get_rawpmu_config(kpc_config_t *configv);
extern uint64_t kpc_fixed_max(void);
extern uint64_t kpc_configurable_max(void);
extern int kpc_set_config_arch(struct kpc_config_remote *mp_config);
extern int kpc_set_period_arch(struct kpc_config_remote *mp_config);
extern void kpc_sample_kperf(uint32_t actionid);

/* Interface for kexts to publish a kpc interface */
struct kpc_driver
{
	uint32_t (*get_classes)(void);
	uint32_t (*get_running)(void);
	int      (*set_running)(uint32_t classes);
	int      (*get_cpu_counters)(boolean_t all_cpus, uint32_t classes, 
	                             int *curcpu, uint64_t *buf);
	int      (*get_curthread_counters)(uint32_t *inoutcount, uint64_t *buf);
	uint32_t (*get_counter_count)(uint32_t classes);
	uint32_t (*get_config_count)(uint32_t classes);
	int      (*get_config)(uint32_t classes, kpc_config_t *current_config);
	int      (*set_config)(uint32_t classes, kpc_config_t *new_config);
	int      (*get_period)(uint32_t classes, uint64_t *period);
	int      (*set_period)(uint32_t classes, uint64_t *period);
};

#endif /* __KERN_KPC_H__ */
