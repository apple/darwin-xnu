/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */

#ifdef  XNU_KERNEL_PRIVATE

#ifndef _KERN_STARTUP_H_
#define _KERN_STARTUP_H_

#include <stdbool.h>
#include <stdint.h>

#include <libkern/section_keywords.h>

__BEGIN_DECLS

#pragma GCC visibility push(hidden)

/*!
 * @enum startup_subsystem_id_t
 *
 * @abstract
 * Represents a stage of kernel intialization, ubnd allows for subsystems
 * to register initializers for a specific stage.
 *
 * @discussion
 * Documentation of each subsystem initialization sequence exists in
 * @file doc/startup.md.
 */
__enum_decl(startup_subsystem_id_t, uint32_t, {
	STARTUP_SUB_NONE = 0,         /**< reserved for the startup subsystem  */

	STARTUP_SUB_TUNABLES,         /**< support for the tunables subsystem  */
	STARTUP_SUB_LOCKS_EARLY,      /**< early locking, before zalloc        */
	STARTUP_SUB_KPRINTF,          /**< kprintf initialization              */

	STARTUP_SUB_PMAP_STEAL,       /**< to perform various pmap carveouts   */
	STARTUP_SUB_VM_KERNEL,        /**< once the kernel VM is ready         */
	STARTUP_SUB_KMEM,             /**< once kmem is ready                  */
	STARTUP_SUB_KMEM_ALLOC,       /**< once kmem_alloc is ready            */
	STARTUP_SUB_ZALLOC,           /**< initialize zalloc and kalloc        */
	STARTUP_SUB_PERCPU,           /**< initialize the percpu subsystem     */
	STARTUP_SUB_LOCKS,            /**< various subsystem locks             */

	STARTUP_SUB_CODESIGNING,      /**< codesigning subsystem               */
	STARTUP_SUB_OSLOG,            /**< oslog and kernel loggging           */
	STARTUP_SUB_MACH_IPC,         /**< Mach IPC                            */
	STARTUP_SUB_SYSCTL,           /**< registers sysctls                   */
	STARTUP_SUB_EARLY_BOOT,       /**< interrupts/premption are turned on  */

	STARTUP_SUB_LOCKDOWN = ~0u,   /**< reserved for the startup subsystem  */
});

/*!
 * Stores the last subsystem to have been fully initialized;
 */
extern startup_subsystem_id_t startup_phase;

/*!
 * @enum startup_debug_t
 *
 * @abstract
 * Flags set in the @c startup_debug global to configure startup debugging.
 */
__options_decl(startup_debug_t, uint32_t, {
	STARTUP_DEBUG_NONE    = 0x00000000,
	STARTUP_DEBUG_VERBOSE = 0x00000001,
});

#if DEBUG || DEVELOPMENT
extern startup_debug_t startup_debug;
#else
#define startup_debug  STARTUP_DEBUG_NONE
#endif

/*!
 * @enum startup_rank
 *
 * @abstract
 * Specifies in which rank a given initializer runs within a given section
 * to register initializers for a specific rank within the subsystem.
 *
 * @description
 * A startup function, declared with @c STARTUP or @c STARTUP_ARG, can specify
 * an rank within the subsystem they initialize.
 *
 * @c STARTUP_RANK_NTH(n) will let callbacks be run at stage @c n (0-based).
 *
 * @c STARTUP_RANK_FIRST, @c STARTUP_RANK_SECOND, @c STARTUP_RANK_THIRD and
 * @c STARTUP_RANK_FOURTH are given as conveniency names for these.
 *
 * @c STARTUP_RANK_MIDDLE is a reserved value that will let startup functions
 * run after all the @c STARTUP_RANK_NTH(n) ones have.
 *
 * @c STARTUP_RANK_NTH_LATE_NTH(n) will let callbacks be run then in @c n rank
 * after the @c STARTUP_RANK_MIDDLE ones (0-based).
 *
 * @c STARTUP_RANK_LAST callbacks will run absolutely last after everything
 * else did for this subsystem.
 */
__enum_decl(startup_rank_t, uint32_t, {
#define STARTUP_RANK_NTH(n) \
	(enum startup_rank)(n)
	STARTUP_RANK_FIRST          = 0,
	STARTUP_RANK_SECOND         = 1,
	STARTUP_RANK_THIRD          = 2,
	STARTUP_RANK_FOURTH         = 3,

	STARTUP_RANK_MIDDLE         = 0x7fffffff,

#define STARTUP_RANK_LATE_NTH(n) \
	(enum startup_rank)(STARTUP_RANK_MIDDLE + 1 + (n))

	STARTUP_RANK_LAST           = 0xffffffff,
});

#if KASAN
/*
 * The use of weird sections that get unmapped confuse the hell out of kasan,
 * so for KASAN leave things in regular __TEXT/__DATA segments
 */
#define STARTUP_CODE_SEGSECT "__TEXT,__text"
#define STARTUP_DATA_SEGSECT "__DATA,__init"
#define STARTUP_HOOK_SEGMENT "__DATA"
#define STARTUP_HOOK_SECTION "__init_entry_set"
#elif defined(__x86_64__)
/* Intel doesn't have a __BOOTDATA but doesn't protect __KLD */
#define STARTUP_CODE_SEGSECT "__TEXT,__text"
#define STARTUP_DATA_SEGSECT "__KLD,__init"
#define STARTUP_HOOK_SEGMENT "__KLD"
#define STARTUP_HOOK_SECTION "__init_entry_set"
#else
/* arm protects __KLD early, so use __BOOTDATA for data */
#define STARTUP_CODE_SEGSECT "__TEXT,__text"
#define STARTUP_DATA_SEGSECT "__BOOTDATA,__init"
#define STARTUP_HOOK_SEGMENT "__BOOTDATA"
#define STARTUP_HOOK_SECTION "__init_entry_set"
#endif

/*!
 * @macro __startup_func
 *
 * @abstract
 * Attribute to place on functions used only during the kernel startup phase.
 *
 * @description
 * Code marked with this attribute will be unmapped after kernel lockdown.
 */
#define __startup_func \
	__PLACE_IN_SECTION(STARTUP_CODE_SEGSECT) \
	__attribute__((noinline, visibility("hidden")))

/*!
 * @macro __startup_data
 *
 * @abstract
 * Attribute to place on globals used during the kernel startup phase.
 *
 * @description
 * Data marked with this attribute will be unmapped after kernel lockdown.
 */
#define __startup_data \
	__PLACE_IN_SECTION(STARTUP_DATA_SEGSECT)

/*!
 * @macro STARTUP
 *
 * @abstract
 * Declares a kernel startup callback.
 */
#define STARTUP(subsystem, rank, func) \
	__STARTUP(func, __LINE__, subsystem, rank, func)

/*!
 * @macro STARTUP_ARG
 *
 * @abstract
 * Declares a kernel startup callback that takes an argument.
 */
#define STARTUP_ARG(subsystem, rank, func, arg) \
	__STARTUP_ARG(func, __LINE__, subsystem, rank, func, arg)

/*!
 * @macro TUNABLE
 *
 * @abstract
 * Declares a read-only kernel tunable that is read from a boot-arg with
 * a default value, without further processing.
 *
 * @param type_t
 * Should be an integer type or bool.
 *
 * @param var
 * The name of the C variable to use for storage.
 *
 * @param key
 * The name of the boot-arg to parse for initialization
 *
 * @param default_value
 * The default value for the tunable if the boot-arg is absent.
 */
#define TUNABLE(type_t, var, key, default_value) \
	SECURITY_READ_ONLY_LATE(type_t) var = default_value; \
	__TUNABLE(type_t, var, key)

/*!
 * @macro TUNABLE_WRITEABLE
 *
 * @abstract
 * Declares a writeable kernel tunable that is read from a boot-arg with
 * a default value, without further processing.
 *
 * @param type_t
 * Should be an integer type or bool.
 *
 * @param var
 * The name of the C variable to use for storage.
 *
 * @param key
 * The name of the boot-arg to parse for initialization
 *
 * @param default_value
 * The default value for the tunable if the boot-arg is absent.
 */
#define TUNABLE_WRITEABLE(type_t, var, key, default_value) \
	type_t var = default_value; \
	__TUNABLE(type_t, var, key)

#pragma mark - internals

#define __TUNABLE(type_t, var, key) \
	static __startup_data char __startup_TUNABLES_name_ ## var[] = key; \
	static __startup_data struct startup_tunable_spec \
	__startup_TUNABLES_spec_ ## var = { \
	    .name = __startup_TUNABLES_name_ ## var, \
	    .var_addr = &var, \
	    .var_len = sizeof(type_t), \
	    .var_is_bool = __builtin_types_compatible_p(bool, type_t), \
	}; \
	__STARTUP_ARG(var, __LINE__, TUNABLES, STARTUP_RANK_FIRST, \
	    kernel_startup_tunable_init, &__startup_TUNABLES_spec_ ## var)


#define __STARTUP1(name, line, subsystem, rank, func, a, b) \
	__PLACE_IN_SECTION(STARTUP_HOOK_SEGMENT "," STARTUP_HOOK_SECTION) \
	static const struct startup_entry \
	__startup_ ## subsystem ## _entry_ ## name ## _ ## line = { \
	    STARTUP_SUB_ ## subsystem, \
	    rank, (typeof(func(a))(*)(const void *))func, b, \
	}

#define __STARTUP(name, line, subsystem, rank, func) \
	__STARTUP1(name, line, subsystem, rank, func, , NULL)

#define __STARTUP_ARG(name, line, subsystem, rank, func, arg) \
	__STARTUP1(name, line, subsystem, rank, func, arg, arg)

struct startup_entry {
	startup_subsystem_id_t subsystem;
	startup_rank_t         rank;
	void                 (*func)(const void *);
	const void            *arg;
};

struct startup_tunable_spec {
	const char *name;
	void       *var_addr;
	int         var_len;
	bool        var_is_bool;
};

/*
 * Kernel and machine startup declarations
 */

/* Initialize kernel */
extern void kernel_startup_bootstrap(void);
extern void kernel_startup_initialize_upto(startup_subsystem_id_t upto);
extern void kernel_startup_tunable_init(const struct startup_tunable_spec *);
extern void kernel_bootstrap(void);

/* Initialize machine dependent stuff */
extern void machine_init(void);

extern void slave_main(void *machine_param);

/*
 * The following must be implemented in machine dependent code.
 */

/* Slave cpu initialization */
extern void slave_machine_init(void *machine_param);

/* Device subystem initialization */
extern void device_service_create(void);

#ifdef  MACH_BSD

/* BSD subsystem initialization */
extern void bsd_init(void);
extern void bsd_early_init(void);

#endif  /* MACH_BSD */

#pragma GCC visibility pop

__END_DECLS

#endif  /* _KERN_STARTUP_H_ */

#endif  /* XNU_KERNEL_PRIVATE */
