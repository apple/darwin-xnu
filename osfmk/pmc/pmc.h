/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#ifndef _MACH_PMC_H_
#define _MACH_PMC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <kern/queue.h>
#include <mach/boolean.h>
#include <mach/mach_time.h>
#include <mach/mach_types.h>

#include <libkern/version.h>

/****************************************************************************
 * The four main object types
 *
 * 1. Performance monitors (perf_monitor_t) - represent the hardware that 
 *     encapsulates a set of performance counters
 * 2. Performance Counters (pmc_t) - represents each individual counter
 * 3. Performance Counter Configs (pmc_config_t) - represents the settings 
 *     applied to a performance counter (e.g., what to count)
 * 4. Performance Counter Reservations (pmc_reservation_t) - represents a config along 
 *     with it's saved counter value, and the context underwhich it will count.  
 *
 ****************************************************************************/

/*
 * The following objects are in-kernel stand-ins for objects that will be implemented
 * in the driver kexts.  They are generally instances of C++ objects.  We make opaque 
 * handles for each distinct type for a little bit of type safety when used from the 
 * kernel layer.  These objects are not to be introspected by the kernel at any time,
 * only used as arguments in the registered driver methods.
 */

// IOPerformanceMonitor instances
typedef void * perf_monitor_object_t;

// IOPerformanceCounter instances
typedef void * pmc_object_t;

// IOPerformanceCounterConfig instances
typedef void * pmc_config_object_t;

// END Kext-implemented objects

// Forward declations
struct pmc_reservation;
typedef struct pmc_reservation *pmc_reservation_t;

struct pmc_config;
typedef struct pmc_config *pmc_config_t;

/****************************************************************************
 * Method types for performance monitor driver registration
 * 
 * Driver registration happens with no intervention from the driver writers -
 * it is handled automatically by the IOProfileFamily kext.  Registration
 * happens whenever any IOPerformanceMonitor subclass attaches to the registry.
 * Failure to successfully register with the kernel will prevent successful attachment
 * to the IORegistry (this way only usable PMCs and Perf Monitors will be shown.)
 ****************************************************************************/

/*!typedef
 * @abstract A pointer to a method that returns whether or not the given performance monitor driver supports context switched counters
 * @param pm A registered performance monitor driver object (see <link>perf_monitor_register</link>).
 * @result TRUE if the driver supports context switching, FALSE otherwise.
 */
typedef boolean_t (*perfmon_supports_context_switch_method_t)(perf_monitor_object_t pm);

/*!typedef
 * @abstract A pointer to a method that enables a set of counters.
 * @discussion Implementations of this method type must be safe to call at interrupt context.
 * @param pmcs An array of pmc_object_t instances (non-NULL).
 * @param pmcCount The number of elements in the @pmcs array.
 * @result KERN_SUCCESS upon successful global enable of the given counters (may return IOKit error codes).
 */
typedef kern_return_t (*perfmon_enable_counters_method_t)(perf_monitor_object_t pm, pmc_object_t *pmcs, uint32_t pmcCount);

/*!typedef
 * @abstract A pointer to a method that disables a set of counters.
 * @discussion Implementations of this method type must be safe to call at interrupt context.
 * See <link>perfmon_enable_counters_method_t</link>
 * @result See <link>perfmon_enable_counters_method_t</link>
 */
typedef kern_return_t (*perfmon_disable_counters_method_t)(perf_monitor_object_t pm, pmc_object_t *pmcs, uint32_t pmcCount);

#define MACH_PERFMON_METHODS_VERSION 0

/*!struct perf_monitor_methods
 * @abstract A set of method pointers to be used when interacting with a performance monitor object
 * @discussion This structure is the set of driver-implemented callback methods to be used when
 * interacting with a new performance monitor from the kernel.
 */
typedef struct perf_monitor_methods {
	uint32_t perf_monitor_methods_version;	// Always set to MACH_PERFMON_METHODS_VERSION when writing driver kexts
	
	// All methods are required.
	perfmon_supports_context_switch_method_t supports_context_switching;
	perfmon_enable_counters_method_t enable_counters;
	perfmon_disable_counters_method_t disable_counters;
}perf_monitor_methods_t;


/****************************************************************************
 * Method types for performance counter registration
 *
 * Registration of individual Performance Counters happens after the 
 * encapsulating Performance Monitor has been registered. This, too, happens
 * with no intervention of driver-writers.  It happens automatically whenever
 * any IOPerformanceCounter subclass attaches to IORegistry.  Failure to register
 * with the kernel will prevent the IOPerformanceCounter instance from attaching
 * to IORegistry.
 ****************************************************************************/

/*!typedef
 * @abstract A pointer to a method that creates a configuration object for a counter
 * @discussion Configuration objects create and hold the hardware representation for a set of driver-defined key-value pairs.
 * Corresponds to IOPerformanceCounter::createConfiguration() method.
 * @param pmc A valid pmc object
 * @result NULL on failure, or a pmc_config_t on success.
 */
typedef pmc_config_object_t (*pmc_create_config_method_t)(pmc_object_t pmc);

/*!typedef 
 * @abstract A pointer to a method to free a configuration object for a pmc
 * @discussion Method should free a pmc config object created with a pmc_create_config_method_t above
 * @param pmc The pmc object used to create the config
 * @param config The config object to release
 */
typedef void (*pmc_free_config_method_t)(pmc_object_t pmc, pmc_config_object_t config);

/*!typedef
 * @abstract A pointer to a method to set a key-value pair on a config object.
 * @discussion Configuration objects take key-value pairs for setting various bits in the pmc configs 
 * Corresponds to IOPerformanceCounterConfiguration::setValueForId() method.
 * @param config Pointer to config object.
 * @param id 8-bit integer ID (determined by the driver).
 * @param value 64-bit integer value (interpretted by the driver).
 * @result KERN_SUCCESS on success, KERN_FAILURE on bad value, KERN_INVALID_ARGUMENT on bad id
 */
typedef kern_return_t (*pmc_config_set_value_method_t)(pmc_config_object_t config, uint8_t id, uint64_t value);

/*!typedef
 * @abstract A pointer to a method that will be called when a Performance Counter causes a PMI interrupt
 * @discussion Implementations of this method type must be safe to call at interrupt context.
 * @param target The pmc_reservation_t that caused the interrupt
 * @param refCon Any value as defined by the end-user who called <link>pmc_config_set_interrupt_threshold</link>
 */
typedef void (*pmc_interrupt_method_t)(void *target, void *refCon);

/*!typedef
 * @abstract A pointer to a method that will set the counter PMI threshold.
 * @param config A configuration object
 * @param threshold The number of events after which to cause an interrupt
 * callback.
 */
typedef kern_return_t (*pmc_config_set_interrupt_threshold_method_t)(pmc_config_object_t config, uint64_t threshold);

/*!typedef
 * @abstract A pointer to a method that will set the method to be called when the counter threshold is reached.
 * @param config A configuration object.
 * @param target A reference pointer used as the first argument to the callback method.
 * @param method A pointer to the method to be called.
 * @param refCon A reference pointer to be used as the second argument to the callback method (may be NULL).
 */
typedef kern_return_t (*pmc_config_set_interrupt_threshold_handler_method_t)(pmc_config_object_t config, void *target, pmc_interrupt_method_t method, void *refCon);

/*!typedef
 * @abstract A pointer to a method that will configure a pmc's control registers according to the given configuration object.
 * @discussion Implementations of this method type must be safe to call at interrupt context.
 * @param pmc The pmc reference object.
 * @param config A configuration object.
 */
typedef kern_return_t (*pmc_set_config_method_t)(pmc_object_t pmc, pmc_config_object_t config);

/*!typedef
 * @abstract A pointer to a method that returns the Performance Monitor Object for a counter
 * @discussion A pointer to a method that returns the Performance Monitor Object for a counter.
 * Implementations of this method type must be safe to call at interrupt context.
 * Corresponds to IOPerformanceCounter::getMonitor() method.
 * @param pmc A valid pmc object
 * @result NULL on failure, or a perf_monitor_object_t on success.
 */
typedef perf_monitor_object_t (*pmc_get_monitor_method_t)(pmc_object_t pmc);

/*!typedef
 * @abstract A pointer to a method that returns the registered name of the PMC.
 * @discussion A pointer to a method that returns the registered name of the PMC.
 * Corresponds to IOPerformanceCounter::getRegisteredName() method.  
 *
 * NOTE: Driver authors must not allocate or copy the string during this method:
 * it may be called from interrupt context or with spin locks held.
 *
 * @param pmc A valid pmc object.
 * @result NULL on failure, or a pointer to the registered name of the pmc.
 */
typedef const char *(*pmc_get_name_method_t)(pmc_object_t pmc);

/*!typedef
 * @abstract A pointer to a method that returns if a pmc is accessible from a given logical core.
 * @discussion A pointer to a method that returns if a pmc is accessible from a given logical core.
 * Implementations of this method type must be safe to call at interrupt context.
 * @param pmc A valid pmc object.
 * @param core The logical core number.
 * @result TRUE if the pmc can be read in the execution context of the given logical core, FALSE otherwise.
 */
typedef boolean_t (*pmc_is_accessible_from_logical_core_method_t)(pmc_object_t pmc, uint32_t core);

/*!typedef 
 * @abstract A pointer to a method that returns an array of the logical cores from which a PMC can be accessed.
 * @discussion A pointer to a method that returns an array of the logical cores from which a PMC can be accessed. Resulting array of cores should not be released by xnu.
 * Implementations of this method type must be safe to call at interrupt context.
 * @param pmc A valid pmc object
 * @param cores A value-returned array of logical cores that can access the given PMC.
 * @param coreCt A value-return count of the number of entries in the @cores array.
 * @result KERN_SUCCESS on success, KERN_FAILURE otherwise.
 */
typedef kern_return_t (*pmc_get_accessible_cores_method_t)(pmc_object_t pmc, uint32_t **cores, size_t *coreCt);

/*!typedef
 * @abstract A pointer to a method that attempts to read the count from the given counter hardware. 
 * @discussion Implementations of this method type must be safe to call from interrupt context.  * @param pmc The counter from which to read
 * @param value Storage for the counter's hardware value.
 */
typedef kern_return_t (*pmc_get_count_method_t)(pmc_object_t pmc, uint64_t *value);

/*!typedef 
 * @abstract A pointer to a method that attempts to write the count to the given counter hardware.
 * @discussion Implementations of this method type must be safe to call from interrupt context.
 * @param pmc The counter to which to write.
 * @param value The value to write to the hardware.
 */
typedef kern_return_t (*pmc_set_count_method_t)(pmc_object_t pmc, uint64_t value);


/*!typedef
 * @abstract A pointer to a method that disables the counter hardware for a given PMC.
 * @discussion A pointer to a method that disables the counter hardware for
 * a given PMC.
 * Implementations of this method type must be safe to call at interrupt context.
 * @param pmc A valid pmc object.
 * @result KERN_SUCCESS on successful disable
 */
typedef kern_return_t (*pmc_disable_method_t)(pmc_object_t pmc);

/*!typedef
 * @abstract A pointer to a method that enables the counter hardware for a given PMC.
 * @discussion A pointer to a method that enables the counter hardware for a given PMC.
 * Implementations of this method type must be safe to call at interrupt context.
 * @param pmc A valid pmc object.
 * @result KERN_SUCCESS on successful enable
 */
typedef kern_return_t (*pmc_enable_method_t)(pmc_object_t pmc);

typedef kern_return_t (*pmc_open_method_t)(pmc_object_t pmc, void *object);
typedef kern_return_t (*pmc_close_method_t)(pmc_object_t pmc, void *object);

#define MACH_PMC_METHODS_VERSION	0

/*!
 * @struct pmc_methods
 * @abstract Performance Counter Registration methods.
 * @discussion This structure represents a set of driver-implemented methods to be used by the kernel
 * when interacting with the associated performance counter.  Since a Performance Monitor may
 * implement any number of distinct types of Performance Counters, each counter registers with
 * its own set of callback methods.
 */
typedef struct pmc_methods {
	uint32_t pmc_methods_version;		// Always set to MACH_PMC_METHODS_VERSION in your driver.

	// All methods are required.
	pmc_create_config_method_t create_config;
	pmc_free_config_method_t free_config;
	pmc_config_set_value_method_t config_set_value;
	pmc_config_set_interrupt_threshold_method_t config_set_threshold;
	pmc_config_set_interrupt_threshold_handler_method_t config_set_handler;
	pmc_set_config_method_t set_config;

	pmc_get_monitor_method_t get_monitor;
	pmc_get_name_method_t get_name;
	pmc_is_accessible_from_logical_core_method_t accessible_from_core;
	pmc_get_accessible_cores_method_t accessible_cores;
	pmc_get_count_method_t get_count;
	pmc_set_count_method_t set_count;
	pmc_disable_method_t disable;
	pmc_enable_method_t enable;
	pmc_open_method_t open;
	pmc_close_method_t close;
}pmc_methods_t;

/*
 * Kext interface Methods
 *
 * These methods would be exported to apple-internal kexts, but not to 3rd-party kexts, and 
 * definitely not to user space.
 *
 * All Performance Monitor and Performance Counter registration (accomplished via the following methods)
 * is handled automatically via IOProfileFamily's base classes.  However, we'd need to export these
 * methods to apple-private KPI so that IOProfileFamily can call these methods when new objects attach
 * to the IORegistry.
 *
 */

/*!fn
 * @abstract Registers a new performance monitor driver and its associated pointers.
 * @discussion Kexts that implement performance monitor drivers will call this method with a
 * filled-in perf_monitor_methods_t structure (with version set to MACH_PERFMON_METHODS_VERSION).  
 * The PMC interface will then register the new driver internally.
 * @param monitor A handle to the performance monitor driver instance you are registering. Must not be NULL.
 * @param methods A filled-in perf_monitor_methods_t structure with version set to MACH_PERFMON_METHODS_VERSION.
 * @result KERN_SUCCESS if the new driver was successfully registered, KERN_INVALID_VALUE if the 
 * version of the passed-in perf_monitor_methods_t structure does not match that which is expected,
 * KERN_RESOURCE_SHORTAGE if the kernel lacks the resources to register another performance monitor
 * driver, KERN_INVALID_ARGUMENT if one or both of the arguments is null
 */

/* Prevent older AppleProfileFamily kexts from loading on newer kernels.
 * Alas, C doesn't necessarily have a cleaner way to do the version number concatenation
 */
#define PERF_REG_NAME1(a, b) a ## b
#define PERF_REG_NAME(a, b) PERF_REG_NAME1(a, b)
#define perf_monitor_register PERF_REG_NAME(perf_monitor_register_, VERSION_MAJOR)

kern_return_t perf_monitor_register(perf_monitor_object_t monitor, perf_monitor_methods_t *methods);

/*!fn
 * @abstract Unregisters a performance monitor driver and frees space associated with its pointers.
 * @discussion Kexts that implement performance monitor drivers will call this method just before they unload
 * to cause the performance monitor they implement to be removed from the kernel's PMC system.
 * @param monitor A handle to a performance monitor driver instance that was previously registered with <link>perf_monitor_register</link>
 * @result KERN_SUCCESS if the new driver was successfully unregistered, KERN_INVALID_VALUE if the 
 * passed-in perf_monitor_object_t does not match any registered performance monitor, KERN_INVALID_ARGUMENT if 
 * the argument is null, KERN_FAILURE if the performance monitor is currently in use.
 */
kern_return_t perf_monitor_unregister(perf_monitor_object_t monitor);

/*!fn
 * @abstract Register a new Performance Counter, and attach it to the given Performance Monitor
 * @discussion This method takes a Performance Monitor driver instance that was previously registered 
 * with <link>perf_monitor_register</link>, and attaches an instance of a Performance Counter 
 * that will be accessed with the given set of pmc methods.
 * @param monitor A handle to a Performance Monitor that was previously registered.
 * @param pmc A handle to the Performance Counter instance to be attached to the monitor object
 * @param methods A filled-in pmc_methods_t structure with version set to MACH_PMC_METHODS_VERSION
 * @param object an Object to be used during the open() and close() methods. Must be a subclass of IOService, cannot be NULL.
 * @result KERN_SUCCESS if the new counter was successfully registered and attached, KERN_INVALID_VALUE if the 
 * version of the passed-in pmc_methods_t structure does not match that which is expected,
 * KERN_RESOURCE_SHORTAGE if the kernel lacks the resources to register another performance counter
 * instance, KERN_INVALID_ARGUMENT if any of the arguments is null
 */
kern_return_t pmc_register(perf_monitor_object_t monitor, pmc_object_t pmc, 
	pmc_methods_t *methods, void *object);

/*!fn
 * @abstract Unregisters a Performance Counter
 * @discussion Does the reverse of <link>pmc_register</link>. 
 * @param monitor The registered Performance Monitor from which to remove a pmc.
 * @param pmc The Performance Counter to unregister.
 * @result KERN_SUCCESS if the counter was successfully unregistered, KERN_INVALID_VALUE if the 
 * passed-in pmc_object_t does not match any registered performance counter, KERN_INVALID_ARGUMENT if 
 * any argument is null, KERN_FAILURE if the performance counter is currently in use.
 */
kern_return_t pmc_unregister(perf_monitor_object_t monitor, pmc_object_t pmc);

/*
 * Here begins the interface in-kernel and in-kext users will use to interact with PMCs and 
 * Performance Monitors.
 *
 * Basic usage is as follows: find your target counter, create a config for it, setup the config, 
 * reserve the counter using that config in a given execution context (system, or 1 task, or 1 thread),
 * start the counter via the reservation object, stop the counter, and read the counter value similarly from the
 * reservation object.  When done, release the reservation object.
 */

/*!struct perf_monitor
 * @abstract In-kernel object to track a driver-implemented performance monitor.
 */
typedef struct perf_monitor {
	/*
	 * A reference-pointer used as the first argument to all callback methods
	 * (to seamlessly work with C++ objects). This is the same value that was 
	 * used in the perf_monitor_register() method.
	 */
	perf_monitor_object_t object;

	// Copy of the pointers used to interact with the above instance
	perf_monitor_methods_t methods;
	
	// reference counted
	uint32_t useCount;
	
	// link to other perf monitors
	queue_chain_t link;
}*perf_monitor_t;

/*!struct pmc
 * @abstract In-kernel object to track an individual driver-implemented performance counter
 */
typedef struct pmc {
	/*
	 * A reference-pointer used as the first argument to all callback methods
	 * (to seamlessly work with C++ objects). This is the same value that was
	 * used in the pmc_register() method.
	 */
	pmc_object_t object;
	
	/* Copy of the pointers used to interact with the above instance */
	pmc_methods_t methods;

	/* Object to be used during open/close methods */
	void *open_object;

	/* reference counted */
	uint32_t useCount;
	
	/* link to parent */
	perf_monitor_t monitor;

	/* link to other PMCs */
	queue_chain_t link;
}*pmc_t;

// Scope flags (highest order bits)
#define PMC_FLAG_SCOPE_SYSTEM	0x80000000U
#define PMC_FLAG_SCOPE_TASK		0x40000000U
#define PMC_FLAG_SCOPE_THREAD	0x20000000U
#define PMC_SCOPE_MASK			0xE0000000U

#define PMC_FLAG_IS_SYSTEM_SCOPE(x)	\
		((x & PMC_FLAG_SCOPE_SYSTEM) == PMC_FLAG_SCOPE_SYSTEM)

#define PMC_FLAG_IS_TASK_SCOPE(x)	\
		((x & PMC_FLAG_SCOPE_TASK) == PMC_FLAG_SCOPE_TASK)

#define PMC_FLAG_IS_THREAD_SCOPE(x)	\
		((x & PMC_FLAG_SCOPE_THREAD) == PMC_FLAG_SCOPE_THREAD)

#define PMC_FLAG_SCOPE(x)		(x & PMC_SCOPE_MASK)

/*
 * Reservation state
 *
 * The state of a reservation is actually a 3-tuple of the current state, an active context count,
 * and a set of modifier flags.  To avoid using locks, these are combined into a single uint32_t
 * that can be modified with OSCompareAndSwap.
 *
 */

typedef uint32_t pmc_state_t;
	
#define PMC_STATE_STATE_INVALID			0x00000000U
#define	PMC_STATE_STATE_STOP			0x10000000U
#define PMC_STATE_STATE_CAN_RUN			0x20000000U
#define PMC_STATE_STATE_LOAD			0x30000000U
#define PMC_STATE_STATE_RUN				0x40000000U
#define PMC_STATE_STATE_STORE			0x50000000U
#define PMC_STATE_STATE_INTERRUPT		0x60000000U
#define PMC_STATE_STATE_DEALLOC			0x70000000U

#define PMC_STATE_STATE_MASK			0xF0000000U

#define PMC_STATE_STATE(x)				((x) & PMC_STATE_STATE_MASK)
#define PMC_STATE_STATE_SET(x, state)	(((x) & ~(PMC_STATE_STATE_MASK)) | state)
	
#define PMC_STATE_FLAGS_STOPPING		0x08000000U
#define PMC_STATE_FLAGS_DEALLOCING		0x04000000U
#define PMC_STATE_FLAGS_INTERRUPTING	0x02000000U
	
#define PMC_STATE_FLAGS_MASK			0x0F000000U

#define PMC_STATE_FLAGS(x)				((x) & PMC_STATE_FLAGS_MASK)
#define PMC_STATE_FLAGS_MODIFY(x, set, clear)	(((x) & ~(clear)) | set)	
	
#define PMC_STATE_CONTEXT_COUNT_MASK	0x0000FFFFU

#define PMC_STATE_CONTEXT_COUNT(x)				((x) & PMC_STATE_CONTEXT_COUNT_MASK)
#define PMC_STATE_CONTEXT_COUNT_MODIFY(x, mod) 	(((PMC_STATE_CONTEXT_COUNT(x) + (mod)) < PMC_STATE_CONTEXT_COUNT_MASK) ? (x) + (mod) : PMC_STATE_CONTEXT_COUNT_MASK)
	
#define PMC_STATE(state, context_count, flags)	(PMC_STATE_STATE(state) | PMC_STATE_FLAGS(flags) | PMC_STATE_CONTEXT_COUNT(context_count))
#define PMC_STATE_MODIFY(x, context_count_mod, flags_set, flags_clear)	(PMC_STATE_FLAGS_MODIFY(PMC_STATE_CONTEXT_COUNT_MODIFY(x, context_count_mod), flags_set, flags_clear))
#define PMC_STATE_MOVE(x, state, context_count_mod, flags_set, flags_clear) (PMC_STATE_STATE_SET(PMC_STATE_MODIFY(x, context_count_mod, flags_set, flags_clear), state))

#define PMC_STATE_INVALID				PMC_STATE(PMC_STATE_STATE_INVALID, 0, 0)
	
/*!struct pmc_reservation
 * @abstract In-kernel object to track an individual reservation
 */
struct pmc_reservation {
	pmc_t pmc;						// Pointer to in-kernel pmc which is reserved
	pmc_config_t config;			// counter configuration

	// stored counter value
	uint64_t value;

	// TODO: Add mach-port (user-export object?)

	volatile uint32_t flags __attribute__((aligned(4)));
	volatile pmc_state_t state __attribute__((aligned(4)));
	volatile uint32_t active_last_context_in __attribute__((aligned(4)));

	union {
		task_t task;		// not retained
		thread_t thread;	// not retained
	};

	queue_chain_t link;
};

// END Kernel-objects


// Methods exported to kernel (and kext) consumers

/*!fn
 * @abstract Creates a new configuration object for the given pmc.
 * @discussion This method is not interrupt safe.
 * @param pmc The Perf Counter for which to create a configuration.
 * @param config A value-return configuration object.
 */
kern_return_t pmc_create_config(pmc_t pmc, pmc_config_t *config);

/*!fn
 * @abstract Releases a configuration object for the given pmc.
 * @discussion This method is not interrupt safe.
 * @param pmc The Perf Counter for which to release a configuration.
 * @param config A configuration object to be released.
 */
void pmc_free_config(pmc_t pmc, pmc_config_t config);

/*!fn
 * @abstract Setup the configuration
 * @discussion Configurations for counter are architecture-neutral key-value pairs (8bit key, 64bit value).  Meanings of the keys and values are defined by the driver-writer and are listed in XML form available for interrogation via the CoreProfile framework. This method is not interrupt safe.
 * @result KERN_SUCCESS on success. 
 */
kern_return_t pmc_config_set_value(pmc_t pmc, pmc_config_t config, uint8_t id, uint64_t value);

/*!fn
 * @abstract Interrupt Threshold Setup
 * @discussion In order to configure a PMC to use PMI (cause an interrupt after so-many events occur), use this method, and provide a function to be called after the interrupt occurs, along with a reference context. PMC Threshold handler methods will have the pmc that generated the interrupt as the first argument when the interrupt handler is invoked, and the given  @refCon (which may be NULL) as the second.  This method is not interrupt safe.
 */
kern_return_t pmc_config_set_interrupt_threshold(pmc_t pmc, pmc_config_t config, uint64_t threshold, pmc_interrupt_method_t method, void *refCon);

/*!fn 
 * @abstract Returns an allocated list of all pmc_t's known to the kernel.
 * @discussion Callers should free the resultant list via <link>pmc_free_pmc_list</link>. This method is not interrupt safe.
 * @param pmcs Storage for the resultant pmc_t array pointer.
 * @param pmcCount Storage for the resultant count of pmc_t's.
 */
kern_return_t pmc_get_pmc_list(pmc_t **pmcs, size_t *pmcCount);

/*!fn
 * @abstract Free a previously allocated list of pmcs.
 * @discussion This method is not interrupt safe.
 * @param pmcs PMC list to free.
 * @param pmcCount Number of pmc_t's in list.
 */
void pmc_free_pmc_list(pmc_t *pmcs, size_t pmcCount);

/*!fn
 * @abstract Finds pmcs by partial string matching.
 * @discussion This method returns a list of pmcs (similar to <link>pmc_get_pmc_list</link>) whose names match the given string up to it's length.  For example, searching for "ia32" would return pmcs "ia32gp0" and "ia32gp1". Results should be released by the caller using <link>pmc_free_pmc_list</link>
 * @param name Partial string to search for.
 * @param pmcs Storage for the resultant pmc_t array pointer.
 * @param pmcCount Storage for the resultant count of pmc_t's.
 */
kern_return_t pmc_find_by_name(const char *name, pmc_t **pmcs, size_t *pmcCount);

/*!fn
 * @abstract Returns a pointer to the human-readable name of the given pmc.
 * @discussion The returned pointer is not a copy, and does not need to be freed. This method is interrupt safe.
 * @param pmc The PMC whose name should be returned.
 */
const char *pmc_get_name(pmc_t pmc);

/*!fn
 * @abstract Returns a list of logical cores from which the given pmc can be read from or written to.
 * @discussion This method can return a NULL list with count of 0 -- this indicates any core can read the given pmc. This method does not allocate the list, therefore callers should take care not to mutate or free the resultant list. This method is interrupt safe.
 * @param pmc The PMC for which to return the cores that can read/write it.
 * @param logicalCores Storage for the pointer to the list.
 * @param logicalCoreCt Value-return number of elements in the returned list.  0 indicates all cores can read/write the given pmc.
 */
kern_return_t pmc_get_accessible_core_list(pmc_t pmc, uint32_t **logicalCores, size_t *logicalCoreCt);

/*!fn
 * @abstract Returns TRUE if the given logical core can read/write the given PMC.
 * @discussion This method is interrupt safe.
 * @param pmc The PMC to test
 * @param logicalCore The core from which to test.
 */
boolean_t pmc_accessible_from_core(pmc_t pmc, uint32_t logicalCore);

/* 
 * BEGIN PMC Reservations
 *
 * These are how you reserve a PMC, start and stop it counting, and read and write 
 * its value. 
 */

/*!fn
 * @abstract Reserve a PMC for System-wide counting.
 * @discussion This method will attempt to reserve the given pmc at system-scope. It will configure the given pmc to count the event indicated by the given configuration object. This method consumes the given configuration object if the return value is KERN_SUCCESS - any other return value indicates the caller should free the configuration object via <link>pmc_free_config</link>. This method is not interrupt safe.
 * @param pmc The PMC to reserve.
 * @param config The configuration object to use with the given pmc.
 * @param reservation A value-return reservation object to be used in pmc_reservation_* methods.
 * @result This method will return one of the following values:
 *	KERN_SUCCESS: The given pmc was successfully reserved in system-scope; the given config object has been consumed and should not be freed by the caller,
 *	KERN_FAILURE: The given pmc is already reserved in a conflicting scope,
 *	KERN_INVALID_ARGUMENT: All three arguments are required to be non-NULL, but at least one is NULL,
 *	KERN_RESOURCE_SHORTAGE: Could not allocate a new reservation object.
 */
kern_return_t pmc_reserve(pmc_t pmc, pmc_config_t config, pmc_reservation_t *reservation);


/*!fn
 * @abstract Reserve a PMC for task-wide counting.
 * @discussion This method will attempt to reserve the given pmc for task-wide counting. The resulting reservation will only count when the task is running on one of the logical cores that can read the given pmc. The semantics of this method are the same as <link>pmc_reserve</link> in all other respects.
 * @param pmc The PMC to reserve
 * @param config The configuration object to use.
 * @param task The task for which to enable the counter.
 * @param reservation A value-return reservation object.
 * @result See <link>pmc_reserve</link>
 */
kern_return_t pmc_reserve_task(pmc_t pmc, pmc_config_t config, task_t task, pmc_reservation_t *reservation);

/*!fn
 * @abstract Reserve a PMC for thread-wide counting.
 * @discussion This method will attempt to reserve the given pmc for thread-wide counting. The resulting reservation will only count when the thread is running on one of the logical cores that can read the given pmc. The semantics of this method are the same as <link>pmc_reserve_task</link> in all other respects.
 * @param pmc The PMC to reserve
 * @param config The configuration object to use.
 * @param thread The thread for which to enable the counter.
 * @param reservation A value-return reservation object.
 * @result See <link>pmc_reserve</link>
 */
kern_return_t pmc_reserve_thread(pmc_t pmc, pmc_config_t config, thread_t thread, pmc_reservation_t *reservation);

/*!fn
 * @abstract Start counting
 * @discussion This method instructs the given reservation to start counting as soon as possible. If the reservation is for a thread (or task) other than the current thread, or for a pmc that is not accessible from the current logical core, the reservation will start counting the next time the thread (or task) runs on a logical core than can access the pmc. This method is interrupt safe. If this method is called from outside of interrupt context, it may block.
 * @param reservation The reservation to start counting
 */
kern_return_t pmc_reservation_start(pmc_reservation_t reservation);

/*!fn
 * @abstract Stop counting
 * @discussion This method instructs the given reservation to stop counting as soon as possible. If the reservation is for a thread (or task) other than the current thread, or for a pmc that is not accessible from the current logical core, the reservation will stop counting the next time the thread (or task) ceases to run on a logical core than can access the pmc. This method is interrupt safe. If called form outside of interrupt context, this method may block.
 * @param reservation The reservation to stop counting
 */
kern_return_t pmc_reservation_stop(pmc_reservation_t reservation);

/*!fn
 * @abstract Read the counter value
 * @discussion This method will read the event count associated with the given reservation. If the pmc is currently on hardware, and the caller is currently executing in a context that both a) matches the reservation's context, and b) can access the reservation's pmc directly, the value will be read directly from the hardware.  Otherwise, the value stored in the reservation is returned. This method is interrupt safe. If the caller is calling from outside of interrupt context, this method may block.
 * @param reservation The reservation whose value to read.
 * @param value Value-return event count
 */
kern_return_t pmc_reservation_read(pmc_reservation_t reservation, uint64_t *value);

/*!fn
 * @abstract Write the counter value
 * @discussion This method will write the event count associated with the given reservation. If the pmc is currently on hardware, and the caller is currently executing in a context that both a) matches the reservation's context, and b) can access the reservation's pmc directly, the value will be written directly to the hardware.  Otherwise, the value stored in the reservation is overwritten. This method is interrupt safe. If the caller is calling from outside of interrupt context, this method may block.
 * @param reservation The reservation to write.
 * @param value The event count to write
 */
kern_return_t pmc_reservation_write(pmc_reservation_t reservation, uint64_t value);

/*!fn
 * @abstract Free a reservation and all associated resources.
 * @discussion This method will free the resources associated with the given reservation and release the associated PMC back to general availability. If the reservation is currently counting, it will be stopped prior to release. This method is not interrupt safe.
 * @param reservation The reservation to free
 */
kern_return_t pmc_reservation_free(pmc_reservation_t reservation);

#if XNU_KERNEL_PRIVATE

/*!fn
 * @abstract Brings up all the necessary infrastructure required to use the pmc sub-system.
 * @discussion For xnu-internal startup routines only.
 */
void pmc_bootstrap(void);

/*!fn
 * @abstract Performs a pmc context switch.
 * @discussion This method will save all PMCs reserved for oldThread (and the task associated with oldThread), as well as restore all PMCs reserved for newThread (and the task associated with newThread). This method is for xnu-internal context switching routines only.
 */
boolean_t pmc_context_switch(thread_t oldThread, thread_t newThread);

#endif	// XNU_KERNEL_PRIVATE

#ifdef __cplusplus
};
#endif

#endif // _MACH_PMC_H_

