/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*
 */

#ifndef	_KERN_CLOCK_H_
#define	_KERN_CLOCK_H_

#include <stdint.h>
#include <mach/mach_types.h>
#include <mach/clock_types.h>
#include <mach/message.h>
#include <mach/mach_time.h>

#include <kern/kern_types.h>

#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

/*
 * Clock operations list structure. Contains vectors to machine
 * dependent clock routines.
 */
struct	clock_ops {
	int		(*c_config)(void);		/* configuration */

	int		(*c_init)(void);		/* initialize */

	kern_return_t	(*c_gettime)(	/* get time */
				mach_timespec_t			*cur_time);

	kern_return_t	(*c_getattr)(	/* get attributes */
				clock_flavor_t			flavor,
				clock_attr_t			attr,
				mach_msg_type_number_t	*count);
};
typedef struct clock_ops	*clock_ops_t;
typedef struct clock_ops	clock_ops_data_t;

/*
 * Actual clock object data structure. Contains the machine
 * dependent operations list and clock operation ports.
 */
struct	clock {
	clock_ops_t			cl_ops;			/* operations list */
	struct ipc_port		*cl_service;	/* service port */
	struct ipc_port		*cl_control;	/* control port */
};
typedef struct clock		clock_data_t;

/*
 * Configure the clock system.
 */
extern void		clock_config(void);
extern void		clock_oldconfig(void);

/*
 * Initialize the clock system.
 */
extern void		clock_init(void);
extern void		clock_oldinit(void);

extern void		clock_timebase_init(void);

/*
 * Initialize the clock ipc service facility.
 */
extern void		clock_service_create(void);

typedef void		(*clock_timer_func_t)(
						uint64_t			timestamp);

extern void			clock_set_timer_func(
						clock_timer_func_t	func);

extern void			clock_set_timer_deadline(
						uint64_t			deadline);

extern void			clock_gettimeofday_set_commpage(
						uint64_t				abstime,
						uint64_t				epoch,
						uint64_t				offset,
						uint32_t				*secs,
						uint32_t				*microsecs);

extern void			machine_delay_until(
						uint64_t		deadline);

#include <stat_time.h>

extern void		hertz_tick(
#if	STAT_TIME
					natural_t		ticks,
#endif	/* STAT_TIME */
					boolean_t		usermode,	/* executing user code */
					natural_t		pc);

extern void		absolutetime_to_microtime(
					uint64_t		abstime,
					uint32_t		*secs,
					uint32_t		*microsecs);

extern void		absolutetime_to_nanotime(
					uint64_t		abstime,
					uint32_t		*secs,
					uint32_t		*nanosecs);

extern void		nanotime_to_absolutetime(
				    uint32_t		secs,
					uint32_t		nanosecs,
					uint64_t		*result);

#endif /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef	XNU_KERNEL_PRIVATE

extern void			clock_adjtime(
						int32_t		*secs,
						int32_t		*microsecs);

extern void			clock_initialize_calendar(void);

extern void			clock_wakeup_calendar(void);

extern void			clock_gettimeofday(
                        uint32_t			*secs,
                        uint32_t			*microsecs);

extern void			clock_set_calendar_microtime(
						uint32_t			secs,
						uint32_t			microsecs);

extern void			clock_get_boottime_nanotime(
						uint32_t			*secs,
						uint32_t			*nanosecs);

extern void			clock_deadline_for_periodic_event(
						uint64_t			interval,
						uint64_t			abstime,
						uint64_t			*deadline);

#endif	/* XNU_KERNEL_PRIVATE */


extern void			clock_get_calendar_microtime(
						uint32_t			*secs,
						uint32_t			*microsecs);

extern void			clock_get_calendar_nanotime(
						uint32_t			*secs,
						uint32_t			*nanosecs);

extern void			clock_get_system_microtime(
						uint32_t			*secs,
						uint32_t			*microsecs);

extern void			clock_get_system_nanotime(
						uint32_t			*secs,
						uint32_t			*nanosecs);

extern void				clock_timebase_info(
							mach_timebase_info_t	info);

extern void				clock_get_uptime(
							uint64_t		*result);

extern void				clock_interval_to_deadline(
							uint32_t		interval,
							uint32_t		scale_factor,
							uint64_t		*result);

extern void				clock_interval_to_absolutetime_interval(
							uint32_t		interval,
							uint32_t		scale_factor,
							uint64_t		*result);

extern void				clock_absolutetime_interval_to_deadline(
							uint64_t		abstime,
							uint64_t		*result);

extern void				clock_delay_until(
							uint64_t		deadline);

extern void				absolutetime_to_nanoseconds(
							uint64_t		abstime,
							uint64_t		*result);

extern void             nanoseconds_to_absolutetime(
							uint64_t		nanoseconds,
							uint64_t		*result);

#ifdef	KERNEL_PRIVATE

/*
 * Obsolete interfaces.
 */

#define MACH_TIMESPEC_SEC_MAX		(0 - 1)
#define MACH_TIMESPEC_NSEC_MAX		(NSEC_PER_SEC - 1)

#define MACH_TIMESPEC_MAX	((mach_timespec_t) {				\
									MACH_TIMESPEC_SEC_MAX,		\
									MACH_TIMESPEC_NSEC_MAX } )
#define MACH_TIMESPEC_ZERO	((mach_timespec_t) { 0, 0 } )

#define ADD_MACH_TIMESPEC_NSEC(t1, nsec)		\
  do {											\
	(t1)->tv_nsec += (clock_res_t)(nsec);		\
	if ((clock_res_t)(nsec) > 0 &&				\
			(t1)->tv_nsec >= NSEC_PER_SEC) {	\
		(t1)->tv_nsec -= NSEC_PER_SEC;			\
		(t1)->tv_sec += 1;						\
	}											\
	else if ((clock_res_t)(nsec) < 0 &&			\
				 (t1)->tv_nsec < 0) {			\
		(t1)->tv_nsec += NSEC_PER_SEC;			\
		(t1)->tv_sec -= 1;						\
	}											\
  } while (0)


extern mach_timespec_t	clock_get_system_value(void);

extern mach_timespec_t	clock_get_calendar_value(void);

extern void				delay_for_interval(
							uint32_t		interval,
							uint32_t		scale_factor);
#ifndef	MACH_KERNEL_PRIVATE

#ifndef	ABSOLUTETIME_SCALAR_TYPE

#define clock_get_uptime(a)		\
	clock_get_uptime(__OSAbsoluteTimePtr(a))

#define clock_interval_to_deadline(a, b, c)		\
	clock_interval_to_deadline((a), (b), __OSAbsoluteTimePtr(c))

#define clock_interval_to_absolutetime_interval(a, b, c)	\
	clock_interval_to_absolutetime_interval((a), (b), __OSAbsoluteTimePtr(c))

#define clock_absolutetime_interval_to_deadline(a, b)	\
	clock_absolutetime_interval_to_deadline(__OSAbsoluteTime(a), __OSAbsoluteTimePtr(b))

#define clock_deadline_for_periodic_event(a, b, c)	\
	clock_deadline_for_periodic_event(__OSAbsoluteTime(a), __OSAbsoluteTime(b), __OSAbsoluteTimePtr(c))

#define clock_delay_until(a)	\
	clock_delay_until(__OSAbsoluteTime(a))

#define absolutetime_to_nanoseconds(a, b)	\
	absolutetime_to_nanoseconds(__OSAbsoluteTime(a), (b))

#define nanoseconds_to_absolutetime(a, b)	\
	nanoseconds_to_absolutetime((a), __OSAbsoluteTimePtr(b))

#endif	/* ABSOLUTETIME_SCALAR_TYPE */

#endif	/* !MACH_KERNEL_PRIVATE */

#endif	/* KERNEL_PRIVATE */

__END_DECLS

#endif	/* _KERN_CLOCK_H_ */
