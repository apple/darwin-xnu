/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 *	File:		kern/clock.c
 *	Purpose:	Routines for the creation and use of kernel
 *			alarm clock services. This file and the ipc
 *			routines in kern/ipc_clock.c constitute the
 *			machine-independent clock service layer.
 */

#include <mach_host.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/processor_info.h>
#include <mach/vm_param.h>

#include <kern/cpu_number.h>
#include <kern/misc_protos.h>
#include <kern/lock.h>
#include <kern/host.h>
#include <kern/spl.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <kern/ipc_host.h>
#include <kern/clock.h>
#include <kern/zalloc.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>

#include <mach/mach_traps.h>
#include <mach/clock_reply.h>
#include <mach/mach_time.h>

#include <mach/clock_server.h>
#include <mach/clock_priv_server.h>
#include <mach/host_priv_server.h>

/*
 * Exported interface
 */

#include <mach/clock_server.h>
#include <mach/mach_host_server.h>

/* local data declarations */
decl_simple_lock_data(static,ClockLock)		/* clock system synchronization */
static struct	zone		*alarm_zone;	/* zone for user alarms */
static struct	alarm		*alrmfree;		/* alarm free list pointer */
static struct	alarm		*alrmdone;		/* alarm done list pointer */
static long					alrm_seqno;		/* uniquely identifies alarms */
static thread_call_data_t	alarm_deliver;

decl_simple_lock_data(static,calend_adjlock)

static timer_call_data_t	calend_adjcall;
static uint64_t				calend_adjdeadline;

static thread_call_data_t	calend_wakecall;

/* external declarations */
extern	struct clock	clock_list[];
extern	int		clock_count;

/* local clock subroutines */
static
void	flush_alarms(
			clock_t			clock);

static
void	post_alarm(
			clock_t			clock,
			alarm_t			alarm);

static
int		check_time(
			alarm_type_t	alarm_type,
			mach_timespec_t	*alarm_time,
			mach_timespec_t	*clock_time);

static
void	clock_alarm_deliver(
			thread_call_param_t		p0,
			thread_call_param_t		p1);

static
void	calend_adjust_call(
			timer_call_param_t	p0,
			timer_call_param_t	p1);

static
void	calend_dowakeup(
			thread_call_param_t		p0,
			thread_call_param_t		p1);

/*
 *	Macros to lock/unlock clock system.
 */
#define LOCK_CLOCK(s)			\
	s = splclock();			\
	simple_lock(&ClockLock);

#define UNLOCK_CLOCK(s)			\
	simple_unlock(&ClockLock);	\
	splx(s);

/*
 *	clock_config:
 *
 *	Called once at boot to configure the clock subsystem.
 */
void
clock_config(void)
{
	clock_t			clock;
	register int 	i;

	assert(cpu_number() == master_cpu);

	simple_lock_init(&ClockLock, 0);
	thread_call_setup(&alarm_deliver, clock_alarm_deliver, NULL);

	simple_lock_init(&calend_adjlock, 0);
	timer_call_setup(&calend_adjcall, calend_adjust_call, NULL);

	thread_call_setup(&calend_wakecall, calend_dowakeup, NULL);

	/*
	 * Configure clock devices.
	 */
	for (i = 0; i < clock_count; i++) {
		clock = &clock_list[i];
		if (clock->cl_ops) {
			if ((*clock->cl_ops->c_config)() == 0)
				clock->cl_ops = 0;
		}
	}

	/*
	 * Initialize the timer callouts.
	 */
	timer_call_initialize();

	/* start alarm sequence numbers at 0 */
	alrm_seqno = 0;
}

/*
 *	clock_init:
 *
 *	Called on a processor each time started.
 */
void
clock_init(void)
{
	clock_t			clock;
	register int	i;

	/*
	 * Initialize basic clock structures.
	 */
	for (i = 0; i < clock_count; i++) {
		clock = &clock_list[i];
		if (clock->cl_ops && clock->cl_ops->c_init)
			(*clock->cl_ops->c_init)();
	}
}

/*
 * Called by machine dependent code
 * to initialize areas dependent on the
 * timebase value.  May be called multiple
 * times during start up.
 */
void
clock_timebase_init(void)
{
	sched_timebase_init();
}

/*
 * Initialize the clock ipc service facility.
 */
void
clock_service_create(void)
{
	clock_t			clock;
	register int	i;

	/*
	 * Initialize ipc clock services.
	 */
	for (i = 0; i < clock_count; i++) {
		clock = &clock_list[i];
		if (clock->cl_ops) {
			ipc_clock_init(clock);
			ipc_clock_enable(clock);
		}
	}

	/*
	 * Perform miscellaneous late
	 * initialization.
	 */
	i = sizeof(struct alarm);
	alarm_zone = zinit(i, (4096/i)*i, 10*i, "alarms");
}

/*
 * Get the service port on a clock.
 */
kern_return_t
host_get_clock_service(
	host_t			host,
	clock_id_t		clock_id,
	clock_t			*clock)		/* OUT */
{
	if (host == HOST_NULL || clock_id < 0 || clock_id >= clock_count) {
		*clock = CLOCK_NULL;
		return (KERN_INVALID_ARGUMENT);
	}

	*clock = &clock_list[clock_id];
	if ((*clock)->cl_ops == 0)
		return (KERN_FAILURE);
	return (KERN_SUCCESS);
}

/*
 * Get the control port on a clock.
 */
kern_return_t
host_get_clock_control(
	host_priv_t		host_priv,
	clock_id_t		clock_id,
	clock_t			*clock)		/* OUT */
{
	if (host_priv == HOST_PRIV_NULL || clock_id < 0 || clock_id >= clock_count) {
		*clock = CLOCK_NULL;
		return (KERN_INVALID_ARGUMENT);
	}

	*clock = &clock_list[clock_id];
	if ((*clock)->cl_ops == 0)
		return (KERN_FAILURE);
	return (KERN_SUCCESS);
}

/*
 * Get the current clock time.
 */
kern_return_t
clock_get_time(
	clock_t			clock,
	mach_timespec_t	*cur_time)	/* OUT */
{
	if (clock == CLOCK_NULL)
		return (KERN_INVALID_ARGUMENT);
	return ((*clock->cl_ops->c_gettime)(cur_time));
}

/*
 * Get clock attributes.
 */
kern_return_t
clock_get_attributes(
	clock_t					clock,
	clock_flavor_t			flavor,
	clock_attr_t			attr,		/* OUT */
	mach_msg_type_number_t	*count)		/* IN/OUT */
{
	if (clock == CLOCK_NULL)
		return (KERN_INVALID_ARGUMENT);
	if (clock->cl_ops->c_getattr)
		return(clock->cl_ops->c_getattr(flavor, attr, count));
	else
		return (KERN_FAILURE);
}

/*
 * Set the current clock time.
 */
kern_return_t
clock_set_time(
	clock_t			clock,
	mach_timespec_t	new_time)
{
	mach_timespec_t	*clock_time;

	if (clock == CLOCK_NULL)
		return (KERN_INVALID_ARGUMENT);
	if (clock->cl_ops->c_settime == NULL)
		return (KERN_FAILURE);
	clock_time = &new_time;
	if (BAD_MACH_TIMESPEC(clock_time))
		return (KERN_INVALID_VALUE);

	/*
	 * Flush all outstanding alarms.
	 */
	flush_alarms(clock);

	/*
	 * Set the new time.
	 */
	return (clock->cl_ops->c_settime(clock_time));
}

/*
 * Set the clock alarm resolution.
 */
kern_return_t
clock_set_attributes(
	clock_t					clock,
	clock_flavor_t			flavor,
	clock_attr_t			attr,
	mach_msg_type_number_t	count)
{
	if (clock == CLOCK_NULL)
		return (KERN_INVALID_ARGUMENT);
	if (clock->cl_ops->c_setattr)
		return (clock->cl_ops->c_setattr(flavor, attr, count));
	else
		return (KERN_FAILURE);
}

/*
 * Setup a clock alarm.
 */
kern_return_t
clock_alarm(
	clock_t					clock,
	alarm_type_t			alarm_type,
	mach_timespec_t			alarm_time,
	ipc_port_t				alarm_port,
	mach_msg_type_name_t	alarm_port_type)
{
	alarm_t					alarm;
	mach_timespec_t			clock_time;
	int						chkstat;
	kern_return_t			reply_code;
	spl_t					s;

	if (clock == CLOCK_NULL)
		return (KERN_INVALID_ARGUMENT);
	if (clock->cl_ops->c_setalrm == 0)
		return (KERN_FAILURE);
	if (IP_VALID(alarm_port) == 0)
		return (KERN_INVALID_CAPABILITY);

	/*
	 * Check alarm parameters. If parameters are invalid,
	 * send alarm message immediately.
	 */
	(*clock->cl_ops->c_gettime)(&clock_time);
	chkstat = check_time(alarm_type, &alarm_time, &clock_time);
	if (chkstat <= 0) {
		reply_code = (chkstat < 0 ? KERN_INVALID_VALUE : KERN_SUCCESS);
		clock_alarm_reply(alarm_port, alarm_port_type,
				  reply_code, alarm_type, clock_time);
		return (KERN_SUCCESS);
	}

	/*
	 * Get alarm and add to clock alarm list.
	 */

	LOCK_CLOCK(s);
	if ((alarm = alrmfree) == 0) {
		UNLOCK_CLOCK(s);
		alarm = (alarm_t) zalloc(alarm_zone);
		if (alarm == 0)
			return (KERN_RESOURCE_SHORTAGE);
		LOCK_CLOCK(s);
	}
	else
		alrmfree = alarm->al_next;

	alarm->al_status = ALARM_CLOCK;
	alarm->al_time = alarm_time;
	alarm->al_type = alarm_type;
	alarm->al_port = alarm_port;
	alarm->al_port_type = alarm_port_type;
	alarm->al_clock = clock;
	alarm->al_seqno = alrm_seqno++;
	post_alarm(clock, alarm);
	UNLOCK_CLOCK(s);

	return (KERN_SUCCESS);
}

/*
 * Sleep on a clock. System trap. User-level libmach clock_sleep
 * interface call takes a mach_timespec_t sleep_time argument which it
 * converts to sleep_sec and sleep_nsec arguments which are then
 * passed to clock_sleep_trap.
 */
kern_return_t
clock_sleep_trap(
	struct clock_sleep_trap_args *args)
{
	mach_port_name_t	clock_name = args->clock_name;
	sleep_type_t		sleep_type = args->sleep_type;
	int					sleep_sec = args->sleep_sec;
	int					sleep_nsec = args->sleep_nsec;
	mach_vm_address_t	wakeup_time_addr = args->wakeup_time;  
	clock_t				clock;
	mach_timespec_t		swtime;
	kern_return_t		rvalue;

	/*
	 * Convert the trap parameters.
	 */
	if (clock_name != MACH_PORT_NULL)
		clock = port_name_to_clock(clock_name);
	else
		clock = &clock_list[SYSTEM_CLOCK];

	swtime.tv_sec  = sleep_sec;
	swtime.tv_nsec = sleep_nsec;

	/*
	 * Call the actual clock_sleep routine.
	 */
	rvalue = clock_sleep_internal(clock, sleep_type, &swtime);

	/*
	 * Return current time as wakeup time.
	 */
	if (rvalue != KERN_INVALID_ARGUMENT && rvalue != KERN_FAILURE) {
		copyout((char *)&swtime, wakeup_time_addr, sizeof(mach_timespec_t));
	}
	return (rvalue);
}	

/*
 * Kernel internally callable clock sleep routine. The calling
 * thread is suspended until the requested sleep time is reached.
 */
kern_return_t
clock_sleep_internal(
	clock_t				clock,
	sleep_type_t		sleep_type,
	mach_timespec_t		*sleep_time)
{
	alarm_t				alarm;
	mach_timespec_t		clock_time;
	kern_return_t		rvalue;
	int					chkstat;
	spl_t				s;

	if (clock == CLOCK_NULL)
		return (KERN_INVALID_ARGUMENT);
	if (clock->cl_ops->c_setalrm == 0)
		return (KERN_FAILURE);

	/*
	 * Check sleep parameters. If parameters are invalid
	 * return an error, otherwise post alarm request.
	 */
	(*clock->cl_ops->c_gettime)(&clock_time);

	chkstat = check_time(sleep_type, sleep_time, &clock_time);
	if (chkstat < 0)
		return (KERN_INVALID_VALUE);
	rvalue = KERN_SUCCESS;
	if (chkstat > 0) {
		wait_result_t wait_result;

		/*
		 * Get alarm and add to clock alarm list.
		 */

		LOCK_CLOCK(s);
		if ((alarm = alrmfree) == 0) {
			UNLOCK_CLOCK(s);
			alarm = (alarm_t) zalloc(alarm_zone);
			if (alarm == 0)
				return (KERN_RESOURCE_SHORTAGE);
			LOCK_CLOCK(s);
		}
		else
			alrmfree = alarm->al_next;

		/*
		 * Wait for alarm to occur.
		 */
		wait_result = assert_wait((event_t)alarm, THREAD_ABORTSAFE);
		if (wait_result == THREAD_WAITING) {
			alarm->al_time = *sleep_time;
			alarm->al_status = ALARM_SLEEP;
			post_alarm(clock, alarm);
			UNLOCK_CLOCK(s);

			wait_result = thread_block(THREAD_CONTINUE_NULL);

			/*
			 * Note if alarm expired normally or whether it
			 * was aborted. If aborted, delete alarm from
			 * clock alarm list. Return alarm to free list.
			 */
			LOCK_CLOCK(s);
			if (alarm->al_status != ALARM_DONE) {
				assert(wait_result != THREAD_AWAKENED);
				if (((alarm->al_prev)->al_next = alarm->al_next) != NULL)
					(alarm->al_next)->al_prev = alarm->al_prev;
				rvalue = KERN_ABORTED;
			}
			*sleep_time = alarm->al_time;
			alarm->al_status = ALARM_FREE;
		} else {
			assert(wait_result == THREAD_INTERRUPTED);
			assert(alarm->al_status == ALARM_FREE);
			rvalue = KERN_ABORTED;
		}
		alarm->al_next = alrmfree;
		alrmfree = alarm;
		UNLOCK_CLOCK(s);
	}
	else
		*sleep_time = clock_time;

	return (rvalue);
}

/*
 * CLOCK INTERRUPT SERVICE ROUTINES.
 */

/*
 * Service clock alarm interrupts. Called from machine dependent
 * layer at splclock(). The clock_id argument specifies the clock,
 * and the clock_time argument gives that clock's current time.
 */
void
clock_alarm_intr(
	clock_id_t			clock_id,
	mach_timespec_t		*clock_time)
{
	clock_t				clock;
	register alarm_t	alrm1;
	register alarm_t	alrm2;
	mach_timespec_t		*alarm_time;
	spl_t				s;

	clock = &clock_list[clock_id];

	/*
	 * Update clock alarm list. All alarms that are due are moved
	 * to the alarmdone list to be serviced by the alarm_thread.
	 */

	LOCK_CLOCK(s);
	alrm1 = (alarm_t) &clock->cl_alarm;
	while ((alrm2 = alrm1->al_next) != NULL) {
		alarm_time = &alrm2->al_time;
		if (CMP_MACH_TIMESPEC(alarm_time, clock_time) > 0)
			break;

		/*
		 * Alarm has expired, so remove it from the
		 * clock alarm list.
		 */  
		if ((alrm1->al_next = alrm2->al_next) != NULL)
			(alrm1->al_next)->al_prev = alrm1;

		/*
		 * If a clock_sleep() alarm, wakeup the thread
		 * which issued the clock_sleep() call.
		 */
		if (alrm2->al_status == ALARM_SLEEP) {
			alrm2->al_next = 0;
			alrm2->al_status = ALARM_DONE;
			alrm2->al_time = *clock_time;
			thread_wakeup((event_t)alrm2);
		}

 		/*
		 * If a clock_alarm() alarm, place the alarm on
		 * the alarm done list and schedule the alarm
		 * delivery mechanism.
		 */
		else {
			assert(alrm2->al_status == ALARM_CLOCK);
			if ((alrm2->al_next = alrmdone) != NULL)
				alrmdone->al_prev = alrm2;
			else
				thread_call_enter(&alarm_deliver);
			alrm2->al_prev = (alarm_t) &alrmdone;
			alrmdone = alrm2;
			alrm2->al_status = ALARM_DONE;
			alrm2->al_time = *clock_time;
		}
	}

	/*
	 * Setup the clock dependent layer to deliver another
	 * interrupt for the next pending alarm.
	 */
	if (alrm2)
		(*clock->cl_ops->c_setalrm)(alarm_time);
	UNLOCK_CLOCK(s);
}

/*
 * ALARM DELIVERY ROUTINES.
 */

static void
clock_alarm_deliver(
	__unused thread_call_param_t		p0,
	__unused thread_call_param_t		p1)
{
	register alarm_t	alrm;
	kern_return_t		code;
	spl_t				s;

	LOCK_CLOCK(s);
	while ((alrm = alrmdone) != NULL) {
		if ((alrmdone = alrm->al_next) != NULL)
			alrmdone->al_prev = (alarm_t) &alrmdone;
		UNLOCK_CLOCK(s);

		code = (alrm->al_status == ALARM_DONE? KERN_SUCCESS: KERN_ABORTED);
		if (alrm->al_port != IP_NULL) {
			/* Deliver message to designated port */
			if (IP_VALID(alrm->al_port)) {
				clock_alarm_reply(alrm->al_port, alrm->al_port_type, code,
								  				alrm->al_type, alrm->al_time);
			}

			LOCK_CLOCK(s);
			alrm->al_status = ALARM_FREE;
			alrm->al_next = alrmfree;
			alrmfree = alrm;
		}
		else
			panic("clock_alarm_deliver");
	}

	UNLOCK_CLOCK(s);
}

/*
 * CLOCK PRIVATE SERVICING SUBROUTINES.
 */

/*
 * Flush all pending alarms on a clock. All alarms
 * are activated and timestamped correctly, so any
 * programs waiting on alarms/threads will proceed
 * with accurate information.
 */
static
void
flush_alarms(
	clock_t				clock)
{
	register alarm_t	alrm1, alrm2;
	spl_t				s;

	/*
	 * Flush all outstanding alarms.
	 */
	LOCK_CLOCK(s);
	alrm1 = (alarm_t) &clock->cl_alarm;
	while ((alrm2 = alrm1->al_next) != NULL) {
		/*
		 * Remove alarm from the clock alarm list.
		 */  
		if ((alrm1->al_next = alrm2->al_next) != NULL)
			(alrm1->al_next)->al_prev = alrm1;

		/*
		 * If a clock_sleep() alarm, wakeup the thread
		 * which issued the clock_sleep() call.
		 */
		if (alrm2->al_status == ALARM_SLEEP) {
			alrm2->al_next = 0;
			thread_wakeup((event_t)alrm2);
		}
		else {
			/*
			 * If a clock_alarm() alarm, place the alarm on
			 * the alarm done list and wakeup the dedicated
			 * kernel alarm_thread to service the alarm.
			 */
			assert(alrm2->al_status == ALARM_CLOCK);
			if ((alrm2->al_next = alrmdone) != NULL)
				alrmdone->al_prev = alrm2;
			else
				thread_wakeup((event_t)&alrmdone);
			alrm2->al_prev = (alarm_t) &alrmdone;
			alrmdone = alrm2;
		}
	}
	UNLOCK_CLOCK(s);
}

/*
 * Post an alarm on a clock's active alarm list. The alarm is
 * inserted in time-order into the clock's active alarm list.
 * Always called from within a LOCK_CLOCK() code section.
 */
static
void
post_alarm(
	clock_t				clock,
	alarm_t				alarm)
{
	register alarm_t	alrm1, alrm2;
	mach_timespec_t		*alarm_time;
	mach_timespec_t		*queue_time;

	/*
	 * Traverse alarm list until queue time is greater
	 * than alarm time, then insert alarm.
	 */
	alarm_time = &alarm->al_time;
	alrm1 = (alarm_t) &clock->cl_alarm;
	while ((alrm2 = alrm1->al_next) != NULL) {
		queue_time = &alrm2->al_time;
		if (CMP_MACH_TIMESPEC(queue_time, alarm_time) > 0)
			break;
		alrm1 = alrm2;
	}
	alrm1->al_next = alarm;
	alarm->al_next = alrm2;
	alarm->al_prev = alrm1;
	if (alrm2)
		alrm2->al_prev  = alarm;

	/*
	 * If the inserted alarm is the 'earliest' alarm,
	 * reset the device layer alarm time accordingly.
	 */
	if (clock->cl_alarm.al_next == alarm)
		(*clock->cl_ops->c_setalrm)(alarm_time);
}

/*
 * Check the validity of 'alarm_time' and 'alarm_type'. If either
 * argument is invalid, return a negative value. If the 'alarm_time'
 * is now, return a 0 value. If the 'alarm_time' is in the future,
 * return a positive value.
 */
static
int
check_time(
	alarm_type_t		alarm_type,
	mach_timespec_t		*alarm_time,
	mach_timespec_t		*clock_time)
{
	int					result;

	if (BAD_ALRMTYPE(alarm_type))
		return (-1);
	if (BAD_MACH_TIMESPEC(alarm_time))
		return (-1);
	if ((alarm_type & ALRMTYPE) == TIME_RELATIVE)
		ADD_MACH_TIMESPEC(alarm_time, clock_time);

	result = CMP_MACH_TIMESPEC(alarm_time, clock_time);

	return ((result >= 0)? result: 0);
}

mach_timespec_t
clock_get_system_value(void)
{
	clock_t				clock = &clock_list[SYSTEM_CLOCK];
	mach_timespec_t		value;

	(void) (*clock->cl_ops->c_gettime)(&value);

	return value;
}

mach_timespec_t
clock_get_calendar_value(void)
{
	clock_t				clock = &clock_list[CALENDAR_CLOCK];
	mach_timespec_t		value = MACH_TIMESPEC_ZERO;

	(void) (*clock->cl_ops->c_gettime)(&value);

	return value;
}

void
clock_deadline_for_periodic_event(
	uint64_t			interval,
	uint64_t			abstime,
	uint64_t			*deadline)
{
	assert(interval != 0);

	*deadline += interval;

	if (*deadline <= abstime) {
		*deadline = abstime + interval;
		abstime = mach_absolute_time();

		if (*deadline <= abstime)
			*deadline = abstime + interval;
	}
}

void
mk_timebase_info_trap(
	struct mk_timebase_info_trap_args *args)
{
	uint32_t					*delta = args->delta;
	uint32_t					*abs_to_ns_numer = args->abs_to_ns_numer;
	uint32_t					*abs_to_ns_denom = args->abs_to_ns_denom;
	uint32_t					*proc_to_abs_numer = args->proc_to_abs_numer;
	uint32_t					*proc_to_abs_denom = args->proc_to_abs_denom;
	mach_timebase_info_data_t	info;
	uint32_t					one = 1;

	clock_timebase_info(&info);

	copyout((void *)&one, CAST_USER_ADDR_T(delta), sizeof (uint32_t));

	copyout((void *)&info.numer, CAST_USER_ADDR_T(abs_to_ns_numer), sizeof (uint32_t));
	copyout((void *)&info.denom, CAST_USER_ADDR_T(abs_to_ns_denom), sizeof (uint32_t));

	copyout((void *)&one, CAST_USER_ADDR_T(proc_to_abs_numer), sizeof (uint32_t));
	copyout((void *)&one, CAST_USER_ADDR_T(proc_to_abs_denom), sizeof (uint32_t));
}

kern_return_t
mach_timebase_info_trap(
	struct mach_timebase_info_trap_args *args)
{
	mach_vm_address_t 			out_info_addr = args->info;
	mach_timebase_info_data_t	info;

	clock_timebase_info(&info);

	copyout((void *)&info, out_info_addr, sizeof (info));

	return (KERN_SUCCESS);
}

static void
mach_wait_until_continue(
	__unused void	*parameter,
	wait_result_t	wresult)
{
	thread_syscall_return((wresult == THREAD_INTERRUPTED)? KERN_ABORTED: KERN_SUCCESS);
	/*NOTREACHED*/
}

kern_return_t
mach_wait_until_trap(
	struct mach_wait_until_trap_args	*args)
{
	uint64_t		deadline = args->deadline;
	wait_result_t	wresult;

	wresult = assert_wait_deadline((event_t)mach_wait_until_trap, THREAD_ABORTSAFE, deadline);
	if (wresult == THREAD_WAITING)
		wresult = thread_block(mach_wait_until_continue);

	return ((wresult == THREAD_INTERRUPTED)? KERN_ABORTED: KERN_SUCCESS);
}

/*
 * Delay primitives.
 */
void
clock_delay_until(
	uint64_t		deadline)
{
	uint64_t		now = mach_absolute_time();

	if (now >= deadline)
		return;

	if (	(deadline - now) < (8 * sched_cswtime)	||
			get_preemption_level() != 0				||
			ml_get_interrupts_enabled() == FALSE	)
		machine_delay_until(deadline);
	else {
		assert_wait_deadline((event_t)clock_delay_until, THREAD_UNINT, deadline - sched_cswtime);

		thread_block(THREAD_CONTINUE_NULL);
	}
}

void
delay_for_interval(
	uint32_t		interval,
	uint32_t		scale_factor)
{
	uint64_t		end;

	clock_interval_to_deadline(interval, scale_factor, &end);

	clock_delay_until(end);
}

void
delay(
	int		usec)
{
	delay_for_interval((usec < 0)? -usec: usec, NSEC_PER_USEC);
}

void
clock_adjtime(
	int32_t		*secs,
	int32_t		*microsecs)
{
	uint32_t	interval;
	spl_t		s;

	s = splclock();
	simple_lock(&calend_adjlock);

	interval = clock_set_calendar_adjtime(secs, microsecs);
	if (interval != 0) {
		if (calend_adjdeadline >= interval)
			calend_adjdeadline -= interval;
		clock_deadline_for_periodic_event(interval, mach_absolute_time(),
												&calend_adjdeadline);

		timer_call_enter(&calend_adjcall, calend_adjdeadline);
	}
	else
		timer_call_cancel(&calend_adjcall);

	simple_unlock(&calend_adjlock);
	splx(s);
}

static void
calend_adjust_call(
	__unused timer_call_param_t		p0,
	__unused timer_call_param_t		p1)
{
	uint32_t	interval;
	spl_t		s;

	s = splclock();
	simple_lock(&calend_adjlock);

	interval = clock_adjust_calendar();
	if (interval != 0) {
		clock_deadline_for_periodic_event(interval, mach_absolute_time(),
								  				&calend_adjdeadline);

		timer_call_enter(&calend_adjcall, calend_adjdeadline);
	}

	simple_unlock(&calend_adjlock);
	splx(s);
}

void
clock_wakeup_calendar(void)
{
	thread_call_enter(&calend_wakecall);
}

extern	void		IOKitResetTime(void); /* XXX */

static void
calend_dowakeup(
	__unused thread_call_param_t		p0,
	__unused thread_call_param_t		p1)
{

	IOKitResetTime();
}
