/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */
/*
 *	The Event Trace Analysis Package
 *	================================
 *
 *	Function:	Traces micro-kernel events.
 *
 *	Macro Notes:	Several macros are added throughout the lock code.
 *			These macros allow for convenient configuration
 *			and code readability.
 *
 *			The macro prefixes determine a specific trace
 *			configuration operation:
 *
 *			CUM	-  Cumulative trace specific operation.
 *			MON	-  Monitored  trace specific operation.
 *			ETAP	-  Both a cumulative and monitored trace
 *				   operation.
 */


#ifndef _KERN_ETAP_MACROS_H_
#define _KERN_ETAP_MACROS_H_

#include <kern/etap_options.h>
#include <kern/lock.h>
#include <mach/etap.h>
#include <mach/etap_events.h>
#include <kern/etap_pool.h>


#if	ETAP

#include <mach/vm_param.h>
#include <mach/message.h>

#include <kern/macro_help.h>

extern void etap_init_phase1(void);
extern void etap_init_phase2(void);
extern void etap_event_table_assign(struct event_table_chain *, etap_event_t);
extern unsigned int  etap_get_pc(void);
extern event_table_t event_table;
extern subs_table_t subs_table;

/*
 *  Time Macros
 */

#define ETAP_TIMESTAMP(t)		rtc_gettime_interrupts_disabled(&t)
#define ETAP_TIME_SUM(t,sum_me)		t += sum_me
#define ETAP_TIME_SUB(t,stop,start)		\
MACRO_BEGIN					\
	(t) = (stop);				\
	SUB_MACH_TIMESPEC(&(t), &(start));	\
MACRO_END
#define ETAP_TIME_SQR(t,sqr_me)		t += sqr_me*sqr_me
#define ETAP_TIME_DIV(r,n,d)		r = (u_short) n/d
#define ETAP_TIME_IS_ZERO(t)		((t).tv_sec == 0)
#define ETAP_TIME_CLEAR(t)		((t).tv_sec = 0)
#define ETAP_TIME_GREATER(t1,t2)	((t1) > (t2))

#else	/* ETAP */

#define etap_init_phase1()
#define etap_init_phase2()
#define etap_event_table_assign(event)
#define ETAP_TIMESTAMP(t)
#define ETAP_TIME_SUB(t,start,stop)
#define ETAP_TIME_CLEAR(t)

#endif	/* ETAP */


/*
 *  ===================================================
 *  ETAP: cumulative trace specific macros
 *  ===================================================
 */

#if	ETAP_LOCK_ACCUMULATE

extern cbuff_entry_t	etap_cbuff_reserve(event_table_t);
#if MACH_LDEBUG
extern simple_lock_t	cbuff_locks;
#else
extern simple_lock_data_t cbuff_locks;
#endif
extern int		cbuff_width;

/*
 *  If cumulative hold tracing is enabled for the event (i.e., acquired lock),
 *  the CUM_HOLD_ACCUMULATE macro will update the appropriate cumulative buffer
 *  entry with the newly collected hold data.
 */

#define CUM_HOLD_ACCUMULATE(cp,total_time,dynamic,trace)		      \
MACRO_BEGIN								      \
    u_short	_bucket;						      \
    if ((cp) != CBUFF_ENTRY_NULL && ((trace) & CUM_DURATION)) {		      \
       if (dynamic)							      \
	   simple_lock_no_trace(&cbuff_locks[dynamic-1]);		      \
       (cp)->hold.triggered++;						      \
       ETAP_TIME_SUM((cp)->hold.time,(total_time));			      \
       ETAP_TIME_SQR((cp)->hold.time_sq,(total_time));			      \
       if (ETAP_TIME_IS_ZERO((cp)->hold.min_time) ||			      \
	   ETAP_TIME_GREATER((cp)->hold.min_time,(total_time)))		      \
	       (cp)->hold.min_time = (total_time);			      \
       if (ETAP_TIME_GREATER((total_time),(cp)->hold.max_time))		      \
	       (cp)->hold.max_time = (total_time);			      \
       ETAP_TIME_DIV(_bucket,(total_time),cbuff_width);			      \
       if (_bucket >= ETAP_CBUFF_IBUCKETS)				      \
	   (cp)->hold_interval[ETAP_CBUFF_IBUCKETS-1]++;		      \
       else								      \
	   (cp)->hold_interval[_bucket]++;				      \
       if (dynamic)							      \
	   simple_unlock_no_trace(&cbuff_locks[dynamic-1]);		      \
    }									      \
MACRO_END

/*
 *  If cumulative wait tracing is enabled for the event (i.e., acquired lock),
 *  the CUM_WAIT_ACCUMULATE macro will update the appropriate cumulative
 *  buffer entry with the newly collected wait data.
 */

#define CUM_WAIT_ACCUMULATE(cp,total_time,dynamic,trace)		      \
MACRO_BEGIN								      \
    u_short    _bucket;							      \
    if ((cp) != CBUFF_ENTRY_NULL && ((trace) & CUM_CONTENTION)) {	      \
       if (dynamic)							      \
	   simple_lock_no_trace(&cbuff_locks[dynamic-1]);		      \
       (cp)->wait.triggered++;						      \
       ETAP_TIME_SUM((cp)->wait.time,(total_time));			      \
       ETAP_TIME_SQR((cp)->wait.time_sq,(total_time));			      \
       if (ETAP_TIME_IS_ZERO((cp)->wait.min_time) ||			      \
	   ETAP_TIME_GREATER((cp)->wait.min_time,(total_time)))		      \
	       (cp)->wait.min_time = (total_time);			      \
       if (ETAP_TIME_GREATER((total_time),(cp)->wait.max_time))		      \
	       (cp)->wait.max_time = (total_time);			      \
       ETAP_TIME_DIV(_bucket,(total_time),cbuff_width);			      \
       if (_bucket >= ETAP_CBUFF_IBUCKETS)				      \
	   (cp)->wait_interval[ETAP_CBUFF_IBUCKETS-1]++;		      \
       else								      \
	   (cp)->wait_interval[_bucket]++;				      \
       if (dynamic)							      \
	   simple_unlock_no_trace(&cbuff_locks[dynamic-1]);		      \
     }									      \
MACRO_END

/*
 *  Initially a lock's cbuff_read pointer is set to CBUFF_ENTRY_NULL. This
 *  saves space in the cumulative buffer in the event that a read lock is
 *  not acquired.  In the case that a read lock is acquired, the
 *  CUM_READ_ENTRY_RESERVE macro is called.  Here a cumulative
 *  record is reserved and initialized.
 */

#define CUM_READ_ENTRY_RESERVE(l,cp,trace)				      \
MACRO_BEGIN								      \
    if ((cp) == CBUFF_ENTRY_NULL && (trace) & ETAP_CUMULATIVE) {	      \
       (cp) = etap_cbuff_reserve(lock_event_table(l));			      \
       if ((cp) != CBUFF_ENTRY_NULL) {					      \
	  (cp)->event = lock_event_table(l)->event;			      \
	  (cp)->instance = (u_int) l;					      \
	  (cp)->kind = READ_LOCK;					      \
       }								      \
    }									      \
MACRO_END

#else  /* ETAP_LOCK_ACCUMULATE */
#define etap_cbuff_reserve(et)
#define CUM_HOLD_ACCUMULATE(cp,t,d,tr)
#define CUM_WAIT_ACCUMULATE(cp,t,d,tr)
#define CUM_READ_ENTRY_RESERVE(l,rep,tr)
#endif /* ETAP_LOCK_ACCUMULATE */

/*
 *  ===============================================
 *  ETAP: monitor trace specific macros
 *  ===============================================
 */

#if	ETAP_MONITOR
extern int			mbuff_entries;
extern monitor_buffer_t		mbuff[];
#endif	/* ETAP_MONITOR */


#if	ETAP_LOCK_MONITOR

/*
 *  If monitor tracing is enabled for the lock, the
 *  MON_DATA_COLLECT macro will write collected lock data to
 *  the next slot in a cpu specific monitor buffer.  Circular
 *  buffer maintenance is also performed here.
 */

#define MON_DATA_COLLECT(l,e,total_time,type,op,trace)			     \
MACRO_BEGIN								     \
	mbuff_entry_t _mp;						     \
	int _cpu, _ent, _s;						     \
	if ((trace) & op) {						     \
	   mp_disable_preemption();					     \
	   _cpu = cpu_number();						     \
	   _s	= splhigh();						     \
	   _ent = mbuff[_cpu]->free;					     \
	   _mp	= &mbuff[_cpu]->entry[_ent];				     \
	   _mp->event	     = lock_event_table(l)->event;		     \
	   _mp->flags	     = ((op) | (type));				     \
	   _mp->instance     = (u_int) (l);				     \
	   _mp->time	     = (total_time);				     \
	   _mp->data[0]	     = (e)->start_pc;				     \
	   _mp->data[1]	     = (e)->end_pc;				     \
	   mbuff[_cpu]->free = (_ent+1) % mbuff_entries;		     \
	   if (mbuff[_cpu]->free == 0)					     \
		mbuff[_cpu]->timestamp++;				     \
	   splx(_s);							     \
	   mp_enable_preemption();					     \
	}								     \
MACRO_END

#define MON_CLEAR_PCS(l)						     \
MACRO_BEGIN								     \
	(l)->start_pc = 0;						     \
	(l)->end_pc   = 0;						     \
MACRO_END

#define MON_ASSIGN_PC(target,source,trace)				     \
	if ((trace) & ETAP_MONITORED) target = source

#else  /* ETAP_LOCK_MONITOR */
#define MON_DATA_COLLECT(l,le,tt,t,o,tr)
#define MON_GET_PC(pc,tr)
#define MON_CLEAR_PCS(l)
#define MON_ASSIGN_PC(t,s,tr)
#endif /* ETAP_LOCK_MONITOR */


#if     ETAP_EVENT_MONITOR

#include <mach/exception_types.h>

#define ETAP_EXCEPTION_PROBE(_f, _th, _ex, _sysnum)             \
        if (_ex == EXC_SYSCALL) {                               \
                ETAP_PROBE_DATA(ETAP_P_SYSCALL_UNIX,            \
                                _f,                             \
                                _th,                            \
                                _sysnum,                        \
                                sizeof(int));                   \
        }
#else   /* ETAP_EVENT_MONITOR */
#define ETAP_EXCEPTION_PROBE(_f, _th, _ex, _sysnum)
#endif  /* ETAP_EVENT_MONITOR */

#if	ETAP_EVENT_MONITOR

#define ETAP_PROBE_DATA_COND(_event, _flags, _thread, _data, _size, _cond)		     \
MACRO_BEGIN								     \
	mbuff_entry_t _mp;						     \
	int _cpu, _ent, _s;						     \
	if (event_table[_event].status && (_cond)) {			     \
	   mp_disable_preemption();					     \
	   _cpu	 = cpu_number();					     \
	   _s	 = splhigh();						     \
	   _ent	 = mbuff[_cpu]->free;					     \
	   _mp = &mbuff[_cpu]->entry[_ent];				     \
	   ETAP_TIMESTAMP(_mp->time);					     \
	   _mp->pc	  = etap_get_pc();				     \
	   _mp->event	  = _event;					     \
	   _mp->flags	  = KERNEL_EVENT | _flags;			     \
	   _mp->instance  = (u_int) _thread;				     \
	   bcopy((char *) _data, (char *) _mp->data, _size);		     \
	   mbuff[_cpu]->free = (_ent+1) % mbuff_entries;		     \
	   if (mbuff[_cpu]->free == 0)					     \
		mbuff[_cpu]->timestamp++;				     \
	   splx(_s);							     \
	   mp_enable_preemption();					     \
	}								     \
MACRO_END

#define ETAP_PROBE(_event, _flags, _thread)				     \
	ETAP_PROBE_DATA_COND(_event, _flags, _thread, 0, 0, 1)

#define ETAP_PROBE_DATA(_event, _flags, _thread, _data, _size)		     \
	ETAP_PROBE_DATA_COND(_event, _flags, _thread, _data, _size,	     \
	(_thread)->etap_trace)

#define ETAP_DATA_LOAD(ed, x)		((ed) = (u_int) (x))
#define ETAP_SET_REASON(_th, _reason)	((_th)->etap_reason = (_reason))

#else	/* ETAP_EVENT_MONITOR */
#define ETAP_PROBE(e,f,th)
#define ETAP_PROBE_DATA(e,f,th,d,s)
#define ETAP_PROBE_DATA_COND(e,f,th,d,s,c)
#define ETAP_DATA_LOAD(d,x);
#define ETAP_SET_REASON(t,r)
#endif	/* ETAP_EVENT_MONITOR */

/*
 *  =================================
 *  ETAP: general lock macros
 *  =================================
 */

#if	ETAP_LOCK_TRACE

#define ETAP_TOTAL_TIME(t,stop,start)	\
	ETAP_TIME_SUB((t),(stop),(start))

#define ETAP_DURATION_TIMESTAMP(e,trace)				\
MACRO_BEGIN								\
	if ((trace) & ETAP_DURATION)					\
	     ETAP_TIMESTAMP((e)->start_hold_time);			\
MACRO_END

#define ETAP_COPY_START_HOLD_TIME(entry,time,trace)			\
MACRO_BEGIN								\
	if ((trace) & ETAP_DURATION)					\
	     (entry)->start_hold_time = time;				\
MACRO_END

#define ETAP_CONTENTION_TIMESTAMP(e,trace)				\
MACRO_BEGIN								\
	if ((trace) & ETAP_CONTENTION)					\
	     ETAP_TIMESTAMP((e)->start_wait_time);			\
MACRO_END

#define ETAP_STAMP(event_table,trace,dynamic)				\
MACRO_BEGIN								\
	if ((event_table) != EVENT_TABLE_NULL) {			\
	    (dynamic) = (event_table)->dynamic;				\
	    (trace)   = (event_table)->status;				\
	}								\
MACRO_END

#define ETAP_WHOLE_OP(l)	\
	(!(ETAP_TIME_IS_ZERO((l)->u.s.start_hold_time)))
#define ETAP_DURATION_ENABLED(trace)	((trace) & ETAP_DURATION)
#define ETAP_CONTENTION_ENABLED(trace)	((trace) & ETAP_CONTENTION)

/*
 *  The ETAP_CLEAR_TRACE_DATA macro sets the etap specific fields
 *  of the simple_lock_t structure to zero.
 *
 *  This is always done just before a simple lock is released.
 */

#define ETAP_CLEAR_TRACE_DATA(l)		\
MACRO_BEGIN					\
	ETAP_TIME_CLEAR((l)->u.s.start_hold_time);	\
	MON_CLEAR_PCS((l));			\
MACRO_END


/* ==================================================
 *  The ETAP_XXX_ENTRY macros manipulate the locks
 *  start_list (a linked list of start data).
 * ==================================================
 */

#define ETAP_CREATE_ENTRY(entry,trace)					   \
MACRO_BEGIN								   \
	if ((trace) & ETAP_TRACE_ON)					   \
	    (entry) = get_start_data_node();				   \
MACRO_END

#define ETAP_LINK_ENTRY(l,entry,trace)					   \
MACRO_BEGIN								   \
	if ((trace) & ETAP_TRACE_ON) {					   \
		(entry)->next = (l)->u.s.start_list;			   \
		(l)->u.s.start_list = (entry);				   \
		(entry)->thread_id = (u_int) current_thread();		   \
		ETAP_TIME_CLEAR((entry)->start_wait_time);		   \
	}								   \
MACRO_END

#define ETAP_FIND_ENTRY(l,entry,trace)					   \
MACRO_BEGIN								   \
	u_int _ct;							   \
	_ct = (u_int) current_thread();					   \
	(entry) = (l)->u.s.start_list;					   \
	while ((entry) != SD_ENTRY_NULL && (entry)->thread_id != _ct)	   \
	      (entry) = (entry)->next;					   \
	if ((entry) == SD_ENTRY_NULL)					   \
	      (trace) = 0;						   \
MACRO_END

#define ETAP_UNLINK_ENTRY(l,entry)					   \
MACRO_BEGIN								   \
	boolean_t	  _first = TRUE;				   \
	start_data_node_t _prev;					   \
	u_int		  _ct;						   \
	_ct = (u_int) current_thread();					   \
	(entry) = (l)->u.s.start_list;					   \
	while ((entry) != SD_ENTRY_NULL && (entry)->thread_id != _ct){	   \
	    _prev = (entry);						   \
	    (entry) = (entry)->next;					   \
	    _first = FALSE;						   \
	}								   \
	if (entry != SD_ENTRY_NULL) {					   \
	    if (_first)							   \
		(l)->u.s.start_list = (entry)->next;			   \
	    else							   \
		_prev->next = (entry)->next;				   \
	    (entry)->next = SD_ENTRY_NULL;				   \
	}								   \
MACRO_END

#define ETAP_DESTROY_ENTRY(entry)					   \
MACRO_BEGIN								   \
	if ((entry) != SD_ENTRY_NULL)					   \
	   free_start_data_node ((entry));				   \
MACRO_END

#else	/* ETAP_LOCK_TRACE */
#define ETAP_TOTAL_TIME(t,stop,start)
#define ETAP_DURATION_TIMESTAMP(le,tr)
#define ETAP_CONTENTION_TIMESTAMP(le,tr)
#define ETAP_COPY_START_HOLD_TIME(le,t,tr)
#define ETAP_STAMP(tt,tr,d)
#define ETAP_DURATION_ENABLED(tr)     (0)  /* always fails */
#define ETAP_CONTENTION_ENABLED(tr)   (0)  /* always fails */
#define ETAP_CLEAR_TRACE_DATA(l)
#define ETAP_CREATE_ENTRY(e,tr)
#define ETAP_LINK_ENTRY(l,e,tr)
#define ETAP_FIND_ENTRY(l,e,tr)
#define ETAP_UNLINK_ENTRY(l,e)
#define ETAP_DESTROY_ENTRY(e)
#endif	/* ETAP_LOCK_TRACE */

#endif	/* _KERN_ETAP_MACROS_H_ */
