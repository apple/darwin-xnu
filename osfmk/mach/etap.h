/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 * 
 */
/*
 * File : etap.h 
 *
 *	  Contains ETAP buffer and table definitions
 *
 */

#ifndef _MACH_ETAP_H_
#define _MACH_ETAP_H_

#include <mach/machine/boolean.h>
#include <mach/etap_events.h>
#include <mach/clock_types.h>
#include <mach/time_value.h>
#include <mach/kern_return.h>


#define ETAP_CBUFF_ENTRIES	20000
#define ETAP_CBUFF_IBUCKETS	10
#define	ETAP_CBUFF_WIDTH	80

#define ETAP_MBUFF_ENTRIES	28000
#define ETAP_MBUFF_DATASIZE	4


/* ===================================
 * Event & Subsystem Table Definitions
 * ===================================
 */

#define EVENT_NAME_LENGTH    20                    /* max event name size  */

struct  event_table_entry {
        unsigned short	event;			   /* etap event type      */
        unsigned short	status;                    /* event trace status   */
        char		name [EVENT_NAME_LENGTH];  /* event text name      */
        unsigned short	dynamic;                   /* dynamic ID (0=none)  */
};

struct  subs_table_entry {
        unsigned short	subs;                      /* etap subsystem type  */
        char		name [EVENT_NAME_LENGTH];  /* subsystem text name  */
};

typedef struct event_table_entry*	event_table_t;
typedef struct subs_table_entry*	subs_table_t;
typedef unsigned short			etap_event_t;

#define EVENT_TABLE_NULL		((event_table_t) 0)

/* =========
 * ETAP Time
 * =========
 */

typedef mach_timespec_t etap_time_t;

/* =============================
 * Cumulative buffer definitions
 * =============================
 */

/*
 *  The cbuff_data structure contains cumulative lock
 *  statistical information for EITHER hold operations
 *  OR wait operations.
 */

struct cbuff_data {
	unsigned long	triggered;       /* number of event occurances  */
	etap_time_t	time;            /* sum of event durations	*/
	etap_time_t	time_sq;         /* sum of squared durations	*/
	etap_time_t	min_time;        /* min duration of event       */
	etap_time_t	max_time;        /* max duration of event  	*/
};

/*
 *  The cbuff_entry contains all trace data for an event.
 *  The cumulative buffer consists of these entries.
 */

struct cbuff_entry {
	etap_event_t	  event;                     /* event type           */
	unsigned short	  kind;                      /* read,write,or simple */
	unsigned int	  instance;                  /* & of event struct    */
	struct cbuff_data hold;                      /* hold trace data      */
	struct cbuff_data wait;                      /* wait trace data      */
	unsigned long hold_interval[ETAP_CBUFF_IBUCKETS];   /* hold interval array  */
	unsigned long wait_interval[ETAP_CBUFF_IBUCKETS];   /* wait interval array  */
};

typedef struct cbuff_entry* cbuff_entry_t;

#define CBUFF_ENTRY_NULL	((cbuff_entry_t)0)

/* 
 *  The cumulative buffer maintains a header which is used by
 *  both the kernel instrumentation and the ETAP user-utilities.
 */

struct cumulative_buffer {
	unsigned long      next;         	   /* next available entry in buffer */
	unsigned short     static_start;          /* first static entry in buffer   */ 
	struct cbuff_entry  entry [ETAP_CBUFF_ENTRIES];  /* buffer entries   */
};

typedef struct cumulative_buffer* cumulative_buffer_t;


/* ===========================
 * ETAP probe data definitions
 * ===========================
 */

typedef	unsigned int	etap_data_t[ETAP_MBUFF_DATASIZE];

#define ETAP_DATA_ENTRY	sizeof(unsigned int)
#define ETAP_DATA_SIZE	ETAP_DATA_ENTRY * ETAP_MBUFF_DATASIZE
#define ETAP_DATA_NULL	(etap_data_t*) 0

/* ==========================
 * Monitor buffer definitions
 * ==========================
 */

/*
 *  The mbuff_entry structure contains trace event instance data.
 */

struct mbuff_entry {
	unsigned short	event;	    /* event type                             */
	unsigned short	flags;      /* event strain flags		      */
	unsigned int	instance;   /* address of event (lock, thread, etc.)  */
	unsigned int	pc;	    /* program counter			      */
	etap_time_t  	time;	    /* operation time                         */
	etap_data_t	data;	    /* event specific data  		      */
};

typedef struct mbuff_entry* mbuff_entry_t;

/* 
 *  Each circular monitor buffer will contain maintanence 
 *  information and mon_entry records.
 */

struct monitor_buffer {
	unsigned long		free;        /* index of next available record */
	unsigned long 		timestamp;   /* timestamp of last wrap around  */
	struct mbuff_entry entry[1]; /* buffer entries (holder)        */
};

typedef struct monitor_buffer* monitor_buffer_t;


/* ===================
 * Event strains/flags
 * ===================
 */					/* | |t|b|e|k|u|m|s|r|w| | | | | */
					/* ----------------------------- */
#define  WRITE_LOCK	0x10		/* | | | | | | | | | |1| | | | | */
#define  READ_LOCK	0x20		/* | | | | | | | | |1| | | | | | */
#define  COMPLEX_LOCK	0x30		/* | | | | | | | | |1|1| | | | | */
#define  SPIN_LOCK	0x40		/* | | | | | | | |1| | | | | | | */
#define  MUTEX_LOCK	0x80		/* | | | | | | |1| | | | | | | | */
#define	 USER_EVENT	0x100		/* | | | | | |1| | | | | | | | | */
#define  KERNEL_EVENT	0x200		/* | | | | |1| | | | | | | | | | */
#define  EVENT_END	0x400		/* | | | |1| | | | | | | | | | | */
#define  EVENT_BEGIN	0x800		/* | | |1| | | | | | | | | | | | */
#define  SYSCALL_TRAP	0x1000		/* | |1| | | | | | | | | | | | | */


/* =========================
 * Event trace status values
 * =========================
 */					/* | | | | | | | | | | |M|M|C|C| */
					/* | | | | | | | | | | |d|c|d|c| */
					/* ----------------------------- */	
#define CUM_CONTENTION	0x1		/* | | | | | | | | | | | | | |1| */
#define CUM_DURATION	0x2		/* | | | | | | | | | | | | |1| | */
#define MON_CONTENTION	0x4		/* | | | | | | | | | | | |1| | | */
#define MON_DURATION	0x8		/* | | | | | | | | | | |1| | | | */

#define ETAP_TRACE_ON	0xf		/* | | | | | | | | | | |1|1|1|1| */
#define ETAP_TRACE_OFF	0x0		/* | | | | | | | | | | | | | | | */


/* ==================
 * ETAP trace flavors
 * ==================
 */
	
/* Mode */

#define ETAP_CUMULATIVE	0x3		/* | | | | | | | | | | | | |1|1| */
#define ETAP_MONITORED	0xc		/* | | | | | | | | | | |1|1| | | */
#define ETAP_RESET   	0xf0f0

/* Type */

#define ETAP_CONTENTION	0x5		/* | | | | | | | | | | | |1| |1| */
#define ETAP_DURATION	0xa		/* | | | | | | | | | | |1| |1| | */


/* ===============================
 * Buffer/Table flavor definitions
 * ===============================
 */

#define  ETAP_TABLE_EVENT    	 	0
#define  ETAP_TABLE_SUBSYSTEM  		1
#define  ETAP_BUFFER_CUMULATIVE       	2
#define  ETAP_BUFFER_MONITORED       	3

/* ==========================
 * ETAP function declarations
 * ==========================
 */

extern
kern_return_t		etap_trace_event(
				   unsigned short 	mode,
				   unsigned short 	type,
				   boolean_t		enable,
				   unsigned int 	nargs,
				   unsigned short 	args[]);

extern
kern_return_t		etap_probe(
				   unsigned short	eventno,
				   unsigned short	event_id,
				   unsigned int		data_size,
				   etap_data_t		*data);

/* =================================================================
 * convienience user probe macro - only used if DO_PROBE is #defined
 * =================================================================
 */
#ifdef DO_PROBE
#define PROBE_DATA(subsys, tag, data0, data1, data2, data3) \
	{ \
	etap_data_t _mmmm; \
	_mmmm[0] = (u_int)data0; \
	_mmmm[1] = (u_int)data1; \
	_mmmm[2] = (u_int)data2; \
	_mmmm[3] = (u_int)data3; \
	etap_probe(subsys, tag, sizeof (etap_data_t), &_mmmm); \
	}
#else
#define PROBE_DATA(type, tag, data0, data1, data2, data3)
#endif	/* DO_PROBE */
#endif  /* _MACH_ETAP_H_ */
