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
 * File:  etap.c
 */

#include <cpus.h>
#include <kern/lock.h>
#include <kern/etap_macros.h>
#include <kern/misc_protos.h>
#include <kern/host.h>
#include <types.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>         /* for kernel_map, ipc_kernel_map */
#if ETAP_MONITOR
#include <machine/machine_tables.h>
#include <mach/clock.h>
#include <mach/clock_reply.h>
#include <mach/default_pager_object.h>
#include <device/device.h>
#include <device/device_reply.h>
#include <device/device_request.h>
#include <mach_debug/mach_debug.h>
/*#include <mach/mach_host.h>*/
#include <mach/mach_norma.h>
#include <mach/mach_port.h>
#include <mach/memory_object_default.h>
#include <mach/memory_object_user.h>
#include <mach/notify_server.h>
#include <mach/prof.h>
#include <machine/unix_map.h>
#endif
#if MACH_KDB
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_command.h>
#if 0 /* WHY?? */
#include <i386/ipl.h>
#endif
#endif

/*
 *	Forwards
 */

kern_return_t
etap_get_info(host_priv_t, int*, int*, vm_offset_t*, vm_offset_t*,
	      int*, int*, int*, int*);

kern_return_t
etap_mon_reconfig(host_priv_t, int);

kern_return_t
etap_new_probe(host_priv_t, vm_address_t, vm_size_t, boolean_t, vm_address_t);

kern_return_t
etap_trace_thread(thread_act_t, boolean_t);

void
etap_trace_reset(int);

void
etap_interrupt_probe(int, int);

void
etap_machcall_probe1(int);

void
etap_machcall_probe2(void);

void
etap_print(void);


#if	ETAP

#ifndef max
#define max(x,y) ((x > y) ? x : y)
#endif  /* max */

event_table_t
etap_event_table_find(etap_event_t);

/* =======================
 *  ETAP Lock definitions
 * =======================
 */

#if	ETAP_LOCK_TRACE
#define	etap_lock	simple_lock_no_trace
#define	etap_unlock	simple_unlock_no_trace
#else	/* ETAP_LOCK_TRACE */
#define etap_lock	simple_lock
#define etap_unlock	simple_unlock
#endif	/* ETAP_LOCK_TRACE */
 
#define	event_table_lock()	etap_lock(&event_table_lock)
#define event_table_unlock()	etap_unlock(&event_table_lock)

#define cumulative_buffer_lock(s)				\
MACRO_BEGIN							\
        s = splhigh();						\
        etap_lock(&cbuff_lock);	 				\
MACRO_END

#define cumulative_buffer_unlock(s)				\
MACRO_BEGIN                                     		\
	etap_unlock(&cbuff_lock);				\
	splx(s);						\
MACRO_END


#if    ETAP_LOCK_ACCUMULATE

/* ========================================
 *  ETAP Cumulative lock trace definitions
 * ========================================
 */

int cbuff_width = ETAP_CBUFF_WIDTH;

/*
 *  Cumulative buffer declaration
 *
 *  For both protection and mapping purposes, the cumulative
 *  buffer must be aligned on a page boundary.  Since the cumulative
 *  buffer must be statically defined, page boundary alignment is not
 *  garenteed.  Instead, the buffer is allocated with 2 extra pages.
 *  The cumulative buffer pointer will round up to the nearest page.
 *
 *  This will garentee page boundary alignment.
 */

#define TWO_PAGES 16384				    /* XXX does this apply ??*/	
#define CBUFF_ALLOCATED_SIZE sizeof(struct cumulative_buffer)+TWO_PAGES

decl_simple_lock_data	(,cbuff_lock)
#if MACH_LDEBUG
simple_lock_t	     	cbuff_locks;
#else
simple_lock_data_t	cbuff_locks;
#endif
char                    cbuff_allocated [CBUFF_ALLOCATED_SIZE];
cumulative_buffer_t	cbuff        = {0};

#endif /* ETAP_LOCK_ACCUMULATE */

#if    ETAP_MONITOR

int mbuff_entries = ETAP_MBUFF_ENTRIES;

/*
 *  Create an array of pointers to monitor buffers.
 *  The buffers themselves are allocated at run-time.
 */

struct monitor_buffer *mbuff[NCPUS];
#endif /* ETAP_MONITOR */

/* ==========================
 *  Event table declarations
 * ==========================
 */

decl_simple_lock_data(,event_table_lock)

const struct event_table_entry event_table_init[] =
{

  /*-----------------------------------------------------------------------*
   *  ETAP EVENT               TRACE STATUS       TEXT NAME        DYNAMIC *
   *-----------------------------------------------------------------------*/

#if	ETAP_EVENT_MONITOR
   {ETAP_P_USER_EVENT0      , ETAP_TRACE_OFF , "p_user_event0" 	  , STATIC},	
   {ETAP_P_USER_EVENT1      , ETAP_TRACE_OFF , "p_user_event1" 	  , STATIC},	
   {ETAP_P_USER_EVENT2      , ETAP_TRACE_OFF , "p_user_event2" 	  , STATIC},	
   {ETAP_P_USER_EVENT3      , ETAP_TRACE_OFF , "p_user_event3" 	  , STATIC},	
   {ETAP_P_USER_EVENT4      , ETAP_TRACE_OFF , "p_user_event4" 	  , STATIC},	
   {ETAP_P_USER_EVENT5      , ETAP_TRACE_OFF , "p_user_event5" 	  , STATIC},	
   {ETAP_P_USER_EVENT6      , ETAP_TRACE_OFF , "p_user_event6" 	  , STATIC},	
   {ETAP_P_USER_EVENT7      , ETAP_TRACE_OFF , "p_user_event7" 	  , STATIC},	
   {ETAP_P_USER_EVENT8      , ETAP_TRACE_OFF , "p_user_event8" 	  , STATIC},	
   {ETAP_P_USER_EVENT9      , ETAP_TRACE_OFF , "p_user_event9" 	  , STATIC},	
   {ETAP_P_USER_EVENT10     , ETAP_TRACE_OFF , "p_user_event10"	  , STATIC},	
   {ETAP_P_USER_EVENT11     , ETAP_TRACE_OFF , "p_user_event11"	  , STATIC},	
   {ETAP_P_USER_EVENT12     , ETAP_TRACE_OFF , "p_user_event12"	  , STATIC},	
   {ETAP_P_USER_EVENT13     , ETAP_TRACE_OFF , "p_user_event13"	  , STATIC},	
   {ETAP_P_USER_EVENT14     , ETAP_TRACE_OFF , "p_user_event14"	  , STATIC},	
   {ETAP_P_USER_EVENT15     , ETAP_TRACE_OFF , "p_user_event15"	  , STATIC},	
   {ETAP_P_USER_EVENT16     , ETAP_TRACE_OFF , "p_user_event16"	  , STATIC},	
   {ETAP_P_USER_EVENT17     , ETAP_TRACE_OFF , "p_user_event17"	  , STATIC},	
   {ETAP_P_USER_EVENT18     , ETAP_TRACE_OFF , "p_user_event18"	  , STATIC},	
   {ETAP_P_USER_EVENT19     , ETAP_TRACE_OFF , "p_user_event19"	  , STATIC},	
   {ETAP_P_USER_EVENT20     , ETAP_TRACE_OFF , "p_user_event20"	  , STATIC},	
   {ETAP_P_USER_EVENT21     , ETAP_TRACE_OFF , "p_user_event21"	  , STATIC},	
   {ETAP_P_USER_EVENT22     , ETAP_TRACE_OFF , "p_user_event22"	  , STATIC},	
   {ETAP_P_USER_EVENT23     , ETAP_TRACE_OFF , "p_user_event23"	  , STATIC},	
   {ETAP_P_USER_EVENT24     , ETAP_TRACE_OFF , "p_user_event24"	  , STATIC},	
   {ETAP_P_USER_EVENT25     , ETAP_TRACE_OFF , "p_user_event25"	  , STATIC},	
   {ETAP_P_USER_EVENT26     , ETAP_TRACE_OFF , "p_user_event26"	  , STATIC},	
   {ETAP_P_USER_EVENT27     , ETAP_TRACE_OFF , "p_user_event27"	  , STATIC},	
   {ETAP_P_USER_EVENT28     , ETAP_TRACE_OFF , "p_user_event28"	  , STATIC},	
   {ETAP_P_USER_EVENT29     , ETAP_TRACE_OFF , "p_user_event29"	  , STATIC},	
   {ETAP_P_USER_EVENT30     , ETAP_TRACE_OFF , "p_user_event30"	  , STATIC},	
   {ETAP_P_USER_EVENT31     , ETAP_TRACE_OFF , "p_user_event31"	  , STATIC},	
   {ETAP_P_SYSCALL_MACH     , ETAP_TRACE_OFF , "p_syscall_mach"   , STATIC},	
   {ETAP_P_SYSCALL_UNIX     , ETAP_TRACE_OFF , "p_syscall_unix"   , STATIC},	
   {ETAP_P_THREAD_LIFE      , ETAP_TRACE_OFF , "p_thread_life" 	  , STATIC},	
   {ETAP_P_THREAD_CTX	    , ETAP_TRACE_OFF , "p_thread_ctx" 	  , STATIC},	
   {ETAP_P_RPC		    , ETAP_TRACE_OFF , "p_rpc"		  , STATIC},
   {ETAP_P_INTERRUPT        , ETAP_TRACE_OFF , "p_interrupt"      , STATIC},
   {ETAP_P_ACT_ABORT        , ETAP_TRACE_OFF , "p_act_abort"      , STATIC},	
   {ETAP_P_PRIORITY         , ETAP_TRACE_OFF , "p_priority"       , STATIC},	
   {ETAP_P_EXCEPTION        , ETAP_TRACE_OFF , "p_exception"      , STATIC},	
   {ETAP_P_DEPRESSION       , ETAP_TRACE_OFF , "p_depression"     , STATIC},	
   {ETAP_P_MISC		    , ETAP_TRACE_OFF , "p_misc"		  , STATIC},		
   {ETAP_P_DETAP	    , ETAP_TRACE_OFF , "p_detap"	  , STATIC}, 
#endif	/* ETAP_EVENT_MONITOR */

#if	ETAP_LOCK_TRACE
   {ETAP_VM_BUCKET          , ETAP_TRACE_OFF , "vm_bucket"        , STATIC},/**/
   {ETAP_VM_HIMEM           , ETAP_TRACE_OFF , "vm_himem"         , STATIC},
   {ETAP_VM_MAP             , ETAP_TRACE_OFF , "vm_map"           ,      1},
   {ETAP_VM_MAP_I           , ETAP_TRACE_OFF , "vm_map_i"         ,      2},
   {ETAP_VM_MEMMAN          , ETAP_TRACE_OFF , "vm_memman"        , STATIC},/**/
   {ETAP_VM_MSYNC           , ETAP_TRACE_OFF , "vm_msync"         ,      3},
   {ETAP_VM_OBJ             , ETAP_TRACE_OFF , "vm_obj"           ,      4},
   {ETAP_VM_OBJ_CACHE       , ETAP_TRACE_OFF , "vm_obj_cache"     ,      5},
   {ETAP_VM_PAGE_ALLOC      , ETAP_TRACE_OFF , "vm_page_alloc"    , STATIC},/**/
   {ETAP_VM_PAGEOUT         , ETAP_TRACE_OFF , "vm_pageout"       , STATIC},
   {ETAP_VM_PAGEQ           , ETAP_TRACE_OFF , "vm_pageq"         , STATIC},
   {ETAP_VM_PAGEQ_FREE      , ETAP_TRACE_OFF , "vm_pageq_free"    , STATIC},
   {ETAP_VM_PMAP            , ETAP_TRACE_OFF , "vm_pmap"          ,      6},
   {ETAP_VM_PMAP_CACHE      , ETAP_TRACE_OFF , "vm_pmap_cache"    , STATIC},
   {ETAP_VM_PMAP_FREE       , ETAP_TRACE_OFF , "vm_pmap_free"     , STATIC},
   {ETAP_VM_PMAP_KERNEL     , ETAP_TRACE_OFF , "vm_pmap_kern"     , STATIC},
   {ETAP_VM_PMAP_SYS        , ETAP_TRACE_OFF , "vm_pmap_sys"      ,      7},
   {ETAP_VM_PMAP_SYS_I      , ETAP_TRACE_OFF , "vm_pmap_sys_i"    ,      8},
   {ETAP_VM_PMAP_UPDATE     , ETAP_TRACE_OFF , "vm_pmap_update"   , STATIC},
   {ETAP_VM_PREPPIN	    , ETAP_TRACE_OFF , "vm_preppin"       , STATIC},
   {ETAP_VM_RESULT          , ETAP_TRACE_OFF , "vm_result"        ,      9},
   {ETAP_VM_TEST            , ETAP_TRACE_OFF , "vm_tes"           , STATIC},/**/
   {ETAP_VM_PMAP_PHYSENTRIES, ETAP_TRACE_OFF , "vm_pmap_physentries", STATIC},
   {ETAP_VM_PMAP_SID        , ETAP_TRACE_OFF , "vm_pmap_sid"      , STATIC},
   {ETAP_VM_PMAP_PTE        , ETAP_TRACE_OFF , "vm_pmap_pte"      , STATIC},
   {ETAP_VM_PMAP_PTE_OVFLW  , ETAP_TRACE_OFF , "vm_pmap_pte_ovflw", STATIC},
   {ETAP_VM_PMAP_TLB        , ETAP_TRACE_OFF , "vm_pmap_tlb"      , STATIC},

   {ETAP_IPC_IHGB	    , ETAP_TRACE_OFF , "ipc_ihgb"         ,     10},/**/
   {ETAP_IPC_IS 	    , ETAP_TRACE_OFF , "ipc_is"           ,     11},/**/
   {ETAP_IPC_IS_REF	    , ETAP_TRACE_OFF , "ipc_is_ref"       ,     12},/**/
   {ETAP_IPC_MQUEUE	    , ETAP_TRACE_OFF , "ipc_mqueue"       , STATIC},/**/
   {ETAP_IPC_OBJECT	    , ETAP_TRACE_OFF , "ipc_object"       , STATIC},/**/
   {ETAP_IPC_PORT_MULT	    , ETAP_TRACE_OFF , "ipc_port_mult"    ,     13},/**/
   {ETAP_IPC_PORT_TIME	    , ETAP_TRACE_OFF , "ipc_port_time"    ,     14},/**/
   {ETAP_IPC_RPC	    , ETAP_TRACE_OFF , "ipc_rpc"          ,     15},/**/
   {ETAP_IPC_PORT_ALLOCQ    , ETAP_TRACE_OFF , "ipc_port_allocq"  , STATIC},/**/

   {ETAP_IO_AHA             , ETAP_TRACE_OFF , "io_aha" 	  , STATIC},
   {ETAP_IO_CHIP            , ETAP_TRACE_OFF , "io_chip"          , STATIC},
   {ETAP_IO_DEV             , ETAP_TRACE_OFF , "io_dev"           ,     16},/**/
   {ETAP_IO_DEV_NUM         , ETAP_TRACE_OFF , "io_dev_num"       , STATIC},
   {ETAP_IO_DEV_PAGEH       , ETAP_TRACE_OFF , "io_dev_pageh"     , STATIC},/**/
   {ETAP_IO_DEV_PAGER       , ETAP_TRACE_OFF , "io_dev_pager"     , STATIC},/**/
   {ETAP_IO_DEV_PORT        , ETAP_TRACE_OFF , "io_dev_port"      , STATIC},/**/
   {ETAP_IO_DEV_REF         , ETAP_TRACE_OFF , "io_dev_new"       ,     17},/**/
   {ETAP_IO_DEVINS          , ETAP_TRACE_OFF , "io_devins"        , STATIC},
   {ETAP_IO_DONE_LIST       , ETAP_TRACE_OFF , "io_done_list"     , STATIC},
   {ETAP_IO_DONE_Q          , ETAP_TRACE_OFF , "io_doneq"         ,     18},
   {ETAP_IO_DONE_REF        , ETAP_TRACE_OFF , "io_done_ref"      ,     19},
   {ETAP_IO_EAHA            , ETAP_TRACE_OFF , "io_eaha" 	  , STATIC},
   {ETAP_IO_HD_PROBE        , ETAP_TRACE_OFF , "io_hd_probe"      , STATIC},
   {ETAP_IO_IOPB            , ETAP_TRACE_OFF , "io_iopb"          , STATIC},
   {ETAP_IO_KDQ	            , ETAP_TRACE_OFF , "io_kdq"           , STATIC},
   {ETAP_IO_KDTTY           , ETAP_TRACE_OFF , "io_kdtty"         , STATIC},
   {ETAP_IO_REQ             , ETAP_TRACE_OFF , "io_req"           ,     20},
   {ETAP_IO_TARGET          , ETAP_TRACE_OFF , "io_target"        , STATIC},
   {ETAP_IO_TTY             , ETAP_TRACE_OFF , "io_tty"           , STATIC},
   {ETAP_IO_IOP_LOCK        , ETAP_TRACE_OFF , "io_iop"           , STATIC},/**/
   {ETAP_IO_DEV_NAME        , ETAP_TRACE_OFF , "io_dev_name"      , STATIC},/**/
   {ETAP_IO_CDLI            , ETAP_TRACE_OFF , "io_cdli"          , STATIC},/**/
   {ETAP_IO_HIPPI_FILTER    , ETAP_TRACE_OFF , "io_hippi_filter"  , STATIC},/**/
   {ETAP_IO_HIPPI_SRC       , ETAP_TRACE_OFF , "io_hippi_src"     , STATIC},/**/
   {ETAP_IO_HIPPI_DST       , ETAP_TRACE_OFF , "io_hippi_dst"     , STATIC},/**/
   {ETAP_IO_HIPPI_PKT       , ETAP_TRACE_OFF , "io_hippi_pkt"     , STATIC},/**/
   {ETAP_IO_NOTIFY          , ETAP_TRACE_OFF , "io_notify"        , STATIC},/**/
   {ETAP_IO_DATADEV         , ETAP_TRACE_OFF , "io_data_device"   , STATIC},/**/
   {ETAP_IO_OPEN	    , ETAP_TRACE_OFF , "io_open"	  , STATIC},
   {ETAP_IO_OPEN_I	    , ETAP_TRACE_OFF , "io_open_i"	  , STATIC},

   {ETAP_THREAD_ACT         , ETAP_TRACE_OFF , "th_act"           ,     21},
   {ETAP_THREAD_ACTION      , ETAP_TRACE_OFF , "th_action"        , STATIC},
   {ETAP_THREAD_LOCK        , ETAP_TRACE_OFF , "th_lock"          ,     22},
   {ETAP_THREAD_LOCK_SET    , ETAP_TRACE_OFF , "th_lock_set"      ,     23},
   {ETAP_THREAD_NEW         , ETAP_TRACE_OFF , "th_new"           ,     24},
   {ETAP_THREAD_PSET        , ETAP_TRACE_OFF , "th_pset"          , STATIC},/**/
   {ETAP_THREAD_PSET_ALL    , ETAP_TRACE_OFF , "th_pset_all"      , STATIC},
   {ETAP_THREAD_PSET_RUNQ   , ETAP_TRACE_OFF , "th_pset_runq"     , STATIC},
   {ETAP_THREAD_PSET_IDLE   , ETAP_TRACE_OFF , "th_pset_idle"     , STATIC},
   {ETAP_THREAD_PSET_QUANT  , ETAP_TRACE_OFF , "th_pset_quant"    , STATIC},
   {ETAP_THREAD_PROC        , ETAP_TRACE_OFF , "th_proc"          , STATIC},
   {ETAP_THREAD_PROC_RUNQ   , ETAP_TRACE_OFF , "th_proc_runq"     , STATIC},
   {ETAP_THREAD_REAPER      , ETAP_TRACE_OFF , "th_reaper"        , STATIC},
   {ETAP_THREAD_RPC         , ETAP_TRACE_OFF , "th_rpc"           ,     25},
   {ETAP_THREAD_SEMA        , ETAP_TRACE_OFF , "th_sema"          ,     26},
   {ETAP_THREAD_STACK       , ETAP_TRACE_OFF , "th_stack"         , STATIC},
   {ETAP_THREAD_STACK_USAGE , ETAP_TRACE_OFF , "th_stack_usage"   , STATIC},
   {ETAP_THREAD_TASK_NEW    , ETAP_TRACE_OFF , "th_task_new"      ,     27},
   {ETAP_THREAD_TASK_ITK    , ETAP_TRACE_OFF , "th_task_itk"      ,     28},
   {ETAP_THREAD_ULOCK       , ETAP_TRACE_OFF , "th_ulock"         ,     29},
   {ETAP_THREAD_WAIT        , ETAP_TRACE_OFF , "th_wait"          , STATIC},
   {ETAP_THREAD_WAKE        , ETAP_TRACE_OFF , "th_wake"          ,     30},
   {ETAP_THREAD_ACT_LIST    , ETAP_TRACE_OFF , "th_act_list"      ,     31},
   {ETAP_THREAD_TASK_SWAP   , ETAP_TRACE_OFF , "th_task_swap"     ,     32},
   {ETAP_THREAD_TASK_SWAPOUT, ETAP_TRACE_OFF , "th_task_swapout"  ,     33},
   {ETAP_THREAD_SWAPPER     , ETAP_TRACE_OFF , "th_swapper"       , STATIC},
 
   {ETAP_NET_IFQ            , ETAP_TRACE_OFF , "net_ifq"          , STATIC},
   {ETAP_NET_KMSG           , ETAP_TRACE_OFF , "net_kmsg"         , STATIC},
   {ETAP_NET_MBUF           , ETAP_TRACE_OFF , "net_mbuf"         , STATIC},/**/
   {ETAP_NET_POOL           , ETAP_TRACE_OFF , "net_pool"         , STATIC},
   {ETAP_NET_Q              , ETAP_TRACE_OFF , "net_q"            , STATIC},
   {ETAP_NET_QFREE          , ETAP_TRACE_OFF , "net_qfree"        , STATIC},
   {ETAP_NET_RCV            , ETAP_TRACE_OFF , "net_rcv"          , STATIC},
   {ETAP_NET_RCV_PLIST      , ETAP_TRACE_OFF , "net_rcv_plist"    , STATIC},/**/
   {ETAP_NET_THREAD         , ETAP_TRACE_OFF , "net_thread"       , STATIC},

   {ETAP_NORMA_XMM          , ETAP_TRACE_OFF , "norma_xmm"        , STATIC},
   {ETAP_NORMA_XMMOBJ       , ETAP_TRACE_OFF , "norma_xmmobj"     , STATIC},
   {ETAP_NORMA_XMMCACHE     , ETAP_TRACE_OFF , "norma_xmmcache"	  , STATIC},
   {ETAP_NORMA_MP           , ETAP_TRACE_OFF , "norma_mp"	  , STATIC},
   {ETAP_NORMA_VOR          , ETAP_TRACE_OFF , "norma_vor"	  , STATIC},/**/
   {ETAP_NORMA_TASK         , ETAP_TRACE_OFF , "norma_task"	  , 38},/**/

   {ETAP_DIPC_CLEANUP	    , ETAP_TRACE_OFF , "dipc_cleanup"     , STATIC},/**/
   {ETAP_DIPC_MSG_PROG	    , ETAP_TRACE_OFF , "dipc_msgp_prog"   , STATIC},/**/
   {ETAP_DIPC_PREP_QUEUE    , ETAP_TRACE_OFF , "dipc_prep_queue"  , STATIC},/**/
   {ETAP_DIPC_PREP_FILL	    , ETAP_TRACE_OFF , "dipc_prep_fill"   , STATIC},/**/
   {ETAP_DIPC_MIGRATE	    , ETAP_TRACE_OFF , "dipc_migrate"	  , STATIC},/**/
   {ETAP_DIPC_DELIVER	    , ETAP_TRACE_OFF , "dipc_deliver"	  , STATIC},/**/
   {ETAP_DIPC_RECV_SYNC	    , ETAP_TRACE_OFF , "dipc_recv_sync"	  , STATIC},/**/
   {ETAP_DIPC_RPC	    , ETAP_TRACE_OFF , "dipc_rpc"	  , STATIC},/**/
   {ETAP_DIPC_MSG_REQ	    , ETAP_TRACE_OFF , "dipc_msg_req"	  , STATIC},/**/
   {ETAP_DIPC_MSG_ORDER	    , ETAP_TRACE_OFF , "dipc_msg_order"	  , STATIC},/**/
   {ETAP_DIPC_MSG_PREPQ	    , ETAP_TRACE_OFF , "dipc_msg_prepq"	  , STATIC},/**/
   {ETAP_DIPC_MSG_FREE	    , ETAP_TRACE_OFF , "dipc_msg_free"	  , STATIC},/**/
   {ETAP_DIPC_KMSG_AST	    , ETAP_TRACE_OFF , "dipc_kmsg_ast"	  , STATIC},/**/
   {ETAP_DIPC_TEST_LOCK	    , ETAP_TRACE_OFF , "dipc_test_lock"	  , STATIC},/**/
   {ETAP_DIPC_SPINLOCK	    , ETAP_TRACE_OFF , "dipc_spinlock"	  , STATIC},/**/
   {ETAP_DIPC_TRACE	    , ETAP_TRACE_OFF , "dipc_trace"	  , STATIC},/**/
   {ETAP_DIPC_REQ_CALLBACK  , ETAP_TRACE_OFF , "dipc_req_clbck"	  , STATIC},/**/
   {ETAP_DIPC_PORT_NAME	    , ETAP_TRACE_OFF , "dipc_port_name"	  , STATIC},/**/
   {ETAP_DIPC_RESTART_PORT  , ETAP_TRACE_OFF , "dipc_restart_port", STATIC},/**/
   {ETAP_DIPC_ZERO_PAGE	    , ETAP_TRACE_OFF , "dipc_zero_page"	  , STATIC},/**/
   {ETAP_DIPC_BLOCKED_NODE  , ETAP_TRACE_OFF , "dipc_blocked_node", STATIC},/**/
   {ETAP_DIPC_TIMER         , ETAP_TRACE_OFF , "dipc_timer"       , STATIC},/**/
   {ETAP_DIPC_SPECIAL_PORT  , ETAP_TRACE_OFF , "dipc_special_port", STATIC},/**/

   {ETAP_KKT_TEST_WORK	    , ETAP_TRACE_OFF , "kkt_test_work"	  , STATIC},/**/
   {ETAP_KKT_TEST_MP	    , ETAP_TRACE_OFF , "kkt_work_mp"	  , STATIC},/**/
   {ETAP_KKT_NODE	    , ETAP_TRACE_OFF , "kkt_node"	  , STATIC},/**/
   {ETAP_KKT_CHANNEL_LIST   , ETAP_TRACE_OFF , "kkt_channel_list" , STATIC},/**/
   {ETAP_KKT_CHANNEL        , ETAP_TRACE_OFF , "kkt_channel"      , STATIC},/**/
   {ETAP_KKT_HANDLE         , ETAP_TRACE_OFF , "kkt_handle"       , STATIC},/**/
   {ETAP_KKT_MAP	    , ETAP_TRACE_OFF , "kkt_map"	  , STATIC},/**/
   {ETAP_KKT_RESOURCE	    , ETAP_TRACE_OFF , "kkt_resource"     , STATIC},/**/

   {ETAP_XKERNEL_MASTER	    , ETAP_TRACE_OFF , "xkernel_master"   , STATIC},/**/
   {ETAP_XKERNEL_EVENT	    , ETAP_TRACE_OFF , "xkernel_event"    , STATIC},/**/
   {ETAP_XKERNEL_ETHINPUT   , ETAP_TRACE_OFF , "xkernel_input"    , STATIC},/**/

   {ETAP_MISC_AST	    , ETAP_TRACE_OFF , "m_ast"            , STATIC},
   {ETAP_MISC_CLOCK	    , ETAP_TRACE_OFF , "m_clock"          , STATIC},
   {ETAP_MISC_EMULATE	    , ETAP_TRACE_OFF , "m_emulate"        ,     34},
   {ETAP_MISC_EVENT         , ETAP_TRACE_OFF , "m_event"          , STATIC},
   {ETAP_MISC_KDB	    , ETAP_TRACE_OFF , "m_kdb"            , STATIC},
   {ETAP_MISC_PCB	    , ETAP_TRACE_OFF , "m_pcb"            ,     35},
   {ETAP_MISC_PRINTF	    , ETAP_TRACE_OFF , "m_printf"         , STATIC},
   {ETAP_MISC_Q             , ETAP_TRACE_OFF , "m_q"              , STATIC},
   {ETAP_MISC_RPC_SUBSYS    , ETAP_TRACE_OFF , "m_rpc_sub"        ,     36},
   {ETAP_MISC_RT_CLOCK      , ETAP_TRACE_OFF , "m_rt_clock"       , STATIC},
   {ETAP_MISC_SD_POOL       , ETAP_TRACE_OFF , "m_sd_pool"        , STATIC},
   {ETAP_MISC_TIMER         , ETAP_TRACE_OFF , "m_timer"          , STATIC},
   {ETAP_MISC_UTIME	    , ETAP_TRACE_OFF , "m_utime"          , STATIC},
   {ETAP_MISC_XPR           , ETAP_TRACE_OFF , "m_xpr"            , STATIC},
   {ETAP_MISC_ZONE          , ETAP_TRACE_OFF , "m_zone"           ,     37},
   {ETAP_MISC_ZONE_ALL      , ETAP_TRACE_OFF , "m_zone_all"       , STATIC},
   {ETAP_MISC_ZONE_GET      , ETAP_TRACE_OFF , "m_zone_get"       , STATIC},
   {ETAP_MISC_ZONE_PTABLE   , ETAP_TRACE_OFF , "m_zone_ptable"    , STATIC},/**/
   {ETAP_MISC_LEDGER        , ETAP_TRACE_OFF , "m_ledger"         , STATIC},/**/
   {ETAP_MISC_SCSIT_TGT     , ETAP_TRACE_OFF , "m_scsit_tgt_lock" , STATIC},/**/
   {ETAP_MISC_SCSIT_SELF    , ETAP_TRACE_OFF , "m_scsit_self_lock", STATIC},/**/
   {ETAP_MISC_SPL	    , ETAP_TRACE_OFF , "m_spl_lock"	  , STATIC},/**/
   {ETAP_MISC_MASTER	    , ETAP_TRACE_OFF , "m_master"	  , STATIC},/**/
   {ETAP_MISC_FLOAT         , ETAP_TRACE_OFF , "m_float"          , STATIC},/**/
   {ETAP_MISC_GROUP         , ETAP_TRACE_OFF , "m_group"          , STATIC},/**/
   {ETAP_MISC_FLIPC         , ETAP_TRACE_OFF , "m_flipc"          , STATIC},/**/
   {ETAP_MISC_MP_IO         , ETAP_TRACE_OFF , "m_mp_io"          , STATIC},/**/
   {ETAP_MISC_KERNEL_TEST   , ETAP_TRACE_OFF , "m_kernel_test"    , STATIC},/**/
 
   {ETAP_NO_TRACE           , ETAP_TRACE_OFF , "NEVER_TRACE"      , STATIC},
#endif	/* ETAP_LOCK_TRACE */
};

/*
 * Variable initially pointing to the event table, then to its mappable
 * copy.  The cast is needed to discard the `const' qualifier; without it
 * gcc issues a warning.
 */
event_table_t event_table = (event_table_t) event_table_init;

/*
 * Linked list of pointers into event_table_init[] so they can be switched
 * into the mappable copy when it is made.
 */
struct event_table_chain *event_table_chain;

/*
 *  max number of event types in the event table
 */

int event_table_max = sizeof(event_table_init)/sizeof(struct event_table_entry);

const struct subs_table_entry subs_table_init[] =
{
  /*------------------------------------------*
   *  ETAP SUBSYSTEM           TEXT NAME      *
   *------------------------------------------*/

#if	ETAP_EVENT_MONITOR
   {ETAP_SUBS_PROBE        ,  "event_probes" },
#endif	/* ETAP_EVENT_MONITOR */

#if	ETAP_LOCK_TRACE
   {ETAP_SUBS_LOCK_DIPC	   ,  "lock_dipc"    },
   {ETAP_SUBS_LOCK_IO      ,  "lock_io"      },
   {ETAP_SUBS_LOCK_IPC     ,  "lock_ipc"     },
   {ETAP_SUBS_LOCK_KKT     ,  "lock_kkt"     },
   {ETAP_SUBS_LOCK_MISC    ,  "lock_misc"    },
   {ETAP_SUBS_LOCK_NET     ,  "lock_net"     },
   {ETAP_SUBS_LOCK_NORMA   ,  "lock_norma"   },
   {ETAP_SUBS_LOCK_THREAD  ,  "lock_thread"  },
   {ETAP_SUBS_LOCK_VM      ,  "lock_vm"      },
   {ETAP_SUBS_LOCK_XKERNEL ,  "lock_xkernel" },
#endif	/* ETAP_LOCK_TRACE */
};

/*
 * Variable initially pointing to the subsystem table, then to its mappable
 * copy.
 */
subs_table_t subs_table = (subs_table_t) subs_table_init;

/*
 *  max number of subsystem types in the subsystem table
 */

int subs_table_max = sizeof(subs_table_init)/sizeof(struct subs_table_entry);

#if ETAP_MONITOR
#define MAX_NAME_SIZE   35

#define SYS_TABLE_MACH_TRAP     0
#define SYS_TABLE_MACH_MESSAGE  1
#define SYS_TABLE_UNIX_SYSCALL  2
#define SYS_TABLE_INTERRUPT     3
#define SYS_TABLE_EXCEPTION     4


extern char *system_table_lookup (unsigned int table,
                                  unsigned int number);


char *mach_trap_names[] = {
/*   0 */       "undefined",
/*   1 */       NULL,
/*   2 */       NULL,
/*   3 */       NULL,
/*   4 */       NULL,
/*   5 */       NULL,
/*   6 */       NULL,
/*   7 */       NULL,
/*   8 */       NULL,
/*   9 */       NULL,
/*  10 */       NULL,
/*  11 */       NULL,
/*  12 */       NULL,
/*  13 */       NULL,
/*  14 */       NULL,
/*  15 */       NULL,
/*  16 */       NULL,
/*  17 */       NULL,
/*  18 */       NULL,
/*  19 */       NULL,
/*  20 */       NULL,
/*  21 */       NULL,
/*  22 */       NULL,
/*  23 */       NULL,
/*  24 */       NULL,
/*  25 */       NULL,
/*  26 */       "mach_reply_port",
/*  27 */       "mach_thread_self",
/*  28 */       "mach_task_self",
/*  29 */       "mach_host_self",
/*  30 */       "vm_read_overwrite",
/*  31 */       "vm_write",
/*  32 */       "mach_msg_overwrite_trap",
/*  33 */       NULL,
/*  34 */       NULL,
#ifdef i386
/*  35 */       "mach_rpc_trap",
/*  36 */       "mach_rpc_return_trap",
#else
/*  35 */	NULL,
/*  36 */	NULL,
#endif /* i386 */
/*  37 */       NULL,
/*  38 */       NULL,
/*  39 */       NULL,
/*  40 */       NULL,
/*  41 */       "init_process",
/*  42 */       NULL,
/*  43 */       "map_fd",
/*  44 */       NULL,
/*  45 */       NULL,
/*  46 */       NULL,
/*  47 */       NULL,
/*  48 */       NULL,
/*  49 */       NULL,
/*  50 */       NULL,
/*  51 */       NULL,
/*  52 */       NULL,
/*  53 */       NULL,
/*  54 */       NULL,
/*  55 */       NULL,
/*  56 */       NULL,
/*  57 */       NULL,
/*  58 */       NULL,
/*  59 */       "swtch_pri",
/*  60 */       "swtch",
/*  61 */       "thread_switch",
/*  62 */       "clock_sleep_trap",
/*  63 */       NULL,
/*  64 */       NULL,
/*  65 */       NULL,
/*  66 */       NULL,
/*  67 */       NULL,
/*  68 */       NULL,
/*  69 */       NULL,
/*  70 */       NULL,
/*  71 */       NULL,
/*  72 */       NULL,
/*  73 */       NULL,
/*  74 */       NULL,
/*  75 */       NULL,
/*  76 */       NULL,
/*  77 */       NULL,
/*  78 */       NULL,
/*  79 */       NULL,
/*  80 */       NULL,
/*  81 */       NULL,
/*  82 */       NULL,
/*  83 */       NULL,
/*  84 */       NULL,
/*  85 */       NULL,
/*  86 */       NULL,
/*  87 */       NULL,
/*  88 */       NULL,
/*  89 */       NULL,
/*  90 */       NULL,
/*  91 */       NULL,
/*  92 */       NULL,
/*  93 */       NULL,
/*  94 */       NULL,
/*  95 */       NULL,
/*  96 */       NULL,
/*  97 */       NULL,
/*  98 */       NULL,
/*  99 */       NULL,
/* 100 */       NULL,
/* 101 */       NULL,
/* 102 */       NULL,
/* 103 */       NULL,
/* 104 */       NULL,
/* 105 */       NULL,
/* 106 */       NULL,
/* 107 */       NULL,
/* 108 */       NULL,
/* 109 */       NULL,
};
#define N_MACH_TRAP_NAMES (sizeof mach_trap_names / sizeof mach_trap_names[0])
#define mach_trap_name(nu) \
        (((nu) < N_MACH_TRAP_NAMES) ? mach_trap_names[nu] : NULL)

struct table_entry {
        char    name[MAX_NAME_SIZE];
        u_int   number;
};

/*
 * Mach message table
 *
 * Note: Most mach system calls are actually implemented as messages.
 */
struct table_entry mach_message_table[] = {
        subsystem_to_name_map_bootstrap,
        subsystem_to_name_map_clock,
        subsystem_to_name_map_clock_reply,
        subsystem_to_name_map_default_pager_object,
        subsystem_to_name_map_device,
        subsystem_to_name_map_device_reply,
        subsystem_to_name_map_device_request,
        subsystem_to_name_map_exc,
/*        subsystem_to_name_map_mach,*/
        subsystem_to_name_map_mach_debug,
/*        subsystem_to_name_map_mach_host,*/
        subsystem_to_name_map_mach_norma,
        subsystem_to_name_map_mach_port,
        subsystem_to_name_map_memory_object,
        subsystem_to_name_map_memory_object_default,
        subsystem_to_name_map_notify,
        subsystem_to_name_map_prof,
        subsystem_to_name_map_sync
};

int     mach_message_table_entries = sizeof(mach_message_table) /
                                     sizeof(struct table_entry);


#endif

/*
 *  ================================
 *  Initialization routines for ETAP
 *  ================================
 */

/*
 *  ROUTINE:    etap_init_phase1		[internal]
 *
 *  FUNCTION:   Event trace instrumentation initialization phase
 *              one of two.  The static phase.  The cumulative buffer
 *              is initialized.
 *
 *  NOTES:      The cumulative buffer is statically allocated and
 *              must be initialized before the first simple_lock_init()
 *              or lock_init() call is made.
 *
 *              The first lock init call is made before dynamic allocation
 *              is available.  Hence, phase one is executed before dynamic
 *              memory allocation is available.
 *
 */

void
etap_init_phase1(void)
{
#if	ETAP_LOCK_ACCUMULATE || MACH_ASSERT
	int x;
#if	MACH_ASSERT
	boolean_t out_of_order;
#endif	/* MACH_ASSERT */
#endif	/* ETAP_LOCK_ACCUMULATE || MACH_ASSERT */

#if	ETAP_LOCK_ACCUMULATE
        /*
         *  Initialize Cumulative Buffer
         *
         *  Note: The cumulative buffer is statically allocated.
         *        This static allocation is necessary since most
         *        of the lock_init calls are made before dynamic
         *        allocation routines are available.
         */

        /*
         *  Align cumulative buffer pointer to a page boundary
	 *  (so it can be maped).
         */

        bzero(&cbuff_allocated[0], CBUFF_ALLOCATED_SIZE);
        cbuff = (cumulative_buffer_t) round_page(&cbuff_allocated);

	simple_lock_init(&cbuff_lock, ETAP_NO_TRACE);

        /*
         *  Set the starting point for cumulative buffer entry
	 *  reservations.
         *
         *  This value must leave enough head room in the
         *  cumulative buffer to contain all dynamic events.
         */

        for (x=0; x < event_table_max; x++)
		if (event_table[x].dynamic > cbuff->static_start)
			cbuff->static_start = event_table[x].dynamic;

        cbuff->next = cbuff->static_start;
#endif	/* ETAP_LOCK_ACCUMULATE */

	/*
	 * Initialize the event table lock
	 */

	simple_lock_init(&event_table_lock, ETAP_NO_TRACE);

#if	MACH_ASSERT
	/*
	 * Check that events are in numerical order so we can do a binary
	 * search on them.  Even better would be to make event numbers be
	 * simple contiguous indexes into event_table[], but that would
	 * break the coding of subsystems in the event number.
	 */
	out_of_order = FALSE;
	for (x = 1; x < event_table_max; x++) {
		if (event_table[x - 1].event > event_table[x].event) {
			printf("events out of order: %s > %s\n",
			       event_table[x - 1].name, event_table[x].name);
			out_of_order = TRUE;
		}
	}
	if (out_of_order)
		panic("etap_init_phase1");
#endif	/* MACH_ASSERT */
}


/*
 *  ROUTINE:    etap_init_phase2		[internal]
 *
 *  FUNCTION:   Event trace instrumentation initialization phase
 *              two of two.  The dynamic phase.  The monitored buffers
 *              are dynamically allocated and initialized.  Cumulative
 *              dynamic entry locks are allocated and initialized.  The
 *              start_data_pool is initialized.
 *
 *  NOTES:      Phase two is executed once dynamic memory allocation
 *              is available.
 *
 */

void
etap_init_phase2(void)
{
        int size;
        int x;
        int ret;
	vm_offset_t table_copy;
	struct event_table_chain *chainp;

	/*
	 * Make mappable copies of the event_table and the subs_table.
	 * These tables were originally mapped as they appear in the
	 * kernel image, but that meant that other kernel variables could
	 * end up being mapped with them, which is ugly.  It also didn't
	 * work on the HP/PA, where pages with physical address == virtual
	 * do not have real pmap entries allocated and therefore can't be
	 * mapped elsewhere.
	 */
	size = sizeof event_table_init + sizeof subs_table_init;
	ret = kmem_alloc(kernel_map, &table_copy, size);
	if (ret != KERN_SUCCESS)
		panic("ETAP: error allocating table copies");
	event_table = (event_table_t) table_copy;
	subs_table = (subs_table_t) (table_copy + sizeof event_table_init);
	bcopy((char *) event_table_init, (char *) event_table,
	      sizeof event_table_init);
	bcopy((char *) subs_table_init, (char *) subs_table,
	      sizeof subs_table_init);

	/* Switch pointers from the old event_table to the new. */
	for (chainp = event_table_chain; chainp != NULL;
	     chainp = chainp->event_table_link) {
		x = chainp->event_tablep - event_table_init;
		assert(x < event_table_max);
		chainp->event_tablep = event_table + x;
	}

#if	ETAP_LOCK_ACCUMULATE

        /*
         *  Because several dynamic locks can point to a single
         *  cumulative buffer entry, dynamic lock writes to the
         *  entry are synchronized.
         *
         *  The spin locks are allocated here.
         *
         */
#if MACH_LDEBUG
	size = sizeof(simple_lock_t) * cbuff->static_start;
#else
	/*
         *  Note: These locks are different from traditional spin locks.
         *        They are of type int instead of type simple_lock_t.
         *        We can reduce lock size this way, since no tracing will
	 *	  EVER be performed on these locks.
         */
	size = sizeof(simple_lock_data_t) * cbuff->static_start;
#endif

        ret = kmem_alloc(kernel_map, (vm_offset_t *) &cbuff_locks, size);

        if (ret != KERN_SUCCESS)
		panic("ETAP: error allocating cumulative write locks");

#if MACH_LDEBUG
	for(x = 0; x < cbuff->static_start; ++x) {
		simple_lock_init(&cbuff_locks[x], ETAP_NO_TRACE);
	}
#else
        bzero((const char *) cbuff_locks, size);
#endif

#endif  /* ETAP_LOCK_ACCUMULATE */


#if	ETAP_MONITOR

        /*
         *  monitor buffer allocation
         */

        size = ((mbuff_entries-1) * sizeof(struct mbuff_entry)) +
		sizeof(struct monitor_buffer);

        for (x=0; x < NCPUS; x++) {
                ret = kmem_alloc(kernel_map,
				 (vm_offset_t *) &mbuff[x],
				 size);

                if (ret != KERN_SUCCESS)
			panic ("ETAP: error allocating monitor buffer\n");

                /* zero fill buffer */
                bzero((char *) mbuff[x], size);
        }

#endif  /* ETAP_MONITOR */


#if	ETAP_LOCK_TRACE

        /*
         *  Initialize the start_data_pool
         */

        init_start_data_pool();

#endif	/* ETAP_LOCK_TRACE */
}


#if	ETAP_LOCK_ACCUMULATE

/*
 *  ROUTINE:    etap_cbuff_reserve		[internal]
 *
 *  FUNCTION:   The cumulative buffer operation which returns a pointer
 *              to a free entry in the cumulative buffer.
 *
 *  NOTES:      Disables interrupts.
 *
 */

cbuff_entry_t
etap_cbuff_reserve(event_table_t etp)
{
	cbuff_entry_t  	avail;
	unsigned short	de;
	spl_t		s;

	/* see if type pointer is initialized */
	if (etp == EVENT_TABLE_NULL || etp->event == ETAP_NO_TRACE)
		return (CBUFF_ENTRY_NULL);

	/* check for DYNAMIC lock */
	if (de = etp->dynamic) {
		if (de <= cbuff->static_start)
			return (&cbuff->entry[de-1]);
		else {
			printf("ETAP: dynamic lock index error [%lu]\n", de);
			return (CBUFF_ENTRY_NULL);
		}
	}

	cumulative_buffer_lock(s);

	/* if buffer is full, reservation requests fail */
	if (cbuff->next >= ETAP_CBUFF_ENTRIES) {
		cumulative_buffer_unlock(s);
		return (CBUFF_ENTRY_NULL);
	}

	avail = &cbuff->entry[cbuff->next++];

	cumulative_buffer_unlock(s);

	return (avail);
}

#endif  /* ETAP_LOCK_ACCUMULATE */

/*
 *  ROUTINE:    etap_event_table_assign		[internal]
 *
 *  FUNCTION:   Returns a pointer to the assigned event type table entry,
 *              using the event type as the index key.
 *
 */

event_table_t
etap_event_table_find(etap_event_t event)
{
        int last_before, first_after, try;

	/* Binary search for the event number.  last_before is the highest-
	   numbered element known to be <= the number we're looking for;
	   first_after is the lowest-numbered element known to be >.  */
	last_before = 0;
	first_after = event_table_max;
	while (last_before < first_after) {
		try = (last_before + first_after) >> 1;
		if (event_table[try].event == event)
			return (&event_table[try]);
		else if (event_table[try].event < event)
			last_before = try;
		else
			first_after = try;
        }
	return EVENT_TABLE_NULL;
}

void
etap_event_table_assign(struct event_table_chain *chainp, etap_event_t event)
{
	event_table_t event_tablep;

	event_tablep = etap_event_table_find(event);
	if (event_tablep == EVENT_TABLE_NULL)
		printf("\nETAP: event not found in event table: %x\n", event);
	else {
		if (event_table == event_table_init) {
			chainp->event_table_link = event_table_chain;
			event_table_chain = chainp;
		}
		chainp->event_tablep = event_tablep;
	}
}

#endif	/* ETAP */

/*
 *
 *  MESSAGE:    etap_get_info			[exported]
 *
 *  FUNCTION:   provides the server with ETAP buffer configurations.
 *
 */

kern_return_t
etap_get_info(
	host_priv_t  host_priv,
	int          *et_entries,
	int          *st_entries,
	vm_offset_t  *et_offset,
	vm_offset_t  *st_offset,
	int          *cb_width,
	int          *mb_size,
	int          *mb_entries,
	int          *mb_cpus)
{

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_ARGUMENT;

#if     ETAP
        *et_entries = event_table_max;
        *st_entries = subs_table_max;
        *et_offset  = (vm_offset_t) ((char*) event_table - 
				     trunc_page((char*) event_table));
        *st_offset  = (vm_offset_t) ((char*) subs_table - 
				     trunc_page((char*) subs_table));
#else   /* ETAP */
        *et_entries = 0;
        *st_entries = 0;
        *et_offset  = 0;
        *st_offset  = 0;
#endif  /* ETAP */

#if     ETAP_LOCK_ACCUMULATE
        *cb_width   = cbuff_width;
#else   /* ETAP_LOCK_ACCUMULATE */
        *cb_width   = 0;
#endif  /* ETAP_LOCK_ACCUMULATE */

#if     ETAP_MONITOR
        *mb_size     = ((mbuff_entries-1) * sizeof(struct mbuff_entry)) +
			sizeof(struct monitor_buffer);
        *mb_entries  = mbuff_entries;
        *mb_cpus     = NCPUS;
#else   /* ETAP_MONITOR */
        *mb_size     = 0;
        *mb_entries  = 0;
        *mb_cpus     = 0;
#endif  /* ETAP_MONITOR */

        return (KERN_SUCCESS);
}
    
/*
 *  ROUTINE:    etap_trace_event		[exported]
 *
 *  FUNCTION:   The etap_trace_event system call is the user's interface to
 *              the ETAP kernel instrumentation. 
 *
 *		This call allows the user to enable and disable tracing modes
 *              on specific event types.  The call also supports a reset option,
 *              where the cumulative buffer data and all event type tracing
 *              is reset to zero.  When the reset option is used, a new
 *              interval width can also be defined using the op parameter.
 *
 */

kern_return_t
etap_trace_event (
	unsigned short	mode,
	unsigned short	type,
	boolean_t	enable,
	unsigned int	nargs,
	unsigned short	args[])
{
#if     ETAP
        event_table_t   event_tablep;
	kern_return_t	ret;
        int             i, args_size;
        unsigned short  status_mask;
	unsigned short  *tmp_args;

        /*
         *  Initialize operation
         */

	if (mode == ETAP_RESET) {
		etap_trace_reset(nargs);
		return (KERN_SUCCESS);
	}

	status_mask = mode & type;

        /*
         *  Copy args array from user space to kernel space
         */
 
	args_size = nargs * sizeof *args;
        tmp_args = (unsigned short *) kalloc(args_size);

        if (tmp_args == NULL)
		return (KERN_NO_SPACE);

        if (copyin((const char *) args, (char *) tmp_args, args_size))
		return (KERN_INVALID_ADDRESS);

        /*
         *  Change appropriate status fields in the event table
         */

	event_table_lock();

	for (i = 0; i < nargs; i++) {
		if (tmp_args[i] != ETAP_NO_TRACE) {
			event_tablep = etap_event_table_find(tmp_args[i]);
			if (event_tablep == EVENT_TABLE_NULL)
				break;
			if (enable)
				event_tablep->status |= status_mask;
			else
				event_tablep->status &= ~status_mask;
		}
	}

	ret = (i < nargs) ? KERN_INVALID_ARGUMENT : KERN_SUCCESS;

	event_table_unlock();

	kfree((vm_offset_t) tmp_args, args_size);

        return (ret);

#else   /* ETAP */

        return (KERN_FAILURE);

#endif  /* ETAP */
}


#if     ETAP

/*
 *  ROUTINE:    etap_trace_reset		[internal]
 *
 *  FUNCTION:   Turns off all tracing and erases all the data accumulated
 *              in the cumulative buffer.  If the user defined a new 
 *		cumulative buffer interval width, it will be assigned here.
 *
 */
void
etap_trace_reset(int new_interval)
{
        event_table_t 	scan;
        int         	x;
        register    	s;

        /* 
         *  Wipe out trace fields in event table
         */

        scan = event_table;

	event_table_lock();

        for (x=0; x < event_table_max; x++) {
		scan->status = ETAP_TRACE_OFF;
		scan++;
        }

	event_table_unlock();

#if     ETAP_LOCK_ACCUMULATE

        /* 
         *  Wipe out cumulative buffer statistical fields for all entries
         */

	cumulative_buffer_lock(s);

        for (x=0; x < ETAP_CBUFF_ENTRIES; x++) {
		bzero ((char *) &cbuff->entry[x].hold, 
                            sizeof(struct cbuff_data));
		bzero ((char *) &cbuff->entry[x].wait,
                            sizeof(struct cbuff_data));
		bzero ((char *) &cbuff->entry[x].hold_interval[0],
                            sizeof(unsigned long) * ETAP_CBUFF_IBUCKETS);
		bzero ((char *) &cbuff->entry[x].wait_interval[0],
                            sizeof(unsigned long) * ETAP_CBUFF_IBUCKETS);
        }  

        /*
         *  Assign interval width if the user defined a new one.
         */

        if (new_interval != 0)
                cbuff_width = new_interval;

	cumulative_buffer_unlock(s);

#endif  /* ETAP_LOCK_ACCUMULATE */
}

#endif	/* ETAP */

/*
 *  ROUTINE:	etap_probe			[exported]
 *
 *  FUNCTION:	The etap_probe system call serves as a user-level probe,
 *		allowing user-level code to store event data into
 *		the monitored buffer(s).  
 */

kern_return_t
etap_probe(
	unsigned short	event_type,
	unsigned short	event_id,
	unsigned int	data_size,	/* total size in bytes */
	etap_data_t	*data)
{

#if    	ETAP_MONITOR

        mbuff_entry_t	mbuff_entryp;
	int 		cpu;
	int		free;
	spl_t		s;


	if (data_size > ETAP_DATA_SIZE)
		return (KERN_INVALID_ARGUMENT);

	if (event_table[event_type].status == ETAP_TRACE_OFF ||
		event_table[event_type].event != event_type)
		return (KERN_NO_ACCESS);

	mp_disable_preemption();
        cpu  = cpu_number();
	s    = splhigh();

        free = mbuff[cpu]->free;
	mbuff_entryp = &mbuff[cpu]->entry[free];

	/*
	 *  Load monitor buffer entry
	 */

	ETAP_TIMESTAMP(mbuff_entryp->time);
	mbuff_entryp->event    = event_id;
        mbuff_entryp->flags    = USER_EVENT;
	mbuff_entryp->instance = (u_int) current_thread();
	mbuff_entryp->pc       = 0;

	if (data != ETAP_DATA_NULL)
		copyin((const char *) data,
		       (char *) mbuff_entryp->data,
		       data_size);

	mbuff[cpu]->free = (free+1) % mbuff_entries;

	if (mbuff[cpu]->free == 0)
                mbuff[cpu]->timestamp++;

	splx(s);
	mp_enable_preemption();

	return (KERN_SUCCESS);

#else   /* ETAP_MONITOR */
        return (KERN_FAILURE);
#endif  /* ETAP_MONITOR */
}

/*
 *  ROUTINE:	etap_trace_thread		[exported]
 *
 *  FUNCTION:	Toggles thread's ETAP trace status bit.
 */

kern_return_t
etap_trace_thread(
	thread_act_t	thr_act,
	boolean_t	trace_status)
{
#if	ETAP_EVENT_MONITOR

	thread_t	thread;
	boolean_t	old_status;
	etap_data_t	probe_data;
	spl_t		s;

	if (thr_act == THR_ACT_NULL)
		return (KERN_INVALID_ARGUMENT);

	thread = act_lock_thread(thr_act);

	if (thread == THREAD_NULL) {
		act_unlock_thread(thr_act);
		return (KERN_INVALID_ARGUMENT);
	}

	s = splsched();
	thread_lock(thread);

	old_status = thread->etap_trace;
	thread->etap_trace = trace_status;

	ETAP_DATA_LOAD(probe_data[0],thr_act->task);
	ETAP_DATA_LOAD(probe_data[1],thr_act);
	ETAP_DATA_LOAD(probe_data[2],thread->sched_pri);

	thread_unlock(thread);
	splx(s);

	act_unlock_thread(thr_act);

	/*
	 *  Thread creation (ETAP_P_THREAD_LIFE: BEGIN) is ONLY recorded
	 *  here since a threads trace status is disabled by default.
	 */
	if (trace_status == TRUE && old_status == FALSE) {
		ETAP_PROBE_DATA(ETAP_P_THREAD_LIFE,
				EVENT_BEGIN,
				thread,
				&probe_data,
				ETAP_DATA_ENTRY*3);
	}

	/*
	 *  Thread termination is (falsely) recorded here if the trace
	 *  status has been disabled.  This event is recorded to allow
	 *  users the option of tracing a portion of a threads execution.
	 */
	if (trace_status == FALSE && old_status == TRUE) {
		ETAP_PROBE_DATA(ETAP_P_THREAD_LIFE,
				EVENT_END,
				thread,
				&probe_data,
				ETAP_DATA_ENTRY*3);
	}

	return (KERN_SUCCESS);

#else	/* ETAP_EVENT_MONITOR */
	return (KERN_FAILURE);
#endif	/* ETAP_EVENT_MONITOR */
}

/*
 *	ROUTINE:	etap_mon_reconfig		[exported]
 *
 *	FUNCTION:	Reallocates monitor buffers to hold specified number
 *			of entries.
 *
 *	NOTES:		In multiprocessor (SMP) case, a lock needs to be added
 *			here and in data collection macros to protect access
 *			to mbuff_entries.
 */
kern_return_t
etap_mon_reconfig(
	host_priv_t  host_priv,
	int	nentries)
{
#if	ETAP_EVENT_MONITOR
	struct monitor_buffer *nmbuff[NCPUS], *ombuff[NCPUS];
	int s, size, osize, i, ret;

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_ARGUMENT;

	if (nentries <= 0)	/* must be at least 1 */
		return (KERN_FAILURE);

	size = ((nentries-1) * sizeof(struct mbuff_entry)) +
		sizeof(struct monitor_buffer);

	for (i = 0; i < NCPUS; ++i) {
		ret = kmem_alloc(kernel_map,
			(vm_offset_t *)&nmbuff[i],
			size);
		if (ret != KERN_SUCCESS) {
			if (i > 0) {
				int j;

				for (j = 0; j < i; ++j) {
					kmem_free(kernel_map,
						(vm_offset_t)nmbuff[j],
						size);
				}
			}
			return (ret);
		}
		bzero((char *) nmbuff[i], size);
	}
	osize = ((mbuff_entries-1) * sizeof (struct mbuff_entry)) +
		sizeof (struct monitor_buffer);

	s = splhigh();
	event_table_lock();
	for (i = 0; i < NCPUS; ++i) {
		ombuff[i] = mbuff[i];
		mbuff[i] = nmbuff[i];
	}
	mbuff_entries = nentries;
	event_table_unlock();
	splx(s);

	for (i = 0; i < NCPUS; ++i) {
		kmem_free(kernel_map,
			(vm_offset_t)ombuff[i],
			osize);
	}
	return (KERN_SUCCESS);
#else
	return (KERN_FAILURE);
#endif	/* ETAP_MONITOR */
}

/*
 *      ROUTINE:        etap_new_probe               [exported]
 *
 *      FUNCTION:       Reallocates monitor probe table, adding a new entry
 *
 */
kern_return_t
etap_new_probe(
	host_priv_t host_priv,
	vm_address_t name,
	vm_size_t namlen,
	boolean_t trace_on,
	vm_address_t id)
{
#if ETAP_EVENT_MONITOR
	event_table_t newtable, oldtable;
	unsigned short i, nid;
	int s;
	vm_size_t newsize = (event_table_max + 1) *
		sizeof (struct event_table_entry);
	boolean_t duplicate_name = FALSE;
	kern_return_t ret;

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_ARGUMENT;

	if (namlen > EVENT_NAME_LENGTH - 1)
		return (KERN_INVALID_ARGUMENT);

	if ((ret = kmem_alloc(kernel_map, (vm_address_t *)&newtable,
		newsize)) != KERN_SUCCESS)
		return (ret);

	bcopy((const char *)event_table, (char *)newtable, event_table_max *
		sizeof (struct event_table_entry));

	if (copyin((const char *)name,
		(char *)&newtable[event_table_max].name, namlen))
		return (KERN_INVALID_ADDRESS);

	newtable[event_table_max].name[EVENT_NAME_LENGTH - 1] = '\0';
	newtable[event_table_max].status = trace_on;
	newtable[event_table_max].dynamic = 0;

	for (nid = i = 0; i < event_table_max; ++i) {
		if (strcmp((char *)newtable[event_table_max].name,
			newtable[i].name) == 0) {
			duplicate_name = TRUE;
			printf("duplicate name\n");
		}
		nid = max(nid, newtable[i].event);
	}
	++nid;

	if (nid >= ETAP_NO_TRACE || duplicate_name == TRUE) {
		kmem_free(kernel_map, (vm_address_t)newtable, newsize);
		if (nid >= ETAP_NO_TRACE) {
			printf("KERN_RESOURCE_SHORTAGE\n");
			return (KERN_RESOURCE_SHORTAGE);
		}
		else {
			printf("KERN_NAME_EXISTS\n");
			return (KERN_NAME_EXISTS);
		}
	}

	newtable[event_table_max].event = nid;

	s = splhigh();
	event_table_lock();
	oldtable = event_table;
	event_table = newtable;
	++event_table_max;
	event_table_unlock();
	splx(s);

	if (oldtable != event_table_init)
		kmem_free(kernel_map, (vm_address_t)oldtable,
			(event_table_max - 1) *
			sizeof (struct event_table_entry));

	*(unsigned short *)id = nid;

	return (KERN_SUCCESS);
#else
	return (KERN_FAILURE);
#endif	/* ETAP_EVENT_MONITOR */

}
/*
 *  ETAP trap probe hooks
 */

void
etap_interrupt_probe(int interrupt, int flag_setting)
{
	u_short	 flag;

	if (flag_setting == 1)
		flag = EVENT_BEGIN;
	else
		flag = EVENT_END;

	ETAP_PROBE_DATA_COND(ETAP_P_INTERRUPT,
			flag,
			current_thread(),
			&interrupt,
			sizeof(int),
			1);
}

void
etap_machcall_probe1(int syscall)
{
	ETAP_PROBE_DATA(ETAP_P_SYSCALL_MACH,
			EVENT_BEGIN | SYSCALL_TRAP,
			current_thread(),
			&syscall,
			sizeof(int));
}	

void
etap_machcall_probe2(void)
{
	ETAP_PROBE_DATA(ETAP_P_SYSCALL_MACH,
			EVENT_END | SYSCALL_TRAP,
			current_thread(),
			0,
			0);
}	

static void print_user_event(mbuff_entry_t);
static void print_kernel_event(mbuff_entry_t, boolean_t);
static void print_lock_event(mbuff_entry_t, const char *);

#if MACH_KDB
void db_show_etap_log(db_expr_t, boolean_t, db_expr_t, char *);
/*
 *
 *  ROUTINE:    etap_print                   [internal]
 *
 *  FUNCTION:   print each mbuff table (for use in debugger)
 *
 */
void
db_show_etap_log(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
#if ETAP_MONITOR
	int cpu = cpu_number(), last, i, first, step, end, restart;
	boolean_t show_data = FALSE;

	last = (mbuff[cpu]->free - 1) % mbuff_entries;

	if(db_option(modif, 'r')) {
		first = last;
		step = -1;
		end = -1;
		restart = mbuff_entries - 1;
	} else {
		first = last + 1;
		step = 1;
		end = mbuff_entries;
		restart = 0;
	}

	if(db_option(modif, 'd'))
		show_data = TRUE;

	for(i = first; i != end; i += step) {
		if (mbuff[cpu]->entry[i].flags & USER_EVENT)
			print_user_event(&mbuff[cpu]->entry[i]);
		else
			print_kernel_event(&mbuff[cpu]->entry[i], show_data);
	}	
	for(i = restart; i != first; i += step) {
		if (mbuff[cpu]->entry[i].flags & USER_EVENT)
			print_user_event(&mbuff[cpu]->entry[i]);
		else
			print_kernel_event(&mbuff[cpu]->entry[i], show_data);
	}	
#else
	printf("ETAP event monitor not configured\n");
#endif	/* ETAP_MONITOR */
}

#if ETAP_MONITOR
static
void
print_user_event(mbuff_entry_t record)
{
        char *s, buf[256];

	db_printf("%x: %x%08x: ", record->instance, record->time.tv_sec,
		record->time.tv_nsec);
        switch (record->pc)
                {
        case ETAP_P_USER_EVENT0: s = "0"; break;
        case ETAP_P_USER_EVENT1: s = "1"; break;
        case ETAP_P_USER_EVENT2: s = "2"; break;
        case ETAP_P_USER_EVENT3: s = "3"; break;
        case ETAP_P_USER_EVENT4: s = "4"; break;
        case ETAP_P_USER_EVENT5: s = "5"; break;
        case ETAP_P_USER_EVENT6: s = "6"; break;
        case ETAP_P_USER_EVENT7: s = "7"; break;
        case ETAP_P_USER_EVENT8: s = "8"; break;
        case ETAP_P_USER_EVENT9: s = "9"; break;
        case ETAP_P_USER_EVENT10: s = "10"; break;
        case ETAP_P_USER_EVENT11: s = "11"; break;
        case ETAP_P_USER_EVENT12: s = "12"; break;
        case ETAP_P_USER_EVENT13: s = "13"; break;
        case ETAP_P_USER_EVENT14: s = "14"; break;
        case ETAP_P_USER_EVENT15: s = "15"; break;
        case ETAP_P_USER_EVENT16: s = "16"; break;
        case ETAP_P_USER_EVENT17: s = "17"; break;
        case ETAP_P_USER_EVENT18: s = "18"; break;
        case ETAP_P_USER_EVENT19: s = "19"; break;
        case ETAP_P_USER_EVENT20: s = "20"; break;
        case ETAP_P_USER_EVENT21: s = "21"; break;
        case ETAP_P_USER_EVENT22: s = "22"; break;
        case ETAP_P_USER_EVENT23: s = "23"; break;
        case ETAP_P_USER_EVENT24: s = "24"; break;
        case ETAP_P_USER_EVENT25: s = "25"; break;
        case ETAP_P_USER_EVENT26: s = "26"; break;
        case ETAP_P_USER_EVENT27: s = "27"; break;
        case ETAP_P_USER_EVENT28: s = "28"; break;
        case ETAP_P_USER_EVENT29: s = "29"; break;
        case ETAP_P_USER_EVENT30: s = "30"; break;
        case ETAP_P_USER_EVENT31: s = "31"; break;
        default:
		sprintf(buf, "dynamic %x", record->pc);
		s = buf;
		break;
                }

        db_printf("user probe %s: [%x] data = %x %x %x %x\n",
               s,
               record->event,
               record->data[0],
               record->data[1],
               record->data[2],
               record->data[3]);
}

static
void
print_kernel_event(mbuff_entry_t record, boolean_t data)
{
	char *text_name;
	int i;

	/* assume zero event means that record was never written to */
	if(record->event == 0)
		return;

	db_printf("%x: %x%08x: ", record->instance, record->time.tv_sec,
		record->time.tv_nsec);

        switch (record->event) {

        case    ETAP_P_THREAD_LIFE :
                if (record->flags & EVENT_BEGIN)
                        db_printf("thread created    [T:%x A:%x] P:%d\n",
                               record->data[0],
                               record->data[1],
                               record->data[2]);
                else
                        db_printf("thread terminated [T:%x A:%x] P:%d\n",
                               record->data[0],
                               record->data[1],
                               record->data[2]);
                break;

        case    ETAP_P_SYSCALL_MACH :
                if (record->flags & SYSCALL_TRAP)
                        text_name = system_table_lookup(SYS_TABLE_MACH_TRAP,
                                                        record->data[0]);
                else
                        text_name = system_table_lookup(SYS_TABLE_MACH_MESSAGE,
                                                        record->data[0]);

                if (record->flags & EVENT_BEGIN)
                        db_printf("mach enter: %s [%x]\n",
			       text_name,
                               record->data[0]);
                else
                        db_printf("mach exit :\n");
                break;

        case    ETAP_P_SYSCALL_UNIX :
                text_name = system_table_lookup(SYS_TABLE_UNIX_SYSCALL,
                                                record->data[0]);

                if (record->flags & EVENT_BEGIN)
                        db_printf("unix enter: %s\n", text_name);
                else
                        db_printf("unix exit : %s\n", text_name);
                break;

        case    ETAP_P_THREAD_CTX :
                if (record->flags & EVENT_END)
                        db_printf("context switch to   %x   ",
                               record->data[0]);
                else    /* EVENT_BEGIN */
                        db_printf("context switch from %x   ",
                               record->data[0]);

                switch (record->data[1]) {
                        case    BLOCKED_ON_SEMAPHORE :
                                db_printf("R: semaphore\n"); break;
                        case    BLOCKED_ON_LOCK :
                                db_printf("R: lock\n"); break;
                        case    BLOCKED_ON_MUTEX_LOCK :
                                db_printf("R: mutex lock\n"); break;
                        case    BLOCKED_ON_COMPLEX_LOCK :
                                db_printf("R: complex lock\n"); break;
                        case    BLOCKED_ON_PORT_RCV :
                                db_printf("R: port receive\n"); break;
                        case    BLOCKED_ON_REAPER_DONE :
                                db_printf("R: reaper thread done\n"); break;
                        case    BLOCKED_ON_IDLE_DONE :
                                db_printf("R: idle thread done\n"); break;
                        case    BLOCKED_ON_TERMINATION :
                                db_printf("R: termination\n"); break;
                        default :
                                if (record->data[2])
                                        db_printf("R: ast %x\n", record->data[2]);
                                else
                                        db_printf("R: undefined block\n");
                        };
                break;

        case    ETAP_P_INTERRUPT :
                if (record->flags & EVENT_BEGIN) {
                        text_name = system_table_lookup(SYS_TABLE_INTERRUPT,
                                                        record->data[0]);
                        db_printf("intr enter: %s\n", text_name);
                } else
                        db_printf("intr exit\n");
                break;

        case    ETAP_P_ACT_ABORT :
                db_printf("activation abort [A %x : S %x]\n",
                       record->data[1],

                       record->data[0]);
                break;

        case    ETAP_P_PRIORITY :
                db_printf("priority changed for %x   N:%d O:%d\n",
                       record->data[0],
                       record->data[1],
                       record->data[2]);
                break;

        case    ETAP_P_EXCEPTION :
                text_name = system_table_lookup(SYS_TABLE_EXCEPTION,
                                                record->data[0]);
                db_printf("exception: %s\n", text_name);
                break;

        case    ETAP_P_DEPRESSION :
                if (record->flags & EVENT_BEGIN)
                        db_printf("priority depressed\n");
                else {
                        if (record->data[0] == 0)
                            db_printf("priority undepressed : timed out\n");
                        else
                            db_printf("priority undepressed : self inflicted\n");
                }
                break;

        case    ETAP_P_MISC :
                db_printf("flags: %x data: %x %x %x %x\n", record->flags,
                        record->data[0], record->data[1], record->data[2],
                        record->data[3]);
                break;

        case    ETAP_P_DETAP :
                printf("flags: %x rtc: %x %09x dtime: %x %09x\n",
                       record->flags, record->data[0], record->data[1],
                       record->data[2], record->data[3]);
                break;

        default:
		for(i = 0; event_table_init[i].event != ETAP_NO_TRACE; ++i)
			if(record->event == event_table_init[i].event) {
				print_lock_event(record, event_table_init[i].name);
				return;
			}
               	db_printf("Unknown event: %d\n", record->event);
		break;
        }
	if(data)
		db_printf("    Data: %08x  %08x  %08x  %08x\n", record->data[0],
			record->data[1], record->data[2], record->data[3]);
}

void print_lock_event(mbuff_entry_t record, const char *name)
{
	char      *sym1, *sym2;
	db_addr_t offset1, offset2;

	db_find_sym_and_offset(record->data[0], &sym1, &offset1);

	db_printf("%15s", name);
	if (record->flags & SPIN_LOCK)
		printf(" spin  ");
	else if (record->flags & READ_LOCK)
		printf(" read  ");
	else if (record->flags & WRITE_LOCK)
		printf(" write ");
	else
		printf(" undef ");

	if (record->flags & ETAP_CONTENTION) {
		db_printf("wait  lock %s+%x\n",
			sym1, offset1);
	}
	else if (record->flags & ETAP_DURATION) {
		db_find_sym_and_offset(record->data[1], &sym2, &offset2);
		db_printf("lock %x+%x  unlock %x+%x\n",
			sym1, offset1, sym2, offset2);
	} else {
		db_printf("illegal op: neither HOLD or WAIT are specified\n");
	}

}

char *
system_table_lookup(unsigned int table, unsigned int number)
{
        int x;
        char *name = NULL;
	unsigned int offset;

        switch (table) {
        case SYS_TABLE_MACH_TRAP:
                name = mach_trap_name(number >> 4);
                break;
        case SYS_TABLE_MACH_MESSAGE:
                for (x=0; x < mach_message_table_entries; x++) {
                        if (mach_message_table[x].number == number) {
                                name = mach_message_table[x].name;
                                break;
                        }
                }
                break;
        case SYS_TABLE_UNIX_SYSCALL:
                number = -number;
                name = syscall_name(number);
                break;
        case SYS_TABLE_INTERRUPT:
		db_find_sym_and_offset((int)ivect[number], &name, &offset);
                break;
        case SYS_TABLE_EXCEPTION:
                name = exception_name(number);
                break;
        }
        return (name != NULL) ? name : "undefined";
}

#endif  /* MACH_KDB */
#endif	/* ETAP_MONITOR */
