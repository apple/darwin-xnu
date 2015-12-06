/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

/* wrapper around kdebug */

#include <sys/kdebug.h>

/* KDEBUG codes */
#define PERF_CODE(SubClass, code) KDBG_CODE(DBG_PERF, SubClass, code)

/* broad sub-classes */
#define PERF_GENERIC    (0) 
#define PERF_THREADINFO (1)
#define PERF_CALLSTACK  (2)
#define PERF_TIMER      (3)
#define PERF_PET        (4)
#define PERF_AST        (5)
#define PERF_KPC        (6)
#define PERF_KDBG       (7)
#define PERF_CSWITCH    (8)
#define PERF_SIGNPOST   (9)
#define PERF_MEMINFO    (10)

/* sub-class codes */
#define PERF_GEN_CODE(code) PERF_CODE(PERF_GENERIC, code)
#define PERF_GEN_EVENT      PERF_GEN_CODE(0)

#define PERF_TI_CODE(code) PERF_CODE(PERF_THREADINFO, code)
#define PERF_TI_SAMPLE     PERF_TI_CODE(0)
#define PERF_TI_DATA       PERF_TI_CODE(1)
#define PERF_TI_XSAMPLE    PERF_TI_CODE(2)
#define PERF_TI_XPEND      PERF_TI_CODE(3)
#define PERF_TI_XDATA      PERF_TI_CODE(4)
#define PERF_TI_CSWITCH    PERF_TI_CODE(5)

#define PERF_CS_CODE(code) PERF_CODE(PERF_CALLSTACK, code)
#define PERF_CS_KSAMPLE    PERF_CS_CODE(0)
#define PERF_CS_UPEND      PERF_CS_CODE(1)
#define PERF_CS_USAMPLE    PERF_CS_CODE(2)
#define PERF_CS_KDATA      PERF_CS_CODE(3)
#define PERF_CS_UDATA      PERF_CS_CODE(4)
#define PERF_CS_KHDR       PERF_CS_CODE(5)
#define PERF_CS_UHDR       PERF_CS_CODE(6)
#define PERF_CS_ERROR      PERF_CS_CODE(7)

#define PERF_TM_CODE(code) PERF_CODE(PERF_TIMER, code)
#define PERF_TM_ASCHED     PERF_TM_CODE(0)
#define PERF_TM_SCHED      PERF_TM_CODE(1)
#define PERF_TM_HNDLR      PERF_TM_CODE(2)

#define PERF_PET_CODE(code) PERF_CODE(PERF_PET, code)
#define PERF_PET_THREAD     PERF_PET_CODE(0)
#define PERF_PET_ERROR      PERF_PET_CODE(1)
#define PERF_PET_RUN        PERF_PET_CODE(2)
#define PERF_PET_PAUSE      PERF_PET_CODE(3)
#define PERF_PET_IDLE       PERF_PET_CODE(4)
#define PERF_PET_SAMPLE     PERF_PET_CODE(5)
#define PERF_PET_SCHED      PERF_PET_CODE(6)
#define PERF_PET_END        PERF_PET_CODE(7)

#define PERF_AST_CODE(code) PERF_CODE(PERF_AST, code)
#define PERF_AST_HNDLR      PERF_AST_CODE(0)
#define PERF_AST_ERROR      PERF_AST_CODE(1)

#define PERF_KPC_CODE(code)    PERF_CODE(PERF_KPC, code)
#define PERF_KPC_HNDLR         PERF_KPC_CODE(0)
#define PERF_KPC_FCOUNTER      PERF_KPC_CODE(1)
#define PERF_KPC_COUNTER       PERF_KPC_CODE(2)
#define PERF_KPC_DATA          PERF_KPC_CODE(3)
#define PERF_KPC_CONFIG        PERF_KPC_CODE(4)
#define PERF_KPC_CFG_REG       PERF_KPC_CODE(5)
#define PERF_KPC_DATA32        PERF_KPC_CODE(6)
#define PERF_KPC_CFG_REG32     PERF_KPC_CODE(7)
#define PERF_KPC_DATA_THREAD   PERF_KPC_CODE(8)
#define PERF_KPC_DATA_THREAD32 PERF_KPC_CODE(9)

#define PERF_KDBG_CODE(code) PERF_CODE(PERF_KDBG, code)
#define PERF_KDBG_HNDLR      PERF_KDBG_CODE(0)

#define PERF_CSWITCH_CODE(code) PERF_CODE(PERF_CSWITCH, code)
#define PERF_CSWITCH_HNDLR      PERF_CSWITCH_CODE(0)

#define PERF_SIGNPOST_CODE(code) PERF_CODE(PERF_SIGNPOST, code)
#define PERF_SIGNPOST_HNDLR      PERF_SIGNPOST_CODE(0)

#define PERF_MI_CODE(code) PERF_CODE(PERF_MEMINFO, code)
#define PERF_MI_SAMPLE     PERF_MI_CODE(0)
#define PERF_MI_DATA       PERF_MI_CODE(1)

/* error sub-codes for trace data */
enum
{
	ERR_TASK,
	ERR_THREAD,
	ERR_PID,
	ERR_FRAMES,
	ERR_GETSTACK,
	ERR_NOMEM,
};

/* level of trace debug */
#define KPERF_DEBUG_DATA    0
#define KPERF_DEBUG_INFO    1
#define KPERF_DEBUG_VERBOSE 2
extern int kperf_debug_level;

/* for logging information / debugging -- optional */
#define BUF_INFO( id, a0, a1, a2, a3) if (kperf_debug_level >= KPERF_DEBUG_INFO) KERNEL_DEBUG_CONSTANT_IST(~KDEBUG_ENABLE_PPT, id,a0,a1,a2,a3,0)

#define BUF_INFO1( id, a0 )         BUF_INFO(id, a0,  0,  0,  0 )
#define BUF_INFO2( id, a0, a1 )     BUF_INFO(id, a0, a1,  0,  0 )
#define BUF_INFO3( id, a0, a1, a2 ) BUF_INFO(id, a0, a1, a2,  0 )

/* for logging actual data -- never compiled out */
#define BUF_DATA( id, a0, a1, a2, a3) KERNEL_DEBUG_CONSTANT_IST(~KDEBUG_ENABLE_PPT, id,a0,a1,a2,a3,0)

/* code neatness */
#define BUF_DATA1( id, a0 )         BUF_DATA(id, a0, 0, 0, 0 )
#define BUF_DATA2( id, a0, a1 )     BUF_DATA(id, a0, a1, 0, 0 )
#define BUF_DATA3( id, a0, a1, a2 ) BUF_DATA(id, a0, a1, a2, 0 )
