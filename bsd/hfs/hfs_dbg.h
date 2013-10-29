/*
 * Copyright (c) 2000, 2005 Apple Computer, Inc. All rights reserved.
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
/*	hfs_dbg.h
 *
 *	(c) 1997 Apple Computer, Inc.  All Rights Reserved
 *
 *	hfs_dbg.h -- debugging macros for HFS file system.
 *
 *	HISTORY
 *	10-Nov-1998 Pat Dirks		Cleaned up definition of DBG_ASSERT to handle embedded '%' correctly.
 *	28-Apr-1998	Scott Roberts	Reorganized and added HFS_DEBUG_STAGE
 *	17-Nov-1997	Pat Dirks		Pat Dirks at Apple Computer
 *								Derived from old hfs version.
 */

struct componentname;
extern void Debugger(const char *message);

/* Define the debugging stage...
		4 -> Do all, aggresive, call_kdp
		3 -> debug asserts and debug err, panic instead of call_kdp
		2 -> debug error, no kdb
		1 -> very little, panic only
*/
#ifndef HFS_DIAGNOSTIC
	#define HFS_DIAGNOSTIC 0
#endif /* HFS_DIAGNOSTIC */

#ifndef HFS_DEBUG_STAGE
#if HFS_DIAGNOSTIC
	#define HFS_DEBUG_STAGE 4
#else
	#define HFS_DEBUG_STAGE 1
#endif /* KERNEL */
#endif	/* HFS_DEBUG_STAGE */

#ifdef KERNEL
  #define PRINTIT kprintf
#else /* KERNEL */
  #define PRINTIT printf
#endif /* KERNEL */

#if (HFS_DEBUG_STAGE > 3)
#define DEBUG_BREAK Debugger("");
#else
#define DEBUG_BREAK
#endif

#if (HFS_DEBUG_STAGE == 4)
    #define DEBUG_BREAK_MSG(PRINTF_ARGS) { PRINTIT PRINTF_ARGS; DEBUG_BREAK };
#elif (HFS_DEBUG_STAGE == 3)
    #define DEBUG_BREAK_MSG(PRINTF_ARGS) { panic PRINTF_ARGS;};
#else
    #define DEBUG_BREAK_MSG(PRINTF_ARGS) { PRINTIT PRINTF_ARGS; };
#endif


#define PRINT_DELAY

/*
 * Debugging macros.
 */
#if	HFS_DIAGNOSTIC
extern int hfs_dbg_all;
extern int hfs_dbg_err;

#ifdef KERNEL
    #if (HFS_DEBUG_STAGE == 4)
		char		gDebugAssertStr[255];
		#define DBG_ASSERT(a) { if (!(a)) { \
				snprintf(gDebugAssertStr, sizeof (gDebugAssertStr), "Oops - File "__FILE__", line %d: assertion '%s' failed.\n", __LINE__, #a); \
                Debugger(gDebugAssertStr); } }
	#else
#define DBG_ASSERT(a) { if (!(a)) { panic("File "__FILE__", line %d: assertion '%s' failed.\n", __LINE__, #a); } }
    #endif /* HFS_DEBUG_STAGE */
#else
    #define DBG_ASSERT(a) assert(a)
#endif /* KERNEL */

#define DBG_ERR(x)	{		\
	if(hfs_dbg_all || hfs_dbg_err) {	\
        PRINTIT("%X: ", proc_selfpid()); \
	    PRINTIT("HFS ERROR: "); \
	    PRINTIT x;			\
	    PRINT_DELAY;  \
	};			\
}

#else	/* HFS_DIAGNOSTIC */

#define DBG_ASSERT(a)
#define DBG_ERR(x)

#endif	/* HFS_DIAGNOSTIC */

