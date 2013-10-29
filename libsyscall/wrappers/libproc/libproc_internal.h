/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
#ifndef _LIBPROC_INTERNALH_
#define _LIBPROC_INTERNALH_

#include <TargetConditionals.h>

#include <sys/cdefs.h>
#include <libproc.h>

__BEGIN_DECLS

#if TARGET_OS_EMBEDDED

#define PROC_SETCPU_ACTION_NONE		0
#define PROC_SETCPU_ACTION_THROTTLE	1
#define PROC_SETCPU_ACTION_SUSPEND	2
#define PROC_SETCPU_ACTION_TERMINATE	3
#define PROC_SETCPU_ACTION_NOTIFY	4

int proc_setcpu_percentage(pid_t pid, int action, int percentage) __OSX_AVAILABLE_STARTING(__MAC_NA, __IPHONE_5_0);
int proc_setcpu_deadline(pid_t pid, int action, uint64_t deadline) __OSX_AVAILABLE_STARTING(__MAC_NA, __IPHONE_5_0);
int proc_setcpu_percentage_withdeadline(pid_t pid, int action, int percentage, uint64_t deadline) __OSX_AVAILABLE_STARTING(__MAC_NA, __IPHONE_5_0);
int proc_clear_cpulimits(pid_t pid) __OSX_AVAILABLE_STARTING(__MAC_NA, __IPHONE_5_0);

#define PROC_APPSTATE_NONE		0
#define PROC_APPSTATE_ACTIVE		1
#define PROC_APPSTATE_BACKGROUND	2
#define PROC_APPSTATE_NONUI		3
#define PROC_APPSTATE_INACTIVE		4

int proc_setappstate(int pid, int appstate);
int proc_appstate(int pid, int * appstatep);

#define PROC_DEVSTATUS_SHORTTERM	1
#define PROC_DEVSTATUS_LONGTERM		2

int proc_devstatusnotify(int devicestatus);

#define PROC_PIDBIND_CLEAR	0
#define PROC_PIDBIND_SET	1
int proc_pidbind(int pid, uint64_t threadid, int bind);

#else /* TARGET_OS_EMBEDDED */

/* resume the process suspend due to low VM resource */
int proc_clear_vmpressure(pid_t pid);
/* set self as the one who is going to resume suspended processes due to low VM. Need to be root */
int proc_set_owner_vmpressure(void);

/* mark yourself to delay idle sleep on disk IO */
int proc_set_delayidlesleep(void);
/* Reset yourself to delay idle sleep on disk IO, if already set */
int proc_clear_delayidlesleep(void);


/* sub policies for PROC_POLICY_APPTYPE */
#define PROC_POLICY_OSX_APPTYPE_NONE            0
#define PROC_POLICY_OSX_APPTYPE_TAL             1       /* TAL based launched */
#define PROC_POLICY_OSX_APPTYPE_WIDGET          2       /* for dashboard client */
#define PROC_POLICY_OSX_APPTYPE_DASHCLIENT      2       /* rename to move away from widget */

/* 
 * Resumes the backgrounded TAL or dashboard client. Only priv users can disable TAL apps.
 * Valid apptype are PROC_POLICY_OSX_APPTYPE_DASHCLIENT and PROC_POLICY_OSX_APPTYPE_TAL.
 * Returns 0 on success otherwise appropriate error code.
 */
int proc_disable_apptype(pid_t pid, int apptype);
int proc_enable_apptype(pid_t pid, int apptype);

#endif /* TARGET_OS_EMBEDDED */

/* mark process as importance donating */
int proc_donate_importance_boost(void);

/* check the message for an importance boost and take an assertion on it */
int proc_importance_assertion_begin_with_msg(mach_msg_header_t  *msg,
											 mach_msg_trailer_t *trailer,
											 uint64_t *assertion_token);

/* drop an assertion */
int proc_importance_assertion_complete(uint64_t assertion_handle);

int proc_set_cpumon_params(pid_t pid, int percentage, int interval) __OSX_AVAILABLE_STARTING(__MAC_10_8, __IPHONE_6_0);
int proc_get_cpumon_params(pid_t pid, int *percentage, int *interval) __OSX_AVAILABLE_STARTING(__MAC_10_8, __IPHONE_6_0);
int proc_set_cpumon_defaults(pid_t pid) __OSX_AVAILABLE_STARTING(__MAC_10_8, __IPHONE_6_0);
int proc_disable_cpumon(pid_t pid) __OSX_AVAILABLE_STARTING(__MAC_10_8, __IPHONE_6_0);

int proc_set_wakemon_params(pid_t pid, int rate_hz, int flags) __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_7_0);
int proc_get_wakemon_params(pid_t pid, int *rate_hz, int *flags) __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_7_0);
int proc_set_wakemon_defaults(pid_t pid) __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_7_0);
int proc_disable_wakemon(pid_t pid) __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_7_0);

#if !TARGET_IPHONE_SIMULATOR

#define PROC_SUPPRESS_SUCCESS                (0)
#define PROC_SUPPRESS_BAD_ARGUMENTS         (-1)
#define PROC_SUPPRESS_OLD_GENERATION        (-2)
#define PROC_SUPPRESS_ALREADY_SUPPRESSED    (-3)

int proc_suppress(pid_t pid, uint64_t *generation);
#endif /* !TARGET_IPHONE_SIMULATOR */

__END_DECLS

#endif /* _LIBPROC_INTERNALH_ */

