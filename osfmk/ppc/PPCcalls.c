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

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <mach/vm_prot.h>
#include <ppc/pmap.h>
#include <ppc/exception.h>
#include <ppc/Diagnostics.h>
#include <ppc/vmachmon.h>
#include <ppc/PseudoKernel.h>
#include <ppc/misc_protos.h>
#include <ppc/hw_perfmon.h>

/*
 *	To add a new entry:
 *		Add an "PPCcall(routine)" to the table in ppc/PPCcalls.h
 *
 *		Add trap definition to mach/ppc/syscall_sw.h and
 *		recompile user library.
 *
 */

#include <ppc/PPCcalls.h>
