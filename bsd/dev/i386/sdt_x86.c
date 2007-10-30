/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)sdt.c	1.6	06/03/24 SMI" */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#define MACH__POSIX_C_SOURCE_PRIVATE 1 /* pulls in suitable savearea from mach/ppc/thread_status.h */
#include <kern/cpu_data.h>
#include <kern/thread.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>

#include <sys/dtrace_glue.h>

#include <sys/sdt_impl.h>

extern sdt_probe_t      **sdt_probetab;

/*ARGSUSED*/
int
sdt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax)
{
#pragma unused(eax)
	uintptr_t stack0 = 0, stack1 = 0, stack2 = 0, stack3 = 0, stack4 = 0;
	sdt_probe_t *sdt = sdt_probetab[SDT_ADDR2NDX(addr)];

	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint == addr) {
                        uintptr_t *stacktop;
                        if (CPU_ON_INTR(CPU))
                                stacktop = (uintptr_t *)dtrace_get_cpu_int_stack_top();
                        else
                                stacktop = (uintptr_t *)(dtrace_get_kernel_stack(current_thread()) + KERNEL_STACK_SIZE);

            if (stack <= stacktop)
                stack0 = *stack++;
            if (stack <= stacktop)
                stack1 = *stack++;
            if (stack <= stacktop)
                stack2 = *stack++;
            if (stack <= stacktop)
                stack3 = *stack++;
            if (stack <= stacktop)
                stack4 = *stack++;

			dtrace_probe(sdt->sdp_id, stack0, stack1, stack2, stack3, stack4);

			return (DTRACE_INVOP_NOP);
		}
	}

	return (0);
}

