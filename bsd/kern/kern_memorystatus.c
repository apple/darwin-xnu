/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
 *
 */
/*-
 * Copyright (c) 1999,2000,2001 Jonathan Lemon <jlemon@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/kern_event.h>
#include <sys/kern_memorystatus.h>

#include <kern/sched_prim.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <libkern/libkern.h>
#include <sys/sysctl.h>

extern unsigned int    vm_page_free_count;
extern unsigned int    vm_page_active_count;
extern unsigned int    vm_page_inactive_count;
extern unsigned int    vm_page_purgeable_count;
extern unsigned int    vm_page_wire_count;

static void kern_memorystatus_thread(void);

int kern_memorystatus_wakeup = 0;
int kern_memorystatus_level = 0;
int kern_memorystatus_last_level = 0;
unsigned int kern_memorystatus_kev_failure_count = 0;

SYSCTL_INT(_kern, OID_AUTO, memorystatus_level, CTLFLAG_RD, &kern_memorystatus_level, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, memorystatus_kev_failure_count, CTLFLAG_RD, &kern_memorystatus_kev_failure_count, 0, "");

__private_extern__ void
kern_memorystatus_init(void)
{
	(void)kernel_thread(kernel_task, kern_memorystatus_thread);
}

static void
kern_memorystatus_thread(void)
{
	struct kev_msg ev_msg;
	struct {
		uint32_t free_pages;
		uint32_t active_pages;
		uint32_t inactive_pages;
		uint32_t purgeable_pages;
		uint32_t wired_pages;
	} data;
	int ret;

	while(1) {
		
		kern_memorystatus_last_level = kern_memorystatus_level;

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_SYSTEM_CLASS;
		ev_msg.kev_subclass   = KEV_MEMORYSTATUS_SUBCLASS;

		/* pass the memory status level in the event code (as percent used) */
		ev_msg.event_code     = 100 - kern_memorystatus_last_level;

		ev_msg.dv[0].data_length = sizeof data;
		ev_msg.dv[0].data_ptr = &data;
		ev_msg.dv[1].data_length = 0;

		data.free_pages = vm_page_free_count;
		data.active_pages = vm_page_active_count;
		data.inactive_pages = vm_page_inactive_count;
		data.purgeable_pages = vm_page_purgeable_count;
		data.wired_pages = vm_page_wire_count;

		ret = kev_post_msg(&ev_msg);
		if (ret) {
			kern_memorystatus_kev_failure_count++;
			printf("%s: kev_post_msg() failed, err %d\n", __func__, ret);
		}

		if (kern_memorystatus_level >= kern_memorystatus_last_level + 5 ||
		    kern_memorystatus_level <= kern_memorystatus_last_level - 5)
			continue;

		assert_wait(&kern_memorystatus_wakeup, THREAD_UNINT);
		(void)thread_block((thread_continue_t)kern_memorystatus_thread);
	}
}
