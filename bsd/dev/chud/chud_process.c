/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/vnode_internal.h> // vn_getpath()
#include <kern/task.h>
#include <sys/user.h>

int	chudxnu_pid_for_task(task_t task);
task_t	chudxnu_task_for_pid(int pid);
int	chudxnu_current_pid(void);

__private_extern__ int
chudxnu_pid_for_task(task_t task)
{
     proc_t p;
    int pid = -1;

    if(task!=TASK_NULL) {
        p = (proc_t)(get_bsdtask_info(task));
        if(p) {
            return (proc_pid(p));
        }
    }
    return pid;
}

__private_extern__ task_t
chudxnu_task_for_pid(int pid)
{
	task_t t = TASK_NULL;
     proc_t p = proc_find(pid);
    if(p) {
        t =  p->task;
	proc_rele(p);
    }
    return (t);
}

__private_extern__ int
chudxnu_current_pid(void)
{
    int pid = -1;
    struct uthread *ut = get_bsdthread_info(current_thread());
    task_t t = current_task();

    if(t != TASK_NULL) {
        pid = chudxnu_pid_for_task(t);
    }
    if(-1 == pid) {
        // no task, so try looking in the uthread and/or proc
        pid = proc_pid(current_proc());

        if(-1 == pid && ut && ut->uu_proc) {
            pid = proc_pid(ut->uu_proc);
        }
    }
    
    return pid;
}
