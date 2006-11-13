/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
    struct proc *p;

    if(task!=TASK_NULL) {
        p = (struct proc *)(get_bsdtask_info(task));
        if(p) {
            return (p->p_pid);
        }
    }
    return -1;
}

__private_extern__ task_t
chudxnu_task_for_pid(int pid)
{
    struct proc *p = pfind(pid);
    if(p) {
        return p->task;
    }
    return TASK_NULL;
}

__private_extern__ int
chudxnu_current_pid(void)
{
    int pid = -1;
    struct uthread *ut = get_bsdthread_info(current_thread());
    task_t t = current_task();

    if(t != TASK_NULL) {
        pid = chudxnu_pid_for_task(t);
    } else {
        // no task, so try looking in the uthread and/or proc
        pid = current_proc()->p_pid;

        if(ut && ut->uu_proc) {
            pid = ut->uu_proc->p_pid;
        }
    }
    
    return pid;
}
