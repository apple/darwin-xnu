/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/proc.h>

__private_extern__
int chudxnu_pid_for_task(task_t task)
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

__private_extern__
task_t chudxnu_task_for_pid(int pid)
{
    struct proc *p = pfind(pid);
    if(p) {
        return p->task;
    }
    return TASK_NULL;
}

__private_extern__
int chudxnu_current_pid(void)
{
    return current_proc()->p_pid;
}
