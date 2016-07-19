/*
 * Copyright (c) 2000-2011, 2015 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_exit.c	8.7 (Berkeley) 2/12/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
 
#include <machine/reg.h>
#include <machine/psl.h>

#include "compat_43.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/tty.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/ptrace.h>
#include <sys/proc_info.h>
#include <sys/_types/_timeval64.h>
#include <sys/user.h>
#include <sys/aio_kern.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>
#include <sys/kdebug.h>
#include <sys/filedesc.h>	/* fdfree */
#if SYSV_SHM
#include <sys/shm_internal.h>	/* shmexit */
#endif
#include <sys/acct.h>		/* acct_process */
#if CONFIG_PERSONAS
#include <sys/persona.h>
#endif

#include <security/audit/audit.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <corpses/task_corpse.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/assert.h>
#include <sys/codesign.h>

#if VM_PRESSURE_EVENTS
#include <kern/vm_pressure.h>
#endif

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

#if CONFIG_DTRACE
/* Do not include dtrace.h, it redefines kmem_[alloc/free] */
extern void (*dtrace_fasttrap_exit_ptr)(proc_t);
extern void (*dtrace_helpers_cleanup)(proc_t);
extern void dtrace_lazy_dofs_destroy(proc_t);

#include <sys/dtrace_ptss.h>
#endif

#if CONFIG_MACF
#include <security/mac.h>
#include <sys/syscall.h>
#endif

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>

#include <vm/vm_protos.h>

#include <sys/sdt.h>

extern boolean_t init_task_died;
void proc_prepareexit(proc_t p, int rv, boolean_t perf_notify);
void vfork_exit(proc_t p, int rv);
void vproc_exit(proc_t p);
__private_extern__ void munge_user64_rusage(struct rusage *a_rusage_p, struct user64_rusage *a_user_rusage_p);
__private_extern__ void munge_user32_rusage(struct rusage *a_rusage_p, struct user32_rusage *a_user_rusage_p);
static int reap_child_locked(proc_t parent, proc_t child, int deadparent, int reparentedtoinit, int locked, int droplock);
static void populate_corpse_crashinfo(proc_t p, void *crash_info_ptr, struct rusage_superset *rup, mach_exception_data_type_t code, mach_exception_data_type_t subcode);
extern int proc_pidpathinfo(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t *retval);

static __attribute__((noinline)) void launchd_crashed_panic(proc_t p, int rv);
extern void proc_piduniqidentifierinfo(proc_t p, struct proc_uniqidentifierinfo *p_uniqidinfo);


/*
 * Things which should have prototypes in headers, but don't
 */
void	proc_exit(proc_t p);
int	wait1continue(int result);
int	waitidcontinue(int result);
kern_return_t sys_perf_notify(thread_t thread, int pid);
kern_return_t task_exception_notify(exception_type_t exception,
	mach_exception_data_type_t code, mach_exception_data_type_t subcode);
void	delay(int);
void gather_rusage_info(proc_t p, rusage_info_current *ru, int flavor);

/*
 * NOTE: Source and target may *NOT* overlap!
 * XXX Should share code with bsd/dev/ppc/unix_signal.c
 */
void
siginfo_user_to_user32(user_siginfo_t *in, user32_siginfo_t *out)
{
	out->si_signo	= in->si_signo;
	out->si_errno	= in->si_errno;
	out->si_code	= in->si_code;
	out->si_pid	= in->si_pid;
	out->si_uid	= in->si_uid;
	out->si_status	= in->si_status;
	out->si_addr	= CAST_DOWN_EXPLICIT(user32_addr_t,in->si_addr);
	/* following cast works for sival_int because of padding */
	out->si_value.sival_ptr	= CAST_DOWN_EXPLICIT(user32_addr_t,in->si_value.sival_ptr);
	out->si_band	= in->si_band;			/* range reduction */
}

void
siginfo_user_to_user64(user_siginfo_t *in, user64_siginfo_t *out)
{
	out->si_signo	= in->si_signo;
	out->si_errno	= in->si_errno;
	out->si_code	= in->si_code;
	out->si_pid	= in->si_pid;
	out->si_uid	= in->si_uid;
	out->si_status	= in->si_status;
	out->si_addr	= in->si_addr;
	/* following cast works for sival_int because of padding */
	out->si_value.sival_ptr	= in->si_value.sival_ptr;
	out->si_band	= in->si_band;			/* range reduction */
}

static int
copyoutsiginfo(user_siginfo_t *native, boolean_t is64, user_addr_t uaddr)
{
	if (is64) {
		user64_siginfo_t sinfo64;
				
		bzero(&sinfo64, sizeof (sinfo64));
		siginfo_user_to_user64(native, &sinfo64);
		return (copyout(&sinfo64, uaddr, sizeof (sinfo64)));
	} else {
		user32_siginfo_t sinfo32;

		bzero(&sinfo32, sizeof (sinfo32));
		siginfo_user_to_user32(native, &sinfo32);
		return (copyout(&sinfo32, uaddr, sizeof (sinfo32)));
	}
}

static void populate_corpse_crashinfo(proc_t p, void *crash_info_ptr, struct rusage_superset *rup, mach_exception_data_type_t code, mach_exception_data_type_t subcode)
{
	mach_vm_address_t uaddr = 0;
	mach_exception_data_type_t exc_codes[EXCEPTION_CODE_MAX];
	exc_codes[0] = code;
	exc_codes[1] = subcode;
	cpu_type_t cputype;
	struct proc_uniqidentifierinfo p_uniqidinfo;
	struct proc_workqueueinfo pwqinfo;
	int retval = 0;
	uint64_t crashed_threadid = thread_tid(current_thread());
	unsigned int pflags = 0;

#if CONFIG_MEMORYSTATUS
	int memstat_dirty_flags = 0;
#endif

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_EXCEPTION_CODES, sizeof(exc_codes), &uaddr)) {
		copyout(exc_codes, uaddr, sizeof(exc_codes));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PID, sizeof(p->p_pid), &uaddr)) {
		copyout(&p->p_pid, uaddr, sizeof(p->p_pid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PPID, sizeof(p->p_ppid), &uaddr)) {
		copyout(&p->p_ppid, uaddr, sizeof(p->p_ppid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CRASHED_THREADID, sizeof(uint64_t), &uaddr)) {
		copyout(&crashed_threadid, uaddr, sizeof(uint64_t));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_RUSAGE, sizeof(struct rusage), &uaddr)) {
		copyout(&rup->ru, uaddr, sizeof(struct rusage));
	}

	if (KERN_SUCCESS ==
	    kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_BSDINFOWITHUNIQID, sizeof(struct proc_uniqidentifierinfo), &uaddr)) {
		proc_piduniqidentifierinfo(p, &p_uniqidinfo);
		copyout(&p_uniqidinfo, uaddr, sizeof(struct proc_uniqidentifierinfo));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_RUSAGE_INFO, sizeof(rusage_info_current), &uaddr)) {
		copyout(&rup->ri, uaddr, sizeof(rusage_info_current));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_CSFLAGS, sizeof(p->p_csflags), &uaddr)) {
		copyout(&p->p_csflags, uaddr, sizeof(p->p_csflags));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_NAME, sizeof(p->p_comm), &uaddr)) {
		copyout(&p->p_comm, uaddr, sizeof(p->p_comm));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_STARTTIME, sizeof(p->p_start), &uaddr)) {
		struct timeval64 t64;
		t64.tv_sec = (int64_t)p->p_start.tv_sec;
		t64.tv_usec = (int64_t)p->p_start.tv_usec;
		copyout(&t64, uaddr, sizeof(t64));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_USERSTACK, sizeof(p->user_stack), &uaddr)) {
		copyout(&p->user_stack, uaddr, sizeof(p->user_stack));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_ARGSLEN, sizeof(p->p_argslen), &uaddr)) {
		copyout(&p->p_argslen, uaddr, sizeof(p->p_argslen));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_ARGC, sizeof(p->p_argc), &uaddr)) {
		copyout(&p->p_argc, uaddr, sizeof(p->p_argc));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_PATH, MAXPATHLEN, &uaddr)) {
		proc_pidpathinfo(p, 0, uaddr, MAXPATHLEN, &retval);
	}

	pflags = p->p_flag & (P_LP64 | P_SUGID);
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_FLAGS, sizeof(pflags), &uaddr)) {
		copyout(&pflags, uaddr, sizeof(pflags));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_UID, sizeof(p->p_uid), &uaddr)) {
		copyout(&p->p_uid, uaddr, sizeof(p->p_uid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_GID, sizeof(p->p_gid), &uaddr)) {
		copyout(&p->p_gid, uaddr, sizeof(p->p_gid));
	}

	cputype = cpu_type() & ~CPU_ARCH_MASK;
	if (IS_64BIT_PROCESS(p))
		cputype |= CPU_ARCH_ABI64;

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CPUTYPE, sizeof(cpu_type_t), &uaddr)) {
		copyout(&cputype, uaddr, sizeof(cpu_type_t));
	}

	bzero(&pwqinfo, sizeof(struct proc_workqueueinfo));
	retval = fill_procworkqueue(p, &pwqinfo);
	if (retval == 0) {
		if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_WORKQUEUEINFO, sizeof(struct proc_workqueueinfo), &uaddr)) {
			copyout(&pwqinfo, uaddr, sizeof(struct proc_workqueueinfo));
		}
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_RESPONSIBLE_PID, sizeof(p->p_responsible_pid), &uaddr)) {
		copyout(&p->p_responsible_pid, uaddr, sizeof(p->p_responsible_pid));
	}

#if CONFIG_MEMORYSTATUS
	memstat_dirty_flags = memorystatus_dirty_get(p);
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_DIRTY_FLAGS, sizeof(memstat_dirty_flags), &uaddr)) {
		copyout(&memstat_dirty_flags, uaddr, sizeof(memstat_dirty_flags));
	}
#endif

}

static __attribute__((noinline)) void
launchd_crashed_panic(proc_t p, int rv)
{
	printf("pid 1 exited (signal %d, exit %d)\n",
	    WTERMSIG(rv), WEXITSTATUS(rv));

#if (DEVELOPMENT || DEBUG)
	/*
	 * For debugging purposes, generate a core file of initproc before
	 * panicking. Leave at least 300 MB free on the root volume, and ignore
	 * the process's corefile ulimit. fsync() the file to ensure it lands on disk
	 * before the panic hits.
	 */

	int             err;
	uint64_t        coredump_start = mach_absolute_time();
	uint64_t        coredump_end;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;

	err = coredump(p, 300, COREDUMP_IGNORE_ULIMIT | COREDUMP_FULLFSYNC);

	coredump_end = mach_absolute_time();

	absolutetime_to_microtime(coredump_end - coredump_start, &tv_sec, &tv_usec);

	tv_msec = tv_usec / 1000;

	if (err != 0) {
		printf("Failed to generate initproc core file: error %d, took %d.%03d seconds\n",
		       err, (uint32_t)tv_sec, tv_msec);
	} else {
		printf("Generated initproc core file in %d.%03d seconds\n",
		       (uint32_t)tv_sec, tv_msec);
	}
#endif

	sync(p, (void *)NULL, (int *)NULL);

	panic_plain("%s exited (signal %d, exit status %d %s)", (p->p_name[0] != '\0' ? p->p_name : "initproc"), WTERMSIG(rv),
	            WEXITSTATUS(rv), ((p->p_csflags & CS_KILLED) ? "CS_KILLED" : ""));
}

/*
 * exit --
 *	Death of process.
 */
void
exit(proc_t p, struct exit_args *uap, int *retval)
{
	exit1(p, W_EXITCODE(uap->rval, 0), retval);

	thread_exception_return();
	/* NOTREACHED */
	while (TRUE)
		thread_block(THREAD_CONTINUE_NULL);
	/* NOTREACHED */
}

/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */
int
exit1(proc_t p, int rv, int *retval)
{
	return exit1_internal(p, rv, retval, TRUE, TRUE, 0);
}

int
exit1_internal(proc_t p, int rv, int *retval, boolean_t thread_can_terminate, boolean_t perf_notify,
	       int jetsam_flags)
{
	thread_t self = current_thread();
	struct task *task = p->task;
	struct uthread *ut;
	int error = 0;

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(self);
	 if (ut->uu_flag & UT_VFORK) {
		if (!thread_can_terminate) {
			return EINVAL;
		}

		vfork_exit(p, rv);
		vfork_return(p , retval, p->p_pid);
		unix_syscall_return(0);
		/* NOT REACHED */
	 }

	/* 
	 * The parameter list of audit_syscall_exit() was augmented to
	 * take the Darwin syscall number as the first parameter,
	 * which is currently required by mac_audit_postselect().
	 */

	/* 
	 * The BSM token contains two components: an exit status as passed
	 * to exit(), and a return value to indicate what sort of exit it 
	 * was.  The exit status is WEXITSTATUS(rv), but it's not clear
 	 * what the return value is.
	 */
	AUDIT_ARG(exit, WEXITSTATUS(rv), 0);
	AUDIT_SYSCALL_EXIT(SYS_exit, p, ut, 0); /* Exit is always successfull */

	DTRACE_PROC1(exit, int, CLD_EXITED);

	/* mark process is going to exit and pull out of DBG/disk throttle */
	/* TODO: This should be done after becoming exit thread */
	proc_set_task_policy(p->task, THREAD_NULL, TASK_POLICY_ATTRIBUTE,
	                     TASK_POLICY_TERMINATED, TASK_POLICY_ENABLE);

        proc_lock(p);
	error = proc_transstart(p, 1, (((jetsam_flags & P_JETSAM_MASK) == P_JETSAM_VNODE) ? 1 : 0));
	if (error == EDEADLK) {
		/* Temp: If deadlock error, then it implies multithreaded exec is
		 * in progress. Instread of letting exit continue and 
		 * corrupting the freed memory, let the exit thread
		 * return. This will save corruption in remote case.
		 */
		proc_unlock(p);
		if (current_proc() == p){
			if (p->exit_thread == self)
				printf("exit_thread failed to exit, leaving process %s[%d] in unkillable limbo\n",
				       p->p_comm, p->p_pid);
			thread_exception_return();
		} else {
			/* external termination like jetsam */
			return(error);
		}
	}

	while (p->exit_thread != self) {
		if (sig_try_locked(p) <= 0) {
			proc_transend(p, 1);
			if (get_threadtask(self) != task) {
				proc_unlock(p);
				return(0);
                        }
			proc_unlock(p);
			
			thread_terminate(self);
			if (!thread_can_terminate) {
				return 0;
			}

			thread_exception_return();
			/* NOTREACHED */
		}
		sig_lock_to_exit(p);
	}

	if (p == initproc && current_proc() == p) {
		init_task_died = TRUE;
	}
	
	p->p_lflag |= P_LEXIT;
	p->p_xstat = rv;
	p->p_lflag |= jetsam_flags;

	proc_transend(p, 1);
	proc_unlock(p);

	proc_prepareexit(p, rv, perf_notify);

	/* Last thread to terminate will call proc_exit() */
	task_terminate_internal(task);

	return(0);
}

void
proc_prepareexit(proc_t p, int rv, boolean_t perf_notify) 
{
	mach_exception_data_type_t code = 0, subcode = 0;

	struct uthread *ut;
	thread_t self = current_thread();
	ut = get_bsdthread_info(self);
	struct rusage_superset *rup;
	int kr = 0;
	int create_corpse = FALSE;

	if (p == initproc) {
		launchd_crashed_panic(p, rv);
		/* NOTREACHED */
	}

 	/* If a core should be generated, notify crash reporter */
	if (hassigprop(WTERMSIG(rv), SA_CORE) || ((p->p_csflags & CS_KILLED) != 0)) {
		/* 
		 * Workaround for processes checking up on PT_DENY_ATTACH:
		 * should be backed out post-Leopard (details in 5431025).
		 */
		if ((SIGSEGV == WTERMSIG(rv)) && 
				(p->p_pptr->p_lflag & P_LNOATTACH)) {
			goto skipcheck;
		}

		/*
		 * Crash Reporter looks for the signal value, original exception
		 * type, and low 20 bits of the original code in code[0] 
		 * (8, 4, and 20 bits respectively). code[1] is unmodified. 
		 */
		code = ((WTERMSIG(rv) & 0xff) << 24) |
			((ut->uu_exception & 0x0f) << 20) | 
			((int)ut->uu_code & 0xfffff);
		subcode = ut->uu_subcode;

		kr = task_exception_notify(EXC_CRASH, code, subcode);

		/* Nobody handled EXC_CRASH?? remember to make corpse */
		if (kr != 0) {
			create_corpse = TRUE;
		}
	}

skipcheck:
	/* Notify the perf server? */
	if (perf_notify) {
		(void)sys_perf_notify(self, p->p_pid);
	}


	/* stash the usage into corpse data if making_corpse == true */
	if (create_corpse == TRUE) {
		kr = task_mark_corpse(current_task());
		if (kr != KERN_SUCCESS) {
			if (kr == KERN_NO_SPACE) {
				printf("Process[%d] has no vm space for corpse info.\n", p->p_pid);
			} else if (kr == KERN_NOT_SUPPORTED) {
				printf("Process[%d] was destined to be corpse. But corpse is disabled by config.\n", p->p_pid);
			} else {
				printf("Process[%d] crashed: %s. Too many corpses being created.\n", p->p_pid, p->p_comm);
			}
			create_corpse = FALSE;
		} else {
			/* XXX: <rdar://problem/20491659> Need to sync ATM buffer before crash */
			kr = task_send_trace_memory(current_task(), p->p_pid, p->p_uniqueid);
		}
	}

	/*
	 * Before this process becomes a zombie, stash resource usage
	 * stats in the proc for external observers to query
	 * via proc_pid_rusage().
	 *
	 * If the zombie allocation fails, just punt the stats.
	 */
	MALLOC_ZONE(rup, struct rusage_superset *,
			sizeof (*rup), M_ZOMBIE, M_WAITOK);
	if (rup != NULL) {
		gather_rusage_info(p, &rup->ri, RUSAGE_INFO_CURRENT);
		rup->ri.ri_phys_footprint = 0;
		rup->ri.ri_proc_exit_abstime = mach_absolute_time();

		/*
		 * Make the rusage_info visible to external observers
		 * only after it has been completely filled in.
		 */
		p->p_ru = rup;
	}
	if (create_corpse) {
		populate_corpse_crashinfo(p, task_get_corpseinfo(current_task()), rup, code, subcode);
	}
	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */

	proc_list_lock();

#if CONFIG_MEMORYSTATUS
	memorystatus_remove(p, TRUE);
#endif

	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list);	/* Place onto zombproc. */
	/* will not be visible via proc_find */
	p->p_listflag |= P_LIST_EXITED;

	proc_list_unlock();


#ifdef PGINPROF
	vmsizmon();
#endif
	/*
	 * If parent is waiting for us to exit or exec,
	 * P_LPPWAIT is set; we will wakeup the parent below.
	 */
	proc_lock(p);
	p->p_lflag &= ~(P_LTRACED | P_LPPWAIT);
	p->p_sigignore = ~(sigcantmask);
	ut->uu_siglist = 0;
	proc_unlock(p);
}

void 
proc_exit(proc_t p)
{
	proc_t q;
	proc_t pp;
	struct task *task = p->task;
	vnode_t tvp = NULLVP;
	struct pgrp * pg;
	struct session *sessp;
	struct uthread * uth;
	pid_t pid;
	int exitval;
	int knote_hint;

	uth = current_uthread();

	proc_lock(p);
	proc_transstart(p, 1, 0);
	if( !(p->p_lflag & P_LEXIT)) {
		/*
		 * This can happen if a thread_terminate() occurs
		 * in a single-threaded process.
		 */
		p->p_lflag |= P_LEXIT;
		proc_transend(p, 1);
		proc_unlock(p);
		proc_prepareexit(p, 0, TRUE);	
		(void) task_terminate_internal(task);
		proc_lock(p);
	} else {
		proc_transend(p, 1);
	}

	p->p_lflag |= P_LPEXIT;

	/*
	 * Other kernel threads may be in the middle of signalling this process.
	 * Wait for those threads to wrap it up before making the process
	 * disappear on them.
	 */
	if ((p->p_lflag & P_LINSIGNAL) || (p->p_sigwaitcnt > 0)) {
		p->p_sigwaitcnt++;
		while ((p->p_lflag & P_LINSIGNAL) || (p->p_sigwaitcnt > 1)) 
			msleep(&p->p_sigmask, &p->p_mlock, PWAIT, "proc_sigdrain", NULL);
		p->p_sigwaitcnt--;
	}

	proc_unlock(p);
	pid = p->p_pid;
	exitval = p->p_xstat;
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON, 
		BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_START,
		pid, exitval, 0, 0, 0);

#if CONFIG_DTRACE
	/*
	 * Free any outstanding lazy dof entries. It is imperative we
	 * always call dtrace_lazy_dofs_destroy, rather than null check
	 * and call if !NULL. If we NULL test, during lazy dof faulting
	 * we can race with the faulting code and proceed from here to
	 * beyond the helpers cleanup. The lazy dof faulting will then
	 * install new helpers which will never be cleaned up, and leak.
	 */
	dtrace_lazy_dofs_destroy(p);

	/*
	 * Clean up any DTrace helper actions or probes for the process.
	 */
	if (p->p_dtrace_helpers != NULL) {
		(*dtrace_helpers_cleanup)(p);
	}

	/*
	 * Clean up any DTrace probes associated with this process.
	 */
	/*
	 * APPLE NOTE: We release ptss pages/entries in dtrace_fasttrap_exit_ptr(),
	 * call this after dtrace_helpers_cleanup()
	 */
	proc_lock(p);
	if (p->p_dtrace_probes && dtrace_fasttrap_exit_ptr) {
		(*dtrace_fasttrap_exit_ptr)(p);
	}
	proc_unlock(p);
#endif

	nspace_proc_exit(p);

#if VM_PRESSURE_EVENTS
	vm_pressure_proc_cleanup(p);
#endif

	/*
	 * need to cancel async IO requests that can be cancelled and wait for those
	 * already active.  MAY BLOCK!
	 */
	
	proc_refdrain(p);

	/* if any pending cpu limits action, clear it */
	task_clear_cpuusage(p->task, TRUE);

	workqueue_mark_exiting(p);
	workqueue_exit(p);
	kqueue_dealloc(p->p_wqkqueue);
	p->p_wqkqueue = NULL;

	_aio_exit( p );

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

	if (uth->uu_lowpri_window) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in flushing files on close
		 * collided with normal I/O operations...
		 * no need to throttle this thread since its going away
		 * but we do need to update our bookeeping w/r to throttled threads
		 */
		throttle_lowpri_io(0);
	}

#if SYSV_SHM
	/* Close ref SYSV Shared memory*/
	if (p->vm_shm)
		shmexit(p);
#endif
#if SYSV_SEM
	/* Release SYSV semaphores */
	semexit(p);
#endif
	
#if PSYNCH
	pth_proc_hashdelete(p);
#endif /* PSYNCH */

	sessp = proc_session(p);
	if (SESS_LEADER(p, sessp)) {

		if (sessp->s_ttyvp != NULLVP) {
			struct vnode *ttyvp;
			int ttyvid;
			int cttyflag = 0;
			struct vfs_context context;
			struct tty *tp;

			/*
			 * Controlling process.
			 * Signal foreground pgrp,
			 * drain controlling terminal
			 * and revoke access to controlling terminal.
			 */
			session_lock(sessp);
			tp = SESSION_TP(sessp);
			if ((tp != TTY_NULL) && (tp->t_session == sessp)) {
				session_unlock(sessp);

				/*
				 * We're going to SIGHUP the foreground process
				 * group. It can't change from this point on
				 * until the revoke is complete.
				 * The process group changes under both the tty
				 * lock and proc_list_lock but we need only one
				 */
				tty_lock(tp);
				ttysetpgrphup(tp);
				tty_unlock(tp);

				tty_pgsignal(tp, SIGHUP, 1);

				session_lock(sessp);
				tp = SESSION_TP(sessp);
			}
			cttyflag = sessp->s_flags & S_CTTYREF;
			sessp->s_flags &= ~S_CTTYREF;
			ttyvp = sessp->s_ttyvp;
			ttyvid = sessp->s_ttyvid;
			sessp->s_ttyvp = NULLVP;
			sessp->s_ttyvid = 0;
			sessp->s_ttyp = TTY_NULL;
			sessp->s_ttypgrpid = NO_PID;
			session_unlock(sessp);

			if ((ttyvp != NULLVP) && (vnode_getwithvid(ttyvp, ttyvid) == 0)) {
				if (tp != TTY_NULL) {
					tty_lock(tp);
					(void) ttywait(tp);
					tty_unlock(tp);
				}
				context.vc_thread = proc_thread(p); /* XXX */
				context.vc_ucred = kauth_cred_proc_ref(p);
				VNOP_REVOKE(ttyvp, REVOKEALL, &context);
				if (cttyflag) {
					/*
					 * Release the extra usecount taken in cttyopen.
					 * usecount should be released after VNOP_REVOKE is called.
					 * This usecount was taken to ensure that
					 * the VNOP_REVOKE results in a close to
					 * the tty since cttyclose is a no-op.
					 */
					vnode_rele(ttyvp);
				}
				vnode_put(ttyvp);
				kauth_cred_unref(&context.vc_ucred);
				ttyvp = NULLVP;
			}
			if (tp) {
				/*
				 * This is cleared even if not set. This is also done in
				 * spec_close to ensure that the flag is cleared.
				 */
				tty_lock(tp);
				ttyclrpgrphup(tp);
				tty_unlock(tp);

				ttyfree(tp);
			}
		}
		session_lock(sessp);
		sessp->s_leader = NULL;
		session_unlock(sessp);
	}
	session_rele(sessp);

	pg = proc_pgrp(p);
	fixjobc(p, pg, 0);
	pg_rele(pg);

	p->p_rlimit[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	(void)acct_process(p);

	proc_list_lock();

	if ((p->p_listflag & P_LIST_EXITCOUNT) == P_LIST_EXITCOUNT) {
		p->p_listflag &= ~P_LIST_EXITCOUNT;
		proc_shutdown_exitcount--;
		if (proc_shutdown_exitcount == 0)
			wakeup(&proc_shutdown_exitcount);
	}

	/* wait till parentrefs are dropped and grant no more */
	proc_childdrainstart(p);
	while ((q = p->p_children.lh_first) != NULL) {
		int reparentedtoinit = (q->p_listflag & P_LIST_DEADPARENT) ? 1 : 0;
		if (q->p_stat == SZOMB) {
			if (p != q->p_pptr)
				panic("parent child linkage broken");
			/* check for sysctl zomb lookup */
			while ((q->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
				msleep(&q->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
			}
			q->p_listflag |= P_LIST_WAITING;
			/*
			 * This is a named reference and it is not granted
			 * if the reap is already in progress. So we get
			 * the reference here exclusively and their can be
			 * no waiters. So there is no need for a wakeup
			 * after we are done.  Also the reap frees the structure
			 * and the proc struct cannot be used for wakeups as well. 
			 * It is safe to use q here as this is system reap
			 */
			(void)reap_child_locked(p, q, 1, reparentedtoinit, 1, 0);
		} else {
			/*
		 	* Traced processes are killed
		 	* since their existence means someone is messing up.
		 	*/
			if (q->p_lflag & P_LTRACED) {
				struct proc *opp;

				/*
				 * Take a reference on the child process to
				 * ensure it doesn't exit and disappear between
				 * the time we drop the list_lock and attempt
				 * to acquire its proc_lock.
				 */
				if (proc_ref_locked(q) != q)
					continue;

				proc_list_unlock();

				opp = proc_find(q->p_oppid);
				if (opp != PROC_NULL) {
					proc_list_lock();
					q->p_oppid = 0;
					proc_list_unlock();
					proc_reparentlocked(q, opp, 0, 0);
					proc_rele(opp);
				} else {
					/* original parent exited while traced */
					proc_list_lock();
					q->p_listflag |= P_LIST_DEADPARENT;
					q->p_oppid = 0;
					proc_list_unlock();
					proc_reparentlocked(q, initproc, 0, 0);
				}

				proc_lock(q);
				q->p_lflag &= ~P_LTRACED;

				if (q->sigwait_thread) {
					thread_t thread = q->sigwait_thread;

					proc_unlock(q);
					/*
				 	* The sigwait_thread could be stopped at a
				 	* breakpoint. Wake it up to kill.
				 	* Need to do this as it could be a thread which is not
				 	* the first thread in the task. So any attempts to kill
				 	* the process would result into a deadlock on q->sigwait.
				 	*/
					thread_resume(thread);
					clear_wait(thread, THREAD_INTERRUPTED);
					threadsignal(thread, SIGKILL, 0);
				} else {
					proc_unlock(q);
				}

				psignal(q, SIGKILL);
				proc_list_lock();
				proc_rele_locked(q);
			} else {
				q->p_listflag |= P_LIST_DEADPARENT;
				proc_reparentlocked(q, initproc, 0, 1);
			}
		}
	}

	proc_childdrainend(p);
	proc_list_unlock();

	/*
	 * Release reference to text vnode
	 */
	tvp = p->p_textvp;
	p->p_textvp = NULL;
	if (tvp != NULLVP) {
		vnode_rele(tvp);
	}

	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.  If we were unable to allocate a zombie
	 * structure, this information is lost.
	 */
	if (p->p_ru != NULL) {
	    calcru(p, &p->p_stats->p_ru.ru_utime, &p->p_stats->p_ru.ru_stime, NULL);
	    p->p_ru->ru = p->p_stats->p_ru;

	    ruadd(&(p->p_ru->ru), &p->p_stats->p_cru);
	}

	/*
	 * Free up profiling buffers.
	 */
	{
		struct uprof *p0 = &p->p_stats->p_prof, *p1, *pn;

		p1 = p0->pr_next;
		p0->pr_next = NULL;
		p0->pr_scale = 0;

		for (; p1 != NULL; p1 = pn) {
			pn = p1->pr_next;
			kfree(p1, sizeof *p1);
		}
	}

	proc_spinlock(p);
	if (thread_call_cancel(p->p_rcall))
		p->p_ractive--;

	while (p->p_ractive > 0) {
		proc_spinunlock(p);
		
		delay(1);

		proc_spinlock(p);
	}
	proc_spinunlock(p);

	thread_call_free(p->p_rcall);
	p->p_rcall = NULL;

	/*
	 * Other substructures are freed from wait().
	 */
	FREE_ZONE(p->p_stats, sizeof *p->p_stats, M_PSTATS);
	p->p_stats = NULL;

	FREE_ZONE(p->p_sigacts, sizeof *p->p_sigacts, M_SIGACTS);
	p->p_sigacts = NULL;

	proc_limitdrop(p, 1);
	p->p_limit = NULL;

	vm_purgeable_disown(p->task);

	/*
	 * Finish up by terminating the task
	 * and halt this thread (only if a
	 * member of the task exiting).
	 */
	p->task = TASK_NULL;
	set_bsdtask_info(task, NULL);

	knote_hint = NOTE_EXIT | (p->p_xstat & 0xffff);
	proc_knote(p, knote_hint);

	/* mark the thread as the one that is doing proc_exit
	 * no need to hold proc lock in uthread_free
	 */
	uth->uu_flag |= UT_PROCEXIT;
	/*
	 * Notify parent that we're gone.
	 */
	pp = proc_parent(p);
	if (pp->p_flag & P_NOCLDWAIT) {

		if (p->p_ru != NULL) {
			proc_lock(pp);
#if 3839178
		/*
		 * If the parent is ignoring SIGCHLD, then POSIX requires
		 * us to not add the resource usage to the parent process -
		 * we are only going to hand it off to init to get reaped.
		 * We should contest the standard in this case on the basis
		 * of RLIMIT_CPU.
		 */
#else	/* !3839178 */
		/*
		 * Add child resource usage to parent before giving
		 * zombie to init.  If we were unable to allocate a
		 * zombie structure, this information is lost.
		 */
			ruadd(&pp->p_stats->p_cru, &p->p_ru->ru);
#endif	/* !3839178 */
			update_rusage_info_child(&pp->p_stats->ri_child, &p->p_ru->ri);
			proc_unlock(pp);
		}
		
		/* kernel can reap this one, no need to move it to launchd */
		proc_list_lock();
		p->p_listflag |= P_LIST_DEADPARENT;
		proc_list_unlock();
	}
	if ((p->p_listflag & P_LIST_DEADPARENT) == 0 || p->p_oppid) {
		if (pp != initproc) {
			proc_lock(pp);
			pp->si_pid = p->p_pid;
			pp->si_status = p->p_xstat;
			pp->si_code = CLD_EXITED;
			/*
			 * p_ucred usage is safe as it is an exiting process
			 * and reference is dropped in reap
			 */
			pp->si_uid = kauth_cred_getruid(p->p_ucred);
			proc_unlock(pp);
		}
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON,
			BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_END,
			pid, exitval, 0, 0, 0);
		p->p_stat = SZOMB;
		/* 
		 * The current process can be reaped so, no one
		 * can depend on this
		 */

		psignal(pp, SIGCHLD);
	
		/* and now wakeup the parent */
		proc_list_lock();
		wakeup((caddr_t)pp);
		proc_list_unlock();
	} else {
		/* should be fine as parent proc would be initproc */
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		proc_list_lock();
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON,
			BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_END,
			pid, exitval, 0, 0, 0);
		/* check for sysctl zomb lookup */
		while ((p->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
			msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
		}
		/* safe to use p as this is a system reap */
		p->p_stat = SZOMB;
		p->p_listflag |= P_LIST_WAITING;

		/*
		 * This is a named reference and it is not granted
		 * if the reap is already in progress. So we get
		 * the reference here exclusively and their can be
		 * no waiters. So there is no need for a wakeup
		 * after we are done. AlsO  the reap frees the structure
		 * and the proc struct cannot be used for wakeups as well. 
		 * It is safe to use p here as this is system reap
		 */
		(void)reap_child_locked(pp, p, 1, 0, 1, 1);
		/* list lock dropped by reap_child_locked */
	}
	if (uth->uu_lowpri_window) {
	        /*
		 * task is marked as a low priority I/O type and we've
		 * somehow picked up another throttle during exit processing...
		 * no need to throttle this thread since its going away
		 * but we do need to update our bookeeping w/r to throttled threads
		 */
		throttle_lowpri_io(0);
	}

	proc_rele(pp);

}


/*
 * reap_child_locked
 *
 * Description:	Given a process from which all status information needed
 *		has already been extracted, if the process is a ptrace
 *		attach process, detach it and give it back to its real
 *		parent, else recover all resources remaining associated
 *		with it.
 *
 * Parameters:	proc_t parent		Parent of process being reaped
 *		proc_t child		Process to reap
 *
 * Returns:	0			Process was not reaped because it
 *					came from an attach
 *		1			Process was reaped
 */
static int
reap_child_locked(proc_t parent, proc_t child, int deadparent, int reparentedtoinit, int locked, int droplock)
{
	proc_t trace_parent = PROC_NULL;	/* Traced parent process, if tracing */

	if (locked == 1)
		proc_list_unlock();
	
	/*
	 * If we got the child via a ptrace 'attach',
	 * we need to give it back to the old parent.
	 *
	 * Exception: someone who has been reparented to launchd before being
	 * ptraced can simply be reaped, refer to radar 5677288
	 * 	p_oppid 		 -> ptraced
	 * 	trace_parent == initproc -> away from launchd
	 * 	reparentedtoinit	 -> came to launchd by reparenting
	 */
	if (child->p_oppid) {
		int knote_hint;
		pid_t oppid;

		proc_lock(child);
		oppid = child->p_oppid;
		child->p_oppid = 0;
		knote_hint = NOTE_EXIT | (child->p_xstat & 0xffff);
		proc_unlock(child);

		if ((trace_parent = proc_find(oppid))
			&& !((trace_parent == initproc) && reparentedtoinit)) {
				
			if (trace_parent != initproc) {
				/* 
				 * proc internal fileds  and p_ucred usage safe 
				 * here as child is dead and is not reaped or 
				 * reparented yet 
				 */
				proc_lock(trace_parent);
				trace_parent->si_pid = child->p_pid;
				trace_parent->si_status = child->p_xstat;
				trace_parent->si_code = CLD_CONTINUED;
				trace_parent->si_uid = kauth_cred_getruid(child->p_ucred);
				proc_unlock(trace_parent);
			}
			proc_reparentlocked(child, trace_parent, 1, 0);
			
			/* resend knote to original parent (and others) after reparenting */
			proc_knote(child, knote_hint);
			
			psignal(trace_parent, SIGCHLD);
			proc_list_lock();
			wakeup((caddr_t)trace_parent);
			child->p_listflag &= ~P_LIST_WAITING;
			wakeup(&child->p_stat);
			proc_list_unlock();
			proc_rele(trace_parent);
			if ((locked == 1) && (droplock == 0))
				proc_list_lock();
			return (0);
		}

		/*
		 * If we can't reparent (e.g. the original parent exited while child was being debugged, or
		 * original parent is the same as the debugger currently exiting), we still need to satisfy
		 * the knote lifecycle for other observers on the system. While the debugger was attached,
		 * the NOTE_EXIT would not have been broadcast during initial child termination.
		 */
		proc_knote(child, knote_hint);

		if (trace_parent != PROC_NULL) {
			proc_rele(trace_parent);
		}
	}
	
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	proc_knote(child, NOTE_REAP);
#pragma clang diagnostic pop

	proc_knote_drain(child);

	child->p_xstat = 0;
	if (child->p_ru) {
		proc_lock(parent);
#if 3839178
		/*
		 * If the parent is ignoring SIGCHLD, then POSIX requires
		 * us to not add the resource usage to the parent process -
		 * we are only going to hand it off to init to get reaped.
		 * We should contest the standard in this case on the basis
		 * of RLIMIT_CPU.
		 */
		if (!(parent->p_flag & P_NOCLDWAIT))
#endif	/* 3839178 */
			ruadd(&parent->p_stats->p_cru, &child->p_ru->ru);
		update_rusage_info_child(&parent->p_stats->ri_child, &child->p_ru->ri);
		proc_unlock(parent);
		FREE_ZONE(child->p_ru, sizeof *child->p_ru, M_ZOMBIE);
		child->p_ru = NULL;
	} else {
		printf("Warning : lost p_ru for %s\n", child->p_comm);
	}

	AUDIT_SESSION_PROCEXIT(child);

	/*
	 * Decrement the count of procs running with this uid.
	 * p_ucred usage is safe here as it is an exited process.
	 * and refernce is dropped after these calls down below
	 * (locking protection is provided by list lock held in chgproccnt)
	 */
#if CONFIG_PERSONAS
	/*
	 * persona_proc_drop calls chgproccnt(-1) on the persona uid,
	 * and (+1) on the child->p_ucred uid
	 */
	persona_proc_drop(child);
#endif
	(void)chgproccnt(kauth_cred_getruid(child->p_ucred), -1);

	/*
	 * Free up credentials.
	 */
	if (IS_VALID_CRED(child->p_ucred)) {
		kauth_cred_unref(&child->p_ucred);
	}

	/*  XXXX Note NOT SAFE TO USE p_ucred from this point onwards */

	/*
	 * Finally finished with old proc entry.
	 * Unlink it from its process group and free it.
	 */
	leavepgrp(child);

	proc_list_lock();
	LIST_REMOVE(child, p_list);	/* off zombproc */
	parent->p_childrencnt--;
	LIST_REMOVE(child, p_sibling);
	/* If there are no more children wakeup parent */
	if ((deadparent != 0) && (LIST_EMPTY(&parent->p_children)))
		wakeup((caddr_t)parent);	/* with list lock held */
	child->p_listflag &= ~P_LIST_WAITING;
	wakeup(&child->p_stat);

	/* Take it out of process hash */
	LIST_REMOVE(child, p_hash);
	child->p_listflag &= ~P_LIST_INHASH;
	proc_checkdeadrefs(child);
	nprocs--;

	if (deadparent) {
		/*
		 * If a child zombie is being reaped because its parent
		 * is exiting, make sure we update the list flag
		 */
		child->p_listflag |= P_LIST_DEADPARENT;
	}

	proc_list_unlock();

#if CONFIG_FINE_LOCK_GROUPS
	lck_mtx_destroy(&child->p_mlock, proc_mlock_grp);
	lck_mtx_destroy(&child->p_fdmlock, proc_fdmlock_grp);
	lck_mtx_destroy(&child->p_ucred_mlock, proc_ucred_mlock_grp);
#if CONFIG_DTRACE
	lck_mtx_destroy(&child->p_dtrace_sprlock, proc_lck_grp);
#endif
	lck_spin_destroy(&child->p_slock, proc_slock_grp);
#else /* CONFIG_FINE_LOCK_GROUPS */
	lck_mtx_destroy(&child->p_mlock, proc_lck_grp);
	lck_mtx_destroy(&child->p_fdmlock, proc_lck_grp);
	lck_mtx_destroy(&child->p_ucred_mlock, proc_lck_grp);
#if CONFIG_DTRACE
	lck_mtx_destroy(&child->p_dtrace_sprlock, proc_lck_grp);
#endif
	lck_spin_destroy(&child->p_slock, proc_lck_grp);
#endif /* CONFIG_FINE_LOCK_GROUPS */
	workqueue_destroy_lock(child);

	FREE_ZONE(child, sizeof *child, M_PROC);
	if ((locked == 1) && (droplock == 0))
		proc_list_lock();

	return (1);
}


int
wait1continue(int result)
{
	proc_t p;
	thread_t thread;
	uthread_t uth;
	struct _wait4_data *wait4_data;
	struct wait4_nocancel_args *uap;
	int *retval;

	if (result)
		return(result);

	p = current_proc();
	thread = current_thread();
	uth = (struct uthread *)get_bsdthread_info(thread);

	wait4_data = &uth->uu_kevent.uu_wait4_data;
	uap = wait4_data->args;
	retval = wait4_data->retval;
	return(wait4_nocancel(p, uap, retval));
}

int
wait4(proc_t q, struct wait4_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(wait4_nocancel(q, (struct wait4_nocancel_args *)uap, retval));
}

int
wait4_nocancel(proc_t q, struct wait4_nocancel_args *uap, int32_t *retval)
{
	int nfound;
	int sibling_count;
	proc_t p;
	int status, error;
	uthread_t uth;
	struct _wait4_data *wait4_data;

	AUDIT_ARG(pid, uap->pid);

	if (uap->pid == 0)
		uap->pid = -q->p_pgrpid;

loop:
	proc_list_lock();
loop1:
	nfound = 0;
	sibling_count = 0;

	for (p = q->p_children.lh_first; p != 0; p = p->p_sibling.le_next) {
		if ( p->p_sibling.le_next != 0 )
			sibling_count++;
		if (uap->pid != WAIT_ANY &&
		    p->p_pid != uap->pid &&
		    p->p_pgrpid != -(uap->pid))
			continue;

		nfound++;

		/* XXX This is racy because we don't get the lock!!!! */

		if (p->p_listflag & P_LIST_WAITING) {
			(void)msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
			goto loop1;
		}
		p->p_listflag |= P_LIST_WAITING;   /* only allow single thread to wait() */


		if (p->p_stat == SZOMB) {
			int reparentedtoinit = (p->p_listflag & P_LIST_DEADPARENT) ? 1 : 0;

			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif
			retval[0] = p->p_pid;
			if (uap->status) {
				/* Legacy apps expect only 8 bits of status */
				status = 0xffff & p->p_xstat;	/* convert to int */
				error = copyout((caddr_t)&status,
				   			uap->status,
						    sizeof(status));
				if (error) 
					goto out;
			}
			if (uap->rusage) {
				if (p->p_ru == NULL) {
					error = ENOMEM;
				} else {
					if (IS_64BIT_PROCESS(q)) {
						struct user64_rusage	my_rusage;
						munge_user64_rusage(&p->p_ru->ru, &my_rusage);
						error = copyout((caddr_t)&my_rusage,
							uap->rusage,
							sizeof (my_rusage));
					}
					else {
						struct user32_rusage	my_rusage;
						munge_user32_rusage(&p->p_ru->ru, &my_rusage);
						error = copyout((caddr_t)&my_rusage,
							uap->rusage,
							sizeof (my_rusage));
					}
				}
				/* information unavailable? */
				if (error) 
					goto out;
			}

			/* Conformance change for 6577252.
			 * When SIGCHLD is blocked and wait() returns because the status
			 * of a child process is available and there are no other 
			 * children processes, then any pending SIGCHLD signal is cleared.
			 */
			if ( sibling_count == 0 ) {
				int mask = sigmask(SIGCHLD);
				uth = current_uthread();

				if ( (uth->uu_sigmask & mask) != 0 ) {
					/* we are blocking SIGCHLD signals.  clear any pending SIGCHLD.
					 * This locking looks funny but it is protecting access to the 
					 * thread via p_uthlist.
					 */
					proc_lock(q); 
					uth->uu_siglist &= ~mask;	/* clear pending signal */
					proc_unlock(q);
				}
			}
			
			/* Clean up */
			(void)reap_child_locked(q, p, 0, reparentedtoinit, 0, 0);

			return (0);
		}
		if (p->p_stat == SSTOP && (p->p_lflag & P_LWAITED) == 0 &&
		    (p->p_lflag & P_LTRACED || uap->options & WUNTRACED)) {
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif
			proc_lock(p);
			p->p_lflag |= P_LWAITED;
			proc_unlock(p);
			retval[0] = p->p_pid;
			if (uap->status) {
				status = W_STOPCODE(p->p_xstat);
				error = copyout((caddr_t)&status,
					uap->status,
				    sizeof(status));
			} else
				error = 0;
			goto out;
		}
		/*
		 * If we are waiting for continued processses, and this
		 * process was continued
		 */
		if ((uap->options & WCONTINUED) &&
		    (p->p_flag & P_CONTINUED)) {
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif

			/* Prevent other process for waiting for this event */
			OSBitAndAtomic(~((uint32_t)P_CONTINUED), &p->p_flag);
			retval[0] = p->p_pid;
			if (uap->status) {
				status = W_STOPCODE(SIGCONT);
				error = copyout((caddr_t)&status,
					uap->status,
				    sizeof(status));
			} else
				error = 0;
			goto out;
		}
		p->p_listflag &= ~P_LIST_WAITING;
		wakeup(&p->p_stat);
	}
	/* list lock is held when we get here any which way */
	if (nfound == 0) {
		proc_list_unlock();
		return (ECHILD);
	}

	if (uap->options & WNOHANG) {
		retval[0] = 0;
		proc_list_unlock();
		return (0);
	}

	/* Save arguments for continuation. Backing storage is in uthread->uu_arg, and will not be deallocated */
	uth = current_uthread();
	wait4_data = &uth->uu_kevent.uu_wait4_data;
	wait4_data->args = uap;
	wait4_data->retval = retval;

	if ((error = msleep0((caddr_t)q, proc_list_mlock, PWAIT | PCATCH | PDROP, "wait", 0, wait1continue)))
		return (error);

	goto loop;
out:
	proc_list_lock();
	p->p_listflag &= ~P_LIST_WAITING;
	wakeup(&p->p_stat);
	proc_list_unlock();
	return (error);
}

#if DEBUG
#define ASSERT_LCK_MTX_OWNED(lock)	\
				lck_mtx_assert(lock, LCK_MTX_ASSERT_OWNED)
#else
#define ASSERT_LCK_MTX_OWNED(lock)	/* nothing */
#endif

int
waitidcontinue(int result)
{
	proc_t p;
	thread_t thread;
	uthread_t uth;
	struct _waitid_data *waitid_data;
	struct waitid_nocancel_args *uap;
	int *retval;

	if (result)
		return (result);

	p = current_proc();
	thread = current_thread();
	uth = (struct uthread *)get_bsdthread_info(thread);

	waitid_data = &uth->uu_kevent.uu_waitid_data;
	uap = waitid_data->args;
	retval = waitid_data->retval;
	return(waitid_nocancel(p, uap, retval));
}

/*
 * Description:	Suspend the calling thread until one child of the process
 *		containing the calling thread changes state.
 *
 * Parameters:	uap->idtype		one of P_PID, P_PGID, P_ALL
 *		uap->id			pid_t or gid_t or ignored
 *		uap->infop		Address of siginfo_t struct in
 *					user space into which to return status
 *		uap->options		flag values
 *
 * Returns:	0			Success
 *		!0			Error returning status to user space
 */
int
waitid(proc_t q, struct waitid_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return (waitid_nocancel(q, (struct waitid_nocancel_args *)uap, retval));
}

int
waitid_nocancel(proc_t q, struct waitid_nocancel_args *uap,
	__unused int32_t *retval)
{
	user_siginfo_t	siginfo;	/* siginfo data to return to caller */
	boolean_t caller64 = IS_64BIT_PROCESS(q);
	int nfound;
	proc_t p;
	int error;
	uthread_t uth;
	struct _waitid_data *waitid_data;

	if (uap->options == 0 ||
	    (uap->options & ~(WNOHANG|WNOWAIT|WCONTINUED|WSTOPPED|WEXITED)))
		return (EINVAL);	/* bits set that aren't recognized */

	switch (uap->idtype) {
	case P_PID:	/* child with process ID equal to... */
	case P_PGID:	/* child with process group ID equal to... */
		if (((int)uap->id) < 0)
			return (EINVAL);
		break;
	case P_ALL:	/* any child */
		break;
	}

loop:
	proc_list_lock();
loop1:
	nfound = 0;
	for (p = q->p_children.lh_first; p != 0; p = p->p_sibling.le_next) {

		switch (uap->idtype) {
		case P_PID:	/* child with process ID equal to... */
			if (p->p_pid != (pid_t)uap->id)
				continue;
			break;
		case P_PGID:	/* child with process group ID equal to... */
			if (p->p_pgrpid != (pid_t)uap->id)
				continue;
			break;
		case P_ALL:	/* any child */
			break;
		}

		/* XXX This is racy because we don't get the lock!!!! */

		/*
		 * Wait collision; go to sleep and restart; used to maintain
		 * the single return for waited process guarantee.
		 */
		if (p->p_listflag & P_LIST_WAITING) {
			(void) msleep(&p->p_stat, proc_list_mlock,
				PWAIT, "waitidcoll", 0);
			goto loop1;
		}
		p->p_listflag |= P_LIST_WAITING;		/* mark busy */

		nfound++;

		bzero(&siginfo, sizeof (siginfo));

		switch (p->p_stat) {
		case SZOMB:		/* Exited */
			if (!(uap->options & WEXITED))
				break;
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif
			siginfo.si_signo = SIGCHLD;
			siginfo.si_pid = p->p_pid;
			siginfo.si_status = WEXITSTATUS(p->p_xstat);
			if (WIFSIGNALED(p->p_xstat)) {
				siginfo.si_code = WCOREDUMP(p->p_xstat) ?
					CLD_DUMPED : CLD_KILLED;
			} else
				siginfo.si_code = CLD_EXITED;

			if ((error = copyoutsiginfo(&siginfo,
			    caller64, uap->infop)) != 0)
				goto out;

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				(void) reap_child_locked(q, p, 0, 0, 0, 0);
				return (0);
			}
			goto out;

		case SSTOP:		/* Stopped */
			/*
			 * If we are not interested in stopped processes, then
			 * ignore this one.
			 */
			if (!(uap->options & WSTOPPED))
				break;

			/*
			 * If someone has already waited it, we lost a race
			 * to be the one to return status.
			 */
			if ((p->p_lflag & P_LWAITED) != 0)
				break;
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif
			siginfo.si_signo = SIGCHLD;
			siginfo.si_pid = p->p_pid;
			siginfo.si_status = p->p_xstat;	/* signal number */
			siginfo.si_code = CLD_STOPPED;

			if ((error = copyoutsiginfo(&siginfo,
			    caller64, uap->infop)) != 0)
				goto out;

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				proc_lock(p);
				p->p_lflag |= P_LWAITED;
				proc_unlock(p);
			}
			goto out;

		default:		/* All other states => Continued */
			if (!(uap->options & WCONTINUED))
				break;

			/*
			 * If the flag isn't set, then this process has not
			 * been stopped and continued, or the status has
			 * already been reaped by another caller of waitid().
			 */
			if ((p->p_flag & P_CONTINUED) == 0)
				break;
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif
			siginfo.si_signo = SIGCHLD;
			siginfo.si_code = CLD_CONTINUED;
			proc_lock(p);
			siginfo.si_pid = p->p_contproc;
			siginfo.si_status = p->p_xstat;
			proc_unlock(p);

			if ((error = copyoutsiginfo(&siginfo,
			    caller64, uap->infop)) != 0)
				goto out;

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				OSBitAndAtomic(~((uint32_t)P_CONTINUED),
				    &p->p_flag);
			}
			goto out;
		}
		ASSERT_LCK_MTX_OWNED(proc_list_mlock);

		/* Not a process we are interested in; go on to next child */

		p->p_listflag &= ~P_LIST_WAITING;
		wakeup(&p->p_stat);
	}
	ASSERT_LCK_MTX_OWNED(proc_list_mlock);

	/* No child processes that could possibly satisfy the request? */

	if (nfound == 0) {
		proc_list_unlock();
		return (ECHILD);
	}

	if (uap->options & WNOHANG) {
		proc_list_unlock();
#if CONFIG_MACF
		if ((error = mac_proc_check_wait(q, p)) != 0)
			return (error);
#endif
		/*
		 * The state of the siginfo structure in this case
		 * is undefined.  Some implementations bzero it, some
		 * (like here) leave it untouched for efficiency.
		 *
		 * Thus the most portable check for "no matching pid with
		 * WNOHANG" is to store a zero into si_pid before
		 * invocation, then check for a non-zero value afterwards.
		 */
		return (0);
	}

	/* Save arguments for continuation. Backing storage is in uthread->uu_arg, and will not be deallocated */
	uth = current_uthread();
	waitid_data = &uth->uu_kevent.uu_waitid_data;
	waitid_data->args = uap;
	waitid_data->retval = retval;

	if ((error = msleep0(q, proc_list_mlock,
	    PWAIT | PCATCH | PDROP, "waitid", 0, waitidcontinue)) != 0)
		return (error);

	goto loop;
out:
	proc_list_lock();
	p->p_listflag &= ~P_LIST_WAITING;
	wakeup(&p->p_stat);
	proc_list_unlock();
	return (error);
}

/*
 * make process 'parent' the new parent of process 'child'.
 */
void
proc_reparentlocked(proc_t child, proc_t parent, int cansignal, int locked)
{
	proc_t oldparent = PROC_NULL;

	if (child->p_pptr == parent)
		return;

	if (locked == 0)
		proc_list_lock();

	oldparent = child->p_pptr;
#if __PROC_INTERNAL_DEBUG
	if (oldparent == PROC_NULL)
		panic("proc_reparent: process %p does not have a parent\n", child);
#endif

	LIST_REMOVE(child, p_sibling);
#if __PROC_INTERNAL_DEBUG
	if (oldparent->p_childrencnt == 0)
		panic("process children count already 0\n");
#endif
	oldparent->p_childrencnt--;
#if __PROC_INTERNAL_DEBUG1
	if (oldparent->p_childrencnt < 0)
		panic("process children count -ve\n");
#endif
	LIST_INSERT_HEAD(&parent->p_children, child, p_sibling);
	parent->p_childrencnt++;	
	child->p_pptr = parent;
	child->p_ppid = parent->p_pid;

	proc_list_unlock();

	if ((cansignal != 0) && (initproc == parent) && (child->p_stat == SZOMB))
		psignal(initproc, SIGCHLD);
	if (locked == 1)
		proc_list_lock();
}

/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */

void
vfork_exit(proc_t p, int rv)
{
	vfork_exit_internal(p, rv, 0);
}

void
vfork_exit_internal(proc_t p, int rv, int forceexit)
{
	thread_t self = current_thread();
#ifdef FIXME
	struct task *task = p->task;
#endif
	struct uthread *ut;

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(self);


	proc_lock(p);
	 if ((p->p_lflag & P_LPEXIT) == P_LPEXIT) {
		/* 
	 	* This happens when a parent exits/killed and vfork is in progress  
		* other threads. But shutdown code for ex has already called exit1()
	 	*/
		proc_unlock(p);
		return;
	}
	p->p_lflag |= (P_LEXIT | P_LPEXIT);
	proc_unlock(p);

	if (forceexit == 0) {
		/*
		 * parent of a vfork child has already called exit() and the 
		 * thread that has vfork in proress terminates. So there is no
		 * separate address space here and it has already been marked for
		 * termination. This was never covered before and could cause problems
		 * if we block here for outside code.
		 */
		/* Notify the perf server */
		(void)sys_perf_notify(self, p->p_pid);
	}

	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */

	proc_list_lock();

#if CONFIG_MEMORYSTATUS
	memorystatus_remove(p, TRUE);
#endif

	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list);	/* Place onto zombproc. */
	/* will not be visible via proc_find */
	p->p_listflag |= P_LIST_EXITED;

	proc_list_unlock();

	proc_lock(p);
	p->p_xstat = rv;
	p->p_lflag &= ~(P_LTRACED | P_LPPWAIT);
	p->p_sigignore = ~0;
	proc_unlock(p);

	proc_spinlock(p);
	if (thread_call_cancel(p->p_rcall))
		p->p_ractive--;

	while (p->p_ractive > 0) {
		proc_spinunlock(p);
		
		delay(1);

		proc_spinlock(p);
	}
	proc_spinunlock(p);

	thread_call_free(p->p_rcall);
	p->p_rcall = NULL;

	ut->uu_siglist = 0;

	vproc_exit(p);
}

void 
vproc_exit(proc_t p)
{
	proc_t q;
	proc_t pp;
	
	vnode_t tvp;
#ifdef FIXME
	struct task *task = p->task;
#endif
	struct pgrp * pg;
	struct session *sessp;
	struct rusage_superset *rup;

	/* XXX Zombie allocation may fail, in which case stats get lost */
	MALLOC_ZONE(rup, struct rusage_superset *,
			sizeof (*rup), M_ZOMBIE, M_WAITOK);

	proc_refdrain(p);

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

	sessp = proc_session(p);
	if (SESS_LEADER(p, sessp)) {
		
		if (sessp->s_ttyvp != NULLVP) {
			struct vnode *ttyvp;
			int ttyvid;
			int cttyflag = 0;
			struct vfs_context context;
			struct tty *tp;

			/*
			 * Controlling process.
			 * Signal foreground pgrp,
			 * drain controlling terminal
			 * and revoke access to controlling terminal.
			 */
			session_lock(sessp);
			tp = SESSION_TP(sessp);
			if ((tp != TTY_NULL) && (tp->t_session == sessp)) {
				session_unlock(sessp);

				/*
				 * We're going to SIGHUP the foreground process
				 * group. It can't change from this point on
				 * until the revoke is complete.
				 * The process group changes under both the tty
				 * lock and proc_list_lock but we need only one
				 */
				tty_lock(tp);
				ttysetpgrphup(tp);
				tty_unlock(tp);

				tty_pgsignal(tp, SIGHUP, 1);

				session_lock(sessp);
				tp = SESSION_TP(sessp);
			}
			cttyflag = sessp->s_flags & S_CTTYREF;
			sessp->s_flags &= ~S_CTTYREF;
			ttyvp = sessp->s_ttyvp;
			ttyvid = sessp->s_ttyvid;
			sessp->s_ttyvp = NULL;
			sessp->s_ttyvid = 0;
			sessp->s_ttyp = TTY_NULL;
			sessp->s_ttypgrpid = NO_PID;
			session_unlock(sessp);

		       if ((ttyvp != NULLVP) && (vnode_getwithvid(ttyvp, ttyvid) == 0)) {
			        if (tp != TTY_NULL) {
					tty_lock(tp);
					(void) ttywait(tp);
					tty_unlock(tp);
				}
				context.vc_thread = proc_thread(p); /* XXX */
				context.vc_ucred = kauth_cred_proc_ref(p);
				VNOP_REVOKE(ttyvp, REVOKEALL, &context);
				if (cttyflag) {
					/*
					 * Release the extra usecount taken in cttyopen.
					 * usecount should be released after VNOP_REVOKE is called.
					 * This usecount was taken to ensure that
					 * the VNOP_REVOKE results in a close to
					 * the tty since cttyclose is a no-op.
					 */
					vnode_rele(ttyvp);
				}
				vnode_put(ttyvp);
				kauth_cred_unref(&context.vc_ucred);
				ttyvp = NULLVP;
			}
			if (tp) {
				/*
				 * This is cleared even if not set. This is also done in
				 * spec_close to ensure that the flag is cleared.
				 */
				tty_lock(tp);
				ttyclrpgrphup(tp);
				tty_unlock(tp);

				ttyfree(tp);
			}
		}
		session_lock(sessp);
		sessp->s_leader = NULL;
		session_unlock(sessp);
	}
	session_rele(sessp);

	pg = proc_pgrp(p);
	fixjobc(p, pg, 0);
	pg_rele(pg);

	p->p_rlimit[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;

	proc_list_lock();
	proc_childdrainstart(p);
	while ((q = p->p_children.lh_first) != NULL) {
		if (q->p_stat == SZOMB) {
			if (p != q->p_pptr)
				panic("parent child linkage broken");
			/* check for lookups by zomb sysctl */
			while ((q->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
				msleep(&q->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
			}
			q->p_listflag |= P_LIST_WAITING;
			/*
			 * This is a named reference and it is not granted
			 * if the reap is already in progress. So we get
			 * the reference here exclusively and their can be
			 * no waiters. So there is no need for a wakeup
			 * after we are done. AlsO  the reap frees the structure
			 * and the proc struct cannot be used for wakeups as well. 
			 * It is safe to use q here as this is system reap
			 */
			(void)reap_child_locked(p, q, 1, 0, 1, 0);
		} else {
			/*
		 	* Traced processes are killed
		 	* since their existence means someone is messing up.
		 	*/
			if (q->p_lflag & P_LTRACED) {
				struct proc *opp;

				proc_list_unlock();

				opp = proc_find(q->p_oppid);
				if (opp != PROC_NULL) {
					proc_list_lock();
					q->p_oppid = 0;
					proc_list_unlock();
					proc_reparentlocked(q, opp, 0, 0);
					proc_rele(opp);
				} else {
					/* original parent exited while traced */
					proc_list_lock();
					q->p_listflag |= P_LIST_DEADPARENT;
					q->p_oppid = 0;
					proc_list_unlock();
					proc_reparentlocked(q, initproc, 0, 0);
				}

				proc_lock(q);
				q->p_lflag &= ~P_LTRACED;

				if (q->sigwait_thread) {
					thread_t thread = q->sigwait_thread;

					proc_unlock(q);
					/*
				 	* The sigwait_thread could be stopped at a
				 	* breakpoint. Wake it up to kill.
				 	* Need to do this as it could be a thread which is not
				 	* the first thread in the task. So any attempts to kill
				 	* the process would result into a deadlock on q->sigwait.
				 	*/
					thread_resume(thread);
					clear_wait(thread, THREAD_INTERRUPTED);
					threadsignal(thread, SIGKILL, 0);
				} else {
					proc_unlock(q);
				}

				psignal(q, SIGKILL);
				proc_list_lock();
			} else {
				q->p_listflag |= P_LIST_DEADPARENT;
				proc_reparentlocked(q, initproc, 0, 1);
			}
		}
	}

	proc_childdrainend(p);
	proc_list_unlock();

	/*
	 * Release reference to text vnode
	 */
	tvp = p->p_textvp;
	p->p_textvp = NULL;
	if (tvp != NULLVP) {
		vnode_rele(tvp);
	}

	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.  If we were unable to allocate a zombie
	 * structure, this information is lost.
	 */
	if (rup != NULL) {
	    rup->ru = p->p_stats->p_ru;
	    timerclear(&rup->ru.ru_utime);
	    timerclear(&rup->ru.ru_stime);

#ifdef  FIXME
	    if (task) {
		mach_task_basic_info_data_t tinfo;
		task_thread_times_info_data_t ttimesinfo;
		int task_info_stuff, task_ttimes_stuff;
		struct timeval ut,st;

		task_info_stuff	= MACH_TASK_BASIC_INFO_COUNT;
		task_info(task, MACH_TASK_BASIC_INFO,
			  &tinfo, &task_info_stuff);
		p->p_ru->ru.ru_utime.tv_sec = tinfo.user_time.seconds;
		p->p_ru->ru.ru_utime.tv_usec = tinfo.user_time.microseconds;
		p->p_ru->ru.ru_stime.tv_sec = tinfo.system_time.seconds;
		p->p_ru->ru.ru_stime.tv_usec = tinfo.system_time.microseconds;

		task_ttimes_stuff = TASK_THREAD_TIMES_INFO_COUNT;
		task_info(task, TASK_THREAD_TIMES_INFO,
			  &ttimesinfo, &task_ttimes_stuff);

		ut.tv_sec = ttimesinfo.user_time.seconds;
		ut.tv_usec = ttimesinfo.user_time.microseconds;
		st.tv_sec = ttimesinfo.system_time.seconds;
		st.tv_usec = ttimesinfo.system_time.microseconds;
		timeradd(&ut,&p->p_ru->ru.ru_utime,&p->p_ru->ru.ru_utime);
			timeradd(&st,&p->p_ru->ru.ru_stime,&p->p_ru->ru.ru_stime);
	    }
#endif /* FIXME */

	    ruadd(&rup->ru, &p->p_stats->p_cru);

		gather_rusage_info(p, &rup->ri, RUSAGE_INFO_CURRENT);
		rup->ri.ri_phys_footprint = 0;
		rup->ri.ri_proc_exit_abstime = mach_absolute_time();

		/*
		 * Now that we have filled in the rusage info, make it
		 * visible to an external observer via proc_pid_rusage().
		 */
		p->p_ru = rup;
	}

	/*
	 * Free up profiling buffers.
	 */
	{
		struct uprof *p0 = &p->p_stats->p_prof, *p1, *pn;

		p1 = p0->pr_next;
		p0->pr_next = NULL;
		p0->pr_scale = 0;

		for (; p1 != NULL; p1 = pn) {
			pn = p1->pr_next;
			kfree(p1, sizeof *p1);
		}
	}

#if PSYNCH
	pth_proc_hashdelete(p);
#endif /* PSYNCH */

	/*
	 * Other substructures are freed from wait().
	 */
	FREE_ZONE(p->p_stats, sizeof *p->p_stats, M_PSTATS);
	p->p_stats = NULL;

	FREE_ZONE(p->p_sigacts, sizeof *p->p_sigacts, M_SIGACTS);
	p->p_sigacts = NULL;

	proc_limitdrop(p, 1);
	p->p_limit = NULL;

	/*
	 * Finish up by terminating the task
	 * and halt this thread (only if a
	 * member of the task exiting).
	 */
	p->task = TASK_NULL;

	/*
	 * Notify parent that we're gone.
	 */
	pp = proc_parent(p);
	if ((p->p_listflag & P_LIST_DEADPARENT) == 0) {
		if (pp != initproc) {
			proc_lock(pp);
			pp->si_pid = p->p_pid;
			pp->si_status = p->p_xstat;
			pp->si_code = CLD_EXITED;
			/*
			 * p_ucred usage is safe as it is an exiting process
			 * and reference is dropped in reap
			 */
			pp->si_uid = kauth_cred_getruid(p->p_ucred);
			proc_unlock(pp);
		}
		/* mark as a zombie */
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		p->p_stat = SZOMB;

		psignal(pp, SIGCHLD);

		/* and now wakeup the parent */
		proc_list_lock();
		wakeup((caddr_t)pp);
		proc_list_unlock();
	} else {
		proc_list_lock();
		/* check for lookups by zomb sysctl */
		while ((p->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
			msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
		}
		p->p_stat = SZOMB;
		p->p_listflag |= P_LIST_WAITING;

		/*
		 * This is a named reference and it is not granted
		 * if the reap is already in progress. So we get
		 * the reference here exclusively and their can be
		 * no waiters. So there is no need for a wakeup
		 * after we are done. AlsO  the reap frees the structure
		 * and the proc struct cannot be used for wakeups as well. 
		 * It is safe to use p here as this is system reap
		 */
		(void)reap_child_locked(pp, p, 0, 0, 1, 1);
		/* list lock dropped by reap_child_locked */
	}
	proc_rele(pp);
}

						
/*
 * munge_rusage
 *	LP64 support - long is 64 bits if we are dealing with a 64 bit user
 *	process.  We munge the kernel version of rusage into the
 *	64 bit version.
 */
__private_extern__  void 
munge_user64_rusage(struct rusage *a_rusage_p, struct user64_rusage *a_user_rusage_p)
{
	/* timeval changes size, so utime and stime need special handling */
	a_user_rusage_p->ru_utime.tv_sec = a_rusage_p->ru_utime.tv_sec;
	a_user_rusage_p->ru_utime.tv_usec = a_rusage_p->ru_utime.tv_usec;
	a_user_rusage_p->ru_stime.tv_sec = a_rusage_p->ru_stime.tv_sec;
	a_user_rusage_p->ru_stime.tv_usec = a_rusage_p->ru_stime.tv_usec;
	/*
	 * everything else can be a direct assign, since there is no loss
	 * of precision implied boing 32->64.
	 */
	a_user_rusage_p->ru_maxrss = a_rusage_p->ru_maxrss;
	a_user_rusage_p->ru_ixrss = a_rusage_p->ru_ixrss;
	a_user_rusage_p->ru_idrss = a_rusage_p->ru_idrss;
	a_user_rusage_p->ru_isrss = a_rusage_p->ru_isrss;
	a_user_rusage_p->ru_minflt = a_rusage_p->ru_minflt;
	a_user_rusage_p->ru_majflt = a_rusage_p->ru_majflt;
	a_user_rusage_p->ru_nswap = a_rusage_p->ru_nswap;
	a_user_rusage_p->ru_inblock = a_rusage_p->ru_inblock;
	a_user_rusage_p->ru_oublock = a_rusage_p->ru_oublock;
	a_user_rusage_p->ru_msgsnd = a_rusage_p->ru_msgsnd;
	a_user_rusage_p->ru_msgrcv = a_rusage_p->ru_msgrcv;
	a_user_rusage_p->ru_nsignals = a_rusage_p->ru_nsignals;
	a_user_rusage_p->ru_nvcsw = a_rusage_p->ru_nvcsw;
	a_user_rusage_p->ru_nivcsw = a_rusage_p->ru_nivcsw;
}

/* For a 64-bit kernel and 32-bit userspace, munging may be needed */
__private_extern__  void 
munge_user32_rusage(struct rusage *a_rusage_p, struct user32_rusage *a_user_rusage_p)
{
	/* timeval changes size, so utime and stime need special handling */
	a_user_rusage_p->ru_utime.tv_sec = a_rusage_p->ru_utime.tv_sec;
	a_user_rusage_p->ru_utime.tv_usec = a_rusage_p->ru_utime.tv_usec;
	a_user_rusage_p->ru_stime.tv_sec = a_rusage_p->ru_stime.tv_sec;
	a_user_rusage_p->ru_stime.tv_usec = a_rusage_p->ru_stime.tv_usec;
	/*
	 * everything else can be a direct assign. We currently ignore
	 * the loss of precision
	 */
	a_user_rusage_p->ru_maxrss = a_rusage_p->ru_maxrss;
	a_user_rusage_p->ru_ixrss = a_rusage_p->ru_ixrss;
	a_user_rusage_p->ru_idrss = a_rusage_p->ru_idrss;
	a_user_rusage_p->ru_isrss = a_rusage_p->ru_isrss;
	a_user_rusage_p->ru_minflt = a_rusage_p->ru_minflt;
	a_user_rusage_p->ru_majflt = a_rusage_p->ru_majflt;
	a_user_rusage_p->ru_nswap = a_rusage_p->ru_nswap;
	a_user_rusage_p->ru_inblock = a_rusage_p->ru_inblock;
	a_user_rusage_p->ru_oublock = a_rusage_p->ru_oublock;
	a_user_rusage_p->ru_msgsnd = a_rusage_p->ru_msgsnd;
	a_user_rusage_p->ru_msgrcv = a_rusage_p->ru_msgrcv;
	a_user_rusage_p->ru_nsignals = a_rusage_p->ru_nsignals;
	a_user_rusage_p->ru_nvcsw = a_rusage_p->ru_nvcsw;
	a_user_rusage_p->ru_nivcsw = a_rusage_p->ru_nivcsw;
}
