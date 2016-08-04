/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)kern_proc.c	8.4 (Berkeley) 1/4/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/* HISTORY
 *  04-Aug-97  Umesh Vaishampayan (umeshv@apple.com)
 *	Added current_proc_EXTERNAL() function for the use of kernel
 * 	lodable modules.
 *
 *  05-Jun-95 Mac Gillon (mgillon) at NeXT
 *	New version based on 3.3NS and 4.4
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/acct.h>
#include <sys/wait.h>
#include <sys/file_internal.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/signalvar.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/kauth.h>
#include <sys/codesign.h>
#include <sys/kernel_types.h>
#include <sys/ubc.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/coalition.h>
#include <sys/coalition.h>
#include <kern/assert.h>
#include <vm/vm_protos.h>
#include <vm/vm_map.h>		/* vm_map_switch_protect() */
#include <vm/vm_pageout.h>
#include <mach/task.h>
#include <mach/message.h>
#include <sys/priv.h>
#include <sys/proc_info.h>
#include <sys/bsdtask_info.h>
#include <sys/persona.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <libkern/crypto/sha1.h>

/*
 * Structure associated with user cacheing.
 */
struct uidinfo {
	LIST_ENTRY(uidinfo) ui_hash;
	uid_t	ui_uid;
	long	ui_proccnt;
};
#define	UIHASH(uid)	(&uihashtbl[(uid) & uihash])
LIST_HEAD(uihashhead, uidinfo) *uihashtbl;
u_long uihash;		/* size of hash table - 1 */

/*
 * Other process lists
 */
struct pidhashhead *pidhashtbl;
u_long pidhash;
struct pgrphashhead *pgrphashtbl;
u_long pgrphash;
struct sesshashhead *sesshashtbl;
u_long sesshash;

struct proclist allproc;
struct proclist zombproc;
extern struct tty cons;

extern int cs_debug;

#if DEBUG
#define __PROC_INTERNAL_DEBUG 1
#endif
/* Name to give to core files */
__XNU_PRIVATE_EXTERN char corefilename[MAXPATHLEN+1] = {"/cores/core.%P"};

#if PROC_REF_DEBUG
extern uint32_t fastbacktrace(uintptr_t* bt, uint32_t max_frames) __attribute__((noinline));
#endif

static void orphanpg(struct pgrp *pg);
void 	proc_name_kdp(task_t t, char * buf, int size);
int	proc_threadname_kdp(void *uth, char *buf, size_t size);
void	proc_starttime_kdp(void *p, uint64_t *tv_sec, uint64_t *tv_usec);
char	*proc_name_address(void *p);

static void  pgrp_add(struct pgrp * pgrp, proc_t parent, proc_t child);
static void pgrp_remove(proc_t p);
static void pgrp_replace(proc_t p, struct pgrp *pgrp);
static void pgdelete_dropref(struct pgrp *pgrp);
extern void pg_rele_dropref(struct pgrp * pgrp);
static int csops_internal(pid_t pid, int ops, user_addr_t uaddr, user_size_t usersize, user_addr_t uaddittoken);
static boolean_t proc_parent_is_currentproc(proc_t p);

struct fixjob_iterargs {
	struct pgrp * pg;
	struct session * mysession;
	int entering;
};

int fixjob_callback(proc_t, void *);

/*
 * Initialize global process hashing structures.
 */
void
procinit(void)
{
	LIST_INIT(&allproc);
	LIST_INIT(&zombproc);
	pidhashtbl = hashinit(maxproc / 4, M_PROC, &pidhash);
	pgrphashtbl = hashinit(maxproc / 4, M_PROC, &pgrphash);
	sesshashtbl = hashinit(maxproc / 4, M_PROC, &sesshash);
	uihashtbl = hashinit(maxproc / 16, M_PROC, &uihash);
#if CONFIG_PERSONAS
	personas_bootstrap();
#endif
}

/*
 * Change the count associated with number of processes
 * a given user is using. This routine protects the uihash
 * with the list lock
 */
int
chgproccnt(uid_t uid, int diff)
{
	struct uidinfo *uip;
	struct uidinfo *newuip = NULL;
	struct uihashhead *uipp;
	int retval;

again:
	proc_list_lock();
	uipp = UIHASH(uid);
	for (uip = uipp->lh_first; uip != 0; uip = uip->ui_hash.le_next)
		if (uip->ui_uid == uid)
			break;
	if (uip) {
		uip->ui_proccnt += diff;
		if (uip->ui_proccnt > 0) {
			retval = uip->ui_proccnt;
			proc_list_unlock();
			goto out;
		}
		if (uip->ui_proccnt < 0)
			panic("chgproccnt: procs < 0");
		LIST_REMOVE(uip, ui_hash);
		retval = 0;
		proc_list_unlock();
		FREE_ZONE(uip, sizeof(*uip), M_PROC);
		goto out;
	}
	if (diff <= 0) {
		if (diff == 0) {
			retval = 0;
			proc_list_unlock();
			goto out;
		}
		panic("chgproccnt: lost user");
	}
	if (newuip != NULL) {
		uip = newuip;
		newuip = NULL;
		LIST_INSERT_HEAD(uipp, uip, ui_hash);
		uip->ui_uid = uid;
		uip->ui_proccnt = diff;
		retval = diff;
		proc_list_unlock();
		goto out;
	}
	proc_list_unlock();
	MALLOC_ZONE(newuip, struct uidinfo *, sizeof(*uip), M_PROC, M_WAITOK);
	if (newuip == NULL)
		panic("chgproccnt: M_PROC zone depleted");
	goto again;
out:
	if (newuip != NULL) 
		FREE_ZONE(newuip, sizeof(*uip), M_PROC);
	return(retval);
}

/*
 * Is p an inferior of the current process?
 */
int
inferior(proc_t p)
{
	int retval = 0;

	proc_list_lock();
	for (; p != current_proc(); p = p->p_pptr)
		if (p->p_pid == 0) 
			goto out;
	retval = 1;
out:
	proc_list_unlock();
	return(retval);
}

/*
 * Is p an inferior of t ?
 */
int
isinferior(proc_t p, proc_t t)
{
	int retval = 0;
	int nchecked = 0;
	proc_t start = p;

	/* if p==t they are not inferior */
	if (p == t)
		return(0);

	proc_list_lock();
	for (; p != t; p = p->p_pptr) {
		nchecked++;

		/* Detect here if we're in a cycle */
		if ((p->p_pid == 0) || (p->p_pptr == start) || (nchecked >= nprocs))
			goto out;
	}
	retval = 1;
out:
	proc_list_unlock();
	return(retval);
}

int
proc_isinferior(int pid1, int pid2)
{
	proc_t p = PROC_NULL;
	proc_t t = PROC_NULL;
	int retval = 0;
	
	if (((p = proc_find(pid1)) != (proc_t)0 ) && ((t = proc_find(pid2)) != (proc_t)0))
		retval = isinferior(p, t);

	if (p != PROC_NULL)
		proc_rele(p);
	if (t != PROC_NULL)
		proc_rele(t);

	return(retval);
}

proc_t
proc_find(int pid)
{
	return(proc_findinternal(pid, 0));
}

proc_t
proc_findinternal(int pid, int locked)
{
	proc_t p = PROC_NULL;

	if (locked == 0) {
		proc_list_lock();
	}

	p = pfind_locked(pid);
	if ((p == PROC_NULL) || (p != proc_ref_locked(p)))
		p = PROC_NULL;

	if (locked == 0) {
		proc_list_unlock();
	}

	return(p);
}

proc_t
proc_findthread(thread_t thread)
{
	proc_t p = PROC_NULL;
	struct uthread *uth;

	proc_list_lock();
	uth = get_bsdthread_info(thread);
	if (uth && (uth->uu_flag & UT_VFORK))
		p = uth->uu_proc;
	else
		p = (proc_t)(get_bsdthreadtask_info(thread));
	p = proc_ref_locked(p);
	proc_list_unlock();
	return(p);
}

#if PROC_REF_DEBUG
void
uthread_reset_proc_refcount(void *uthread) {
	uthread_t uth;

	if (proc_ref_tracking_disabled) {
		return;
	}

	uth = (uthread_t) uthread;

	uth->uu_proc_refcount = 0;
	uth->uu_pindex = 0;
}

int
uthread_get_proc_refcount(void *uthread) {
	uthread_t uth;

	if (proc_ref_tracking_disabled) {
		return 0;
	}

	uth = (uthread_t) uthread;

	return uth->uu_proc_refcount;
}

static void
record_procref(proc_t p, int count) {
	uthread_t uth;

	if (proc_ref_tracking_disabled) {
		return;
	}

	uth = current_uthread();
	uth->uu_proc_refcount += count;

	if (count == 1) {
		if (uth->uu_pindex < NUM_PROC_REFS_TO_TRACK) {
			fastbacktrace((uintptr_t *) &uth->uu_proc_pcs[uth->uu_pindex], PROC_REF_STACK_DEPTH);

			uth->uu_proc_ps[uth->uu_pindex] = p;
			uth->uu_pindex++;
		}
	}
}
#endif

int 
proc_rele(proc_t p)
{
	proc_list_lock();
	proc_rele_locked(p);
	proc_list_unlock();

	return(0);
}

proc_t
proc_self(void)
{
	struct proc * p;

	p = current_proc();

	proc_list_lock();
	if (p != proc_ref_locked(p))
		p = PROC_NULL;
	proc_list_unlock();
	return(p);
}


proc_t
proc_ref_locked(proc_t p)
{
	proc_t p1 = p;
	
	/* if process still in creation return failure */
	if ((p == PROC_NULL) || ((p->p_listflag & P_LIST_INCREATE) != 0))
			return (PROC_NULL);
	/* do not return process marked for termination */
	if ((p->p_stat != SZOMB) && ((p->p_listflag & P_LIST_EXITED) == 0) && ((p->p_listflag & (P_LIST_DRAINWAIT | P_LIST_DRAIN | P_LIST_DEAD)) == 0)) {
		p->p_refcount++;
#if PROC_REF_DEBUG
		record_procref(p, 1);
#endif
	}
	else 
		p1 = PROC_NULL;

	return(p1);
}

void
proc_rele_locked(proc_t p)
{

	if (p->p_refcount > 0) {
		p->p_refcount--;
#if PROC_REF_DEBUG
		record_procref(p, -1);
#endif
		if ((p->p_refcount == 0) && ((p->p_listflag & P_LIST_DRAINWAIT) == P_LIST_DRAINWAIT)) {
			p->p_listflag &= ~P_LIST_DRAINWAIT;
			wakeup(&p->p_refcount);
		}
	} else
		panic("proc_rele_locked  -ve ref\n");

}

proc_t
proc_find_zombref(int pid)
{
	proc_t p;

	proc_list_lock();

 again:
	p = pfind_locked(pid);

	/* should we bail? */
	if ((p == PROC_NULL)					/* not found */
	    || ((p->p_listflag & P_LIST_INCREATE) != 0)		/* not created yet */
	    || ((p->p_listflag & P_LIST_EXITED) == 0)) {	/* not started exit */

		proc_list_unlock();
		return (PROC_NULL);
	}

	/* If someone else is controlling the (unreaped) zombie - wait */
	if ((p->p_listflag & P_LIST_WAITING) != 0) {
		(void)msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
		goto again;
	}
	p->p_listflag |=  P_LIST_WAITING;

	proc_list_unlock();

	return(p);
}

void
proc_drop_zombref(proc_t p)
{
	proc_list_lock();
	if ((p->p_listflag & P_LIST_WAITING) ==  P_LIST_WAITING) {
		p->p_listflag &= ~P_LIST_WAITING;
		wakeup(&p->p_stat);
	}
	proc_list_unlock();
}


void
proc_refdrain(proc_t p)
{

	proc_list_lock();

	p->p_listflag |= P_LIST_DRAIN;
	while (p->p_refcount) {
		p->p_listflag |= P_LIST_DRAINWAIT;
		msleep(&p->p_refcount, proc_list_mlock, 0, "proc_refdrain", 0) ;
	}
	p->p_listflag &= ~P_LIST_DRAIN;
	p->p_listflag |= P_LIST_DEAD;

	proc_list_unlock();


}

proc_t 
proc_parentholdref(proc_t p)
{
	proc_t parent = PROC_NULL;
	proc_t pp;
	int loopcnt = 0;


	proc_list_lock();
loop:
	pp = p->p_pptr;
	if ((pp == PROC_NULL) || (pp->p_stat == SZOMB) || ((pp->p_listflag & (P_LIST_CHILDDRSTART | P_LIST_CHILDDRAINED)) == (P_LIST_CHILDDRSTART | P_LIST_CHILDDRAINED))) {
		parent = PROC_NULL;
		goto out;
	}
		
	if ((pp->p_listflag & (P_LIST_CHILDDRSTART | P_LIST_CHILDDRAINED)) == P_LIST_CHILDDRSTART) {
		pp->p_listflag |= P_LIST_CHILDDRWAIT;
		msleep(&pp->p_childrencnt, proc_list_mlock, 0, "proc_parent", 0);
		loopcnt++;
		if (loopcnt == 5) {
			parent = PROC_NULL;
			goto out;
		}
		goto loop;
	}

	if ((pp->p_listflag & (P_LIST_CHILDDRSTART | P_LIST_CHILDDRAINED)) == 0) {
		pp->p_parentref++;
		parent = pp;
		goto out;
	}
	
out:
	proc_list_unlock();
	return(parent);
}
int 
proc_parentdropref(proc_t p, int listlocked)
{
	if (listlocked == 0)
		proc_list_lock();

	if (p->p_parentref > 0) {
		p->p_parentref--;
		if ((p->p_parentref == 0) && ((p->p_listflag & P_LIST_PARENTREFWAIT) == P_LIST_PARENTREFWAIT)) {
			p->p_listflag &= ~P_LIST_PARENTREFWAIT;
			wakeup(&p->p_parentref);
		}
	} else
		panic("proc_parentdropref  -ve ref\n");
	if (listlocked == 0)
		proc_list_unlock();

	return(0);
}

void
proc_childdrainstart(proc_t p)
{
#if __PROC_INTERNAL_DEBUG
	if ((p->p_listflag & P_LIST_CHILDDRSTART) == P_LIST_CHILDDRSTART)
		panic("proc_childdrainstart: childdrain already started\n");
#endif
	p->p_listflag |= P_LIST_CHILDDRSTART;
	/* wait for all that hold parentrefs to drop */
	while (p->p_parentref > 0) {
		p->p_listflag |= P_LIST_PARENTREFWAIT;
		msleep(&p->p_parentref, proc_list_mlock, 0, "proc_childdrainstart", 0) ;
	}
}


void
proc_childdrainend(proc_t p)
{
#if __PROC_INTERNAL_DEBUG
	if (p->p_childrencnt > 0)
		panic("exiting: children stil hanging around\n");
#endif
	p->p_listflag |= P_LIST_CHILDDRAINED;
	if ((p->p_listflag & (P_LIST_CHILDLKWAIT |P_LIST_CHILDDRWAIT)) != 0) {
		p->p_listflag &= ~(P_LIST_CHILDLKWAIT |P_LIST_CHILDDRWAIT);
		wakeup(&p->p_childrencnt);
	}
}

void
proc_checkdeadrefs(__unused proc_t p)
{
#if __PROC_INTERNAL_DEBUG
	if ((p->p_listflag  & P_LIST_INHASH) != 0)
		panic("proc being freed and still in hash %p: %u\n", p, p->p_listflag);
	if (p->p_childrencnt != 0)
		panic("proc being freed and pending children cnt %p:%d\n", p, p->p_childrencnt);
	if (p->p_refcount != 0)
		panic("proc being freed and pending refcount %p:%d\n", p, p->p_refcount);
	if (p->p_parentref != 0)
		panic("proc being freed and pending parentrefs %p:%d\n", p, p->p_parentref);
#endif
}

int
proc_pid(proc_t p)
{
	if (p != NULL)
		return (p->p_pid);
	return -1;
}

int
proc_ppid(proc_t p)
{
	if (p != NULL)
		return (p->p_ppid);
	return -1;
}

int
proc_selfpid(void)
{
	return (current_proc()->p_pid);
}

int
proc_selfppid(void)
{
	return (current_proc()->p_ppid);
}

int
proc_selfcsflags(void)
{
	return (current_proc()->p_csflags);
}

#if CONFIG_DTRACE
static proc_t
dtrace_current_proc_vforking(void)
{
	thread_t th = current_thread();
	struct uthread *ut = get_bsdthread_info(th);

	if (ut &&
	    ((ut->uu_flag & (UT_VFORK|UT_VFORKING)) == (UT_VFORK|UT_VFORKING))) {
		/*
		 * Handle the narrow window where we're in the vfork syscall,
		 * but we're not quite ready to claim (in particular, to DTrace)
		 * that we're running as the child.
		 */
		return (get_bsdtask_info(get_threadtask(th)));
	}
	return (current_proc());
}

int
dtrace_proc_selfpid(void)
{
	return (dtrace_current_proc_vforking()->p_pid);
}

int 
dtrace_proc_selfppid(void)
{
	return (dtrace_current_proc_vforking()->p_ppid);
}

uid_t
dtrace_proc_selfruid(void)
{
	return (dtrace_current_proc_vforking()->p_ruid);
}
#endif /* CONFIG_DTRACE */

proc_t 
proc_parent(proc_t p)
{
	proc_t parent;
	proc_t pp;

	proc_list_lock();
loop:
	pp = p->p_pptr;
	parent =  proc_ref_locked(pp);
	if ((parent == PROC_NULL) && (pp != PROC_NULL) && (pp->p_stat != SZOMB) && ((pp->p_listflag & P_LIST_EXITED) != 0) && ((pp->p_listflag & P_LIST_CHILDDRAINED)== 0)){
		pp->p_listflag |= P_LIST_CHILDLKWAIT;
		msleep(&pp->p_childrencnt, proc_list_mlock, 0, "proc_parent", 0);
		goto loop;
	}
	proc_list_unlock();
	return(parent);
}

static boolean_t
proc_parent_is_currentproc(proc_t p)
{
	boolean_t ret = FALSE;
	
	proc_list_lock();
	if (p->p_pptr == current_proc())
		ret = TRUE;

	proc_list_unlock();
	return ret;
}

void
proc_name(int pid, char * buf, int size)
{
	proc_t p;

	if ((p = proc_find(pid)) != PROC_NULL) {
		strlcpy(buf, &p->p_comm[0], size);
		proc_rele(p);
	}
}

void
proc_name_kdp(task_t t, char * buf, int size)
{
	proc_t p = get_bsdtask_info(t);
	if (p == PROC_NULL)
		return;

	if ((size_t)size > sizeof(p->p_comm))
		strlcpy(buf, &p->p_name[0], MIN((int)sizeof(p->p_name), size));
	else
		strlcpy(buf, &p->p_comm[0], MIN((int)sizeof(p->p_comm), size));
}


int
proc_threadname_kdp(void *uth, char *buf, size_t size)
{
	if (size < MAXTHREADNAMESIZE) {
		/* this is really just a protective measure for the future in
		 * case the thread name size in stackshot gets out of sync with
		 * the BSD max thread name size. Note that bsd_getthreadname
		 * doesn't take input buffer size into account. */
		return -1;
	}

	if (uth != NULL) {
		bsd_getthreadname(uth, buf);
	}
	return 0;
}

/* note that this function is generally going to be called from stackshot,
 * and the arguments will be coming from a struct which is declared packed
 * thus the input arguments will in general be unaligned. We have to handle
 * that here. */
void
proc_starttime_kdp(void *p, uint64_t *tv_sec, uint64_t *tv_usec)
{
	proc_t pp = (proc_t)p;
	struct uint64p {
		uint64_t val;
	} __attribute__((packed));

	if (pp != PROC_NULL) {
		if (tv_sec != NULL)
			((struct uint64p *)tv_sec)->val = pp->p_start.tv_sec;
		if (tv_usec != NULL)
			((struct uint64p *)tv_usec)->val = pp->p_start.tv_usec;
	}
}

char *
proc_name_address(void *p)
{
	return &((proc_t)p)->p_comm[0];
}

void
proc_selfname(char * buf, int  size)
{
	proc_t p;

	if ((p = current_proc())!= (proc_t)0) {
		strlcpy(buf, &p->p_comm[0], size);
	}
}

void
proc_signal(int pid, int signum)
{
	proc_t p;

	if ((p = proc_find(pid)) != PROC_NULL) {
			psignal(p, signum);
			proc_rele(p);
	}	
}

int
proc_issignal(int pid, sigset_t mask)
{
	proc_t p;
	int error=0;

	if ((p = proc_find(pid)) != PROC_NULL) {
		error = proc_pendingsignals(p, mask);
		proc_rele(p);
	}	

	return(error);
}

int
proc_noremotehang(proc_t p)
{
	int retval = 0;

	if (p)
		retval = p->p_flag & P_NOREMOTEHANG;
	return(retval? 1: 0);

}

int
proc_exiting(proc_t p)
{
	int retval = 0;

	if (p)
		retval = p->p_lflag & P_LEXIT;
	return(retval? 1: 0);
}

int
proc_forcequota(proc_t p)
{
	int retval = 0;

	if (p)
		retval = p->p_flag & P_FORCEQUOTA;
	return(retval? 1: 0);

}

int
proc_suser(proc_t p)
{
	kauth_cred_t my_cred;
	int error;

	my_cred = kauth_cred_proc_ref(p);
	error = suser(my_cred, &p->p_acflag);
	kauth_cred_unref(&my_cred);
	return(error);
}

task_t
proc_task(proc_t proc)
{
	return (task_t)proc->task;
}

/*      
 * Obtain the first thread in a process
 *
 * XXX This is a bad thing to do; it exists predominantly to support the
 * XXX use of proc_t's in places that should really be using
 * XXX thread_t's instead.  This maintains historical behaviour, but really
 * XXX needs an audit of the context (proxy vs. not) to clean up.
 */
thread_t
proc_thread(proc_t proc)                                                
{           
        uthread_t uth = TAILQ_FIRST(&proc->p_uthlist);

        if (uth != NULL)
                return(uth->uu_context.vc_thread);

	return(NULL);
}       

kauth_cred_t
proc_ucred(proc_t p)
{
	return(p->p_ucred);
}

struct uthread *
current_uthread()
{
	thread_t th = current_thread();

	return((struct uthread *)get_bsdthread_info(th));
}


int
proc_is64bit(proc_t p)
{
	return(IS_64BIT_PROCESS(p));
}

int
proc_pidversion(proc_t p)
{
	return(p->p_idversion);
}

uint32_t
proc_persona_id(proc_t p)
{
	return (uint32_t)persona_id_from_proc(p);
}

uint32_t
proc_getuid(proc_t p)
{
	return(p->p_uid);
}

uint32_t
proc_getgid(proc_t p)
{
	return(p->p_gid);
}

uint64_t
proc_uniqueid(proc_t p)
{
	return(p->p_uniqueid);
}

uint64_t
proc_puniqueid(proc_t p)
{
	return(p->p_puniqueid);
}

void
proc_coalitionids(__unused proc_t p, __unused uint64_t ids[COALITION_NUM_TYPES])
{
#if CONFIG_COALITIONS
	task_coalition_ids(p->task, ids);
#else
	memset(ids, 0, sizeof(uint64_t [COALITION_NUM_TYPES]));
#endif
	return;
}

uint64_t
proc_was_throttled(proc_t p)
{
	return (p->was_throttled);
}

uint64_t
proc_did_throttle(proc_t p)
{
	return (p->did_throttle);
}

int
proc_getcdhash(proc_t p, unsigned char *cdhash)
{
	return vn_getcdhash(p->p_textvp, p->p_textoff, cdhash);
}

void
proc_getexecutableuuid(proc_t p, unsigned char *uuidbuf, unsigned long size)
{
	if (size >= sizeof(p->p_uuid)) {
		memcpy(uuidbuf, p->p_uuid, sizeof(p->p_uuid));
	}
}

/* Return vnode for executable with an iocount. Must be released with vnode_put() */
vnode_t
proc_getexecutablevnode(proc_t p)
{
	vnode_t tvp  = p->p_textvp;

	if ( tvp != NULLVP) {
		if (vnode_getwithref(tvp) == 0) {
			return tvp;
		}
	}       

	return NULLVP;
}


void
bsd_set_dependency_capable(task_t task)
{
    proc_t p = get_bsdtask_info(task);

    if (p) {
	OSBitOrAtomic(P_DEPENDENCY_CAPABLE, &p->p_flag);
    }
}


int
IS_64BIT_PROCESS(proc_t p)
{
	if (p && (p->p_flag & P_LP64))
		return(1);
	else
		return(0);
}

/*
 * Locate a process by number
 */
proc_t
pfind_locked(pid_t pid)
{
	proc_t p;
#if DEBUG
	proc_t q;
#endif

	if (!pid)
		return (kernproc);

	for (p = PIDHASH(pid)->lh_first; p != 0; p = p->p_hash.le_next) {
		if (p->p_pid == pid) {
#if DEBUG
			for (q = p->p_hash.le_next; q != 0; q = q->p_hash.le_next) {
				if ((p !=q) && (q->p_pid == pid))	
					panic("two procs with same pid %p:%p:%d:%d\n", p, q, p->p_pid, q->p_pid);
			}
#endif
			return (p);
		}
	}
	return (NULL);
}

/*
 * Locate a zombie by PID
 */
__private_extern__ proc_t
pzfind(pid_t pid)
{
	proc_t p;


	proc_list_lock();

	for (p = zombproc.lh_first; p != 0; p = p->p_list.le_next)
		if (p->p_pid == pid)
			break;

	proc_list_unlock();

	return (p);
}

/*
 * Locate a process group by number
 */

struct pgrp *
pgfind(pid_t pgid)
{
	struct pgrp * pgrp;

	proc_list_lock();
	pgrp = pgfind_internal(pgid);
	if ((pgrp == NULL) || ((pgrp->pg_listflags & PGRP_FLAG_TERMINATE) != 0))
		pgrp = PGRP_NULL;
	else
		pgrp->pg_refcount++;
	proc_list_unlock();
	return(pgrp);
}



struct pgrp *
pgfind_internal(pid_t pgid)
{
	struct pgrp *pgrp;

	for (pgrp = PGRPHASH(pgid)->lh_first; pgrp != 0; pgrp = pgrp->pg_hash.le_next)
		if (pgrp->pg_id == pgid)
			return (pgrp);
	return (NULL);
}

void
pg_rele(struct pgrp * pgrp)
{
	if(pgrp == PGRP_NULL)
		return;
	pg_rele_dropref(pgrp);
}

void
pg_rele_dropref(struct pgrp * pgrp)
{
	proc_list_lock();
	if ((pgrp->pg_refcount == 1) && ((pgrp->pg_listflags & PGRP_FLAG_TERMINATE) == PGRP_FLAG_TERMINATE)) {
		proc_list_unlock();
		pgdelete_dropref(pgrp);
		return;
	}

	pgrp->pg_refcount--;
	proc_list_unlock();
}

struct session *
session_find_internal(pid_t sessid)
{
	struct session *sess;

	for (sess = SESSHASH(sessid)->lh_first; sess != 0; sess = sess->s_hash.le_next)
		if (sess->s_sid == sessid)
			return (sess);
	return (NULL);
}


/*
 * Make a new process ready to become a useful member of society by making it
 * visible in all the right places and initialize its own lists to empty.
 *
 * Parameters:	parent			The parent of the process to insert
 *		child			The child process to insert
 *
 * Returns:	(void)
 *
 * Notes:	Insert a child process into the parents process group, assign
 *		the child the parent process pointer and PPID of the parent,
 *		place it on the parents p_children list as a sibling,
 *		initialize its own child list, place it in the allproc list,
 *		insert it in the proper hash bucket, and initialize its
 *		event list.
 */
void
pinsertchild(proc_t parent, proc_t child)
{
	struct pgrp * pg;

	LIST_INIT(&child->p_children);
	TAILQ_INIT(&child->p_evlist);
	child->p_pptr = parent;
	child->p_ppid = parent->p_pid;
	child->p_puniqueid = parent->p_uniqueid;

	pg = proc_pgrp(parent);
	pgrp_add(pg, parent, child);
	pg_rele(pg);

	proc_list_lock();
	
#if CONFIG_MEMORYSTATUS
	memorystatus_add(child, TRUE);
#endif
	
	parent->p_childrencnt++;
	LIST_INSERT_HEAD(&parent->p_children, child, p_sibling);

	LIST_INSERT_HEAD(&allproc, child, p_list);
	/* mark the completion of proc creation */
	child->p_listflag &= ~P_LIST_INCREATE;

	proc_list_unlock();
}

/*
 * Move p to a new or existing process group (and session)
 *
 * Returns:	0			Success
 *		ESRCH			No such process
 */
int
enterpgrp(proc_t p, pid_t pgid, int mksess)
{
	struct pgrp *pgrp;
	struct pgrp *mypgrp;
	struct session * procsp;

	pgrp = pgfind(pgid);
	mypgrp = proc_pgrp(p);
	procsp = proc_session(p);

#if DIAGNOSTIC
	if (pgrp != NULL && mksess)	/* firewalls */
		panic("enterpgrp: setsid into non-empty pgrp");
	if (SESS_LEADER(p, procsp))
		panic("enterpgrp: session leader attempted setpgrp");
#endif
	if (pgrp == PGRP_NULL) {
		pid_t savepid = p->p_pid;
		proc_t np = PROC_NULL;
		/*
		 * new process group
		 */
#if DIAGNOSTIC
		if (p->p_pid != pgid)
			panic("enterpgrp: new pgrp and pid != pgid");
#endif
		MALLOC_ZONE(pgrp, struct pgrp *, sizeof(struct pgrp), M_PGRP,
		    M_WAITOK);
		if (pgrp == NULL)
			panic("enterpgrp: M_PGRP zone depleted");
		if ((np = proc_find(savepid)) == NULL || np != p) {
			if (np != PROC_NULL)
				proc_rele(np);
			if (mypgrp != PGRP_NULL)
				pg_rele(mypgrp);
			if (procsp != SESSION_NULL)
				session_rele(procsp);
			FREE_ZONE(pgrp, sizeof(struct pgrp), M_PGRP);
			return (ESRCH);
		}
		proc_rele(np);
		if (mksess) {
			struct session *sess;

			/*
			 * new session
			 */
			MALLOC_ZONE(sess, struct session *,
				sizeof(struct session), M_SESSION, M_WAITOK);
			if (sess == NULL)
				panic("enterpgrp: M_SESSION zone depleted");
			sess->s_leader = p;
			sess->s_sid = p->p_pid;
			sess->s_count = 1;
			sess->s_ttyvp = NULL;
			sess->s_ttyp = TTY_NULL;
			sess->s_flags = 0;
			sess->s_listflags = 0;
			sess->s_ttypgrpid = NO_PID;
#if CONFIG_FINE_LOCK_GROUPS
			lck_mtx_init(&sess->s_mlock, proc_mlock_grp, proc_lck_attr);
#else
			lck_mtx_init(&sess->s_mlock, proc_lck_grp, proc_lck_attr);
#endif
			bcopy(procsp->s_login, sess->s_login,
			    sizeof(sess->s_login));
			OSBitAndAtomic(~((uint32_t)P_CONTROLT), &p->p_flag);
			proc_list_lock();
			LIST_INSERT_HEAD(SESSHASH(sess->s_sid), sess, s_hash);
			proc_list_unlock();
			pgrp->pg_session = sess;
#if DIAGNOSTIC
			if (p != current_proc())
				panic("enterpgrp: mksession and p != curproc");
#endif
		} else {
			proc_list_lock();
			pgrp->pg_session = procsp;
			
			if ((pgrp->pg_session->s_listflags & (S_LIST_TERM | S_LIST_DEAD)) != 0)
				panic("enterpgrp:  providing ref to terminating session ");	
			pgrp->pg_session->s_count++;
			proc_list_unlock();
		}
		pgrp->pg_id = pgid;
#if CONFIG_FINE_LOCK_GROUPS
		lck_mtx_init(&pgrp->pg_mlock, proc_mlock_grp, proc_lck_attr);
#else
		lck_mtx_init(&pgrp->pg_mlock, proc_lck_grp, proc_lck_attr);
#endif
		LIST_INIT(&pgrp->pg_members);
		pgrp->pg_membercnt = 0;
		pgrp->pg_jobc = 0;
		proc_list_lock();
		pgrp->pg_refcount = 1;
		pgrp->pg_listflags = 0;
		LIST_INSERT_HEAD(PGRPHASH(pgid), pgrp, pg_hash);
		proc_list_unlock();
	} else if (pgrp == mypgrp) {
		pg_rele(pgrp);
		if (mypgrp != NULL)
			pg_rele(mypgrp);
		if (procsp != SESSION_NULL)
			session_rele(procsp);
		return (0);
	}

	if (procsp != SESSION_NULL)
		session_rele(procsp);
	/*
	 * Adjust eligibility of affected pgrps to participate in job control.
	 * Increment eligibility counts before decrementing, otherwise we
	 * could reach 0 spuriously during the first call.
	 */
	fixjobc(p, pgrp, 1);
	fixjobc(p, mypgrp, 0);

	if(mypgrp != PGRP_NULL)
		pg_rele(mypgrp);
	pgrp_replace(p, pgrp);
	pg_rele(pgrp);

	return(0);
}

/*
 * remove process from process group
 */
int
leavepgrp(proc_t p)
{

	pgrp_remove(p);
	return (0);
}

/*
 * delete a process group
 */
static void
pgdelete_dropref(struct pgrp *pgrp)
{
	struct tty *ttyp;
	int emptypgrp  = 1;
	struct session *sessp;


	pgrp_lock(pgrp);
	if (pgrp->pg_membercnt != 0) {
		emptypgrp = 0;
	}
	pgrp_unlock(pgrp);

	proc_list_lock();
	pgrp->pg_refcount--;
	if ((emptypgrp == 0) || (pgrp->pg_membercnt != 0)) {
		proc_list_unlock();
		return;
	}

	pgrp->pg_listflags |= PGRP_FLAG_TERMINATE;
	
	if (pgrp->pg_refcount > 0) {
		proc_list_unlock();
		return;
	}

	pgrp->pg_listflags |= PGRP_FLAG_DEAD;
	LIST_REMOVE(pgrp, pg_hash);

	proc_list_unlock();
	
	ttyp = SESSION_TP(pgrp->pg_session);
	if (ttyp != TTY_NULL) {
		if (ttyp->t_pgrp == pgrp) {
			tty_lock(ttyp);
			/* Re-check after acquiring the lock */
			if (ttyp->t_pgrp == pgrp) {
				ttyp->t_pgrp = NULL;
				pgrp->pg_session->s_ttypgrpid = NO_PID;
			}
			tty_unlock(ttyp);
		}
	}

	proc_list_lock();

	sessp = pgrp->pg_session;
	if ((sessp->s_listflags & (S_LIST_TERM | S_LIST_DEAD)) != 0)
			panic("pg_deleteref: manipulating refs of already terminating session");
	if (--sessp->s_count == 0) {
		if ((sessp->s_listflags & (S_LIST_TERM | S_LIST_DEAD)) != 0)
			panic("pg_deleteref: terminating already terminated session");
		sessp->s_listflags |= S_LIST_TERM;
		ttyp = SESSION_TP(sessp);
		LIST_REMOVE(sessp, s_hash);
		proc_list_unlock();
		if (ttyp != TTY_NULL) {
			tty_lock(ttyp);
			if (ttyp->t_session == sessp)
				ttyp->t_session = NULL;
			tty_unlock(ttyp);
		}
		proc_list_lock();
		sessp->s_listflags |= S_LIST_DEAD;
		if (sessp->s_count != 0)
			panic("pg_deleteref: freeing session in use");	
		proc_list_unlock();
#if CONFIG_FINE_LOCK_GROUPS
		lck_mtx_destroy(&sessp->s_mlock, proc_mlock_grp);
#else
		lck_mtx_destroy(&sessp->s_mlock, proc_lck_grp);
#endif
		FREE_ZONE(sessp, sizeof(struct session), M_SESSION);
	} else
		proc_list_unlock();
#if CONFIG_FINE_LOCK_GROUPS
	lck_mtx_destroy(&pgrp->pg_mlock, proc_mlock_grp);
#else
	lck_mtx_destroy(&pgrp->pg_mlock, proc_lck_grp);
#endif
	FREE_ZONE(pgrp, sizeof(*pgrp), M_PGRP);
}


/*
 * Adjust pgrp jobc counters when specified process changes process group.
 * We count the number of processes in each process group that "qualify"
 * the group for terminal job control (those with a parent in a different
 * process group of the same session).  If that count reaches zero, the
 * process group becomes orphaned.  Check both the specified process'
 * process group and that of its children.
 * entering == 0 => p is leaving specified group.
 * entering == 1 => p is entering specified group.
 */
int
fixjob_callback(proc_t p, void * arg)
{
	struct fixjob_iterargs *fp;
	struct pgrp * pg, *hispg;
	struct session * mysession, *hissess;
	int entering;

	fp = (struct fixjob_iterargs *)arg;
	pg = fp->pg;
	mysession = fp->mysession;
	entering = fp->entering;

	hispg = proc_pgrp(p);
	hissess = proc_session(p);

	if ((hispg  != pg) &&
	    (hissess == mysession)) {
		pgrp_lock(hispg);
		if (entering) {
			hispg->pg_jobc++;
			pgrp_unlock(hispg);
		} else if (--hispg->pg_jobc == 0) {
			pgrp_unlock(hispg);
			orphanpg(hispg);
		} else
			pgrp_unlock(hispg);
	}
	if (hissess != SESSION_NULL)
		session_rele(hissess);
	if (hispg != PGRP_NULL)
		pg_rele(hispg);

	return(PROC_RETURNED);
}

void
fixjobc(proc_t p, struct pgrp *pgrp, int entering)
{
	struct pgrp *hispgrp = PGRP_NULL;
	struct session *hissess = SESSION_NULL;
	struct session *mysession = pgrp->pg_session;
	proc_t parent;
	struct fixjob_iterargs fjarg;
	boolean_t proc_parent_self;

	/*
	 * Check if p's parent is current proc, if yes then no need to take 
	 * a ref; calling proc_parent with current proc as parent may 
	 * deadlock if current proc is exiting.
	 */
	proc_parent_self = proc_parent_is_currentproc(p);
	if (proc_parent_self)
		parent = current_proc();
	else 
		parent = proc_parent(p);

	if (parent != PROC_NULL) {
		hispgrp = proc_pgrp(parent);	
		hissess = proc_session(parent);
		if (!proc_parent_self)
			proc_rele(parent);
	}


	/*
	 * Check p's parent to see whether p qualifies its own process
	 * group; if so, adjust count for p's process group.
	 */
	if ((hispgrp != pgrp) &&
	    (hissess == mysession)) {
		pgrp_lock(pgrp);
		if (entering) {
			pgrp->pg_jobc++;
			pgrp_unlock(pgrp);
		 }else if (--pgrp->pg_jobc == 0) {
			pgrp_unlock(pgrp);
			orphanpg(pgrp);
		} else
			pgrp_unlock(pgrp);
	}

	if (hissess != SESSION_NULL)
		session_rele(hissess);
	if (hispgrp != PGRP_NULL)
		pg_rele(hispgrp);

	/*
	 * Check this process' children to see whether they qualify
	 * their process groups; if so, adjust counts for children's
	 * process groups.
	 */
	fjarg.pg = pgrp;
	fjarg.mysession = mysession;
	fjarg.entering = entering;
	proc_childrenwalk(p, fixjob_callback, &fjarg);
}

/* 
 * A process group has become orphaned;
 * if there are any stopped processes in the group,
 * hang-up all process in that group.
 */
static void
orphanpg(struct pgrp * pgrp)
{
	proc_t p;
	pid_t * pid_list;
	int count, pidcount, i, alloc_count;

	if (pgrp == PGRP_NULL)
		return;
	count = 0;
	pgrp_lock(pgrp);
	for (p = pgrp->pg_members.lh_first; p != 0; p = p->p_pglist.le_next) {
		if (p->p_stat == SSTOP) {
			for (p = pgrp->pg_members.lh_first; p != 0;
				p = p->p_pglist.le_next) 
				count++;
			break;	/* ??? stops after finding one.. */
		}
	}
	pgrp_unlock(pgrp);

	count += 20;
	if (count > hard_maxproc)
		count = hard_maxproc;
	alloc_count = count * sizeof(pid_t);
	pid_list = (pid_t *)kalloc(alloc_count);
	bzero(pid_list, alloc_count);
	
	pidcount = 0;
	pgrp_lock(pgrp);
	for (p = pgrp->pg_members.lh_first; p != 0;
	     p = p->p_pglist.le_next) {
		if (p->p_stat == SSTOP) {
			for (p = pgrp->pg_members.lh_first; p != 0;
				p = p->p_pglist.le_next) {
				pid_list[pidcount] = p->p_pid;
				pidcount++;
				if (pidcount >= count)
					break;
			}
			break; /* ??? stops after finding one.. */
		}
	}
	pgrp_unlock(pgrp);
		
	if (pidcount == 0)
		goto out;


	for (i = 0; i< pidcount; i++) {
		/* No handling or proc0 */
		if (pid_list[i] == 0)
			continue;
		p = proc_find(pid_list[i]);
		if (p) {
			proc_transwait(p, 0);
			pt_setrunnable(p);
			psignal(p, SIGHUP);
			psignal(p, SIGCONT);
			proc_rele(p);
		}
	}
out:
	kfree(pid_list, alloc_count);
	return;
}

int
proc_is_classic(proc_t p __unused)
{
    return (0);
}

/* XXX Why does this function exist?  Need to kill it off... */
proc_t
current_proc_EXTERNAL(void)
{
	return (current_proc());
}

int
proc_is_forcing_hfs_case_sensitivity(proc_t p)
{
	return (p->p_vfs_iopolicy & P_VFS_IOPOLICY_FORCE_HFS_CASE_SENSITIVITY) ? 1 : 0;
}

/*
 * proc_core_name(name, uid, pid)
 * Expand the name described in corefilename, using name, uid, and pid.
 * corefilename is a printf-like string, with three format specifiers:
 *	%N	name of process ("name")
 *	%P	process id (pid)
 *	%U	user id (uid)
 * For example, "%N.core" is the default; they can be disabled completely
 * by using "/dev/null", or all core files can be stored in "/cores/%U/%N-%P".
 * This is controlled by the sysctl variable kern.corefile (see above).
 */
__private_extern__ int
proc_core_name(const char *name, uid_t uid, pid_t pid, char *cf_name,
		size_t cf_name_len)
{
	const char *format, *appendstr;
	char id_buf[11];		/* Buffer for pid/uid -- max 4B */
	size_t i, l, n;

	if (cf_name == NULL)
		goto toolong;

	format = corefilename;
	for (i = 0, n = 0; n < cf_name_len && format[i]; i++) {
		switch (format[i]) {
		case '%':	/* Format character */
			i++;
			switch (format[i]) {
			case '%':
				appendstr = "%";
				break;
			case 'N':	/* process name */
				appendstr = name;
				break;
			case 'P':	/* process id */
				snprintf(id_buf, sizeof(id_buf), "%u", pid);
				appendstr = id_buf;
				break;
			case 'U':	/* user id */
				snprintf(id_buf, sizeof(id_buf), "%u", uid);
				appendstr = id_buf;
				break;
			default:
				appendstr = "";
			  	log(LOG_ERR,
				    "Unknown format character %c in `%s'\n",
				    format[i], format);
			}
			l = strlen(appendstr);
			if ((n + l) >= cf_name_len)
				goto toolong;
			bcopy(appendstr, cf_name + n, l);
			n += l;
			break;
		default:
			cf_name[n++] = format[i];
		}
	}
	if (format[i] != '\0')
		goto toolong;
	return (0);
toolong:
	log(LOG_ERR, "pid %ld (%s), uid (%u): corename is too long\n",
	    (long)pid, name, (uint32_t)uid);
	return (1);
}

/* Code Signing related routines */

int 
csops(__unused proc_t p, struct csops_args *uap, __unused int32_t *retval)
{
	return(csops_internal(uap->pid, uap->ops, uap->useraddr, 
		uap->usersize, USER_ADDR_NULL));
}

int 
csops_audittoken(__unused proc_t p, struct csops_audittoken_args *uap, __unused int32_t *retval)
{
	if (uap->uaudittoken == USER_ADDR_NULL)
		return(EINVAL);
	return(csops_internal(uap->pid, uap->ops, uap->useraddr, 
		uap->usersize, uap->uaudittoken));
}

static int
csops_copy_token(void *start, size_t length, user_size_t usize, user_addr_t uaddr)
{
	char fakeheader[8] = { 0 };
	int error;

	if (usize < sizeof(fakeheader))
		return ERANGE;

	/* if no blob, fill in zero header */
	if (NULL == start) {
		start = fakeheader;
		length = sizeof(fakeheader);
	} else if (usize < length) {
		/* ... if input too short, copy out length of entitlement */
		uint32_t length32 = htonl((uint32_t)length);
		memcpy(&fakeheader[4], &length32, sizeof(length32));
		
		error = copyout(fakeheader, uaddr, sizeof(fakeheader));
		if (error == 0)
			return ERANGE; /* input buffer to short, ERANGE signals that */
		return error;
	}
	return copyout(start, uaddr, length);
}

static int
csops_internal(pid_t pid, int ops, user_addr_t uaddr, user_size_t usersize, user_addr_t uaudittoken)
{
	size_t usize = (size_t)CAST_DOWN(size_t, usersize);
	proc_t pt;
	int forself;
	int error;
	vnode_t tvp;
	off_t toff;
	unsigned char cdhash[SHA1_RESULTLEN];
	audit_token_t token;
	unsigned int upid=0, uidversion = 0;
	
	forself = error = 0;

	if (pid == 0) 
		pid = proc_selfpid();
	if (pid == proc_selfpid())
		forself = 1;


	switch (ops) {
		case CS_OPS_STATUS:
		case CS_OPS_CDHASH:
		case CS_OPS_PIDOFFSET:
		case CS_OPS_ENTITLEMENTS_BLOB:
		case CS_OPS_IDENTITY:
		case CS_OPS_BLOB:
			break;	/* not restricted to root */
		default:
			if (forself == 0 && kauth_cred_issuser(kauth_cred_get()) != TRUE)
				return(EPERM);
			break;
	}

	pt = proc_find(pid);
	if (pt == PROC_NULL)
		return(ESRCH);

	upid = pt->p_pid;
	uidversion = pt->p_idversion;
	if (uaudittoken != USER_ADDR_NULL) {
		
		error = copyin(uaudittoken, &token, sizeof(audit_token_t));
		if (error != 0)
			goto out;
		/* verify the audit token pid/idversion matches with proc */
		if ((token.val[5] != upid) || (token.val[7] != uidversion)) {
			error = ESRCH;
			goto out;
		}
	}

#if CONFIG_MACF
	switch (ops) {
		case CS_OPS_MARKINVALID:
		case CS_OPS_MARKHARD:
		case CS_OPS_MARKKILL:
		case CS_OPS_MARKRESTRICT:
		case CS_OPS_SET_STATUS:
			if ((error = mac_proc_check_set_cs_info(current_proc(), pt, ops)))
				goto out;
			break;
		default:
			if ((error = mac_proc_check_get_cs_info(current_proc(), pt, ops)))
				goto out;
	}
#endif

	switch (ops) {

		case CS_OPS_STATUS: {
			uint32_t retflags;

			proc_lock(pt);
			retflags = pt->p_csflags;
			if (cs_enforcement(pt))
				retflags |= CS_ENFORCEMENT;
			if (csproc_get_platform_binary(pt))
				retflags |= CS_PLATFORM_BINARY;
			proc_unlock(pt);

			if (uaddr != USER_ADDR_NULL)
				error = copyout(&retflags, uaddr, sizeof(uint32_t));
			break;
		}
		case CS_OPS_MARKINVALID:
			proc_lock(pt);
			if ((pt->p_csflags & CS_VALID) == CS_VALID) {	/* is currently valid */
				pt->p_csflags &= ~CS_VALID;	/* set invalid */
				if ((pt->p_csflags & CS_KILL) == CS_KILL) {
					pt->p_csflags |= CS_KILLED;
					proc_unlock(pt);
					if (cs_debug) {
						printf("CODE SIGNING: marked invalid by pid %d: "
			       			"p=%d[%s] honoring CS_KILL, final status 0x%x\n",
			       			proc_selfpid(), pt->p_pid, pt->p_comm, pt->p_csflags);
					}
					psignal(pt, SIGKILL);
				} else
					proc_unlock(pt);
			} else
				proc_unlock(pt);
				
			break;

		case CS_OPS_MARKHARD:
			proc_lock(pt);
			pt->p_csflags |= CS_HARD;
			if ((pt->p_csflags & CS_VALID) == 0) {
				/* @@@ allow? reject? kill? @@@ */
				proc_unlock(pt);
				error = EINVAL;
				goto out;
			} else
				proc_unlock(pt);
			break;

		case CS_OPS_MARKKILL:
			proc_lock(pt);
			pt->p_csflags |= CS_KILL;
			if ((pt->p_csflags & CS_VALID) == 0) {
				proc_unlock(pt);
				psignal(pt, SIGKILL);
			} else
				proc_unlock(pt);
			break;

		case CS_OPS_PIDOFFSET:
			toff = pt->p_textoff;
			proc_rele(pt);
			error = copyout(&toff, uaddr, sizeof(toff));
			return(error);

		case CS_OPS_CDHASH:

			/* pt already holds a reference on its p_textvp */
			tvp = pt->p_textvp;
			toff = pt->p_textoff;

			if (tvp == NULLVP || usize != SHA1_RESULTLEN) {
				proc_rele(pt);
				return EINVAL;
			}

			error = vn_getcdhash(tvp, toff, cdhash);
			proc_rele(pt);

			if (error == 0) {
				error = copyout(cdhash, uaddr, sizeof (cdhash));
			}

			return error;

		case CS_OPS_ENTITLEMENTS_BLOB: {
			void *start;
			size_t length;

			proc_lock(pt);

			if ((pt->p_csflags & (CS_VALID | CS_DEBUGGED)) == 0) {
				proc_unlock(pt);
				error = EINVAL;
				break;
			}

			error = cs_entitlements_blob_get(pt, &start, &length);
			proc_unlock(pt);
			if (error)
				break;

			error = csops_copy_token(start, length, usize, uaddr);
			break;
		}
		case CS_OPS_MARKRESTRICT:
			proc_lock(pt);
			pt->p_csflags |= CS_RESTRICT;
			proc_unlock(pt);
			break;

		case CS_OPS_SET_STATUS: {
			uint32_t flags;

			if (usize < sizeof(flags)) {
				error = ERANGE;
				break;
			}

			error = copyin(uaddr, &flags, sizeof(flags));
			if (error)
				break;

			/* only allow setting a subset of all code sign flags */
			flags &=
			    CS_HARD | CS_EXEC_SET_HARD |
			    CS_KILL | CS_EXEC_SET_KILL |
			    CS_RESTRICT |
			    CS_REQUIRE_LV |
			    CS_ENFORCEMENT | CS_EXEC_SET_ENFORCEMENT |
			    CS_ENTITLEMENTS_VALIDATED;

			proc_lock(pt);
			if (pt->p_csflags & CS_VALID)
				pt->p_csflags |= flags;
			else
				error = EINVAL;
			proc_unlock(pt);

			break;
		}
		case CS_OPS_BLOB: {
			void *start;
			size_t length;

			proc_lock(pt);
			if ((pt->p_csflags & (CS_VALID | CS_DEBUGGED)) == 0) {
				proc_unlock(pt);
				error = EINVAL;
				break;
			}

			error = cs_blob_get(pt, &start, &length);
			proc_unlock(pt);
			if (error)
				break;

			error = csops_copy_token(start, length, usize, uaddr);
			break;
		}
		case CS_OPS_IDENTITY: {
			const char *identity;
			uint8_t fakeheader[8];
			uint32_t idlen;
			size_t length;

			/*
			 * Make identity have a blob header to make it
			 * easier on userland to guess the identity
			 * length.
			 */
			if (usize < sizeof(fakeheader)) {
			    error = ERANGE;
			    break;
			}
			memset(fakeheader, 0, sizeof(fakeheader));

			proc_lock(pt);
			if ((pt->p_csflags & (CS_VALID | CS_DEBUGGED)) == 0) {
				proc_unlock(pt);
				error = EINVAL;
				break;
			}

			identity = cs_identity_get(pt);
			proc_unlock(pt);
			if (identity == NULL) {
				error = ENOENT;
				break;
			}
			
			length = strlen(identity) + 1; /* include NUL */
			idlen = htonl(length + sizeof(fakeheader));
			memcpy(&fakeheader[4], &idlen, sizeof(idlen));

			error = copyout(fakeheader, uaddr, sizeof(fakeheader));
			if (error)
				break;

			if (usize < sizeof(fakeheader) + length)
				error = ERANGE;
			else if (usize > sizeof(fakeheader))
				error = copyout(identity, uaddr + sizeof(fakeheader), length);

			break;
		}

		default:
			error = EINVAL;
			break;
	}
out:
	proc_rele(pt);
	return(error);
}

int
proc_iterate(flags, callout, arg, filterfn, filterarg)
	int flags;
	int (*callout)(proc_t, void *);
	void * arg;
	int (*filterfn)(proc_t, void *);
	void * filterarg;
{
	proc_t p;
	pid_t * pid_list;
	int count, pidcount, alloc_count, i, retval;

	count = nprocs+ 10;
	if (count > hard_maxproc)
		count = hard_maxproc;
	alloc_count = count * sizeof(pid_t);
	pid_list = (pid_t *)kalloc(alloc_count);
	bzero(pid_list, alloc_count);


	proc_list_lock();


	pidcount = 0;
	if (flags & PROC_ALLPROCLIST) {
		for (p = allproc.lh_first; (p != 0); p = p->p_list.le_next) {
			if (p->p_stat == SIDL)
				continue;
			if ( (filterfn == 0 ) || (filterfn(p, filterarg) != 0)) {
				pid_list[pidcount] = p->p_pid;
				pidcount++;
				if (pidcount >= count)
					break;
			}
		}
	}
	if ((pidcount <  count ) && (flags & PROC_ZOMBPROCLIST)) {
		for (p = zombproc.lh_first; p != 0; p = p->p_list.le_next) {
			if ( (filterfn == 0 ) || (filterfn(p, filterarg) != 0)) {
				pid_list[pidcount] = p->p_pid;
				pidcount++;
				if (pidcount >= count)
					break;
			}
		}
	}
		

	proc_list_unlock();


	for (i = 0; i< pidcount; i++) {
		p = proc_find(pid_list[i]);
		if (p) {
			if ((flags & PROC_NOWAITTRANS) == 0)
				proc_transwait(p, 0);
			retval = callout(p, arg);

			switch (retval) {
		  		case PROC_RETURNED:
		  			proc_rele(p);
		  			break;
		  		case PROC_RETURNED_DONE:
			  		proc_rele(p);
			  		goto out;
		  		case PROC_CLAIMED_DONE:
					goto out;
		  		case PROC_CLAIMED:
		  		default:
					break;
			}
		} else if (flags & PROC_ZOMBPROCLIST) {
			p = proc_find_zombref(pid_list[i]);
			if (p != PROC_NULL) {
				retval = callout(p, arg);
		
				switch (retval) {
		  			case PROC_RETURNED:
		  				proc_drop_zombref(p);
		  				break;
		  			case PROC_RETURNED_DONE:
						proc_drop_zombref(p);
						goto out;
		  			case PROC_CLAIMED_DONE:
						goto out;
		  			case PROC_CLAIMED:
		  			default:
						break;
				}
			}
		}
	}

out: 
	kfree(pid_list, alloc_count);
	return(0);

}


#if 0
/* This is for iteration in case of trivial non blocking callouts */
int
proc_scanall(flags, callout, arg)
	int flags;
	int (*callout)(proc_t, void *);
	void * arg;
{
	proc_t p;
	int retval;


	proc_list_lock();


	if (flags & PROC_ALLPROCLIST) {
		for (p = allproc.lh_first; (p != 0); p = p->p_list.le_next) {
			retval = callout(p, arg);
			if (retval == PROC_RETURNED_DONE)
				goto out;
		}
	}
	if (flags & PROC_ZOMBPROCLIST) {
		for (p = zombproc.lh_first; p != 0; p = p->p_list.le_next) {
			retval = callout(p, arg);
			if (retval == PROC_RETURNED_DONE)
				goto out;
		}
	}
out:

	proc_list_unlock();

	return(0);
}
#endif


int
proc_rebootscan(callout, arg, filterfn, filterarg)
	int (*callout)(proc_t, void *);
	void * arg;
	int (*filterfn)(proc_t, void *);
	void * filterarg;
{
	proc_t p;
	int lockheld = 0, retval;

	proc_shutdown_exitcount = 0;

ps_allprocscan:

	proc_list_lock();

	lockheld = 1;

	for (p = allproc.lh_first; (p != 0); p = p->p_list.le_next) {
		if ( (filterfn == 0 ) || (filterfn(p, filterarg) != 0)) {
			p = proc_ref_locked(p);

			proc_list_unlock();
			lockheld = 0;

			if (p) {
				proc_transwait(p, 0);
				retval = callout(p, arg);
				proc_rele(p);
	
				switch (retval) {
					case PROC_RETURNED_DONE:
					case PROC_CLAIMED_DONE:
						goto out;
				}
			}
			goto ps_allprocscan;	
		} /* filter pass */
	} /* allproc walk thru */

	if (lockheld == 1) {
		proc_list_unlock();
		lockheld = 0;
	}

out: 
	return(0);

}


int
proc_childrenwalk(parent, callout, arg)
	struct proc * parent;
	int (*callout)(proc_t, void *);
	void * arg;
{
	register struct proc *p;
	pid_t * pid_list;
	int count, pidcount, alloc_count, i, retval;

	count = nprocs+ 10;
	if (count > hard_maxproc)
		count = hard_maxproc;
	alloc_count = count * sizeof(pid_t);
	pid_list = (pid_t *)kalloc(alloc_count);
	bzero(pid_list, alloc_count);


	proc_list_lock();


	pidcount = 0;
	for (p = parent->p_children.lh_first; (p != 0); p = p->p_sibling.le_next) {
		if (p->p_stat == SIDL)
			continue;
		pid_list[pidcount] = p->p_pid;
		pidcount++;
		if (pidcount >= count)
			break;
	}
	proc_list_unlock();


	for (i = 0; i< pidcount; i++) {
		p = proc_find(pid_list[i]);
		if (p) {
			proc_transwait(p, 0);
			retval = callout(p, arg);

			switch (retval) {
		  		case PROC_RETURNED:
		  		case PROC_RETURNED_DONE:
			  		proc_rele(p);
			  		if (retval == PROC_RETURNED_DONE) {
						goto out;
			  		}
			  		break;

		  		case PROC_CLAIMED_DONE:
					goto out;
		  		case PROC_CLAIMED:
		  		default:
					break;
			}
		}
	}

out: 
	kfree(pid_list, alloc_count);
	return(0);

}

/*
 */
/* PGRP_BLOCKITERATE is not implemented yet */
int
pgrp_iterate(pgrp, flags, callout, arg, filterfn, filterarg)
	struct pgrp *pgrp;
	int flags;
	int (*callout)(proc_t, void *);
	void * arg;
	int (*filterfn)(proc_t, void *);
	void * filterarg;
{
	proc_t p;
	pid_t * pid_list;
	int count, pidcount, i, alloc_count;
	int retval;
	pid_t pgid;
	int dropref = flags & PGRP_DROPREF;
#if 0
	int serialize = flags & PGRP_BLOCKITERATE;
#else
	int serialize = 0;
#endif

	if (pgrp == 0)
		return(0);
	count = pgrp->pg_membercnt + 10;
	if (count > hard_maxproc)
		count = hard_maxproc;
	alloc_count = count * sizeof(pid_t);
	pid_list = (pid_t *)kalloc(alloc_count);
	bzero(pid_list, alloc_count);
	
	pgrp_lock(pgrp);
	if (serialize  != 0) {
		while ((pgrp->pg_listflags & PGRP_FLAG_ITERABEGIN) == PGRP_FLAG_ITERABEGIN) {
			pgrp->pg_listflags |= PGRP_FLAG_ITERWAIT;
			msleep(&pgrp->pg_listflags, &pgrp->pg_mlock, 0, "pgrp_iterate", 0);
		}
		pgrp->pg_listflags |= PGRP_FLAG_ITERABEGIN;
	}

	pgid = pgrp->pg_id;

	pidcount = 0;
	for (p = pgrp->pg_members.lh_first; p != 0;
	     p = p->p_pglist.le_next) {
		if ( (filterfn == 0 ) || (filterfn(p, filterarg) != 0)) {
			pid_list[pidcount] = p->p_pid;
			pidcount++;
			if (pidcount >= count)
				break;
		}
	}
		

	pgrp_unlock(pgrp);
	if ((serialize == 0) && (dropref != 0))
		pg_rele(pgrp);


	for (i = 0; i< pidcount; i++) {
		/* No handling or proc0 */
		if (pid_list[i] == 0)
			continue;
		p = proc_find(pid_list[i]);
		if (p) {
			if (p->p_pgrpid != pgid) {
				proc_rele(p);
				continue;
			}
			proc_transwait(p, 0);
			retval = callout(p, arg);

			switch (retval) {
		  		case PROC_RETURNED:
		  		case PROC_RETURNED_DONE:
			  		proc_rele(p);
			  		if (retval == PROC_RETURNED_DONE) {
						goto out;
			  		}
			  		break;

		  		case PROC_CLAIMED_DONE:
					goto out;
		  		case PROC_CLAIMED:
		  		default:
					break;
			}
		}
	}
out:
	if (serialize != 0) {
		pgrp_lock(pgrp);
		pgrp->pg_listflags &= ~PGRP_FLAG_ITERABEGIN;
		if ((pgrp->pg_listflags & PGRP_FLAG_ITERWAIT) == PGRP_FLAG_ITERWAIT) {
			pgrp->pg_listflags &= ~PGRP_FLAG_ITERWAIT;
			wakeup(&pgrp->pg_listflags);
		}
		pgrp_unlock(pgrp);
		if (dropref != 0)
			pg_rele(pgrp);
	}
	kfree(pid_list, alloc_count);
	return(0);
}

static void
pgrp_add(struct pgrp * pgrp, struct proc * parent, struct proc * child)
{
	proc_list_lock();
	child->p_pgrp = pgrp;
	child->p_pgrpid = pgrp->pg_id;
	child->p_listflag |= P_LIST_INPGRP;
	/*
	 * When pgrp is being freed , a process can still 
	 * request addition using setpgid from bash when 
 	 * login is terminated (login cycler) return ESRCH
	 * Safe to hold lock due to refcount on pgrp 
	 */
	if ((pgrp->pg_listflags & (PGRP_FLAG_TERMINATE | PGRP_FLAG_DEAD)) == PGRP_FLAG_TERMINATE) {
		pgrp->pg_listflags &= ~PGRP_FLAG_TERMINATE;	
	}

	if ((pgrp->pg_listflags & PGRP_FLAG_DEAD) == PGRP_FLAG_DEAD)
		panic("pgrp_add : pgrp is dead adding process");
	proc_list_unlock();

	pgrp_lock(pgrp);
	pgrp->pg_membercnt++;
	if ( parent != PROC_NULL) {
		LIST_INSERT_AFTER(parent, child, p_pglist);
	 }else {
		LIST_INSERT_HEAD(&pgrp->pg_members, child, p_pglist);
	}
	pgrp_unlock(pgrp);

	proc_list_lock();
	if (((pgrp->pg_listflags & (PGRP_FLAG_TERMINATE | PGRP_FLAG_DEAD)) == PGRP_FLAG_TERMINATE) && (pgrp->pg_membercnt != 0)) {
		pgrp->pg_listflags &= ~PGRP_FLAG_TERMINATE;	
	}
	proc_list_unlock();
}

static void
pgrp_remove(struct proc * p)
{
	struct pgrp * pg;

	pg = proc_pgrp(p);

	proc_list_lock();
#if __PROC_INTERNAL_DEBUG
	if ((p->p_listflag & P_LIST_INPGRP) == 0)
		panic("removing from pglist but no named ref\n");
#endif
	p->p_pgrpid = PGRPID_DEAD;
	p->p_listflag &= ~P_LIST_INPGRP;
	p->p_pgrp = NULL;
	proc_list_unlock();

	if (pg == PGRP_NULL)
		panic("pgrp_remove: pg is NULL");
	pgrp_lock(pg);
	pg->pg_membercnt--;

	if (pg->pg_membercnt < 0)
		panic("pgprp: -ve membercnt pgprp:%p p:%p\n",pg, p);

	LIST_REMOVE(p, p_pglist);
	if (pg->pg_members.lh_first == 0) {
		pgrp_unlock(pg);
		pgdelete_dropref(pg);
	} else {
		pgrp_unlock(pg);
		pg_rele(pg);
	}
}


/* cannot use proc_pgrp as it maybe stalled */
static void
pgrp_replace(struct proc * p, struct pgrp * newpg)
{
        struct pgrp * oldpg;



       proc_list_lock();

	while ((p->p_listflag & P_LIST_PGRPTRANS) == P_LIST_PGRPTRANS) {
		p->p_listflag |= P_LIST_PGRPTRWAIT;
		(void)msleep(&p->p_pgrpid, proc_list_mlock, 0, "proc_pgrp", 0);
	}

	p->p_listflag |= P_LIST_PGRPTRANS;

	oldpg = p->p_pgrp;
	if (oldpg == PGRP_NULL)
		panic("pgrp_replace: oldpg NULL");
	oldpg->pg_refcount++;
#if __PROC_INTERNAL_DEBUG
        if ((p->p_listflag & P_LIST_INPGRP) == 0)
                panic("removing from pglist but no named ref\n");
#endif
        p->p_pgrpid = PGRPID_DEAD;
        p->p_listflag &= ~P_LIST_INPGRP;
        p->p_pgrp = NULL;
 
       proc_list_unlock();

       pgrp_lock(oldpg);
       oldpg->pg_membercnt--;
       if (oldpg->pg_membercnt < 0)
                panic("pgprp: -ve membercnt pgprp:%p p:%p\n",oldpg, p);
       LIST_REMOVE(p, p_pglist);
        if (oldpg->pg_members.lh_first == 0) {
                pgrp_unlock(oldpg);
                pgdelete_dropref(oldpg);
        } else {
                pgrp_unlock(oldpg);
                pg_rele(oldpg);
        }

        proc_list_lock();
        p->p_pgrp = newpg;
        p->p_pgrpid = newpg->pg_id;
        p->p_listflag |= P_LIST_INPGRP;
        /*
         * When pgrp is being freed , a process can still
         * request addition using setpgid from bash when 
         * login is terminated (login cycler) return ESRCH
         * Safe to hold lock due to refcount on pgrp 
         */
        if ((newpg->pg_listflags & (PGRP_FLAG_TERMINATE | PGRP_FLAG_DEAD)) == PGRP_FLAG_TERMINATE) {
                newpg->pg_listflags &= ~PGRP_FLAG_TERMINATE;
        }

        if ((newpg->pg_listflags & PGRP_FLAG_DEAD) == PGRP_FLAG_DEAD)
                panic("pgrp_add : pgrp is dead adding process");
        proc_list_unlock();

        pgrp_lock(newpg);
        newpg->pg_membercnt++;
	LIST_INSERT_HEAD(&newpg->pg_members, p, p_pglist);
        pgrp_unlock(newpg);

        proc_list_lock();
        if (((newpg->pg_listflags & (PGRP_FLAG_TERMINATE | PGRP_FLAG_DEAD)) == PGRP_FLAG_TERMINATE) && (newpg->pg_membercnt != 0)) {
                newpg->pg_listflags &= ~PGRP_FLAG_TERMINATE;
        }

	p->p_listflag &= ~P_LIST_PGRPTRANS;
	if ((p->p_listflag & P_LIST_PGRPTRWAIT) == P_LIST_PGRPTRWAIT) {
		p->p_listflag &= ~P_LIST_PGRPTRWAIT;
		wakeup(&p->p_pgrpid);
		
	}
        proc_list_unlock();
}

void
pgrp_lock(struct pgrp * pgrp)
{
	lck_mtx_lock(&pgrp->pg_mlock);
}

void
pgrp_unlock(struct pgrp * pgrp)
{
	lck_mtx_unlock(&pgrp->pg_mlock);
}

void
session_lock(struct session * sess)
{
	lck_mtx_lock(&sess->s_mlock);
}


void
session_unlock(struct session * sess)
{
	lck_mtx_unlock(&sess->s_mlock);
}

struct pgrp *
proc_pgrp(proc_t p)
{
	struct pgrp * pgrp;

	if (p == PROC_NULL)
		return(PGRP_NULL);
	proc_list_lock();

	while ((p->p_listflag & P_LIST_PGRPTRANS) == P_LIST_PGRPTRANS) {
		p->p_listflag |= P_LIST_PGRPTRWAIT;
		(void)msleep(&p->p_pgrpid, proc_list_mlock, 0, "proc_pgrp", 0);
	}
		
	pgrp = p->p_pgrp;

	assert(pgrp != NULL);

	if (pgrp != PGRP_NULL) {
		pgrp->pg_refcount++;
		if ((pgrp->pg_listflags & (PGRP_FLAG_TERMINATE | PGRP_FLAG_DEAD)) != 0)
			panic("proc_pgrp: ref being povided for dead pgrp");
	}
		
	proc_list_unlock();
	
	return(pgrp);
}

struct pgrp *
tty_pgrp(struct tty * tp)
{
	struct pgrp * pg = PGRP_NULL;

	proc_list_lock();
	pg = tp->t_pgrp;

	if (pg != PGRP_NULL) {
		if ((pg->pg_listflags & PGRP_FLAG_DEAD) != 0)
			panic("tty_pgrp: ref being povided for dead pgrp");
		pg->pg_refcount++;
	}
	proc_list_unlock();

	return(pg);
}

struct session *
proc_session(proc_t p)
{
	struct session * sess = SESSION_NULL;
	
	if (p == PROC_NULL)
		return(SESSION_NULL);

	proc_list_lock();

	/* wait during transitions */
	while ((p->p_listflag & P_LIST_PGRPTRANS) == P_LIST_PGRPTRANS) {
		p->p_listflag |= P_LIST_PGRPTRWAIT;
		(void)msleep(&p->p_pgrpid, proc_list_mlock, 0, "proc_pgrp", 0);
	}

	if ((p->p_pgrp != PGRP_NULL) && ((sess = p->p_pgrp->pg_session) != SESSION_NULL)) {
		if ((sess->s_listflags & (S_LIST_TERM | S_LIST_DEAD)) != 0)
			panic("proc_session:returning sesssion ref on terminating session");
		sess->s_count++;
	}
	proc_list_unlock();
	return(sess);
}

void
session_rele(struct session *sess)
{
	proc_list_lock();
	if (--sess->s_count == 0) {
		if ((sess->s_listflags & (S_LIST_TERM | S_LIST_DEAD)) != 0)
			panic("session_rele: terminating already terminated session");
		sess->s_listflags |= S_LIST_TERM;
		LIST_REMOVE(sess, s_hash);
		sess->s_listflags |= S_LIST_DEAD;
		if (sess->s_count != 0)
			panic("session_rele: freeing session in use");	
		proc_list_unlock();
#if CONFIG_FINE_LOCK_GROUPS
		lck_mtx_destroy(&sess->s_mlock, proc_mlock_grp);
#else
		lck_mtx_destroy(&sess->s_mlock, proc_lck_grp);
#endif
		FREE_ZONE(sess, sizeof(struct session), M_SESSION);
	} else
		proc_list_unlock();
}

int
proc_transstart(proc_t p, int locked, int non_blocking)
{
	if (locked == 0)
		proc_lock(p);
	while ((p->p_lflag & P_LINTRANSIT) == P_LINTRANSIT) {
		if (((p->p_lflag & P_LTRANSCOMMIT) == P_LTRANSCOMMIT) || non_blocking) {
			if (locked == 0)
				proc_unlock(p);
			return EDEADLK;
		}
		p->p_lflag |= P_LTRANSWAIT;
		msleep(&p->p_lflag, &p->p_mlock, 0, "proc_signstart", NULL);
	}
	p->p_lflag |= P_LINTRANSIT;
	p->p_transholder = current_thread();
	if (locked == 0)
		proc_unlock(p);
	return 0;
}

void
proc_transcommit(proc_t p, int locked)
{
	if (locked == 0)
		proc_lock(p);

	assert ((p->p_lflag & P_LINTRANSIT) == P_LINTRANSIT);
	assert (p->p_transholder == current_thread());
	p->p_lflag |= P_LTRANSCOMMIT;

	if ((p->p_lflag & P_LTRANSWAIT) == P_LTRANSWAIT) {
		p->p_lflag &= ~P_LTRANSWAIT;
		wakeup(&p->p_lflag);
	}
	if (locked == 0)
		proc_unlock(p);
}

void
proc_transend(proc_t p, int locked)
{
	if (locked == 0)
		proc_lock(p);

	p->p_lflag &= ~( P_LINTRANSIT | P_LTRANSCOMMIT);
	p->p_transholder = NULL;

	if ((p->p_lflag & P_LTRANSWAIT) == P_LTRANSWAIT) {
		p->p_lflag &= ~P_LTRANSWAIT;
		wakeup(&p->p_lflag);
	}
	if (locked == 0)
		proc_unlock(p);
}

int
proc_transwait(proc_t p, int locked)
{
	if (locked == 0)
		proc_lock(p);
	while ((p->p_lflag & P_LINTRANSIT) == P_LINTRANSIT) {
		if ((p->p_lflag & P_LTRANSCOMMIT) == P_LTRANSCOMMIT && current_proc() == p) {
			if (locked == 0)
				proc_unlock(p);
			return EDEADLK;
		}
		p->p_lflag |= P_LTRANSWAIT;
		msleep(&p->p_lflag, &p->p_mlock, 0, "proc_signstart", NULL);
	}
	if (locked == 0)
		proc_unlock(p);
	return 0;
}

void
proc_klist_lock(void)
{
	lck_mtx_lock(proc_klist_mlock);
}

void
proc_klist_unlock(void)
{
	lck_mtx_unlock(proc_klist_mlock);
}

void
proc_knote(struct proc * p, long hint)
{
	proc_klist_lock();
	KNOTE(&p->p_klist, hint);
	proc_klist_unlock();
}

void
proc_knote_drain(struct proc *p)
{
	struct knote *kn = NULL;

	/*
	 * Clear the proc's klist to avoid references after the proc is reaped.
	 */
	proc_klist_lock();
	while ((kn = SLIST_FIRST(&p->p_klist))) {
		kn->kn_ptr.p_proc = PROC_NULL;
		KNOTE_DETACH(&p->p_klist, kn);
	}
	proc_klist_unlock();
}

void 
proc_setregister(proc_t p)
{
	proc_lock(p);
	p->p_lflag |= P_LREGISTER;
	proc_unlock(p);
}

void 
proc_resetregister(proc_t p)
{
	proc_lock(p);
	p->p_lflag &= ~P_LREGISTER;
	proc_unlock(p);
}

pid_t
proc_pgrpid(proc_t p)
{
	return p->p_pgrpid;
}

pid_t
proc_selfpgrpid()
{
	return current_proc()->p_pgrpid;
}


/* return control and action states */
int
proc_getpcontrol(int pid, int * pcontrolp)
{
	proc_t p;

	p = proc_find(pid);
	if (p == PROC_NULL)
		return(ESRCH);
	if (pcontrolp != NULL)
		*pcontrolp = p->p_pcaction;

	proc_rele(p);
	return(0);
}

int
proc_dopcontrol(proc_t p)
{
	int pcontrol;

	proc_lock(p);

	pcontrol = PROC_CONTROL_STATE(p);

	if (PROC_ACTION_STATE(p) == 0) {
		switch(pcontrol) {
			case P_PCTHROTTLE:
				PROC_SETACTION_STATE(p);
				proc_unlock(p);
				printf("low swap: throttling pid %d (%s)\n", p->p_pid, p->p_comm);
				break;

			case P_PCSUSP:
				PROC_SETACTION_STATE(p);
				proc_unlock(p);
				printf("low swap: suspending pid %d (%s)\n", p->p_pid, p->p_comm);
				task_suspend(p->task);
				break;

			case P_PCKILL:
				PROC_SETACTION_STATE(p);
				proc_unlock(p);
				printf("low swap: killing pid %d (%s)\n", p->p_pid, p->p_comm);
				psignal(p, SIGKILL);
				break;

			default:
				proc_unlock(p);
		}

	} else 
		proc_unlock(p);

	return(PROC_RETURNED);
}


/*
 * Resume a throttled or suspended process.  This is an internal interface that's only
 * used by the user level code that presents the GUI when we run out of swap space and 
 * hence is restricted to processes with superuser privileges.
 */

int
proc_resetpcontrol(int pid)
{
	proc_t p;
	int pcontrol;
	int error;
	proc_t self = current_proc();

	/* if the process has been validated to handle resource control or root is valid one */
	if (((self->p_lflag & P_LVMRSRCOWNER) == 0) && (error = suser(kauth_cred_get(), 0)))
		return error;

	p = proc_find(pid);
	if (p == PROC_NULL)
		return(ESRCH);
	
	proc_lock(p);

	pcontrol = PROC_CONTROL_STATE(p);

	if(PROC_ACTION_STATE(p) !=0) {
		switch(pcontrol) {
			case P_PCTHROTTLE:
				PROC_RESETACTION_STATE(p);
				proc_unlock(p);
				printf("low swap: unthrottling pid %d (%s)\n", p->p_pid, p->p_comm);
				break;

			case P_PCSUSP:
				PROC_RESETACTION_STATE(p);
				proc_unlock(p);
				printf("low swap: resuming pid %d (%s)\n", p->p_pid, p->p_comm);
				task_resume(p->task);
				break;

			case P_PCKILL:
				/* Huh? */
				PROC_SETACTION_STATE(p);
				proc_unlock(p);
				printf("low swap: attempt to unkill pid %d (%s) ignored\n", p->p_pid, p->p_comm);
				break;

			default:
				proc_unlock(p);
		}

	} else 
		proc_unlock(p);

	proc_rele(p);
	return(0);
}



struct no_paging_space
{
	uint64_t	pcs_max_size;
	uint64_t	pcs_uniqueid;
	int		pcs_pid;
	int		pcs_proc_count;
	uint64_t	pcs_total_size;

	uint64_t	npcs_max_size;
	uint64_t	npcs_uniqueid;
	int		npcs_pid;
	int		npcs_proc_count;
	uint64_t	npcs_total_size;

	int		apcs_proc_count;
	uint64_t	apcs_total_size;
};


static int
proc_pcontrol_filter(proc_t p, void *arg)
{
	struct no_paging_space *nps;
	uint64_t	compressed;

	nps = (struct no_paging_space *)arg;

	compressed = get_task_compressed(p->task);

	if (PROC_CONTROL_STATE(p)) {
		if (PROC_ACTION_STATE(p) == 0) {
			if (compressed > nps->pcs_max_size) {
				nps->pcs_pid = p->p_pid;
				nps->pcs_uniqueid = p->p_uniqueid;
				nps->pcs_max_size = compressed;
			}
			nps->pcs_total_size += compressed;
			nps->pcs_proc_count++;
		} else {
			nps->apcs_total_size += compressed;
			nps->apcs_proc_count++;
		}
	} else {
		if (compressed > nps->npcs_max_size) {
			nps->npcs_pid = p->p_pid;
			nps->npcs_uniqueid = p->p_uniqueid;
			nps->npcs_max_size = compressed;
		}
		nps->npcs_total_size += compressed;
		nps->npcs_proc_count++;

	}
	return (0);
}


static int
proc_pcontrol_null(__unused proc_t p, __unused void *arg)
{
	return(PROC_RETURNED);
}


/*
 * Deal with the low on compressor pool space condition... this function
 * gets called when we are approaching the limits of the compressor pool or
 * we are unable to create a new swap file.
 * Since this eventually creates a memory deadlock situtation, we need to take action to free up
 * memory resources (both compressed and uncompressed) in order to prevent the system from hanging completely.
 * There are 2 categories of processes to deal with.  Those that have an action
 * associated with them by the task itself and those that do not.  Actionable 
 * tasks can have one of three categories specified:  ones that
 * can be killed immediately, ones that should be suspended, and ones that should
 * be throttled.  Processes that do not have an action associated with them are normally
 * ignored unless they are utilizing such a large percentage of the compressor pool (currently 50%)
 * that only by killing them can we hope to put the system back into a usable state.
 */

#define	NO_PAGING_SPACE_DEBUG	0

extern uint64_t	vm_compressor_pages_compressed(void);

struct timeval	last_no_space_action = {0, 0};

int
no_paging_space_action()
{
	proc_t		p;
	struct no_paging_space nps;
	struct timeval	now;

	/*
	 * Throttle how often we come through here.  Once every 5 seconds should be plenty.
	 */
	microtime(&now);

	if (now.tv_sec <= last_no_space_action.tv_sec + 5)
		return (0);

	/*
	 * Examine all processes and find the biggest (biggest is based on the number of pages this 
	 * task has in the compressor pool) that has been marked to have some action
	 * taken when swap space runs out... we also find the biggest that hasn't been marked for
	 * action.
	 *
	 * If the biggest non-actionable task is over the "dangerously big" threashold (currently 50% of
	 * the total number of pages held by the compressor, we go ahead and kill it since no other task
	 * can have any real effect on the situation.  Otherwise, we go after the actionable process.
	 */
	bzero(&nps, sizeof(nps));

	proc_iterate(PROC_ALLPROCLIST, proc_pcontrol_null, (void *)NULL, proc_pcontrol_filter, (void *)&nps);

#if NO_PAGING_SPACE_DEBUG
	printf("low swap: npcs_proc_count = %d, npcs_total_size = %qd, npcs_max_size = %qd\n",
	       nps.npcs_proc_count, nps.npcs_total_size, nps.npcs_max_size);
	printf("low swap: pcs_proc_count = %d, pcs_total_size = %qd, pcs_max_size = %qd\n",
	       nps.pcs_proc_count, nps.pcs_total_size, nps.pcs_max_size);
	printf("low swap: apcs_proc_count = %d, apcs_total_size = %qd\n",
	       nps.apcs_proc_count, nps.apcs_total_size);
#endif
	if (nps.npcs_max_size > (vm_compressor_pages_compressed() * 50) / 100) {
		/*
		 * for now we'll knock out any task that has more then 50% of the pages
		 * held by the compressor
		 */
		if ((p = proc_find(nps.npcs_pid)) != PROC_NULL) {
	
			if (nps.npcs_uniqueid == p->p_uniqueid) {
				/*
				 * verify this is still the same process
				 * in case the proc exited and the pid got reused while
				 * we were finishing the proc_iterate and getting to this point
				 */
				last_no_space_action = now;

				printf("low swap: killing pid %d (%s)\n", p->p_pid, p->p_comm);
				psignal(p, SIGKILL);
			
				proc_rele(p);

				return (0);
			}
				
			proc_rele(p);
		}
	}

	if (nps.pcs_max_size > 0) {
		if ((p = proc_find(nps.pcs_pid)) != PROC_NULL) {

			if (nps.pcs_uniqueid == p->p_uniqueid) {
				/*
				 * verify this is still the same process
				 * in case the proc exited and the pid got reused while
				 * we were finishing the proc_iterate and getting to this point
				 */
				last_no_space_action = now;
		
				proc_dopcontrol(p);
			
				proc_rele(p);
				
				return (1);
			}
	
			proc_rele(p);
		}
	}
	last_no_space_action = now;

	printf("low swap: unable to find any eligible processes to take action on\n");

	return (0);
}

int 
proc_trace_log(__unused proc_t p,  struct proc_trace_log_args *uap, __unused int *retval)
{
	int ret = 0;
	proc_t target_proc = PROC_NULL;
	pid_t target_pid = uap->pid;
	uint64_t target_uniqueid = uap->uniqueid;
	task_t target_task = NULL;

	if (priv_check_cred(kauth_cred_get(), PRIV_PROC_TRACE_INSPECT, 0)) {
		ret = EPERM;
		goto out;
	}
	target_proc = proc_find(target_pid);
	if (target_proc != PROC_NULL) {
		if (target_uniqueid != proc_uniqueid(target_proc)) {
			ret = ENOENT;
			goto out;
		}

		target_task = proc_task(target_proc);
		if (task_send_trace_memory(target_task, target_pid, target_uniqueid)) {
			ret = EINVAL;
			goto out;
		}
	} else
		ret = ENOENT;

out:
	if (target_proc != PROC_NULL)
		proc_rele(target_proc);
	return (ret);
}

#if VM_SCAN_FOR_SHADOW_CHAIN
extern int vm_map_shadow_max(vm_map_t map);
int proc_shadow_max(void);
int proc_shadow_max(void)
{
	int		retval, max;
	proc_t		p;
	task_t		task;
	vm_map_t	map;

	max = 0;
	proc_list_lock();
	for (p = allproc.lh_first; (p != 0); p = p->p_list.le_next) {
		if (p->p_stat == SIDL)
			continue;
		task = p->task;
		if (task == NULL) {
			continue;
		}
		map = get_task_map(task);
		if (map == NULL) {
			continue;
		}
		retval = vm_map_shadow_max(map);
		if (retval > max) {
			max = retval;
		}
	}
	proc_list_unlock();
	return max;
}
#endif /* VM_SCAN_FOR_SHADOW_CHAIN */

void proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid);
void proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
	if (target_proc != NULL) {
		target_proc->p_responsible_pid = responsible_pid;
	}
	return;
}

int
proc_chrooted(proc_t p)
{
	int retval = 0;

	if (p) {
		proc_fdlock(p);
		retval = (p->p_fd->fd_rdir != NULL) ? 1 : 0;
		proc_fdunlock(p);
	}

	return retval;
}
