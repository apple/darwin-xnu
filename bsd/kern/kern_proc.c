/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
#include <ufs/ufs/quota.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/signalvar.h>
#include <sys/syslog.h>
#include <sys/kernel_types.h>

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
struct proclist allproc;
struct proclist zombproc;
extern struct tty cons;

/* Name to give to core files */
__private_extern__ char corefilename[MAXPATHLEN+1] = {"/cores/core.%P"};

static void orphanpg(struct pgrp *pg);

/*
 * Initialize global process hashing structures.
 */
void
procinit()
{

	LIST_INIT(&allproc);
	LIST_INIT(&zombproc);
	pidhashtbl = hashinit(maxproc / 4, M_PROC, &pidhash);
	pgrphashtbl = hashinit(maxproc / 4, M_PROC, &pgrphash);
	uihashtbl = hashinit(maxproc / 16, M_PROC, &uihash);
}

/*
 * Change the count associated with number of processes
 * a given user is using.
 */
int
chgproccnt(uid, diff)
	uid_t	uid;
	int	diff;
{
	register struct uidinfo *uip;
	register struct uihashhead *uipp;

	uipp = UIHASH(uid);
	for (uip = uipp->lh_first; uip != 0; uip = uip->ui_hash.le_next)
		if (uip->ui_uid == uid)
			break;
	if (uip) {
		uip->ui_proccnt += diff;
		if (uip->ui_proccnt > 0)
			return (uip->ui_proccnt);
		if (uip->ui_proccnt < 0)
			panic("chgproccnt: procs < 0");
		LIST_REMOVE(uip, ui_hash);
		FREE_ZONE(uip, sizeof *uip, M_PROC);
		return (0);
	}
	if (diff <= 0) {
		if (diff == 0)
			return(0);
		panic("chgproccnt: lost user");
	}
	MALLOC_ZONE(uip, struct uidinfo *, sizeof(*uip), M_PROC, M_WAITOK);
	if (uip == NULL)
		panic("chgproccnt: M_PROC zone depleted");
	LIST_INSERT_HEAD(uipp, uip, ui_hash);
	uip->ui_uid = uid;
	uip->ui_proccnt = diff;
	return (diff);
}

/*
 * Is p an inferior of the current process?
 */
int
inferior(p)
	register struct proc *p;
{

	for (; p != current_proc(); p = p->p_pptr)
		if (p->p_pid == 0)
			return (0);
	return (1);
}
/*
 * Is p an inferior of t ?
 */
int
isinferior(struct proc *p, struct proc *t)
{

	/* if p==t they are not inferior */
	if (p == t)
		return(0);
	for (; p != t; p = p->p_pptr)
		if (p->p_pid == 0)
			return (0);
	return (1);
}

int
proc_isinferior(int pid1, int pid2)
{
	proc_t p;
	proc_t t;

	if (((p = pfind(pid1)) != (struct proc *)0 ) && ((t = pfind(pid2)) != (struct proc *)0))
		return (isinferior(p, t));
	return(0);
}

proc_t
proc_find(int pid)
{
	return(pfind(pid));
}

int 
proc_rele(__unused proc_t p)
{
	return(0);
}

proc_t
proc_self()
{
	return(current_proc());
}


int
proc_pid(proc_t p)
{
	return(p->p_pid);
}

int 
proc_ppid(proc_t p)
{
	if (p->p_pptr != (struct proc *)0) 
		return(p->p_pptr->p_pid);
	return(0);
}

int 
proc_selfpid(void)
{
	struct proc *p = current_proc();
	return(p->p_pid);
}


int 
proc_selfppid(void)
{
	struct proc *p = current_proc();
	if (p->p_pptr)
		return(p->p_pptr->p_pid);
	else
		return(0);
}

void
proc_name(int pid, char * buf, int size)
{
	struct proc  *p;

	if ((p = pfind(pid))!= (struct proc *)0) {
		strncpy(buf, &p->p_comm[0], size);
		buf[size-1] = 0;
	}
}

void
proc_selfname(char * buf, int  size)
{
	struct proc  *p;

	if ((p = current_proc())!= (struct proc *)0) {
		strncpy(buf, &p->p_comm[0], size);
		buf[size-1] = 0;
	}
}

void
proc_signal(int pid, int signum)
{
	proc_t p;

	if ((p = pfind(pid))!= (struct proc *)0) {
			psignal(p, signum);
	}	
}

int
proc_issignal(int pid, sigset_t mask)
{
	proc_t p;

	if ((p = pfind(pid))!= (struct proc *)0) {
		return(proc_pendingsignals(p, mask));
	}	
	return(0);
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
		retval = p->p_flag & P_WEXIT;
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
proc_tbe(proc_t p)
{
	int retval = 0;

	if (p)
		retval = p->p_flag & P_TBE;
	return(retval? 1: 0);

}

int
proc_suser(proc_t p)
{
	return(suser(p->p_ucred, NULL));
	
}

kauth_cred_t
proc_ucred(proc_t p)
{
	return(p->p_ucred);
}


int
proc_is64bit(proc_t p)
{
	return(IS_64BIT_PROCESS(p));
}

/* LP64todo - figure out how to identify 64-bit processes if NULL procp */
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
struct proc *
pfind(pid)
	register pid_t pid;
{
	register struct proc *p;

	if (!pid)
		return (kernproc);

	for (p = PIDHASH(pid)->lh_first; p != 0; p = p->p_hash.le_next)
		if (p->p_pid == pid)
			return (p);
	return (NULL);
}

/*
 * Locate a zombie by PID
 */
__private_extern__ struct proc *
pzfind(pid)
	register pid_t pid;
{
	register struct proc *p;

	for (p = zombproc.lh_first; p != 0; p = p->p_list.le_next)
		if (p->p_pid == pid)
			return (p);
	return (NULL);
}

/*
 * Locate a process group by number
 */
struct pgrp *
pgfind(pgid)
	register pid_t pgid;
{
	register struct pgrp *pgrp;

	for (pgrp = PGRPHASH(pgid)->lh_first; pgrp != 0; pgrp = pgrp->pg_hash.le_next)
		if (pgrp->pg_id == pgid)
			return (pgrp);
	return (NULL);
}


/*
 * Move p to a new or existing process group (and session)
 */
int
enterpgrp(p, pgid, mksess)
	register struct proc *p;
	pid_t pgid;
	int mksess;
{
	register struct pgrp *pgrp = pgfind(pgid);

#if DIAGNOSTIC
	if (pgrp != NULL && mksess)	/* firewalls */
		panic("enterpgrp: setsid into non-empty pgrp");
	if (SESS_LEADER(p))
		panic("enterpgrp: session leader attempted setpgrp");
#endif
	if (pgrp == NULL) {
		pid_t savepid = p->p_pid;
		struct proc *np;
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
		if ((np = pfind(savepid)) == NULL || np != p) {
			FREE_ZONE(pgrp, sizeof(struct pgrp), M_PGRP);
			return (ESRCH);
		}
		if (mksess) {
			register struct session *sess;

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
			sess->s_ttyp = NULL;
			bcopy(p->p_session->s_login, sess->s_login,
			    sizeof(sess->s_login));
			p->p_flag &= ~P_CONTROLT;
			pgrp->pg_session = sess;
#if DIAGNOSTIC
			if (p != current_proc())
				panic("enterpgrp: mksession and p != curproc");
#endif
		} else {
			pgrp->pg_session = p->p_session;
			pgrp->pg_session->s_count++;
		}
		pgrp->pg_id = pgid;
		LIST_INIT(&pgrp->pg_members);
		LIST_INSERT_HEAD(PGRPHASH(pgid), pgrp, pg_hash);
		pgrp->pg_jobc = 0;
	} else if (pgrp == p->p_pgrp)
		return (0);

	/*
	 * Adjust eligibility of affected pgrps to participate in job control.
	 * Increment eligibility counts before decrementing, otherwise we
	 * could reach 0 spuriously during the first call.
	 */
	fixjobc(p, pgrp, 1);
	fixjobc(p, p->p_pgrp, 0);

	LIST_REMOVE(p, p_pglist);
	if (p->p_pgrp->pg_members.lh_first == 0)
		pgdelete(p->p_pgrp);
	p->p_pgrp = pgrp;
	LIST_INSERT_HEAD(&pgrp->pg_members, p, p_pglist);
	return (0);
}

/*
 * remove process from process group
 */
int
leavepgrp(p)
	register struct proc *p;
{

	LIST_REMOVE(p, p_pglist);
	if (p->p_pgrp->pg_members.lh_first == 0)
		pgdelete(p->p_pgrp);
	p->p_pgrp = 0;
	return (0);
}

/*
 * delete a process group
 */
void
pgdelete(pgrp)
	register struct pgrp *pgrp;
{
	struct tty * ttyp;
	int removettypgrp = 0;

	ttyp = pgrp->pg_session->s_ttyp;
	if (pgrp->pg_session->s_ttyp != NULL && 
	    pgrp->pg_session->s_ttyp->t_pgrp == pgrp) {
		pgrp->pg_session->s_ttyp->t_pgrp = NULL;
		removettypgrp = 1;
	}
	LIST_REMOVE(pgrp, pg_hash);
	if (--pgrp->pg_session->s_count == 0) {
		if (removettypgrp && (ttyp == &cons) && (ttyp->t_session == pgrp->pg_session))
			ttyp->t_session = 0;
		FREE_ZONE(pgrp->pg_session, sizeof(struct session), M_SESSION);
	}
	FREE_ZONE(pgrp, sizeof *pgrp, M_PGRP);
}

void
sessrele(sess)
	struct session *sess;
{
	if (--sess->s_count == 0)
		FREE_ZONE(sess, sizeof (struct session), M_SESSION);
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
void
fixjobc(struct proc *p, struct pgrp *pgrp, int entering)
{
	register struct pgrp *hispgrp;
	register struct session *mysession = pgrp->pg_session;

	/*
	 * Check p's parent to see whether p qualifies its own process
	 * group; if so, adjust count for p's process group.
	 */
	if ((hispgrp = p->p_pptr->p_pgrp) != pgrp &&
	    hispgrp->pg_session == mysession) {
		if (entering)
			pgrp->pg_jobc++;
		else if (--pgrp->pg_jobc == 0)
			orphanpg(pgrp);
	}

	/*
	 * Check this process' children to see whether they qualify
	 * their process groups; if so, adjust counts for children's
	 * process groups.
	 */
	for (p = p->p_children.lh_first; p != 0; p = p->p_sibling.le_next)
		if ((hispgrp = p->p_pgrp) != pgrp &&
		    hispgrp->pg_session == mysession &&
		    p->p_stat != SZOMB) {
			if (entering)
				hispgrp->pg_jobc++;
			else if (--hispgrp->pg_jobc == 0)
				orphanpg(hispgrp);
		}
}

/* 
 * A process group has become orphaned;
 * if there are any stopped processes in the group,
 * hang-up all process in that group.
 */
static void
orphanpg(struct pgrp *pg)
{
	register struct proc *p;

	for (p = pg->pg_members.lh_first; p != 0; p = p->p_pglist.le_next) {
		if (p->p_stat == SSTOP) {
			for (p = pg->pg_members.lh_first; p != 0;
			    p = p->p_pglist.le_next) {
				pt_setrunnable(p);
				psignal(p, SIGHUP);
				psignal(p, SIGCONT);
			}
			return;
		}
	}
}

#ifdef DEBUG
void pgrpdump(void);	/* forward declare here (called from debugger) */

void
pgrpdump(void)
{
	struct pgrp *pgrp;
	struct proc *p;
	u_long i;

	for (i = 0; i <= pgrphash; i++) {
		if ((pgrp = pgrphashtbl[i].lh_first) != NULL) {
			printf("\tindx %d\n", i);
			for (; pgrp != 0; pgrp = pgrp->pg_hash.le_next) {
				printf("\tpgrp 0x%08x, pgid %d, sess %p, sesscnt %d, mem %p\n",
				    pgrp, pgrp->pg_id, pgrp->pg_session,
				    pgrp->pg_session->s_count,
				    pgrp->pg_members.lh_first);
				for (p = pgrp->pg_members.lh_first; p != 0;
				    p = p->p_pglist.le_next) {
					printf("\t\tpid %d addr 0x%08x pgrp 0x%08x\n", 
					    p->p_pid, p, p->p_pgrp);
				}
			}
		}
	}
}
#endif /* DEBUG */

/* XXX should be __private_extern__ */
int
proc_is_classic(struct proc *p)
{
    return (p->p_flag & P_CLASSIC) ? 1 : 0;
}

/* XXX Why does this function exist?  Need to kill it off... */
struct proc *
current_proc_EXTERNAL(void)
{
	return (current_proc());
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
__private_extern__ char *
proc_core_name(const char *name, uid_t uid, pid_t pid)
{
	const char *format, *appendstr;
	char *temp;
	char id_buf[11];		/* Buffer for pid/uid -- max 4B */
	size_t i, l, n;

	format = corefilename;
	MALLOC(temp, char *, MAXPATHLEN, M_TEMP, M_NOWAIT | M_ZERO);
	if (temp == NULL)
		return (NULL);
	for (i = 0, n = 0; n < MAXPATHLEN && format[i]; i++) {
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
				sprintf(id_buf, "%u", pid);
				appendstr = id_buf;
				break;
			case 'U':	/* user id */
				sprintf(id_buf, "%u", uid);
				appendstr = id_buf;
				break;
			default:
				appendstr = "";
			  	log(LOG_ERR,
				    "Unknown format character %c in `%s'\n",
				    format[i], format);
			}
			l = strlen(appendstr);
			if ((n + l) >= MAXPATHLEN)
				goto toolong;
			bcopy(appendstr, temp + n, l);
			n += l;
			break;
		default:
			temp[n++] = format[i];
		}
	}
	if (format[i] != '\0')
		goto toolong;
	return (temp);
toolong:
	log(LOG_ERR, "pid %ld (%s), uid (%lu): corename is too long\n",
	    (long)pid, name, (u_long)uid);
	FREE(temp, M_TEMP);
	return (NULL);
}
