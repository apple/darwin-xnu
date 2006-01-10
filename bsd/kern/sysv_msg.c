/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
/*
 * Implementation of SVID messages
 *
 * Author:  Daniel Boulet
 *
 * Copyright 1993 Daniel Boulet and RTMX Inc.
 *
 * This system call was implemented by Daniel Boulet under contract from RTMX.
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/msg.h>
#include <sys/malloc.h>
#include <mach/mach_types.h>

#include <bsm/audit_kernel.h>

#include <sys/filedesc.h>
#include <sys/file_internal.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/ipcs.h>

static void msginit(void *);

#define MSG_DEBUG
#undef MSG_DEBUG_OK

static void msg_freehdr(struct msg *msghdr);

typedef int     sy_call_t(struct proc *, void *, int *);

/* XXX casting to (sy_call_t *) is bogus, as usual. */
static sy_call_t *msgcalls[] = {
	(sy_call_t *)msgctl, (sy_call_t *)msgget,
	(sy_call_t *)msgsnd, (sy_call_t *)msgrcv
};

static int		nfree_msgmaps;	/* # of free map entries */
static short		free_msgmaps;	/* free map entries list head */
static struct msg	*free_msghdrs;	/* list of free msg headers */
char			*msgpool;	/* MSGMAX byte long msg buffer pool */
struct msgmap		*msgmaps;	/* MSGSEG msgmap structures */
struct msg		*msghdrs;	/* MSGTQL msg headers */
struct user_msqid_ds	*msqids;	/* MSGMNI user_msqid_ds struct's */

static lck_grp_t       *sysv_msg_subsys_lck_grp;
static lck_grp_attr_t  *sysv_msg_subsys_lck_grp_attr;
static lck_attr_t      *sysv_msg_subsys_lck_attr;
static lck_mtx_t        sysv_msg_subsys_mutex;

#define SYSV_MSG_SUBSYS_LOCK() lck_mtx_lock(&sysv_msg_subsys_mutex)
#define SYSV_MSG_SUBSYS_UNLOCK() lck_mtx_unlock(&sysv_msg_subsys_mutex)

void sysv_msg_lock_init(void);


#ifdef __APPLE_API_PRIVATE
struct msginfo msginfo = {
		MSGMAX,		/* = (MSGSSZ*MSGSEG) : max chars in a message */
		MSGMNI,		/* = 40 : max message queue identifiers */
		MSGMNB,		/* = 2048 : max chars in a queue */
		MSGTQL,		/* = 40 : max messages in system */
		MSGSSZ,		/* = 8 : size of a message segment (2^N long) */
		MSGSEG		/* = 2048 : number of message segments */
};
#endif /* __APPLE_API_PRIVATE */

/* Initialize the mutex governing access to the SysV msg subsystem */
__private_extern__ void
sysv_msg_lock_init( void )
{
	sysv_msg_subsys_lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(sysv_msg_subsys_lck_grp_attr);

	sysv_msg_subsys_lck_grp = lck_grp_alloc_init("sysv_msg_subsys_lock", sysv_msg_subsys_lck_grp_attr);

	sysv_msg_subsys_lck_attr = lck_attr_alloc_init();
	/* lck_attr_setdebug(sysv_msg_subsys_lck_attr); */
	lck_mtx_init(&sysv_msg_subsys_mutex, sysv_msg_subsys_lck_grp, sysv_msg_subsys_lck_attr);
}

static __inline__ user_time_t
sysv_msgtime(void)
{
	struct timeval	tv;
	microtime(&tv);
	return (tv.tv_sec);
}

/*
 * NOTE: Source and target may *NOT* overlap! (target is smaller)
 */
static void
msqid_ds_64to32(struct user_msqid_ds *in, struct msqid_ds *out)
{
	out->msg_perm	= in->msg_perm;
	out->msg_qnum	= in->msg_qnum;
	out->msg_cbytes	= in->msg_cbytes;	/* for ipcs */
	out->msg_qbytes	= in->msg_qbytes;
	out->msg_lspid	= in->msg_lspid;
	out->msg_lrpid	= in->msg_lrpid;
	out->msg_stime	= in->msg_stime;	/* XXX loss of range */
	out->msg_rtime	= in->msg_rtime;	/* XXX loss of range */
	out->msg_ctime	= in->msg_ctime;	/* XXX loss of range */
}

/*
 * NOTE: Source and target may are permitted to overlap! (source is smaller);
 * this works because we copy fields in order from the end of the struct to
 * the beginning.
 */
static void
msqid_ds_32to64(struct msqid_ds *in, struct user_msqid_ds *out)
{
	out->msg_ctime	= in->msg_ctime;
	out->msg_rtime	= in->msg_rtime;
	out->msg_stime	= in->msg_stime;
	out->msg_lrpid	= in->msg_lrpid;
	out->msg_lspid	= in->msg_lspid;
	out->msg_qbytes	= in->msg_qbytes;
	out->msg_cbytes	= in->msg_cbytes;	/* for ipcs */
	out->msg_qnum	= in->msg_qnum;
	out->msg_perm	= in->msg_perm;
}

/* This routine assumes the system is locked prior to calling this routine */
void 
msginit(__unused void *dummy)
{
	static int initted = 0;
	register int i;

	/* Lazy initialization on first system call; we don't have SYSINIT(). */
	if (initted)
		return;
	initted = 1;

	msgpool = (char *)_MALLOC(msginfo.msgmax, M_SHM, M_WAITOK);
	MALLOC(msgmaps, struct msgmap *,
			sizeof(struct msgmap) * msginfo.msgseg, 
			M_SHM, M_WAITOK);
	MALLOC(msghdrs, struct msg *,
			sizeof(struct msg) * msginfo.msgtql, 
			M_SHM, M_WAITOK);
	MALLOC(msqids, struct user_msqid_ds *,
			sizeof(struct user_msqid_ds) * msginfo.msgmni, 
			M_SHM, M_WAITOK);

	/*
	 * msginfo.msgssz should be a power of two for efficiency reasons.
	 * It is also pretty silly if msginfo.msgssz is less than 8
	 * or greater than about 256 so ...
	 */

	i = 8;
	while (i < 1024 && i != msginfo.msgssz)
		i <<= 1;
    	if (i != msginfo.msgssz) {
		printf("msginfo.msgssz=%d (0x%x)\n", msginfo.msgssz,
		    msginfo.msgssz);
		panic("msginfo.msgssz not a small power of 2");
	}

	if (msginfo.msgseg > 32767) {
		printf("msginfo.msgseg=%d\n", msginfo.msgseg);
		panic("msginfo.msgseg > 32767");
	}

	if (msgmaps == NULL)
		panic("msgmaps is NULL");

	for (i = 0; i < msginfo.msgseg; i++) {
		if (i > 0)
			msgmaps[i-1].next = i;
		msgmaps[i].next = -1;	/* implies entry is available */
	}
	free_msgmaps = 0;
	nfree_msgmaps = msginfo.msgseg;

	if (msghdrs == NULL)
		panic("msghdrs is NULL");

	for (i = 0; i < msginfo.msgtql; i++) {
		msghdrs[i].msg_type = 0;
		if (i > 0)
			msghdrs[i-1].msg_next = &msghdrs[i];
		msghdrs[i].msg_next = NULL;
    	}
	free_msghdrs = &msghdrs[0];

	if (msqids == NULL)
		panic("msqids is NULL");

	for (i = 0; i < msginfo.msgmni; i++) {
		msqids[i].msg_qbytes = 0;	/* implies entry is available */
		msqids[i].msg_perm.seq = 0;	/* reset to a known value */
	}
}

/*
 * Entry point for all MSG calls
 */
	/* XXX actually varargs. */
int
msgsys(struct proc *p, struct msgsys_args *uap, register_t *retval)
{
	if (uap->which >= sizeof(msgcalls)/sizeof(msgcalls[0]))
		return (EINVAL);
	return ((*msgcalls[uap->which])(p, &uap->a2, retval));
}

static void
msg_freehdr(struct msg *msghdr)
{
	while (msghdr->msg_ts > 0) {
		short next;
		if (msghdr->msg_spot < 0 || msghdr->msg_spot >= msginfo.msgseg)
			panic("msghdr->msg_spot out of range");
		next = msgmaps[msghdr->msg_spot].next;
		msgmaps[msghdr->msg_spot].next = free_msgmaps;
		free_msgmaps = msghdr->msg_spot;
		nfree_msgmaps++;
		msghdr->msg_spot = next;
		if (msghdr->msg_ts >= msginfo.msgssz)
			msghdr->msg_ts -= msginfo.msgssz;
		else
			msghdr->msg_ts = 0;
	}
	if (msghdr->msg_spot != -1)
		panic("msghdr->msg_spot != -1");
	msghdr->msg_next = free_msghdrs;
	free_msghdrs = msghdr;
}

int
msgctl(struct proc *p, struct msgctl_args *uap, register_t *retval)
{
	int msqid = uap->msqid;
	int cmd = uap->cmd;
	kauth_cred_t cred = kauth_cred_get();
	int rval, eval;
	struct user_msqid_ds msqbuf;
	struct user_msqid_ds *msqptr;
	struct user_msqid_ds umsds;

	SYSV_MSG_SUBSYS_LOCK();

	msginit( 0);

#ifdef MSG_DEBUG_OK
	printf("call to msgctl(%d, %d, 0x%qx)\n", msqid, cmd, uap->buf);
#endif

	AUDIT_ARG(svipc_cmd, cmd);
	AUDIT_ARG(svipc_id, msqid);
	msqid = IPCID_TO_IX(msqid);

	if (msqid < 0 || msqid >= msginfo.msgmni) {
#ifdef MSG_DEBUG_OK
		printf("msqid (%d) out of range (0<=msqid<%d)\n", msqid,
		    msginfo.msgmni);
#endif
		eval = EINVAL;
		goto msgctlout;
	}

	msqptr = &msqids[msqid];

	if (msqptr->msg_qbytes == 0) {
#ifdef MSG_DEBUG_OK
		printf("no such msqid\n");
#endif
		eval = EINVAL;
		goto msgctlout;
	}
	if (msqptr->msg_perm.seq != IPCID_TO_SEQ(uap->msqid)) {
#ifdef MSG_DEBUG_OK
		printf("wrong sequence number\n");
#endif
		eval = EINVAL;
		goto msgctlout;
	}

	eval = 0;
	rval = 0;

	switch (cmd) {

	case IPC_RMID:
	{
		struct msg *msghdr;
		if ((eval = ipcperm(cred, &msqptr->msg_perm, IPC_M)))
			goto msgctlout;

		/* Free the message headers */
		msghdr = msqptr->msg_first;
		while (msghdr != NULL) {
			struct msg *msghdr_tmp;

			/* Free the segments of each message */
			msqptr->msg_cbytes -= msghdr->msg_ts;
			msqptr->msg_qnum--;
			msghdr_tmp = msghdr;
			msghdr = msghdr->msg_next;
			msg_freehdr(msghdr_tmp);
		}

		if (msqptr->msg_cbytes != 0)
			panic("msg_cbytes is messed up");
		if (msqptr->msg_qnum != 0)
			panic("msg_qnum is messed up");

		msqptr->msg_qbytes = 0;	/* Mark it as free */

		wakeup((caddr_t)msqptr);
	}

		break;

	case IPC_SET:
		if ((eval = ipcperm(cred, &msqptr->msg_perm, IPC_M)))
			goto msgctlout;

		SYSV_MSG_SUBSYS_UNLOCK();

		if (IS_64BIT_PROCESS(p)) {
			eval = copyin(uap->buf, &msqbuf, sizeof(struct user_msqid_ds));
		} else {
			eval = copyin(uap->buf, &msqbuf, sizeof(struct msqid_ds));
			/* convert in place; ugly, but safe */
			msqid_ds_32to64((struct msqid_ds *)&msqbuf, &msqbuf);
		}
		if (eval)
			return(eval);

		SYSV_MSG_SUBSYS_LOCK();

		if (msqbuf.msg_qbytes > msqptr->msg_qbytes) {
			eval = suser(cred, &p->p_acflag);
			if (eval)
				goto msgctlout;
		}


		/* compare (msglen_t) value against restrict (int) value */
		if (msqbuf.msg_qbytes > (msglen_t)msginfo.msgmnb) {
#ifdef MSG_DEBUG_OK
			printf("can't increase msg_qbytes beyond %d (truncating)\n",
			    msginfo.msgmnb);
#endif
			msqbuf.msg_qbytes = msginfo.msgmnb;	/* silently restrict qbytes to system limit */
		}
		if (msqbuf.msg_qbytes == 0) {
#ifdef MSG_DEBUG_OK
			printf("can't reduce msg_qbytes to 0\n");
#endif
			eval = EINVAL;
			goto msgctlout;
		}
		msqptr->msg_perm.uid = msqbuf.msg_perm.uid;	/* change the owner */
		msqptr->msg_perm.gid = msqbuf.msg_perm.gid;	/* change the owner */
		msqptr->msg_perm.mode = (msqptr->msg_perm.mode & ~0777) |
		    (msqbuf.msg_perm.mode & 0777);
		msqptr->msg_qbytes = msqbuf.msg_qbytes;
		msqptr->msg_ctime = sysv_msgtime();
		break;

	case IPC_STAT:
		if ((eval = ipcperm(cred, &msqptr->msg_perm, IPC_R))) {
#ifdef MSG_DEBUG_OK
			printf("requester doesn't have read access\n");
#endif
			goto msgctlout;
		}

		bcopy(msqptr, &umsds, sizeof(struct user_msqid_ds));

		SYSV_MSG_SUBSYS_UNLOCK();
		if (IS_64BIT_PROCESS(p)) {
			eval = copyout(&umsds, uap->buf, sizeof(struct user_msqid_ds));
		} else {
			struct msqid_ds msqid_ds32;
			msqid_ds_64to32(&umsds, &msqid_ds32);
			eval = copyout(&msqid_ds32, uap->buf, sizeof(struct msqid_ds));
		}
		SYSV_MSG_SUBSYS_LOCK();
		break;

	default:
#ifdef MSG_DEBUG_OK
		printf("invalid command %d\n", cmd);
#endif
		eval = EINVAL;
		goto msgctlout;
	}

	if (eval == 0)
		*retval = rval;
msgctlout:
	SYSV_MSG_SUBSYS_UNLOCK();
	return(eval);
}

int
msgget(__unused struct proc *p, struct msgget_args *uap, register_t *retval)
{
	int msqid, eval;
	int key = uap->key;
	int msgflg = uap->msgflg;
	kauth_cred_t cred = kauth_cred_get();
	struct user_msqid_ds *msqptr = NULL;

	SYSV_MSG_SUBSYS_LOCK();
	msginit( 0);

#ifdef MSG_DEBUG_OK
	printf("msgget(0x%x, 0%o)\n", key, msgflg);
#endif

	if (key != IPC_PRIVATE) {
		for (msqid = 0; msqid < msginfo.msgmni; msqid++) {
			msqptr = &msqids[msqid];
			if (msqptr->msg_qbytes != 0 &&
			    msqptr->msg_perm.key == key)
				break;
		}
		if (msqid < msginfo.msgmni) {
#ifdef MSG_DEBUG_OK
			printf("found public key\n");
#endif
			if ((msgflg & IPC_CREAT) && (msgflg & IPC_EXCL)) {
#ifdef MSG_DEBUG_OK
				printf("not exclusive\n");
#endif
				eval = EEXIST;
				goto msggetout;
			}
			if ((eval = ipcperm(cred, &msqptr->msg_perm, msgflg & 0700 ))) {
#ifdef MSG_DEBUG_OK
				printf("requester doesn't have 0%o access\n",
				    msgflg & 0700);
#endif
				goto msggetout;
			}
			goto found;
		}
	}

#ifdef MSG_DEBUG_OK
	printf("need to allocate the user_msqid_ds\n");
#endif
	if (key == IPC_PRIVATE || (msgflg & IPC_CREAT)) {
		for (msqid = 0; msqid < msginfo.msgmni; msqid++) {
			/*
			 * Look for an unallocated and unlocked user_msqid_ds.
			 * user_msqid_ds's can be locked by msgsnd or msgrcv
			 * while they are copying the message in/out.  We
			 * can't re-use the entry until they release it.
			 */
			msqptr = &msqids[msqid];
			if (msqptr->msg_qbytes == 0 &&
			    (msqptr->msg_perm.mode & MSG_LOCKED) == 0)
				break;
		}
		if (msqid == msginfo.msgmni) {
#ifdef MSG_DEBUG_OK
			printf("no more user_msqid_ds's available\n");
#endif
			eval = ENOSPC;
			goto msggetout;
		}
#ifdef MSG_DEBUG_OK
		printf("msqid %d is available\n", msqid);
#endif
		msqptr->msg_perm.key = key;
		msqptr->msg_perm.cuid = kauth_cred_getuid(cred);
		msqptr->msg_perm.uid = kauth_cred_getuid(cred);
		msqptr->msg_perm.cgid = cred->cr_gid;
		msqptr->msg_perm.gid = cred->cr_gid;
		msqptr->msg_perm.mode = (msgflg & 0777);
		/* Make sure that the returned msqid is unique */
		msqptr->msg_perm.seq++;
		msqptr->msg_first = NULL;
		msqptr->msg_last = NULL;
		msqptr->msg_cbytes = 0;
		msqptr->msg_qnum = 0;
		msqptr->msg_qbytes = msginfo.msgmnb;
		msqptr->msg_lspid = 0;
		msqptr->msg_lrpid = 0;
		msqptr->msg_stime = 0;
		msqptr->msg_rtime = 0;
		msqptr->msg_ctime = sysv_msgtime();
	} else {
#ifdef MSG_DEBUG_OK
		printf("didn't find it and wasn't asked to create it\n");
#endif
		eval = ENOENT;
		goto msggetout;
	}

found:
	/* Construct the unique msqid */
	*retval = IXSEQ_TO_IPCID(msqid, msqptr->msg_perm);
	AUDIT_ARG(svipc_id, *retval);
	eval = 0;
msggetout:
	SYSV_MSG_SUBSYS_UNLOCK();
	return(eval);
}


int
msgsnd(struct proc *p, struct msgsnd_args *uap, register_t *retval)
{
	int msqid = uap->msqid;
	user_addr_t user_msgp = uap->msgp;
	size_t msgsz = (size_t)uap->msgsz;	/* limit to 4G */
	int msgflg = uap->msgflg;
	int segs_needed, eval;
	struct user_msqid_ds *msqptr;
	struct msg *msghdr;
	short next;
	user_long_t msgtype;


	SYSV_MSG_SUBSYS_LOCK();
	msginit( 0);

#ifdef MSG_DEBUG_OK
	printf("call to msgsnd(%d, 0x%qx, %d, %d)\n", msqid, user_msgp, msgsz,
	    msgflg);
#endif

	AUDIT_ARG(svipc_id, msqid);
	msqid = IPCID_TO_IX(msqid);

	if (msqid < 0 || msqid >= msginfo.msgmni) {
#ifdef MSG_DEBUG_OK
		printf("msqid (%d) out of range (0<=msqid<%d)\n", msqid,
		    msginfo.msgmni);
#endif
		eval = EINVAL;
		goto msgsndout;
	}

	msqptr = &msqids[msqid];
	if (msqptr->msg_qbytes == 0) {
#ifdef MSG_DEBUG_OK
		printf("no such message queue id\n");
#endif
		eval = EINVAL;
		goto msgsndout;
	}
	if (msqptr->msg_perm.seq != IPCID_TO_SEQ(uap->msqid)) {
#ifdef MSG_DEBUG_OK
		printf("wrong sequence number\n");
#endif
		eval = EINVAL;
		goto msgsndout;
	}

	if ((eval = ipcperm(kauth_cred_get(), &msqptr->msg_perm, IPC_W))) {
#ifdef MSG_DEBUG_OK
		printf("requester doesn't have write access\n");
#endif
		goto msgsndout;
	}

	segs_needed = (msgsz + msginfo.msgssz - 1) / msginfo.msgssz;
#ifdef MSG_DEBUG_OK
	printf("msgsz=%d, msgssz=%d, segs_needed=%d\n", msgsz, msginfo.msgssz,
	    segs_needed);
#endif
	for (;;) {
		int need_more_resources = 0;

		/*
		 * check msgsz
		 * (inside this loop in case msg_qbytes changes while we sleep)
		 */

		if (msgsz > msqptr->msg_qbytes) {
#ifdef MSG_DEBUG_OK
			printf("msgsz > msqptr->msg_qbytes\n");
#endif
			eval = EINVAL;
			goto msgsndout;
		}

		if (msqptr->msg_perm.mode & MSG_LOCKED) {
#ifdef MSG_DEBUG_OK
			printf("msqid is locked\n");
#endif
			need_more_resources = 1;
		}
		if (msgsz + msqptr->msg_cbytes > msqptr->msg_qbytes) {
#ifdef MSG_DEBUG_OK
			printf("msgsz + msg_cbytes > msg_qbytes\n");
#endif
			need_more_resources = 1;
		}
		if (segs_needed > nfree_msgmaps) {
#ifdef MSG_DEBUG_OK
			printf("segs_needed > nfree_msgmaps\n");
#endif
			need_more_resources = 1;
		}
		if (free_msghdrs == NULL) {
#ifdef MSG_DEBUG_OK
			printf("no more msghdrs\n");
#endif
			need_more_resources = 1;
		}

		if (need_more_resources) {
			int we_own_it;

			if ((msgflg & IPC_NOWAIT) != 0) {
#ifdef MSG_DEBUG_OK
				printf("need more resources but caller doesn't want to wait\n");
#endif
				eval = EAGAIN;
				goto msgsndout;
			}

			if ((msqptr->msg_perm.mode & MSG_LOCKED) != 0) {
#ifdef MSG_DEBUG_OK
				printf("we don't own the user_msqid_ds\n");
#endif
				we_own_it = 0;
			} else {
				/* Force later arrivals to wait for our
				   request */
#ifdef MSG_DEBUG_OK
				printf("we own the user_msqid_ds\n");
#endif
				msqptr->msg_perm.mode |= MSG_LOCKED;
				we_own_it = 1;
			}
#ifdef MSG_DEBUG_OK
			printf("goodnight\n");
#endif
			eval = msleep((caddr_t)msqptr, &sysv_msg_subsys_mutex, (PZERO - 4) | PCATCH,
			    "msgwait", 0);
#ifdef MSG_DEBUG_OK
			printf("good morning, eval=%d\n", eval);
#endif
			if (we_own_it)
				msqptr->msg_perm.mode &= ~MSG_LOCKED;
			if (eval != 0) {
#ifdef MSG_DEBUG_OK
				printf("msgsnd:  interrupted system call\n");
#endif
				eval = EINTR;
				goto msgsndout;
			}

			/*
			 * Make sure that the msq queue still exists
			 */

			if (msqptr->msg_qbytes == 0) {
#ifdef MSG_DEBUG_OK
				printf("msqid deleted\n");
#endif
				/* The SVID says to return EIDRM. */
#ifdef EIDRM
				eval = EIDRM;
#else
				/* Unfortunately, BSD doesn't define that code
				   yet! */
				eval = EINVAL;
#endif
				goto msgsndout;
			
			}

		} else {
#ifdef MSG_DEBUG_OK
			printf("got all the resources that we need\n");
#endif
			break;
		}
	}

	/*
	 * We have the resources that we need.
	 * Make sure!
	 */

	if (msqptr->msg_perm.mode & MSG_LOCKED)
		panic("msg_perm.mode & MSG_LOCKED");
	if (segs_needed > nfree_msgmaps)
		panic("segs_needed > nfree_msgmaps");
	if (msgsz + msqptr->msg_cbytes > msqptr->msg_qbytes)
		panic("msgsz + msg_cbytes > msg_qbytes");
	if (free_msghdrs == NULL)
		panic("no more msghdrs");

	/*
	 * Re-lock the user_msqid_ds in case we page-fault when copying in
	 * the message
	 */

	if ((msqptr->msg_perm.mode & MSG_LOCKED) != 0)
		panic("user_msqid_ds is already locked");
	msqptr->msg_perm.mode |= MSG_LOCKED;

	/*
	 * Allocate a message header
	 */

	msghdr = free_msghdrs;
	free_msghdrs = msghdr->msg_next;
	msghdr->msg_spot = -1;
	msghdr->msg_ts = msgsz;

	/*
	 * Allocate space for the message
	 */

	while (segs_needed > 0) {
		if (nfree_msgmaps <= 0)
			panic("not enough msgmaps");
		if (free_msgmaps == -1)
			panic("nil free_msgmaps");
		next = free_msgmaps;
		if (next <= -1)
			panic("next too low #1");
		if (next >= msginfo.msgseg)
			panic("next out of range #1");
#ifdef MSG_DEBUG_OK
		printf("allocating segment %d to message\n", next);
#endif
		free_msgmaps = msgmaps[next].next;
		nfree_msgmaps--;
		msgmaps[next].next = msghdr->msg_spot;
		msghdr->msg_spot = next;
		segs_needed--;
	}

	/*
	 * Copy in the message type.  For a 64 bit process, this is 64 bits,
	 * but we only ever use the low 32 bits, so the cast is OK.
	 */
	if (IS_64BIT_PROCESS(p)) {
		SYSV_MSG_SUBSYS_UNLOCK();
		eval = copyin(user_msgp, &msgtype, sizeof(msgtype));
		SYSV_MSG_SUBSYS_LOCK();
		msghdr->msg_type = CAST_DOWN(long,msgtype);
		user_msgp = user_msgp + sizeof(msgtype);	/* ptr math */
	} else {
		SYSV_MSG_SUBSYS_UNLOCK();
		eval = copyin(user_msgp, &msghdr->msg_type, sizeof(long));
		SYSV_MSG_SUBSYS_LOCK();
		user_msgp = user_msgp + sizeof(long);		/* ptr math */
	}

	if (eval != 0) {
#ifdef MSG_DEBUG_OK
		printf("error %d copying the message type\n", eval);
#endif
		msg_freehdr(msghdr);
		msqptr->msg_perm.mode &= ~MSG_LOCKED;
		wakeup((caddr_t)msqptr);
		goto msgsndout;
	}


	/*
	 * Validate the message type
	 */
	if (msghdr->msg_type < 1) {
		msg_freehdr(msghdr);
		msqptr->msg_perm.mode &= ~MSG_LOCKED;
		wakeup((caddr_t)msqptr);
#ifdef MSG_DEBUG_OK
		printf("mtype (%d) < 1\n", msghdr->msg_type);
#endif
		eval = EINVAL;
		goto msgsndout;
	}

	/*
	 * Copy in the message body
	 */
	next = msghdr->msg_spot;
	while (msgsz > 0) {
		size_t tlen;
		/* compare input (size_t) value against restrict (int) value */
		if (msgsz > (size_t)msginfo.msgssz)
			tlen = msginfo.msgssz;
		else
			tlen = msgsz;
		if (next <= -1)
			panic("next too low #2");
		if (next >= msginfo.msgseg)
			panic("next out of range #2");

		SYSV_MSG_SUBSYS_UNLOCK();
		eval = copyin(user_msgp, &msgpool[next * msginfo.msgssz], tlen);
		SYSV_MSG_SUBSYS_LOCK();

		if (eval != 0) {
#ifdef MSG_DEBUG_OK
			printf("error %d copying in message segment\n", eval);
#endif
			msg_freehdr(msghdr);
			msqptr->msg_perm.mode &= ~MSG_LOCKED;
			wakeup((caddr_t)msqptr);

			goto msgsndout;
		}
		msgsz -= tlen;
		user_msgp = user_msgp + tlen;	/* ptr math */
		next = msgmaps[next].next;
	}
	if (next != -1)
		panic("didn't use all the msg segments");

	/*
	 * We've got the message.  Unlock the user_msqid_ds.
	 */

	msqptr->msg_perm.mode &= ~MSG_LOCKED;

	/*
	 * Make sure that the user_msqid_ds is still allocated.
	 */

	if (msqptr->msg_qbytes == 0) {
		msg_freehdr(msghdr);
		wakeup((caddr_t)msqptr);
		/* The SVID says to return EIDRM. */
#ifdef EIDRM
		eval = EIDRM;
#else
		/* Unfortunately, BSD doesn't define that code yet! */
		eval = EINVAL;
#endif
		goto msgsndout;
	}

	/*
	 * Put the message into the queue
	 */

	if (msqptr->msg_first == NULL) {
		msqptr->msg_first = msghdr;
		msqptr->msg_last = msghdr;
	} else {
		msqptr->msg_last->msg_next = msghdr;
		msqptr->msg_last = msghdr;
	}
	msqptr->msg_last->msg_next = NULL;

	msqptr->msg_cbytes += msghdr->msg_ts;
	msqptr->msg_qnum++;
	msqptr->msg_lspid = p->p_pid;
	msqptr->msg_stime = sysv_msgtime();

	wakeup((caddr_t)msqptr);
	*retval = 0;
	eval = 0;

msgsndout:
	SYSV_MSG_SUBSYS_UNLOCK();
	return(eval);
}


int
msgrcv(struct proc *p, struct msgrcv_args *uap, user_ssize_t *retval)
{
	int msqid = uap->msqid;
	user_addr_t user_msgp = uap->msgp;
	size_t msgsz = (size_t)uap->msgsz;	/* limit to 4G */
	long msgtyp = (long)uap->msgtyp;	/* limit to 32 bits */
	int msgflg = uap->msgflg;
	size_t len;
	struct user_msqid_ds *msqptr;
	struct msg *msghdr;
	int eval;
	short next;
	user_long_t msgtype;
	long msg_type_long;

	SYSV_MSG_SUBSYS_LOCK();
	msginit( 0);

#ifdef MSG_DEBUG_OK
	printf("call to msgrcv(%d, 0x%qx, %d, %ld, %d)\n", msqid, user_msgp,
	    msgsz, msgtyp, msgflg);
#endif

	AUDIT_ARG(svipc_id, msqid);
	msqid = IPCID_TO_IX(msqid);

	if (msqid < 0 || msqid >= msginfo.msgmni) {
#ifdef MSG_DEBUG_OK
		printf("msqid (%d) out of range (0<=msqid<%d)\n", msqid,
		    msginfo.msgmni);
#endif
		eval = EINVAL;
		goto msgrcvout;
	}

	msqptr = &msqids[msqid];
	if (msqptr->msg_qbytes == 0) {
#ifdef MSG_DEBUG_OK
		printf("no such message queue id\n");
#endif
		eval = EINVAL;
		goto msgrcvout;
	}
	if (msqptr->msg_perm.seq != IPCID_TO_SEQ(uap->msqid)) {
#ifdef MSG_DEBUG_OK
		printf("wrong sequence number\n");
#endif
		eval = EINVAL;
		goto msgrcvout;
	}

	if ((eval = ipcperm(kauth_cred_get(), &msqptr->msg_perm, IPC_R))) {
#ifdef MSG_DEBUG_OK
		printf("requester doesn't have read access\n");
#endif
		goto msgrcvout;
	}

	msghdr = NULL;
	while (msghdr == NULL) {
		if (msgtyp == 0) {
			msghdr = msqptr->msg_first;
			if (msghdr != NULL) {
				if (msgsz < msghdr->msg_ts &&
				    (msgflg & MSG_NOERROR) == 0) {
#ifdef MSG_DEBUG_OK
					printf("first message on the queue is too big (want %d, got %d)\n",
					    msgsz, msghdr->msg_ts);
#endif
					eval = E2BIG;
					goto msgrcvout;
				}
				if (msqptr->msg_first == msqptr->msg_last) {
					msqptr->msg_first = NULL;
					msqptr->msg_last = NULL;
				} else {
					msqptr->msg_first = msghdr->msg_next;
					if (msqptr->msg_first == NULL)
						panic("msg_first/last messed up #1");
				}
			}
		} else {
			struct msg *previous;
			struct msg **prev;

			previous = NULL;
			prev = &(msqptr->msg_first);
			while ((msghdr = *prev) != NULL) {
				/*
				 * Is this message's type an exact match or is
				 * this message's type less than or equal to
				 * the absolute value of a negative msgtyp?
				 * Note that the second half of this test can
				 * NEVER be true if msgtyp is positive since
				 * msg_type is always positive!
				 */

				if (msgtyp == msghdr->msg_type ||
				    msghdr->msg_type <= -msgtyp) {
#ifdef MSG_DEBUG_OK
					printf("found message type %d, requested %d\n",
					    msghdr->msg_type, msgtyp);
#endif
					if (msgsz < msghdr->msg_ts &&
					    (msgflg & MSG_NOERROR) == 0) {
#ifdef MSG_DEBUG_OK
						printf("requested message on the queue is too big (want %d, got %d)\n",
						    msgsz, msghdr->msg_ts);
#endif
						eval = E2BIG;
						goto msgrcvout;
					}
					*prev = msghdr->msg_next;
					if (msghdr == msqptr->msg_last) {
						if (previous == NULL) {
							if (prev !=
							    &msqptr->msg_first)
								panic("msg_first/last messed up #2");
							msqptr->msg_first =
							    NULL;
							msqptr->msg_last =
							    NULL;
						} else {
							if (prev ==
							    &msqptr->msg_first)
								panic("msg_first/last messed up #3");
							msqptr->msg_last =
							    previous;
						}
					}
					break;
				}
				previous = msghdr;
				prev = &(msghdr->msg_next);
			}
		}

		/*
		 * We've either extracted the msghdr for the appropriate
		 * message or there isn't one.
		 * If there is one then bail out of this loop.
		 */

		if (msghdr != NULL)
			break;

		/*
		 * Hmph!  No message found.  Does the user want to wait?
		 */

		if ((msgflg & IPC_NOWAIT) != 0) {
#ifdef MSG_DEBUG_OK
			printf("no appropriate message found (msgtyp=%d)\n",
			    msgtyp);
#endif
			/* The SVID says to return ENOMSG. */
#ifdef ENOMSG
			eval = ENOMSG;
#else
			/* Unfortunately, BSD doesn't define that code yet! */
			eval = EAGAIN;
#endif
			goto msgrcvout;
		}

		/*
		 * Wait for something to happen
		 */

#ifdef MSG_DEBUG_OK
		printf("msgrcv:  goodnight\n");
#endif
		eval = msleep((caddr_t)msqptr, &sysv_msg_subsys_mutex, (PZERO - 4) | PCATCH, "msgwait",
		    0);
#ifdef MSG_DEBUG_OK
		printf("msgrcv:  good morning (eval=%d)\n", eval);
#endif

		if (eval != 0) {
#ifdef MSG_DEBUG_OK
			printf("msgsnd:  interrupted system call\n");
#endif
			eval = EINTR;
			goto msgrcvout;
		}

		/*
		 * Make sure that the msq queue still exists
		 */

		if (msqptr->msg_qbytes == 0 ||
		    msqptr->msg_perm.seq != IPCID_TO_SEQ(uap->msqid)) {
#ifdef MSG_DEBUG_OK
			printf("msqid deleted\n");
#endif
			/* The SVID says to return EIDRM. */
#ifdef EIDRM
			eval = EIDRM;
#else
			/* Unfortunately, BSD doesn't define that code yet! */
			eval = EINVAL;
#endif
			goto msgrcvout;
		}
	}

	/*
	 * Return the message to the user.
	 *
	 * First, do the bookkeeping (before we risk being interrupted).
	 */

	msqptr->msg_cbytes -= msghdr->msg_ts;
	msqptr->msg_qnum--;
	msqptr->msg_lrpid = p->p_pid;
	msqptr->msg_rtime = sysv_msgtime();

	/*
	 * Make msgsz the actual amount that we'll be returning.
	 * Note that this effectively truncates the message if it is too long
	 * (since msgsz is never increased).
	 */

#ifdef MSG_DEBUG_OK
	printf("found a message, msgsz=%d, msg_ts=%d\n", msgsz,
	    msghdr->msg_ts);
#endif
	if (msgsz > msghdr->msg_ts)
		msgsz = msghdr->msg_ts;

	/*
	 * Return the type to the user.
	 */

	/*
	 * Copy out the message type.  For a 64 bit process, this is 64 bits,
	 * but we only ever use the low 32 bits, so the cast is OK.
	 */
	if (IS_64BIT_PROCESS(p)) {
		msgtype = msghdr->msg_type;
		SYSV_MSG_SUBSYS_UNLOCK();
		eval = copyout(&msgtype, user_msgp, sizeof(msgtype));
		SYSV_MSG_SUBSYS_LOCK();
		user_msgp = user_msgp + sizeof(msgtype);	/* ptr math */
	} else {
		msg_type_long = msghdr->msg_type;
		SYSV_MSG_SUBSYS_UNLOCK();
		eval = copyout(&msg_type_long, user_msgp, sizeof(long));
		SYSV_MSG_SUBSYS_LOCK();
		user_msgp = user_msgp + sizeof(long);		/* ptr math */
	}

	if (eval != 0) {
#ifdef MSG_DEBUG_OK
		printf("error (%d) copying out message type\n", eval);
#endif
		msg_freehdr(msghdr);
		wakeup((caddr_t)msqptr);

		goto msgrcvout;
	}


	/*
	 * Return the segments to the user
	 */

	next = msghdr->msg_spot;
	for (len = 0; len < msgsz; len += msginfo.msgssz) {
		size_t tlen;

		/* compare input (size_t) value against restrict (int) value */
		if (msgsz > (size_t)msginfo.msgssz)
			tlen = msginfo.msgssz;
		else
			tlen = msgsz;
		if (next <= -1)
			panic("next too low #3");
		if (next >= msginfo.msgseg)
			panic("next out of range #3");
		SYSV_MSG_SUBSYS_UNLOCK();
		eval = copyout(&msgpool[next * msginfo.msgssz],
		    user_msgp, tlen);
		SYSV_MSG_SUBSYS_LOCK();
		if (eval != 0) {
#ifdef MSG_DEBUG_OK
			printf("error (%d) copying out message segment\n",
			    eval);
#endif
			msg_freehdr(msghdr);
			wakeup((caddr_t)msqptr);
			goto msgrcvout;
		}
		user_msgp = user_msgp + tlen;	/* ptr math */
		next = msgmaps[next].next;
	}

	/*
	 * Done, return the actual number of bytes copied out.
	 */

	msg_freehdr(msghdr);
	wakeup((caddr_t)msqptr);
	*retval = msgsz;
	eval = 0;
msgrcvout:
	SYSV_MSG_SUBSYS_UNLOCK();
	return(eval);
}

static int
IPCS_msg_sysctl(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	int error;
	int cursor;
	union {
		struct IPCS_command u32;
		struct user_IPCS_command u64;
	} ipcs;
	struct msqid_ds msqid_ds32;	/* post conversion, 32 bit version */
	void *msqid_dsp;
	size_t ipcs_sz = sizeof(struct user_IPCS_command);
	size_t msqid_ds_sz = sizeof(struct user_msqid_ds);
	struct proc *p = current_proc();

	if (!IS_64BIT_PROCESS(p)) {
		ipcs_sz = sizeof(struct IPCS_command);
		msqid_ds_sz = sizeof(struct msqid_ds);
	}

	/* Copy in the command structure */
	if ((error = SYSCTL_IN(req, &ipcs, ipcs_sz)) != 0) {
		return(error);
	}

	if (!IS_64BIT_PROCESS(p))	/* convert in place */
		ipcs.u64.ipcs_data = CAST_USER_ADDR_T(ipcs.u32.ipcs_data);

	/* Let us version this interface... */
	if (ipcs.u64.ipcs_magic != IPCS_MAGIC) {
		return(EINVAL);
	}

	SYSV_MSG_SUBSYS_LOCK();

	switch(ipcs.u64.ipcs_op) {
	case IPCS_MSG_CONF:	/* Obtain global configuration data */
		if (ipcs.u64.ipcs_datalen != sizeof(struct msginfo)) {
			error = ERANGE;
			break;
		}
		if (ipcs.u64.ipcs_cursor != 0) {	/* fwd. compat. */
			error = EINVAL;
			break;
		}
		SYSV_MSG_SUBSYS_UNLOCK();
		error = copyout(&msginfo, ipcs.u64.ipcs_data, ipcs.u64.ipcs_datalen);
		SYSV_MSG_SUBSYS_LOCK();
		break;

	case IPCS_MSG_ITER:	/* Iterate over existing segments */
		/* Not done up top so we can set limits via sysctl (later) */
		msginit( 0);

		cursor = ipcs.u64.ipcs_cursor;
		if (cursor < 0 || cursor >= msginfo.msgmni) {
			error = ERANGE;
			break;
		}
		if (ipcs.u64.ipcs_datalen != (int)msqid_ds_sz) {
			error = ENOMEM;
			break;
		}
		for( ; cursor < msginfo.msgmni; cursor++) {
			if (msqids[cursor].msg_qbytes != 0)	/* allocated */
				break;
			continue;
		}
		if (cursor == msginfo.msgmni) {
			error = ENOENT;
			break;
		}

		msqid_dsp = &msqids[cursor];	/* default: 64 bit */

		/*
		 * If necessary, convert the 64 bit kernel segment
		 * descriptor to a 32 bit user one.
		 */
		if (!IS_64BIT_PROCESS(p)) {
			msqid_ds_64to32(msqid_dsp, &msqid_ds32);
			msqid_dsp = &msqid_ds32;
		}
		SYSV_MSG_SUBSYS_UNLOCK();
		error = copyout(msqid_dsp, ipcs.u64.ipcs_data, ipcs.u64.ipcs_datalen);
		if (!error) {
			/* update cursor */
			ipcs.u64.ipcs_cursor = cursor + 1;

			if (!IS_64BIT_PROCESS(p))	/* convert in place */
				ipcs.u32.ipcs_data = CAST_DOWN(void *,ipcs.u64.ipcs_data);
			error = SYSCTL_OUT(req, &ipcs, ipcs_sz);
		}
		SYSV_MSG_SUBSYS_LOCK();
		break;

	default:
		error = EINVAL;
		break;
	}

	SYSV_MSG_SUBSYS_UNLOCK();
	return(error);
}

SYSCTL_DECL(_kern_sysv_ipcs);
SYSCTL_PROC(_kern_sysv_ipcs, OID_AUTO, msg, CTLFLAG_RW|CTLFLAG_ANYBODY,
	0, 0, IPCS_msg_sysctl,
	"S,IPCS_msg_command",
	"ipcs msg command interface");
