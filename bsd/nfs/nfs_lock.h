/*-
 * Copyright (c) 1998 Berkeley Software Design, Inc. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Berkeley Software Design Inc's name may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN INC BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      from nfs_lock.h,v 2.2 1998/04/28 19:38:41 don Exp
 * $FreeBSD$
 */

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

/*
 * lockd uses the nfsclnt system call for the unique kernel services it needs.
 * It passes in a request structure with a version number at the start.
 * This prevents libc from needing to change if the information passed
 * between lockd and the kernel needs to change.
 *
 * If a structure changes, you must bump the version number.
 */

#include <nfs/nfsproto.h>

/*
 * The fifo where the kernel writes requests for locks on remote NFS files,
 * and where lockd reads these requests.  Note this is no longer hardwired
 * in the kernel binary - lockd passes the file descriptor down via nfsclnt()
 */
#define	_PATH_LCKFIFO	"/var/run/nfslockd"

/*
 * The structure that the kernel hands lockd for each lock request.
 */
#define LOCKD_MSG_VERSION	3
typedef struct nfs_lock_msg {
	int			lm_version;		/* LOCKD_MSG version */
	int			lm_flags;		/* request flags */
	u_int64_t		lm_xid;			/* unique message transaction ID */
	struct flock		lm_fl;			/* The lock request. */
	struct sockaddr_storage lm_addr;		/* The address. */
	size_t			lm_fh_len;		/* The file handle length. */
	struct xucred		lm_cred;		/* user cred for lock req */
	u_int8_t		lm_fh[NFS_SMALLFH];	/* The file handle. */
} LOCKD_MSG;

/* lm_flags */
#define LOCKD_MSG_BLOCK		0x0001	/* a blocking request */
#define LOCKD_MSG_TEST		0x0002	/* just a lock test */
#define LOCKD_MSG_NFSV3		0x0004  /* NFSv3 request */
#define LOCKD_MSG_CANCEL	0x0008  /* cancelling blocked request */

/* The structure used to maintain the pending request queue */
typedef struct nfs_lock_msg_request {
	TAILQ_ENTRY(nfs_lock_msg_request) lmr_next;	/* in-kernel pending request list */
	int			lmr_answered;		/* received an answer? */
	int			lmr_errno;		/* return status */
	int			lmr_saved_errno;	/* original return status */
	LOCKD_MSG		lmr_msg;		/* the message */
} LOCKD_MSG_REQUEST;

TAILQ_HEAD(nfs_lock_msg_queue, nfs_lock_msg_request);
typedef struct nfs_lock_msg_queue LOCKD_MSG_QUEUE;


/*
 * The structure that lockd hands the kernel for each lock answer.
 */
#define LOCKD_ANS_VERSION	2
struct lockd_ans {
	int		la_version;		/* lockd_ans version */
	int		la_errno;		/* return status */
	u_int64_t	la_xid;			/* unique message transaction ID */
	int		la_flags;		/* answer flags */
	pid_t		la_pid;			/* pid of lock requester/owner */
	off_t		la_start;		/* lock starting offset */
	off_t		la_len;			/* lock length */
	size_t		la_fh_len;		/* The file handle length. */
	u_int8_t	la_fh[NFS_SMALLFH];	/* The file handle. */
};

/* la_flags */
#define LOCKD_ANS_GRANTED	0x0001	/* NLM_GRANTED request */
#define LOCKD_ANS_LOCK_INFO	0x0002	/* lock info valid */
#define LOCKD_ANS_LOCK_EXCL	0x0004	/* lock is exclusive */


#ifdef KERNEL
void	nfs_lockinit(void);
int	nfs_dolock(struct vop_advlock_args *ap);
int	nfslockdans(struct proc *p, struct lockd_ans *ansp);
int	nfslockdfd(struct proc *p, int fd);
int	nfslockdwait(struct proc *p);
#endif
#endif /* __APPLE_API_PRIVATE */
