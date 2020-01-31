/*
 * Copyright (c) 2011-2014 Apple Inc.  All rights reserved.
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
#include <stdint.h>
#include <sys/param.h>
#include <sys/mount_internal.h>
#include <sys/malloc.h>
#include <sys/queue.h>

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <kern/debug.h>
#include <kern/thread.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>

#ifdef NFS_UC_DEBUG
#define DPRINT(fmt, ...) printf(fmt,## __VA_ARGS__)
#else
#define DPRINT(fmt, ...)
#endif

struct nfsrv_uc_arg {
	TAILQ_ENTRY(nfsrv_uc_arg) nua_svcq;
	socket_t nua_so;
	struct nfsrv_sock *nua_slp;
	int nua_waitflag;  /* Should always be MBUF_DONTWAIT */
	uint32_t nua_flags;
	uint32_t nua_qi;
};
#define NFS_UC_QUEUED   0x0001

#define NFS_UC_HASH_SZ 7
#define NFS_UC_HASH(x) ((((uint32_t)(uintptr_t)(x)) >> 3) % nfsrv_uc_thread_count)

TAILQ_HEAD(nfsrv_uc_q, nfsrv_uc_arg);

static struct nfsrv_uc_queue {
	lck_mtx_t               *ucq_lock;
	struct nfsrv_uc_q       ucq_queue[1];
	thread_t                ucq_thd;
	uint32_t                ucq_flags;
} nfsrv_uc_queue_tbl[NFS_UC_HASH_SZ];
#define NFS_UC_QUEUE_SLEEPING   0x0001

static lck_grp_t *nfsrv_uc_group;
static lck_mtx_t *nfsrv_uc_shutdown_lock;
static volatile int nfsrv_uc_shutdown = 0;
static int32_t nfsrv_uc_thread_count;

extern kern_return_t thread_terminate(thread_t);

#ifdef NFS_UC_Q_DEBUG
int nfsrv_uc_use_proxy = 1;
uint32_t nfsrv_uc_queue_limit;
uint32_t nfsrv_uc_queue_max_seen;
volatile uint32_t nfsrv_uc_queue_count;
#endif

/*
 * Thread that dequeues up-calls and runs the nfsrv_rcv routine
 */
static void
nfsrv_uc_thread(void *arg, wait_result_t wr __unused)
{
	int qi = (int)(uintptr_t)arg;
	int error;
	struct nfsrv_uc_arg *ep = NULL;
	struct nfsrv_uc_queue *myqueue = &nfsrv_uc_queue_tbl[qi];

	DPRINT("nfsrv_uc_thread %d started\n", qi);
	while (!nfsrv_uc_shutdown) {
		lck_mtx_lock(myqueue->ucq_lock);

		while (!nfsrv_uc_shutdown && TAILQ_EMPTY(myqueue->ucq_queue)) {
			myqueue->ucq_flags |= NFS_UC_QUEUE_SLEEPING;
			error = msleep(myqueue, myqueue->ucq_lock, PSOCK, "nfsd_upcall_handler", NULL);
			myqueue->ucq_flags &= ~NFS_UC_QUEUE_SLEEPING;
			if (error) {
				printf("nfsrv_uc_thread received error %d\n", error);
			}
		}
		if (nfsrv_uc_shutdown) {
			lck_mtx_unlock(myqueue->ucq_lock);
			break;
		}


		ep = TAILQ_FIRST(myqueue->ucq_queue);
		DPRINT("nfsrv_uc_thread:%d dequeue %p from %p\n", qi, ep, myqueue);

		TAILQ_REMOVE(myqueue->ucq_queue, ep, nua_svcq);

		ep->nua_flags &= ~NFS_UC_QUEUED;

		lck_mtx_unlock(myqueue->ucq_lock);

#ifdef NFS_UC_Q_DEBUG
		OSDecrementAtomic(&nfsrv_uc_queue_count);
#endif

		DPRINT("calling nfsrv_rcv for %p\n", (void *)ep->nua_slp);
		nfsrv_rcv(ep->nua_so, (void *)ep->nua_slp, ep->nua_waitflag);
	}

	lck_mtx_lock(nfsrv_uc_shutdown_lock);
	nfsrv_uc_thread_count--;
	wakeup(&nfsrv_uc_thread_count);
	lck_mtx_unlock(nfsrv_uc_shutdown_lock);

	thread_terminate(current_thread());
}

/*
 * Dequeue a closed nfsrv_sock if needed from the up-call queue.
 * Call from nfsrv_zapsock
 */
void
nfsrv_uc_dequeue(struct nfsrv_sock *slp)
{
	struct nfsrv_uc_arg *ap = slp->ns_ua;
	struct nfsrv_uc_queue *myqueue = &nfsrv_uc_queue_tbl[ap->nua_qi];

	/*
	 * We assume that the socket up-calls have been stop and the socket
	 * is shutting down so no need for acquiring the lock to check that
	 * the flag is cleared.
	 */
	if (ap == NULL || (ap->nua_flags & NFS_UC_QUEUED) == 0) {
		return;
	}
	/* If we're queued we might race with nfsrv_uc_thread */
	lck_mtx_lock(myqueue->ucq_lock);
	if (ap->nua_flags & NFS_UC_QUEUED) {
		printf("nfsrv_uc_dequeue remove %p\n", ap);
		TAILQ_REMOVE(myqueue->ucq_queue, ap, nua_svcq);
		ap->nua_flags &= ~NFS_UC_QUEUED;
#ifdef NFS_UC_Q_DEBUG
		OSDecrementAtomic(&nfsrv_uc_queue_count);
#endif
	}
	FREE(slp->ns_ua, M_TEMP);
	slp->ns_ua = NULL;
	lck_mtx_unlock(myqueue->ucq_lock);
}

/*
 * Allocate and initialize globals for nfsrv_sock up-call support.
 */
void
nfsrv_uc_init(void)
{
	int i;

	nfsrv_uc_group = lck_grp_alloc_init("nfs_upcall_locks", LCK_GRP_ATTR_NULL);
	for (i = 0; i < NFS_UC_HASH_SZ; i++) {
		TAILQ_INIT(nfsrv_uc_queue_tbl[i].ucq_queue);
		nfsrv_uc_queue_tbl[i].ucq_lock = lck_mtx_alloc_init(nfsrv_uc_group, LCK_ATTR_NULL);
		nfsrv_uc_queue_tbl[i].ucq_thd = THREAD_NULL;
		nfsrv_uc_queue_tbl[i].ucq_flags = 0;
	}
	nfsrv_uc_shutdown_lock = lck_mtx_alloc_init(nfsrv_uc_group, LCK_ATTR_NULL);
}

/*
 * Start up-call threads to service nfsrv_sock(s)
 * Called from the first call of nfsrv_uc_addsock
 */
static void
nfsrv_uc_start(void)
{
	int32_t i;
	int error;

#ifdef NFS_UC_Q_DEBUG
	if (!nfsrv_uc_use_proxy) {
		return;
	}
#endif
	DPRINT("nfsrv_uc_start\n");

	/* Wait until previous shutdown finishes */
	lck_mtx_lock(nfsrv_uc_shutdown_lock);
	while (nfsrv_uc_shutdown || nfsrv_uc_thread_count > 0) {
		msleep(&nfsrv_uc_thread_count, nfsrv_uc_shutdown_lock, PSOCK, "nfsd_upcall_shutdown_wait", NULL);
	}

	/* Start up-call threads */
	for (i = 0; i < NFS_UC_HASH_SZ; i++) {
		error = kernel_thread_start(nfsrv_uc_thread, (void *)(uintptr_t)i, &nfsrv_uc_queue_tbl[nfsrv_uc_thread_count].ucq_thd);
		if (!error) {
			nfsrv_uc_thread_count++;
		} else {
			printf("nfsd: Could not start nfsrv_uc_thread: %d\n", error);
		}
	}
	if (nfsrv_uc_thread_count == 0) {
		printf("nfsd: Could not start nfsd proxy up-call service. Falling back\n");
		goto out;
	}

out:
#ifdef NFS_UC_Q_DEBUG
	nfsrv_uc_queue_count = 0ULL;
	nfsrv_uc_queue_max_seen = 0ULL;
#endif
	lck_mtx_unlock(nfsrv_uc_shutdown_lock);
}

/*
 * Stop the up-call threads.
 * Called from nfsrv_uc_cleanup.
 */
static void
nfsrv_uc_stop(void)
{
	int32_t i;
	int32_t thread_count = nfsrv_uc_thread_count;

	DPRINT("Entering nfsrv_uc_stop\n");

	/* Signal up-call threads to stop */
	nfsrv_uc_shutdown = 1;
	for (i = 0; i < thread_count; i++) {
		lck_mtx_lock(nfsrv_uc_queue_tbl[i].ucq_lock);
		wakeup(&nfsrv_uc_queue_tbl[i]);
		lck_mtx_unlock(nfsrv_uc_queue_tbl[i].ucq_lock);
	}

	/* Wait until they are done shutting down */
	lck_mtx_lock(nfsrv_uc_shutdown_lock);
	while (nfsrv_uc_thread_count > 0) {
		msleep(&nfsrv_uc_thread_count, nfsrv_uc_shutdown_lock, PSOCK, "nfsd_upcall_shutdown_stop", NULL);
	}

	/* Deallocate old threads */
	for (i = 0; i < nfsrv_uc_thread_count; i++) {
		if (nfsrv_uc_queue_tbl[i].ucq_thd != THREAD_NULL) {
			thread_deallocate(nfsrv_uc_queue_tbl[i].ucq_thd);
		}
		nfsrv_uc_queue_tbl[i].ucq_thd = THREAD_NULL;
	}

	/* Enable restarting */
	nfsrv_uc_shutdown = 0;
	lck_mtx_unlock(nfsrv_uc_shutdown_lock);
}

/*
 * Shutdown up-calls for nfsrv_socks.
 *	Make sure nothing is queued on the up-call queues
 *	Shutdown the up-call threads
 * Called from nfssvc_cleanup.
 */
void
nfsrv_uc_cleanup(void)
{
	int i;

	DPRINT("Entering nfsrv_uc_cleanup\n");

	/*
	 * Every thing should be dequeued at this point or will be as sockets are closed
	 * but to be safe, we'll make sure.
	 */
	for (i = 0; i < NFS_UC_HASH_SZ; i++) {
		struct nfsrv_uc_queue *queue = &nfsrv_uc_queue_tbl[i];

		lck_mtx_lock(queue->ucq_lock);
		while (!TAILQ_EMPTY(queue->ucq_queue)) {
			struct nfsrv_uc_arg *ep = TAILQ_FIRST(queue->ucq_queue);
			TAILQ_REMOVE(queue->ucq_queue, ep, nua_svcq);
			ep->nua_flags &= ~NFS_UC_QUEUED;
		}
		lck_mtx_unlock(queue->ucq_lock);
	}

	nfsrv_uc_stop();
}

/*
 * This is the nfs up-call routine for server sockets.
 * We used to set nfsrv_rcv as the up-call routine, but
 * recently that seems like we are doing to much work for
 * the interface thread, so we just queue the arguments
 * that we would have gotten for nfsrv_rcv and let a
 * worker thread dequeue them and pass them on to nfsrv_rcv.
 */
static void
nfsrv_uc_proxy(socket_t so, void *arg, int waitflag)
{
	struct nfsrv_uc_arg *uap = (struct nfsrv_uc_arg *)arg;
	int qi = uap->nua_qi;
	struct nfsrv_uc_queue *myqueue = &nfsrv_uc_queue_tbl[qi];

	lck_mtx_lock(myqueue->ucq_lock);
	DPRINT("nfsrv_uc_proxy called for %p (%p)\n", uap, uap->nua_slp);
	DPRINT("\tUp-call queued on %d for wakeup of %p\n", qi, myqueue);
	if (uap == NULL || uap->nua_flags & NFS_UC_QUEUED) {
		lck_mtx_unlock(myqueue->ucq_lock);
		return;  /* Already queued or freed */
	}

	uap->nua_so = so;
	uap->nua_waitflag = waitflag;

	TAILQ_INSERT_TAIL(myqueue->ucq_queue, uap, nua_svcq);

	uap->nua_flags |= NFS_UC_QUEUED;
	if (myqueue->ucq_flags | NFS_UC_QUEUE_SLEEPING) {
		wakeup(myqueue);
	}

#ifdef NFS_UC_Q_DEBUG
	{
		uint32_t count = OSIncrementAtomic(&nfsrv_uc_queue_count);

		/* This is a bit racey but just for debug */
		if (count > nfsrv_uc_queue_max_seen) {
			nfsrv_uc_queue_max_seen = count;
		}

		if (nfsrv_uc_queue_limit && count > nfsrv_uc_queue_limit) {
			panic("nfsd up-call queue limit exceeded\n");
		}
	}
#endif
	lck_mtx_unlock(myqueue->ucq_lock);
}


/*
 * Set the up-call routine on the socket associated with the passed in
 * nfsrv_sock.
 * Assumes nfsd_mutex is held.
 */
void
nfsrv_uc_addsock(struct nfsrv_sock *slp, int start)
{
	int on = 1;
	struct nfsrv_uc_arg *arg;

	if (start && nfsrv_uc_thread_count == 0) {
		nfsrv_uc_start();
	}

	/*
	 * We don't take a lock since once we're up nfsrv_uc_thread_count does
	 * not change until shutdown and then we should not be adding sockets to
	 * generate up-calls.
	 */
	if (nfsrv_uc_thread_count) {
		MALLOC(arg, struct nfsrv_uc_arg *, sizeof(struct nfsrv_uc_arg), M_TEMP, M_WAITOK | M_ZERO);
		if (arg == NULL) {
			goto direct;
		}

		slp->ns_ua = arg;
		arg->nua_slp = slp;
		arg->nua_qi = NFS_UC_HASH(slp);

		sock_setupcall(slp->ns_so, nfsrv_uc_proxy, arg);
	} else {
direct:
		slp->ns_ua = NULL;
		DPRINT("setting nfsrv_rcv up-call\n");
		sock_setupcall(slp->ns_so, nfsrv_rcv, slp);
	}

	/* just playin' it safe */
	sock_setsockopt(slp->ns_so, SOL_SOCKET, SO_UPCALLCLOSEWAIT, &on, sizeof(on));

	return;
}
