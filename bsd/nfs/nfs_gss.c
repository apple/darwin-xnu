/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

/*************
 * These functions implement RPCSEC_GSS security for the NFS client and server.
 * The code is specific to the use of Kerberos v5 and the use of DES MAC MD5
 * protection as described in Internet RFC 2203 and 2623.
 *
 * In contrast to the original AUTH_SYS authentication, RPCSEC_GSS is stateful.
 * It requires the client and server negotiate a secure connection as part of a
 * security context. The context state is maintained in client and server structures.
 * On the client side, each user of an NFS mount is assigned their own context,
 * identified by UID, on their first use of the mount, and it persists until the
 * unmount or until the context is renewed.  Each user context has a corresponding
 * server context which the server maintains until the client destroys it, or
 * until the context expires.
 *
 * The client and server contexts are set up dynamically.  When a user attempts
 * to send an NFS request, if there is no context for the user, then one is
 * set up via an exchange of NFS null procedure calls as described in RFC 2203.
 * During this exchange, the client and server pass a security token that is
 * forwarded via Mach upcall to the gssd, which invokes the GSS-API to authenticate
 * the user to the server (and vice-versa). The client and server also receive
 * a unique session key that can be used to digitally sign the credentials and
 * verifier or optionally to provide data integrity and/or privacy.
 *
 * Once the context is complete, the client and server enter a normal data
 * exchange phase - beginning with the NFS request that prompted the context
 * creation. During this phase, the client's RPC header contains an RPCSEC_GSS
 * credential and verifier, and the server returns a verifier as well.
 * For simple authentication, the verifier contains a signed checksum of the
 * RPC header, including the credential.  The server's verifier has a signed
 * checksum of the current sequence number.
 *
 * Each client call contains a sequence number that nominally increases by one
 * on each request.  The sequence number is intended to prevent replay attacks.
 * Since the protocol can be used over UDP, there is some allowance for
 * out-of-sequence requests, so the server checks whether the sequence numbers
 * are within a sequence "window". If a sequence number is outside the lower
 * bound of the window, the server silently drops the request. This has some
 * implications for retransmission. If a request needs to be retransmitted, the
 * client must bump the sequence number even if the request XID is unchanged.
 *
 * When the NFS mount is unmounted, the client sends a "destroy" credential
 * to delete the server's context for each user of the mount. Since it's
 * possible for the client to crash or disconnect without sending the destroy
 * message, the server has a thread that reaps contexts that have been idle
 * too long.
 */

#include <stdint.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/mount_internal.h>
#include <sys/vnode.h>
#include <sys/ubc.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>

#include <kern/host.h>
#include <libkern/libkern.h>

#include <mach/task.h>
#include <mach/task_special_ports.h>
#include <mach/host_priv.h>
#include <mach/thread_act.h>
#include <mach/mig_errors.h>
#include <mach/vm_map.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <gssd/gssd_mach.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfs_gss.h>

#define NFS_GSS_MACH_MAX_RETRIES 3

#if NFSSERVER
u_long nfs_gss_svc_ctx_hash;
struct nfs_gss_svc_ctx_hashhead *nfs_gss_svc_ctx_hashtbl;
lck_mtx_t *nfs_gss_svc_ctx_mutex;
lck_grp_t *nfs_gss_svc_grp;
#endif /* NFSSERVER */

#if NFSCLIENT
lck_grp_t *nfs_gss_clnt_grp;
#endif /* NFSCLIENT */

/*
 * These octet strings are used to encode/decode ASN.1 tokens
 * in the RPCSEC_GSS verifiers.
 */
static u_char krb5_tokhead[] = { 0x60, 0x23 };
static u_char krb5_mech[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
static u_char krb5_mic[]  = { 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
static u_char krb5_wrap[] = { 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff };
static u_char iv0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // DES MAC Initialization Vector

/*
 * The size of the Kerberos v5 ASN.1 token
 * in the verifier.
 *
 * Note that the second octet of the krb5_tokhead (0x23) is a
 * DER-encoded size field that has variable length.  If the size
 * is 128 bytes or greater, then it uses two bytes, three bytes
 * if 65536 or greater, and so on.  Since the MIC tokens are
 * separate from the data, the size is always the same: 35 bytes (0x23).
 * However, the wrap token is different. Its size field includes the
 * size of the token + the encrypted data that follows. So the size
 * field may be two, three or four bytes.
 */
#define KRB5_SZ_TOKHEAD sizeof(krb5_tokhead)
#define KRB5_SZ_MECH	sizeof(krb5_mech)
#define KRB5_SZ_ALG	sizeof(krb5_mic) // 8 - same as krb5_wrap
#define KRB5_SZ_SEQ	8
#define KRB5_SZ_CKSUM	8
#define KRB5_SZ_EXTRA	3  // a wrap token may be longer by up to this many octets
#define KRB5_SZ_TOKEN	(KRB5_SZ_TOKHEAD + KRB5_SZ_MECH + KRB5_SZ_ALG + KRB5_SZ_SEQ + KRB5_SZ_CKSUM)
#define KRB5_SZ_TOKMAX	(KRB5_SZ_TOKEN + KRB5_SZ_EXTRA)

#if NFSCLIENT
static int	nfs_gss_clnt_ctx_find(struct nfsreq *);
static int	nfs_gss_clnt_ctx_failover(struct nfsreq *);
static int	nfs_gss_clnt_ctx_init(struct nfsreq *, struct nfs_gss_clnt_ctx *);
static int	nfs_gss_clnt_ctx_callserver(struct nfsreq *, struct nfs_gss_clnt_ctx *);
static char	*nfs_gss_clnt_svcname(struct nfsmount *);
static int	nfs_gss_clnt_gssd_upcall(struct nfsreq *, struct nfs_gss_clnt_ctx *);
static void	nfs_gss_clnt_ctx_remove(struct nfsmount *, struct nfs_gss_clnt_ctx *);
static int	nfs_gss_clnt_ctx_delay(struct nfsreq *, int *);
#endif /* NFSCLIENT */

#if NFSSERVER
static struct nfs_gss_svc_ctx *nfs_gss_svc_ctx_find(uint32_t);
static void	nfs_gss_svc_ctx_insert(struct nfs_gss_svc_ctx *);
static void	nfs_gss_svc_ctx_timer(void *, void *);
static int	nfs_gss_svc_gssd_upcall(struct nfs_gss_svc_ctx *);
static int	nfs_gss_svc_seqnum_valid(struct nfs_gss_svc_ctx *, uint32_t);
#endif /* NFSSERVER */

static void	task_release_special_port(mach_port_t);
static mach_port_t task_copy_special_port(mach_port_t);
static void	nfs_gss_mach_alloc_buffer(u_char *, uint32_t, vm_map_copy_t *);
static int	nfs_gss_mach_vmcopyout(vm_map_copy_t, uint32_t, u_char *);
static int	nfs_gss_token_get(des_key_schedule, u_char *, u_char *, int, uint32_t *, u_char *);
static int	nfs_gss_token_put(des_key_schedule, u_char *, u_char *, int, int, u_char *);
static int	nfs_gss_der_length_size(int);
static void	nfs_gss_der_length_put(u_char **, int);
static int	nfs_gss_der_length_get(u_char **);
static int	nfs_gss_mchain_length(mbuf_t);
static int	nfs_gss_append_chain(struct nfsm_chain *, mbuf_t);
static void	nfs_gss_nfsm_chain(struct nfsm_chain *, mbuf_t);
static void	nfs_gss_cksum_mchain(des_key_schedule, mbuf_t, u_char *, int, int, u_char *);
static void	nfs_gss_cksum_chain(des_key_schedule, struct nfsm_chain *, u_char *, int, int, u_char *);
static void	nfs_gss_cksum_rep(des_key_schedule, uint32_t, u_char *);
static void	nfs_gss_encrypt_mchain(u_char *, mbuf_t, int, int, int);
static void	nfs_gss_encrypt_chain(u_char *, struct nfsm_chain *, int, int, int);
static DES_LONG	des_cbc_cksum(des_cblock *, des_cblock *, long, des_key_schedule, des_cblock *);
static void	des_cbc_encrypt(des_cblock *, des_cblock *, long, des_key_schedule,
			des_cblock *, des_cblock *, int);

#if NFSSERVER
thread_call_t nfs_gss_svc_ctx_timer_call;
int nfs_gss_timer_on = 0;
uint32_t nfs_gss_ctx_count = 0;
const uint32_t nfs_gss_ctx_max = GSS_SVC_MAXCONTEXTS;
#endif /* NFSSERVER */

/*
 * Initialization when NFS starts
 */
void
nfs_gss_init(void)
{
#if NFSCLIENT
	nfs_gss_clnt_grp = lck_grp_alloc_init("rpcsec_gss_clnt", LCK_GRP_ATTR_NULL);
#endif /* NFSCLIENT */

#if NFSSERVER
	nfs_gss_svc_grp  = lck_grp_alloc_init("rpcsec_gss_svc",  LCK_GRP_ATTR_NULL);

	nfs_gss_svc_ctx_hashtbl = hashinit(SVC_CTX_HASHSZ, M_TEMP, &nfs_gss_svc_ctx_hash);
	nfs_gss_svc_ctx_mutex = lck_mtx_alloc_init(nfs_gss_svc_grp, LCK_ATTR_NULL);

	nfs_gss_svc_ctx_timer_call = thread_call_allocate(nfs_gss_svc_ctx_timer, NULL);
#endif /* NFSSERVER */
}

#if NFSCLIENT

/*
 * Find the context for a particular user.
 *
 * If the context doesn't already exist
 * then create a new context for this user.
 *
 * Note that the code allows superuser (uid == 0)
 * to adopt the context of another user.
 */
static int
nfs_gss_clnt_ctx_find(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;
	struct nfs_gss_clnt_ctx *cp;
	uid_t uid = kauth_cred_getuid(req->r_cred);
	int error = 0;
	int retrycnt = 0;

retry:	
	lck_mtx_lock(&nmp->nm_lock);
	TAILQ_FOREACH(cp, &nmp->nm_gsscl, gss_clnt_entries) {
		if (cp->gss_clnt_uid == uid) {
			if (cp->gss_clnt_flags & GSS_CTX_INVAL)
				continue;
			lck_mtx_unlock(&nmp->nm_lock);
			nfs_gss_clnt_ctx_ref(req, cp);
			return (0);
		}
	}

	if (uid == 0) {
		/*
		 * If superuser is trying to get access, then co-opt
		 * the first valid context in the list.
		 * XXX Ultimately, we need to allow superuser to
		 * go ahead and attempt to set up its own context
		 * in case one is set up for it.
		 */
		TAILQ_FOREACH(cp, &nmp->nm_gsscl, gss_clnt_entries) {
			if (!(cp->gss_clnt_flags & GSS_CTX_INVAL)) {
				lck_mtx_unlock(&nmp->nm_lock);
				nfs_gss_clnt_ctx_ref(req, cp);
				return (0);
			}
		}
	}

	/*
	 * Not found - create a new context
	 */

	/*
	 * If the thread is async, then it cannot get
	 * kerberos creds and set up a proper context.
	 * If no sec= mount option is given, attempt
	 * to failover to sec=sys.
	 */
	if (req->r_thread == NULL) {
		if ((nmp->nm_flag & NFSMNT_SECGIVEN) == 0) {
			error = nfs_gss_clnt_ctx_failover(req);
		} else {
			printf("nfs_gss_clnt_ctx_find: no context for async\n");
			error = EAUTH;
		}

		lck_mtx_unlock(&nmp->nm_lock);
		return (error);
	}
		

	MALLOC(cp, struct nfs_gss_clnt_ctx *, sizeof(*cp), M_TEMP, M_WAITOK|M_ZERO);
	if (cp == NULL) {
		lck_mtx_unlock(&nmp->nm_lock);
		return (ENOMEM);
	}

	cp->gss_clnt_uid = uid;
	cp->gss_clnt_mtx = lck_mtx_alloc_init(nfs_gss_clnt_grp, LCK_ATTR_NULL);
	cp->gss_clnt_thread = current_thread();
	nfs_gss_clnt_ctx_ref(req, cp);
	TAILQ_INSERT_TAIL(&nmp->nm_gsscl, cp, gss_clnt_entries);
	lck_mtx_unlock(&nmp->nm_lock);

	error = nfs_gss_clnt_ctx_init(req, cp);
	if (error)
		nfs_gss_clnt_ctx_unref(req);

	if (error == ENEEDAUTH) {
		error = nfs_gss_clnt_ctx_delay(req, &retrycnt);
		if (!error)
			goto retry;
	}

	/*
	 * If we failed to set up a Kerberos context for this
	 * user and no sec= mount option was given then set
	 * up a dummy context that allows this user to attempt
	 * sec=sys calls.
	 */
	if (error && (nmp->nm_flag & NFSMNT_SECGIVEN) == 0) {
		lck_mtx_lock(&nmp->nm_lock);
		error = nfs_gss_clnt_ctx_failover(req);
		lck_mtx_unlock(&nmp->nm_lock);
	}

	return (error);
}

/*
 * Set up a dummy context to allow the use of sec=sys
 * for this user, if the server allows sec=sys.
 * The context is valid for GSS_CLNT_SYS_VALID seconds,
 * so that the user will periodically attempt to fail back
 * and get a real credential.
 *
 * Assumes context list (nm_lock) is locked
 */
static int
nfs_gss_clnt_ctx_failover(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;
	struct nfs_gss_clnt_ctx *cp;
	uid_t uid = kauth_cred_getuid(req->r_cred);
	struct timeval now;

	MALLOC(cp, struct nfs_gss_clnt_ctx *, sizeof(*cp), M_TEMP, M_WAITOK|M_ZERO);
	if (cp == NULL)
		return (ENOMEM);

	cp->gss_clnt_service = RPCSEC_GSS_SVC_SYS;
	cp->gss_clnt_uid = uid;
	cp->gss_clnt_mtx = lck_mtx_alloc_init(nfs_gss_clnt_grp, LCK_ATTR_NULL);
	microuptime(&now);
	cp->gss_clnt_ctime = now.tv_sec;	// time stamp
	nfs_gss_clnt_ctx_ref(req, cp);
	TAILQ_INSERT_TAIL(&nmp->nm_gsscl, cp, gss_clnt_entries);

	return (0);
}

/*
 * Inserts an RPCSEC_GSS credential into an RPC header.
 * After the credential is inserted, the code continues
 * to build the verifier which contains a signed checksum
 * of the RPC header.
 */
int
nfs_gss_clnt_cred_put(struct nfsreq *req, struct nfsm_chain *nmc, mbuf_t args)
{
	struct nfsmount *nmp = req->r_nmp;
	struct nfs_gss_clnt_ctx *cp;
	uint32_t seqnum = 0;
	int error = 0;
	int slpflag = 0;
	int start, len, offset = 0;
	int pad, toklen;
	struct nfsm_chain nmc_tmp;
	struct gss_seq *gsp;
	u_char tokbuf[KRB5_SZ_TOKMAX];
	u_char cksum[8];
	struct timeval now;

retry:
	if (req->r_gss_ctx == NULL) {
		/*
		 * Find the context for this user.
		 * If no context is found, one will
		 * be created.
		 */
		error = nfs_gss_clnt_ctx_find(req);
		if (error)
			return (error);
	}
	cp = req->r_gss_ctx;

	/*
	 * If it's a dummy context for a user that's using
	 * a fallback to sec=sys, then just return an error
	 * so rpchead can encode an RPCAUTH_UNIX cred.
	 */
	if (cp->gss_clnt_service == RPCSEC_GSS_SVC_SYS) {
		/*
		 * The dummy context is valid for just
		 * GSS_CLNT_SYS_VALID seconds.  If the context
		 * is older than this, mark it invalid and try
		 * again to get a real one.
		 */
		lck_mtx_lock(cp->gss_clnt_mtx);
		microuptime(&now);
		if (now.tv_sec > cp->gss_clnt_ctime + GSS_CLNT_SYS_VALID) {
			cp->gss_clnt_flags |= GSS_CTX_INVAL;
			lck_mtx_unlock(cp->gss_clnt_mtx);
			nfs_gss_clnt_ctx_unref(req);
			goto retry;
		}
		lck_mtx_unlock(cp->gss_clnt_mtx);
		return (ENEEDAUTH);
	}

	/*
	 * If the context thread isn't null, then the context isn't
	 * yet complete and is for the exclusive use of the thread
	 * doing the context setup. Wait until the context thread
	 * is null.
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	if (cp->gss_clnt_thread && cp->gss_clnt_thread != current_thread()) {
		cp->gss_clnt_flags |= GSS_NEEDCTX;
		slpflag = (PZERO-1) | PDROP | (((nmp->nm_flag & NFSMNT_INT) && req->r_thread) ? PCATCH : 0);
		msleep(cp, cp->gss_clnt_mtx, slpflag, "ctxwait", NULL);
		if ((error = nfs_sigintr(nmp, req, req->r_thread, 0)))
			return (error);
		nfs_gss_clnt_ctx_unref(req);
		goto retry;
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);

	if (cp->gss_clnt_flags & GSS_CTX_COMPLETE) {
		/*
		 * Get a sequence number for this request.
		 * Check whether the oldest request in the window is complete.
		 * If it's still pending, then wait until it's done before
		 * we allocate a new sequence number and allow this request
		 * to proceed.
		 */
		lck_mtx_lock(cp->gss_clnt_mtx);
		while (win_getbit(cp->gss_clnt_seqbits, 
			((cp->gss_clnt_seqnum - cp->gss_clnt_seqwin) + 1) % cp->gss_clnt_seqwin)) {
			cp->gss_clnt_flags |= GSS_NEEDSEQ;
			slpflag = (PZERO-1) | (((nmp->nm_flag & NFSMNT_INT) && req->r_thread) ? PCATCH : 0);
			msleep(cp, cp->gss_clnt_mtx, slpflag, "seqwin", NULL);
			if ((error = nfs_sigintr(nmp, req, req->r_thread, 0))) {
				lck_mtx_unlock(cp->gss_clnt_mtx);
				return (error);
			}
			if (cp->gss_clnt_flags & GSS_CTX_INVAL) {
				/* Renewed while while we were waiting */
				lck_mtx_unlock(cp->gss_clnt_mtx);
				nfs_gss_clnt_ctx_unref(req);
				goto retry;
			}
		}
		seqnum = ++cp->gss_clnt_seqnum;
		win_setbit(cp->gss_clnt_seqbits, seqnum % cp->gss_clnt_seqwin);
		lck_mtx_unlock(cp->gss_clnt_mtx);

		MALLOC(gsp, struct gss_seq *, sizeof(*gsp), M_TEMP, M_WAITOK|M_ZERO);
		if (gsp == NULL)
			return (ENOMEM);
		gsp->gss_seqnum = seqnum;
		SLIST_INSERT_HEAD(&req->r_gss_seqlist, gsp, gss_seqnext);
	}

	/* Insert the credential */
	nfsm_chain_add_32(error, nmc, RPCSEC_GSS);
	nfsm_chain_add_32(error, nmc, 5 * NFSX_UNSIGNED + cp->gss_clnt_handle_len);
	nfsm_chain_add_32(error, nmc, RPCSEC_GSS_VERS_1);
	nfsm_chain_add_32(error, nmc, cp->gss_clnt_proc);
	nfsm_chain_add_32(error, nmc, seqnum);
	nfsm_chain_add_32(error, nmc, cp->gss_clnt_service);
	nfsm_chain_add_32(error, nmc, cp->gss_clnt_handle_len);
	nfsm_chain_add_opaque(error, nmc, cp->gss_clnt_handle, cp->gss_clnt_handle_len);

	/*
	 * Now add the verifier
	 */
	if (cp->gss_clnt_proc == RPCSEC_GSS_INIT ||
		cp->gss_clnt_proc == RPCSEC_GSS_CONTINUE_INIT) {
		/*
		 * If the context is still being created
		 * then use a null verifier.
		 */
		nfsm_chain_add_32(error, nmc, RPCAUTH_NULL);	// flavor
		nfsm_chain_add_32(error, nmc, 0);		// length
		nfsm_chain_build_done(error, nmc);
		if (!error)
			nfs_gss_append_chain(nmc, args);
		return (error);
	}

	offset = nmp->nm_sotype == SOCK_STREAM ? NFSX_UNSIGNED : 0; // record mark
	nfsm_chain_build_done(error, nmc);
	nfs_gss_cksum_chain(cp->gss_clnt_sched, nmc, krb5_mic, offset, 0, cksum);

	toklen = nfs_gss_token_put(cp->gss_clnt_sched, krb5_mic, tokbuf, 1, 0, cksum);
	nfsm_chain_add_32(error, nmc, RPCSEC_GSS);	// flavor
	nfsm_chain_add_32(error, nmc, toklen);		// length
	nfsm_chain_add_opaque(error, nmc, tokbuf, toklen);
	nfsm_chain_build_done(error, nmc);
	if (error)
		return (error);

	/*
	 * Now we may have to compute integrity or encrypt the call args
	 * per RFC 2203 Section 5.3.2
	 */
	switch (cp->gss_clnt_service) {
	case RPCSEC_GSS_SVC_NONE:
		nfs_gss_append_chain(nmc, args);
		break;
	case RPCSEC_GSS_SVC_INTEGRITY:
		len = nfs_gss_mchain_length(args);	// Find args length
		req->r_gss_arglen = len;		// Stash the args len
		len += NFSX_UNSIGNED;			// Add seqnum length
		nfsm_chain_add_32(error, nmc, len);	// and insert it
		start = nfsm_chain_offset(nmc);
		nfsm_chain_add_32(error, nmc, seqnum);	// Insert seqnum
		req->r_gss_argoff = nfsm_chain_offset(nmc); // Offset to args
		nfsm_chain_build_done(error, nmc);
		if (error)
			return (error);
		nfs_gss_append_chain(nmc, args);	// Append the args mbufs

		/* Now compute a checksum over the seqnum + args */
		nfs_gss_cksum_chain(cp->gss_clnt_sched, nmc, krb5_mic, start, len, cksum);

		/* Insert it into a token and append to the request */
		toklen = nfs_gss_token_put(cp->gss_clnt_sched, krb5_mic, tokbuf, 1, 0, cksum);
		nfsm_chain_finish_mbuf(error, nmc);	// force checksum into new mbuf
		nfsm_chain_add_32(error, nmc, toklen);
		nfsm_chain_add_opaque(error, nmc, tokbuf, toklen);
		nfsm_chain_build_done(error, nmc);
		break;
	case RPCSEC_GSS_SVC_PRIVACY:
		/* Prepend a new mbuf with the confounder & sequence number */
		nfsm_chain_build_alloc_init(error, &nmc_tmp, 3 * NFSX_UNSIGNED);
		nfsm_chain_add_32(error, &nmc_tmp, random());	// confounder bytes 1-4
		nfsm_chain_add_32(error, &nmc_tmp, random());	// confounder bytes 4-8
		nfsm_chain_add_32(error, &nmc_tmp, seqnum);
		nfsm_chain_build_done(error, &nmc_tmp);
		if (error)
			return (error);
		nfs_gss_append_chain(&nmc_tmp, args);		// Append the args mbufs

		len = nfs_gss_mchain_length(args);		// Find args length
		len += 3 * NFSX_UNSIGNED;			// add confounder & seqnum
		req->r_gss_arglen = len;			// Stash length

		/*
		 * Append a pad trailer - per RFC 1964 section 1.2.2.3
		 * Since XDR data is always 32-bit aligned, it
		 * needs to be padded either by 4 bytes or 8 bytes.
		 */
		nfsm_chain_finish_mbuf(error, &nmc_tmp);	// force padding into new mbuf
		if (len % 8 > 0) {
			nfsm_chain_add_32(error, &nmc_tmp, 0x04040404);
			len += NFSX_UNSIGNED;
		} else {
			nfsm_chain_add_32(error, &nmc_tmp, 0x08080808);
			nfsm_chain_add_32(error, &nmc_tmp, 0x08080808);
			len +=  2 * NFSX_UNSIGNED;
		}
		nfsm_chain_build_done(error, &nmc_tmp);

		/* Now compute a checksum over the confounder + seqnum + args */
		nfs_gss_cksum_chain(cp->gss_clnt_sched, &nmc_tmp, krb5_wrap, 0, len, cksum);

		/* Insert it into a token */
		toklen = nfs_gss_token_put(cp->gss_clnt_sched, krb5_wrap, tokbuf, 1, len, cksum);
		nfsm_chain_add_32(error, nmc, toklen + len);	// token + args length
		nfsm_chain_add_opaque_nopad(error, nmc, tokbuf, toklen);
		req->r_gss_argoff = nfsm_chain_offset(nmc);	// Stash offset
		nfsm_chain_build_done(error, nmc);
		if (error)
			return (error);
		nfs_gss_append_chain(nmc, nmc_tmp.nmc_mhead);	// Append the args mbufs

		/* Finally, encrypt the args */
		nfs_gss_encrypt_chain(cp->gss_clnt_skey, &nmc_tmp, 0, len, DES_ENCRYPT);

		/* Add null XDR pad if the ASN.1 token misaligned the data */
		pad = nfsm_pad(toklen + len);
		if (pad > 0) {
			nfsm_chain_add_opaque_nopad(error, nmc, iv0, pad);
			nfsm_chain_build_done(error, nmc);
		}
		break;
	}

	return (error);
}

/*
 * When receiving a reply, the client checks the verifier
 * returned by the server. Check that the verifier is the
 * correct type, then extract the sequence number checksum
 * from the token in the credential and compare it with a
 * computed checksum of the sequence number in the request
 * that was sent.
 */
int
nfs_gss_clnt_verf_get(
	struct nfsreq *req,
	struct nfsm_chain *nmc,
	uint32_t verftype,
	uint32_t verflen,
	uint32_t *accepted_statusp)
{
	u_char tokbuf[KRB5_SZ_TOKMAX];
	u_char cksum1[8], cksum2[8];
	uint32_t seqnum = 0;
	struct nfs_gss_clnt_ctx *cp = req->r_gss_ctx;
	struct nfsm_chain nmc_tmp;
	struct gss_seq *gsp;
	uint32_t reslen, start, cksumlen, toklen;
	int error = 0;

	reslen = cksumlen = 0;
	*accepted_statusp = 0;

	if (cp == NULL)
		return (EAUTH);
	/*
	 * If it's not an RPCSEC_GSS verifier, then it has to
	 * be a null verifier that resulted from either
	 * a CONTINUE_NEEDED reply during context setup or
	 * from the reply to an AUTH_UNIX call from a dummy
	 * context that resulted from a fallback to sec=sys.
	 */
	if (verftype != RPCSEC_GSS) {
		if (verftype != RPCAUTH_NULL)
			return (EAUTH);
		if (cp->gss_clnt_flags & GSS_CTX_COMPLETE &&
			cp->gss_clnt_service != RPCSEC_GSS_SVC_SYS)
			return (EAUTH);
		if (verflen > 0)
			nfsm_chain_adv(error, nmc, nfsm_rndup(verflen));
		nfsm_chain_get_32(error, nmc, *accepted_statusp);
		return (error);
	}

	if (verflen != KRB5_SZ_TOKEN)
		return (EAUTH);

	/*
	 * If we received an RPCSEC_GSS verifier but the
	 * context isn't yet complete, then it must be
	 * the context complete message from the server.
	 * The verifier will contain an encrypted checksum
	 * of the window but we don't have the session key
	 * yet so we can't decrypt it. Stash the verifier
	 * and check it later in nfs_gss_clnt_ctx_init() when
	 * the context is complete.
	 */
	if (!(cp->gss_clnt_flags & GSS_CTX_COMPLETE)) {
		MALLOC(cp->gss_clnt_verf, u_char *, verflen, M_TEMP, M_WAITOK|M_ZERO);
		if (cp->gss_clnt_verf == NULL)
			return (ENOMEM);
		nfsm_chain_get_opaque(error, nmc, verflen, cp->gss_clnt_verf);
		nfsm_chain_get_32(error, nmc, *accepted_statusp);
		return (error);
	}

	/*
	 * Get the 8 octet sequence number
	 * checksum out of the verifier token.
	 */
	nfsm_chain_get_opaque(error, nmc, verflen, tokbuf);
	if (error)
		goto nfsmout;
	error = nfs_gss_token_get(cp->gss_clnt_sched, krb5_mic, tokbuf, 0, NULL, cksum1);
	if (error)
		goto nfsmout;

	/*
	 * Search the request sequence numbers for this reply, starting
	 * with the most recent, looking for a checksum that matches
	 * the one in the verifier returned by the server.
	 */
	SLIST_FOREACH(gsp, &req->r_gss_seqlist, gss_seqnext) {
		nfs_gss_cksum_rep(cp->gss_clnt_sched, gsp->gss_seqnum, cksum2);
		if (bcmp(cksum1, cksum2, 8) == 0)
			break;
	}
	if (gsp == NULL)
		return (EAUTH);

	/*
	 * Get the RPC accepted status
	 */
	nfsm_chain_get_32(error, nmc, *accepted_statusp);
	if (*accepted_statusp != RPC_SUCCESS)
		return (0);

	/*
	 * Now we may have to check integrity or decrypt the results
	 * per RFC 2203 Section 5.3.2
	 */
	switch (cp->gss_clnt_service) {
	case RPCSEC_GSS_SVC_NONE:
		/* nothing to do */
		break;
	case RPCSEC_GSS_SVC_INTEGRITY:
		/*
		 * Here's what we expect in the integrity results:
		 *
		 * - length of seq num + results (4 bytes)
		 * - sequence number (4 bytes)
		 * - results (variable bytes)
		 * - length of checksum token (37)
		 * - checksum of seqnum + results (37 bytes)
		 */
		nfsm_chain_get_32(error, nmc, reslen);		// length of results
		if (reslen > NFS_MAXPACKET) {
			error = EBADRPC;
			goto nfsmout;
		}

		/* Compute a checksum over the sequence number + results */
		start = nfsm_chain_offset(nmc);
		nfs_gss_cksum_chain(cp->gss_clnt_sched, nmc, krb5_mic, start, reslen, cksum1);

		/*
		 * Get the sequence number prepended to the results
		 * and compare it against the list in the request.
		 */
		nfsm_chain_get_32(error, nmc, seqnum);
		SLIST_FOREACH(gsp, &req->r_gss_seqlist, gss_seqnext) {
			if (seqnum == gsp->gss_seqnum)
				break;
		}
		if (gsp == NULL) {
			error = EBADRPC;
			goto nfsmout;
		}

		/*
		 * Advance to the end of the results and
		 * fetch the checksum computed by the server.
		 */
		nmc_tmp = *nmc;	
		reslen -= NFSX_UNSIGNED;			// already skipped seqnum
		nfsm_chain_adv(error, &nmc_tmp, reslen);	// skip over the results
		nfsm_chain_get_32(error, &nmc_tmp, cksumlen);	// length of checksum
		if (cksumlen != KRB5_SZ_TOKEN) {
			error = EBADRPC;
			goto nfsmout;
		}
		nfsm_chain_get_opaque(error, &nmc_tmp, cksumlen, tokbuf);
		if (error)
			goto nfsmout;
		error = nfs_gss_token_get(cp->gss_clnt_sched, krb5_mic, tokbuf, 0,
			NULL, cksum2);
		if (error)
			goto nfsmout;

		/* Verify that the checksums are the same */
		if (bcmp(cksum1, cksum2, 8) != 0) {
			error = EBADRPC;
			goto nfsmout;
		}
		break;
	case RPCSEC_GSS_SVC_PRIVACY:
		/*
		 * Here's what we expect in the privacy results:
		 *
		 * - length of confounder + seq num + token + results
		 * - wrap token (37-40 bytes)
		 * - confounder (8 bytes)
		 * - sequence number (4 bytes)
		 * - results (encrypted)
		 */
		nfsm_chain_get_32(error, nmc, reslen);		// length of results
		if (reslen > NFS_MAXPACKET) {
			error = EBADRPC;
			goto nfsmout;
		}

		/* Get the token that prepends the encrypted results */
		nfsm_chain_get_opaque(error, nmc, KRB5_SZ_TOKMAX, tokbuf);
		if (error)
			goto nfsmout;
		error = nfs_gss_token_get(cp->gss_clnt_sched, krb5_wrap, tokbuf, 0,
			&toklen, cksum1);
		if (error)
			goto nfsmout;
		nfsm_chain_reverse(nmc, nfsm_pad(toklen));
		reslen -= toklen;				// size of confounder + seqnum + results

		/* decrypt the confounder + sequence number + results */
		start = nfsm_chain_offset(nmc);
		nfs_gss_encrypt_chain(cp->gss_clnt_skey, nmc, start, reslen, DES_DECRYPT);

		/* Compute a checksum over the confounder + sequence number + results */
		nfs_gss_cksum_chain(cp->gss_clnt_sched, nmc, krb5_wrap, start, reslen, cksum2);

		/* Verify that the checksums are the same */
		if (bcmp(cksum1, cksum2, 8) != 0) {
			error = EBADRPC;
			goto nfsmout;
		}

		nfsm_chain_adv(error, nmc, 8);	// skip over the confounder

		/*
		 * Get the sequence number prepended to the results
		 * and compare it against the list in the request.
		 */
		nfsm_chain_get_32(error, nmc, seqnum);
		SLIST_FOREACH(gsp, &req->r_gss_seqlist, gss_seqnext) {
			if (seqnum == gsp->gss_seqnum)
				break;
		}
		if (gsp == NULL) {
			error = EBADRPC;
			goto nfsmout;
		}

		break;
	}
nfsmout:
	return (error);
}

/*
 * An RPCSEC_GSS request with no integrity or privacy consists
 * of just the header mbufs followed by the arg mbufs.
 *
 * However, integrity or privacy both trailer mbufs to the args,
 * which means we have to do some work to restore the arg mbuf
 * chain to its previous state in case we need to retransmit.
 *
 * The location and length of the args is marked by two fields
 * in the request structure: r_gss_argoff and r_gss_arglen,
 * which are stashed when the NFS request is built.
 */ 
int
nfs_gss_clnt_args_restore(struct nfsreq *req)
{
	struct nfs_gss_clnt_ctx *cp = req->r_gss_ctx;
	struct nfsm_chain mchain, *nmc = &mchain;
	int len, error = 0;

	if (cp == NULL) 
		return (EAUTH);

	if ((cp->gss_clnt_flags & GSS_CTX_COMPLETE) == 0)
		return (ENEEDAUTH);

	nfsm_chain_dissect_init(error, nmc, req->r_mhead);	// start at RPC header
	nfsm_chain_adv(error, nmc, req->r_gss_argoff);		// advance to args
	if (error)
		return (error);

	switch (cp->gss_clnt_service) {
	case RPCSEC_GSS_SVC_NONE:
		/* nothing to do */
		break;
	case RPCSEC_GSS_SVC_INTEGRITY:
		/*
		 * All we have to do here is remove the appended checksum mbufs.
		 * We know that the checksum starts in a new mbuf beyond the end
		 * of the args.
		 */
		nfsm_chain_adv(error, nmc, req->r_gss_arglen);	// adv to last args mbuf
		if (error)
			return (error);

		mbuf_freem(mbuf_next(nmc->nmc_mcur));		// free the cksum mbuf
		error = mbuf_setnext(nmc->nmc_mcur, NULL);
		break;
	case RPCSEC_GSS_SVC_PRIVACY:
		/*
		 * The args are encrypted along with prepended confounders and seqnum.
		 * First we decrypt, the confounder, seqnum and args then skip to the
		 * final mbuf of the args.
		 * The arglen includes 8 bytes of confounder and 4 bytes of seqnum.
		 * Finally, we remove between 4 and 8 bytes of encryption padding
		 * as well as any alignment padding in the trailing mbuf.
		 */
		len = req->r_gss_arglen;
		len += len % 8 > 0 ? 4 : 8;			// add DES padding length
		nfs_gss_encrypt_chain(cp->gss_clnt_skey, nmc,
			req->r_gss_argoff, len, DES_DECRYPT);
		nfsm_chain_adv(error, nmc, req->r_gss_arglen);
		if (error)
			return (error);
		mbuf_freem(mbuf_next(nmc->nmc_mcur));		// free the pad mbuf
		error = mbuf_setnext(nmc->nmc_mcur, NULL);
		break;
	}

	return (error);
}

/*
 * This function sets up  a new context on the client.
 * Context setup alternates upcalls to the gssd with NFS nullproc calls
 * to the server.  Each of these calls exchanges an opaque token, obtained
 * via the gssd's calls into the GSS-API on either the client or the server.
 * This cycle of calls ends when the client's upcall to the gssd and the
 * server's response both return GSS_S_COMPLETE.  At this point, the client
 * should have its session key and a handle that it can use to refer to its
 * new context on the server.
 */
static int
nfs_gss_clnt_ctx_init(struct nfsreq *req, struct nfs_gss_clnt_ctx *cp)
{
	struct nfsmount *nmp = req->r_nmp;
	int client_complete = 0;
	int server_complete = 0;
	u_char cksum1[8], cksum2[8];
	int error = 0;
	struct timeval now;

	/* Initialize a new client context */

	cp->gss_clnt_svcname = nfs_gss_clnt_svcname(nmp);
	if (cp->gss_clnt_svcname == NULL) {
		error = EAUTH;
		goto nfsmout;
	}
	cp->gss_clnt_proc = RPCSEC_GSS_INIT;

	cp->gss_clnt_service =
		nmp->nm_auth == RPCAUTH_KRB5  ? RPCSEC_GSS_SVC_NONE :
		nmp->nm_auth == RPCAUTH_KRB5I ? RPCSEC_GSS_SVC_INTEGRITY :
		nmp->nm_auth == RPCAUTH_KRB5P ? RPCSEC_GSS_SVC_PRIVACY : 0;

	/*
	 * Now loop around alternating gss_init_sec_context and
	 * gss_accept_sec_context upcalls to the gssd on the client
	 * and server side until the context is complete - or fails.
	 */
	for (;;) {

		/* Upcall to the gss_init_sec_context in the gssd */
		error = nfs_gss_clnt_gssd_upcall(req, cp);
		if (error)
			goto nfsmout;

		if (cp->gss_clnt_major == GSS_S_COMPLETE) {
			client_complete = 1;
			if (server_complete)
				break;
		} else if (cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
			error = EAUTH;
			goto nfsmout;
		}

		/*
		 * Pass the token to the server.
		 */
		error = nfs_gss_clnt_ctx_callserver(req, cp);
		if (error)
			goto nfsmout;

		if (cp->gss_clnt_major == GSS_S_COMPLETE) {
			server_complete = 1;
			if (client_complete)
				break;
		} else if (cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
			error = EAUTH;
			goto nfsmout;
		}

		cp->gss_clnt_proc = RPCSEC_GSS_CONTINUE_INIT;
	}

	/*
	 * The context is apparently established successfully
	 */
	cp->gss_clnt_flags |= GSS_CTX_COMPLETE;
	cp->gss_clnt_proc = RPCSEC_GSS_DATA;
	microuptime(&now);
	cp->gss_clnt_ctime = now.tv_sec;	// time stamp

	/*
	 * Construct a key schedule from our shiny new session key
	 */
	error = des_key_sched((des_cblock *) cp->gss_clnt_skey, cp->gss_clnt_sched);
	if (error) {
		error = EAUTH;
		goto nfsmout;
	}

	/*
	 * Compute checksum of the server's window
	 */
	nfs_gss_cksum_rep(cp->gss_clnt_sched, cp->gss_clnt_seqwin, cksum1);

	/*
	 * and see if it matches the one in the
	 * verifier the server returned.
	 */
	error = nfs_gss_token_get(cp->gss_clnt_sched, krb5_mic, cp->gss_clnt_verf, 0,
		NULL, cksum2);
	FREE(cp->gss_clnt_verf, M_TEMP);
	cp->gss_clnt_verf = NULL;

	if (error || bcmp(cksum1, cksum2, 8) != 0) {
		error = EAUTH;
		goto nfsmout;
	}

	/*
	 * Set an initial sequence number somewhat randomized.
	 * Start small so we don't overflow GSS_MAXSEQ too quickly.
	 * Add the size of the sequence window so seqbits arithmetic
	 * doesn't go negative.
	 */
	cp->gss_clnt_seqnum = (random() & 0xffff) + cp->gss_clnt_seqwin;

	/*
	 * Allocate a bitmap to keep track of which requests
	 * are pending within the sequence number window.
	 */
	MALLOC(cp->gss_clnt_seqbits, uint32_t *,
		nfsm_rndup((cp->gss_clnt_seqwin + 7) / 8), M_TEMP, M_WAITOK|M_ZERO);
	if (cp->gss_clnt_seqbits == NULL)
		error = EAUTH;
nfsmout:
	/*
	 * If there's an error, just mark it as invalid.
	 * It will be removed when the reference count
	 * drops to zero.
	 */
	if (error)
		cp->gss_clnt_flags |= GSS_CTX_INVAL;

	/*
	 * Wake any threads waiting to use the context
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	cp->gss_clnt_thread = NULL;
	if (cp->gss_clnt_flags & GSS_NEEDCTX) {
		cp->gss_clnt_flags &= ~GSS_NEEDCTX;
		wakeup(cp);
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);

	return (error);
}

/*
 * Call the NFS server using a null procedure for context setup.
 * Even though it's a null procedure and nominally has no arguments
 * RFC 2203 requires that the GSS-API token be passed as an argument
 * and received as a reply.
 */
static int
nfs_gss_clnt_ctx_callserver(struct nfsreq *req, struct nfs_gss_clnt_ctx *cp)
{
	struct nfsmount *nmp = req->r_nmp;
	struct nfsm_chain nmreq, nmrep;
	int error = 0, status;
	u_int64_t xid;
	int sz;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);
	sz = NFSX_UNSIGNED + nfsm_rndup(cp->gss_clnt_tokenlen);
	nfsm_chain_build_alloc_init(error, &nmreq, sz);
	nfsm_chain_add_32(error, &nmreq, cp->gss_clnt_tokenlen);
	nfsm_chain_add_opaque(error, &nmreq, cp->gss_clnt_token, cp->gss_clnt_tokenlen);
	nfsm_chain_build_done(error, &nmreq);
	if (error)
		goto nfsmout;

	/* Call the server */
	error = nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC_NULL,
			req->r_thread, req->r_cred, 0, &nmrep, &xid, &status);
	if (cp->gss_clnt_token != NULL) {
		FREE(cp->gss_clnt_token, M_TEMP);
		cp->gss_clnt_token = NULL;
	}
	if (!error)
		error = status;
	if (error)
		goto nfsmout;

	/* Get the server's reply */

	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_handle_len);
	if (cp->gss_clnt_handle != NULL)
		FREE(cp->gss_clnt_handle, M_TEMP);
	if (cp->gss_clnt_handle_len > 0) {
		MALLOC(cp->gss_clnt_handle, u_char *, cp->gss_clnt_handle_len, M_TEMP, M_WAITOK);
		if (cp->gss_clnt_handle == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		nfsm_chain_get_opaque(error, &nmrep, cp->gss_clnt_handle_len, cp->gss_clnt_handle);
	}
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_major);
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_minor);
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_seqwin);
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_tokenlen);
	if (error)
		goto nfsmout;
	if (cp->gss_clnt_tokenlen > 0) {
		MALLOC(cp->gss_clnt_token, u_char *, cp->gss_clnt_tokenlen, M_TEMP, M_WAITOK);
		if (cp->gss_clnt_token == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		nfsm_chain_get_opaque(error, &nmrep, cp->gss_clnt_tokenlen, cp->gss_clnt_token);
	}

	/*
	 * Make sure any unusual errors are expanded and logged by gssd
	 */
	if (cp->gss_clnt_major != GSS_S_COMPLETE &&
	    cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
		char who[] = "server";

		(void) mach_gss_log_error(
			cp->gss_clnt_mport,
			vfs_statfs(nmp->nm_mountp)->f_mntfromname,
			cp->gss_clnt_uid,
			who,
			cp->gss_clnt_major,
			cp->gss_clnt_minor);
	}

nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	return (error);
}

/*
 * Ugly hack to get the service principal from the f_mntfromname field in 
 * the statfs struct. We assume a format of server:path. We don't currently
 * support url's or other bizarre formats like path@server. A better solution
 * here might be to allow passing the service principal down in the mount args.
 * For kerberos we just use the default realm. 
 */
static char *
nfs_gss_clnt_svcname(struct nfsmount *nmp)
{
	char *svcname, *d;
	char* mntfromhere = &vfs_statfs(nmp->nm_mountp)->f_mntfromname[0];
	int len;

	len = strlen(mntfromhere) + 5; /* "nfs/" plus null */
	MALLOC(svcname, char *, len, M_TEMP, M_NOWAIT);
	if (svcname == NULL)
		return (NULL);
	strlcpy(svcname, "nfs/", len);
	strlcat(svcname, mntfromhere, len);
	d = strchr(svcname, ':');
	if (d)
		*d = '\0';

	return (svcname);
}

/*
 * Make an upcall to the gssd using Mach RPC
 * The upcall is made using a task special port.
 * This allows launchd to fire up the gssd in the
 * user's session.  This is important, since gssd
 * must have access to the user's credential cache.
 */
static int
nfs_gss_clnt_gssd_upcall(struct nfsreq *req, struct nfs_gss_clnt_ctx *cp)
{
	kern_return_t kr;
	byte_buffer okey = NULL;
	uint32_t skeylen = 0;
	int retry_cnt = 0;
	vm_map_copy_t itoken = NULL;
	byte_buffer otoken = NULL;
	int error = 0;
	char uprinc[1];

	/*
	 * NFS currently only supports default principals or
	 * principals based on the uid of the caller.
	 *
	 * N.B. Note we define a one character array for the principal
	 * so that we can hold an empty string required by mach, since 
	 * the kernel is being compiled with -Wwrite-strings.
	 */
	uprinc[0] = '\0';
	if (cp->gss_clnt_mport == NULL) {
		kr = task_get_gssd_port(get_threadtask(req->r_thread), &cp->gss_clnt_mport);
		if (kr != KERN_SUCCESS) {
			printf("nfs_gss_clnt_gssd_upcall: can't get gssd port, status %d\n", kr);
			return (EAUTH);
		}
		if (!IPC_PORT_VALID(cp->gss_clnt_mport)) {
			printf("nfs_gss_clnt_gssd_upcall: gssd port not valid\n");
			cp->gss_clnt_mport = NULL;
			return (EAUTH);
		}
	}

	if (cp->gss_clnt_tokenlen > 0)
		nfs_gss_mach_alloc_buffer(cp->gss_clnt_token, cp->gss_clnt_tokenlen, &itoken);

retry:
	kr = mach_gss_init_sec_context(
		cp->gss_clnt_mport,
		KRB5_MECH,
		(byte_buffer) itoken, (mach_msg_type_number_t) cp->gss_clnt_tokenlen,
		cp->gss_clnt_uid,
		uprinc,
		cp->gss_clnt_svcname,
		GSSD_MUTUAL_FLAG | GSSD_NO_UI,
		&cp->gss_clnt_gssd_verf,
		&cp->gss_clnt_context,
		&cp->gss_clnt_cred_handle,
		&okey,  (mach_msg_type_number_t *) &skeylen,
		&otoken, (mach_msg_type_number_t *) &cp->gss_clnt_tokenlen,
		&cp->gss_clnt_major,
		&cp->gss_clnt_minor);

	if (kr != 0) {
		printf("nfs_gss_clnt_gssd_upcall: mach_gss_init_sec_context failed: %x\n", kr);
		if (kr == MIG_SERVER_DIED && cp->gss_clnt_cred_handle == 0 &&
			retry_cnt++ < NFS_GSS_MACH_MAX_RETRIES)
			goto retry;
		task_release_special_port(cp->gss_clnt_mport);
		cp->gss_clnt_mport = NULL;
		return (EAUTH);
	}

	/*
	 * Make sure any unusual errors are expanded and logged by gssd
	 */
	if (cp->gss_clnt_major != GSS_S_COMPLETE &&
	    cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
		char who[] = "client";

		(void) mach_gss_log_error(
			cp->gss_clnt_mport,
			vfs_statfs(req->r_nmp->nm_mountp)->f_mntfromname,
			cp->gss_clnt_uid,
			who,
			cp->gss_clnt_major,
			cp->gss_clnt_minor);
	}

	if (skeylen > 0) {
		if (skeylen != SKEYLEN) {
			printf("nfs_gss_clnt_gssd_upcall: bad key length (%d)\n", skeylen);
			return (EAUTH);
		}
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) okey, skeylen, cp->gss_clnt_skey);
		if (error)
			return (EAUTH);
	}

	if (cp->gss_clnt_tokenlen > 0) {
		MALLOC(cp->gss_clnt_token, u_char *, cp->gss_clnt_tokenlen, M_TEMP, M_WAITOK);
		if (cp->gss_clnt_token == NULL)
			return (ENOMEM);
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) otoken, cp->gss_clnt_tokenlen,
			cp->gss_clnt_token);
		if (error)
			return (EAUTH);
	}

	return (0);
}

/*
 * Invoked at the completion of an RPC call that uses an RPCSEC_GSS
 * credential. The sequence number window that the server returns
 * at context setup indicates the maximum number of client calls that
 * can be outstanding on a context. The client maintains a bitmap that
 * represents the server's window.  Each pending request has a bit set
 * in the window bitmap.  When a reply comes in or times out, we reset
 * the bit in the bitmap and if there are any other threads waiting for
 * a context slot we notify the waiting thread(s).
 *
 * Note that if a request is retransmitted, it will have a single XID
 * but it may be associated with multiple sequence numbers.  So we
 * may have to reset multiple sequence number bits in the window bitmap.
 */
void
nfs_gss_clnt_rpcdone(struct nfsreq *req)
{
	struct nfs_gss_clnt_ctx *cp = req->r_gss_ctx;
	struct gss_seq *gsp, *ngsp;
	int i = 0;

	if (cp == NULL || !(cp->gss_clnt_flags & GSS_CTX_COMPLETE))
		return;	// no context - don't bother
	/*
	 * Reset the bit for this request in the
	 * sequence number window to indicate it's done.
	 * We do this even if the request timed out.
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	gsp = SLIST_FIRST(&req->r_gss_seqlist);
	if (gsp && gsp->gss_seqnum > (cp->gss_clnt_seqnum - cp->gss_clnt_seqwin))
		win_resetbit(cp->gss_clnt_seqbits,
			gsp->gss_seqnum % cp->gss_clnt_seqwin);

	/*
	 * Limit the seqnum list to GSS_CLNT_SEQLISTMAX entries
	 */
	SLIST_FOREACH_SAFE(gsp, &req->r_gss_seqlist, gss_seqnext, ngsp) {
		if (++i > GSS_CLNT_SEQLISTMAX) {
			SLIST_REMOVE(&req->r_gss_seqlist, gsp, gss_seq, gss_seqnext);
			FREE(gsp, M_TEMP);
		}
	}

	/*
	 * If there's a thread waiting for
	 * the window to advance, wake it up.
	 */
	if (cp->gss_clnt_flags & GSS_NEEDSEQ) {
		cp->gss_clnt_flags &= ~GSS_NEEDSEQ;
		wakeup(cp);
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);
}

/*
 * Create a reference to a context from a request
 * and bump the reference count
 */
void
nfs_gss_clnt_ctx_ref(struct nfsreq *req, struct nfs_gss_clnt_ctx *cp)
{
	req->r_gss_ctx = cp;

	lck_mtx_lock(cp->gss_clnt_mtx);
	cp->gss_clnt_refcnt++;
	lck_mtx_unlock(cp->gss_clnt_mtx);
}

/*
 * Remove a context reference from a request
 * If the reference count drops to zero, and the
 * context is invalid, destroy the context
 */
void
nfs_gss_clnt_ctx_unref(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;
	struct nfs_gss_clnt_ctx *cp = req->r_gss_ctx;

	if (cp == NULL)
		return;

	req->r_gss_ctx = NULL;

	lck_mtx_lock(cp->gss_clnt_mtx);
	if (--cp->gss_clnt_refcnt == 0
		&& cp->gss_clnt_flags & GSS_CTX_INVAL) {
		lck_mtx_unlock(cp->gss_clnt_mtx);

		if (nmp)
			lck_mtx_lock(&nmp->nm_lock);
		nfs_gss_clnt_ctx_remove(nmp, cp);
		if (nmp)
			lck_mtx_unlock(&nmp->nm_lock);

		return;
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);
}

/*
 * Remove a context
 */
static void
nfs_gss_clnt_ctx_remove(struct nfsmount *nmp, struct nfs_gss_clnt_ctx *cp)
{
	/*
	 * If dequeueing, assume nmp->nm_lock is held
	 */
	if (nmp != NULL)
		TAILQ_REMOVE(&nmp->nm_gsscl, cp, gss_clnt_entries);

	if (cp->gss_clnt_mport)
		task_release_special_port(cp->gss_clnt_mport);
	if (cp->gss_clnt_mtx)
		lck_mtx_destroy(cp->gss_clnt_mtx, nfs_gss_clnt_grp);
	if (cp->gss_clnt_handle)
		FREE(cp->gss_clnt_handle, M_TEMP);
	if (cp->gss_clnt_seqbits)
		FREE(cp->gss_clnt_seqbits, M_TEMP);
	if (cp->gss_clnt_token)
		FREE(cp->gss_clnt_token, M_TEMP);
	if (cp->gss_clnt_svcname)
		FREE(cp->gss_clnt_svcname, M_TEMP);
	FREE(cp, M_TEMP);
}

/*
 * The context for a user is invalid.
 * Mark the context as invalid, then
 * create a new context.
 */
int
nfs_gss_clnt_ctx_renew(struct nfsreq *req)
{
	struct nfs_gss_clnt_ctx *cp = req->r_gss_ctx;
	struct nfsmount *nmp = req->r_nmp;
	struct nfs_gss_clnt_ctx *ncp;
	int error = 0;
	uid_t saved_uid;
	mach_port_t saved_mport;
	int retrycnt = 0;

	if (cp == NULL || !(cp->gss_clnt_flags & GSS_CTX_COMPLETE))
		return (0);

	lck_mtx_lock(cp->gss_clnt_mtx);
	if (cp->gss_clnt_flags & GSS_CTX_INVAL) {
		lck_mtx_unlock(cp->gss_clnt_mtx);
		nfs_gss_clnt_ctx_unref(req);
		return (0);	// already being renewed
	}
	saved_uid = cp->gss_clnt_uid;
	saved_mport = task_copy_special_port(cp->gss_clnt_mport);

	/* Remove the old context */
	lck_mtx_lock(&nmp->nm_lock);
	cp->gss_clnt_flags |= GSS_CTX_INVAL;
	lck_mtx_unlock(&nmp->nm_lock);

	/*
	 * If there's a thread waiting
	 * in the old context, wake it up.
	 */
	if (cp->gss_clnt_flags & (GSS_NEEDCTX | GSS_NEEDSEQ)) {
		cp->gss_clnt_flags &= ~GSS_NEEDSEQ;
		wakeup(cp);
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);

retry:
	/*
	 * Create a new context
	 */
	MALLOC(ncp, struct nfs_gss_clnt_ctx *, sizeof(*ncp),
		M_TEMP, M_WAITOK|M_ZERO);
	if (ncp == NULL) {
		return (ENOMEM);
	}

	ncp->gss_clnt_uid = saved_uid;
	ncp->gss_clnt_mport = task_copy_special_port(saved_mport); // re-use the gssd port
	ncp->gss_clnt_mtx = lck_mtx_alloc_init(nfs_gss_clnt_grp, LCK_ATTR_NULL);
	ncp->gss_clnt_thread = current_thread();
	lck_mtx_lock(&nmp->nm_lock);
	TAILQ_INSERT_TAIL(&nmp->nm_gsscl, ncp, gss_clnt_entries);
	lck_mtx_unlock(&nmp->nm_lock);

	/* Adjust reference counts to new and old context */
	nfs_gss_clnt_ctx_unref(req);
	nfs_gss_clnt_ctx_ref(req, ncp);

	error = nfs_gss_clnt_ctx_init(req, ncp); // Initialize new context
	if (error == ENEEDAUTH) {
		error = nfs_gss_clnt_ctx_delay(req, &retrycnt);
		if (!error)
			goto retry;
	}

	task_release_special_port(saved_mport);
	if (error)
		nfs_gss_clnt_ctx_unref(req);

	return (error);
}

/*
 * Destroy all the contexts associated with a mount.
 * The contexts are also destroyed by the server.
 */
void
nfs_gss_clnt_ctx_unmount(struct nfsmount *nmp, int mntflags)
{
	struct nfs_gss_clnt_ctx *cp;
	struct ucred temp_cred;
	kauth_cred_t cred;
	struct nfsm_chain nmreq, nmrep;
	u_int64_t xid;
	int error, status;
	struct nfsreq req;

	bzero((caddr_t) &temp_cred, sizeof(temp_cred));
	temp_cred.cr_ngroups = 1;
	req.r_nmp = nmp;

	for (;;) {
		lck_mtx_lock(&nmp->nm_lock);
		cp = TAILQ_FIRST(&nmp->nm_gsscl);
		lck_mtx_unlock(&nmp->nm_lock);
		if (cp == NULL)
			break;

		nfs_gss_clnt_ctx_ref(&req, cp);

		/*
		 * Tell the server to destroy its context.
		 * But don't bother if it's a forced unmount
		 * or if it's a dummy sec=sys context.
		 */
		if (!(mntflags & MNT_FORCE) && cp->gss_clnt_service != RPCSEC_GSS_SVC_SYS) {
			temp_cred.cr_uid = cp->gss_clnt_uid;
			cred = kauth_cred_create(&temp_cred);
			cp->gss_clnt_proc = RPCSEC_GSS_DESTROY;

			error = 0;
			nfsm_chain_null(&nmreq);
			nfsm_chain_null(&nmrep);
			nfsm_chain_build_alloc_init(error, &nmreq, 0);
			nfsm_chain_build_done(error, &nmreq);
			if (!error)
				nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC_NULL,
					current_thread(), cred, 0, &nmrep, &xid, &status);
			nfsm_chain_cleanup(&nmreq);
			nfsm_chain_cleanup(&nmrep);
			kauth_cred_unref(&cred);
		}

		/*
		 * Mark the context invalid then drop
		 * the reference to remove it if its
		 * refcount is zero.
		 */
		cp->gss_clnt_flags |= GSS_CTX_INVAL;
		nfs_gss_clnt_ctx_unref(&req);
	}
}

/*
 * If we get a failure in trying to establish a context we need to wait a 
 * little while to see if the server is feeling better. In our case this is
 * probably a failure in directory services not coming up in a timely fashion.
 * This routine sort of mimics receiving a jukebox error.
 */
static int
nfs_gss_clnt_ctx_delay(struct nfsreq *req, int *retry)
{
	int timeo = (1 << *retry) * NFS_TRYLATERDEL;
	int error = 0;
	struct nfsmount *nmp = req->r_nmp;
	struct timeval now;
	time_t waituntil;

	if ((nmp->nm_flag & NFSMNT_SOFT) && *retry > nmp->nm_retry)
		return (ETIMEDOUT);
	if (timeo > 60)
		timeo = 60;

	microuptime(&now);
	waituntil = now.tv_sec + timeo;
	while (now.tv_sec < waituntil) {
		tsleep(&lbolt, PSOCK, "nfs_gss_clnt_ctx_delay", 0);
		error = nfs_sigintr(nmp, req, current_thread(), 0);
		if (error)
			break;
		microuptime(&now);
	}
	*retry += 1;

	return (error);
}


#endif /* NFSCLIENT */

/*************
 *
 * Server functions
 */

#if NFSSERVER

/*
 * Find a server context based on a handle value received
 * in an RPCSEC_GSS credential.
 */
static struct nfs_gss_svc_ctx *
nfs_gss_svc_ctx_find(uint32_t handle)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *cp;
	
	head = &nfs_gss_svc_ctx_hashtbl[SVC_CTX_HASH(handle)];

	lck_mtx_lock(nfs_gss_svc_ctx_mutex);
	LIST_FOREACH(cp, head, gss_svc_entries)
		if (cp->gss_svc_handle == handle)
			break;
	lck_mtx_unlock(nfs_gss_svc_ctx_mutex);

	return (cp);
}

/*
 * Insert a new server context into the hash table
 * and start the context reap thread if necessary.
 */
static void
nfs_gss_svc_ctx_insert(struct nfs_gss_svc_ctx *cp)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	
	head = &nfs_gss_svc_ctx_hashtbl[SVC_CTX_HASH(cp->gss_svc_handle)];

	lck_mtx_lock(nfs_gss_svc_ctx_mutex);
	LIST_INSERT_HEAD(head, cp, gss_svc_entries);
	nfs_gss_ctx_count++;

	if (!nfs_gss_timer_on) {
		nfs_gss_timer_on = 1;
		nfs_interval_timer_start(nfs_gss_svc_ctx_timer_call,
			GSS_TIMER_PERIOD * MSECS_PER_SEC);
	}
	lck_mtx_unlock(nfs_gss_svc_ctx_mutex);
}

/*
 * This function is called via the kernel's callout
 * mechanism.  It runs only when there are
 * cached RPCSEC_GSS contexts.
 */
void
nfs_gss_svc_ctx_timer(__unused void *param1, __unused void *param2)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *cp, *next;
	uint64_t timenow;
	int contexts = 0;
	int i;

	lck_mtx_lock(nfs_gss_svc_ctx_mutex);
	clock_get_uptime(&timenow);

	/*
	 * Scan all the hash chains
	 * Assume nfs_gss_svc_ctx_mutex is held
	 */
	for (i = 0; i < SVC_CTX_HASHSZ; i++) {
		/*
		 * For each hash chain, look for entries
		 * that haven't been used in a while.
		 */
		head = &nfs_gss_svc_ctx_hashtbl[i];
		for (cp = LIST_FIRST(head); cp; cp = next) {
			contexts++;
			next = LIST_NEXT(cp, gss_svc_entries);
			if (timenow > cp->gss_svc_expiretime) {
				/*
				 * A stale context - remove it
				 */
				LIST_REMOVE(cp, gss_svc_entries);
				if (cp->gss_svc_seqbits)
					FREE(cp->gss_svc_seqbits, M_TEMP);
				lck_mtx_destroy(cp->gss_svc_mtx, nfs_gss_svc_grp);
				FREE(cp, M_TEMP);
				contexts--;
			}
		}
	}

	nfs_gss_ctx_count = contexts;

	/*
	 * If there are still some cached contexts left,
	 * set up another callout to check on them later.
	 */
	nfs_gss_timer_on = nfs_gss_ctx_count > 0;
	if (nfs_gss_timer_on)
		nfs_interval_timer_start(nfs_gss_svc_ctx_timer_call,
			GSS_TIMER_PERIOD * MSECS_PER_SEC);

	lck_mtx_unlock(nfs_gss_svc_ctx_mutex);
}

/*
 * Here the server receives an RPCSEC_GSS credential in an
 * RPC call header.  First there's some checking to make sure
 * the credential is appropriate - whether the context is still
 * being set up, or is complete.  Then we use the handle to find
 * the server's context and validate the verifier, which contains
 * a signed checksum of the RPC header. If the verifier checks
 * out, we extract the user's UID and groups from the context
 * and use it to set up a UNIX credential for the user's request.
 */
int
nfs_gss_svc_cred_get(struct nfsrv_descript *nd, struct nfsm_chain *nmc)
{
	uint32_t vers, proc, seqnum, service;
	uint32_t handle, handle_len;
	struct nfs_gss_svc_ctx *cp = NULL;
	uint32_t flavor = 0, verflen = 0;
	int error = 0;
	uint32_t arglen, start, toklen, cksumlen;
	u_char tokbuf[KRB5_SZ_TOKMAX];
	u_char cksum1[8], cksum2[8];
	struct nfsm_chain nmc_tmp;

	vers = proc = seqnum = service = handle_len = 0;
	arglen = cksumlen = 0;

	nfsm_chain_get_32(error, nmc, vers);
	if (vers != RPCSEC_GSS_VERS_1) {
		error = NFSERR_AUTHERR | AUTH_REJECTCRED;
		goto nfsmout;
	}

	nfsm_chain_get_32(error, nmc, proc);
	nfsm_chain_get_32(error, nmc, seqnum);
	nfsm_chain_get_32(error, nmc, service);
	nfsm_chain_get_32(error, nmc, handle_len);
	if (error)
		goto nfsmout;

	/*
	 * Make sure context setup/destroy is being done with a nullproc
	 */
	if (proc != RPCSEC_GSS_DATA && nd->nd_procnum != NFSPROC_NULL) {
		error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
		goto nfsmout;
	}

	/*
	 * If the sequence number is greater than the max
	 * allowable, reject and have the client init a
	 * new context.
	 */
	if (seqnum > GSS_MAXSEQ) {
		error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
		goto nfsmout;
	}

	nd->nd_sec = 
		service == RPCSEC_GSS_SVC_NONE ?      RPCAUTH_KRB5 :
		service == RPCSEC_GSS_SVC_INTEGRITY ? RPCAUTH_KRB5I :
		service == RPCSEC_GSS_SVC_PRIVACY ?   RPCAUTH_KRB5P : 0;

	if (proc == RPCSEC_GSS_INIT) {
		/*
		 * Limit the total number of contexts
		 */
		if (nfs_gss_ctx_count > nfs_gss_ctx_max) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}

		/*
		 * Set up a new context
		 */
		MALLOC(cp, struct nfs_gss_svc_ctx *, sizeof(*cp), M_TEMP, M_WAITOK|M_ZERO);
		if (cp == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
	} else {

		/*
		 * Use the handle to find the context
		 */
		if (handle_len != sizeof(handle)) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
			goto nfsmout;
		}
		nfsm_chain_get_32(error, nmc, handle);
		if (error)
			goto nfsmout;
		cp = nfs_gss_svc_ctx_find(handle);
		if (cp == NULL) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}
	}

	cp->gss_svc_proc = proc;

	if (proc == RPCSEC_GSS_DATA || proc == RPCSEC_GSS_DESTROY) {
		struct ucred temp_cred;

		if (cp->gss_svc_seqwin == 0) {
			/*
			 * Context isn't complete
			 */
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}

		if (!nfs_gss_svc_seqnum_valid(cp, seqnum)) {
			/*
			 * Sequence number is bad
			 */
			error = EINVAL;	// drop the request
			goto nfsmout;
		}

		/* Now compute the client's call header checksum */
		nfs_gss_cksum_chain(cp->gss_svc_sched, nmc, krb5_mic, 0, 0, cksum1);

		/*
		 * Validate the verifier.
		 * The verifier contains an encrypted checksum
		 * of the call header from the XID up to and
		 * including the credential.  We compute the
		 * checksum and compare it with what came in
		 * the verifier.
		 */
		nfsm_chain_get_32(error, nmc, flavor);
		nfsm_chain_get_32(error, nmc, verflen);
		if (flavor != RPCSEC_GSS || verflen != KRB5_SZ_TOKEN)
			error = NFSERR_AUTHERR | AUTH_BADVERF;
		nfsm_chain_get_opaque(error, nmc, verflen, tokbuf);
		if (error)
			goto nfsmout;

		/* Get the checksum from the token inside the verifier */
		error = nfs_gss_token_get(cp->gss_svc_sched, krb5_mic, tokbuf, 1,
			NULL, cksum2);
		if (error)
			goto nfsmout;

		if (bcmp(cksum1, cksum2, 8) != 0) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}

		nd->nd_gss_seqnum = seqnum;

		/*
		 * Set up the user's cred
		 */
		bzero(&temp_cred, sizeof(temp_cred));
		temp_cred.cr_uid = cp->gss_svc_uid;
		bcopy(cp->gss_svc_gids, temp_cred.cr_groups,
				sizeof(gid_t) * cp->gss_svc_ngroups);
		temp_cred.cr_ngroups = cp->gss_svc_ngroups;

		nd->nd_cr = kauth_cred_create(&temp_cred);
		if (nd->nd_cr == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		clock_interval_to_deadline(GSS_CTX_EXPIRE, NSEC_PER_SEC,
			&cp->gss_svc_expiretime);

		/*
		 * If the call arguments are integrity or privacy protected
		 * then we need to check them here.
		 */
		switch (service) {
		case RPCSEC_GSS_SVC_NONE:
			/* nothing to do */
			break;
		case RPCSEC_GSS_SVC_INTEGRITY:
			/*
			 * Here's what we expect in the integrity call args:
			 *
			 * - length of seq num + call args (4 bytes)
			 * - sequence number (4 bytes)
			 * - call args (variable bytes)
			 * - length of checksum token (37)
			 * - checksum of seqnum + call args (37 bytes)
			 */
			nfsm_chain_get_32(error, nmc, arglen);		// length of args
			if (arglen > NFS_MAXPACKET) {
				error = EBADRPC;
				goto nfsmout;
			}

			/* Compute the checksum over the call args */
			start = nfsm_chain_offset(nmc);
			nfs_gss_cksum_chain(cp->gss_svc_sched, nmc, krb5_mic, start, arglen, cksum1);
	
			/*
			 * Get the sequence number prepended to the args
			 * and compare it against the one sent in the
			 * call credential.
			 */
			nfsm_chain_get_32(error, nmc, seqnum);
			if (seqnum != nd->nd_gss_seqnum) {
				error = EBADRPC;			// returns as GARBAGEARGS
				goto nfsmout;
			}
	
			/*
			 * Advance to the end of the args and
			 * fetch the checksum computed by the client.
			 */
			nmc_tmp = *nmc;	
			arglen -= NFSX_UNSIGNED;			// skipped seqnum
			nfsm_chain_adv(error, &nmc_tmp, arglen);	// skip args
			nfsm_chain_get_32(error, &nmc_tmp, cksumlen);	// length of checksum
			if (cksumlen != KRB5_SZ_TOKEN) {
				error = EBADRPC;
				goto nfsmout;
			}
			nfsm_chain_get_opaque(error, &nmc_tmp, cksumlen, tokbuf);
			if (error)
				goto nfsmout;
			error = nfs_gss_token_get(cp->gss_svc_sched, krb5_mic, tokbuf, 1,
				NULL, cksum2);
	
			/* Verify that the checksums are the same */
			if (error || bcmp(cksum1, cksum2, 8) != 0) {
				error = EBADRPC;
				goto nfsmout;
			}
			break;
		case RPCSEC_GSS_SVC_PRIVACY:
			/*
			 * Here's what we expect in the privacy call args:
			 *
			 * - length of confounder + seq num + token + call args
			 * - wrap token (37-40 bytes)
			 * - confounder (8 bytes)
			 * - sequence number (4 bytes)
			 * - call args (encrypted)
			 */
			nfsm_chain_get_32(error, nmc, arglen);		// length of args
			if (arglen > NFS_MAXPACKET) {
				error = EBADRPC;
				goto nfsmout;
			}
	
			/* Get the token that prepends the encrypted args */
			nfsm_chain_get_opaque(error, nmc, KRB5_SZ_TOKMAX, tokbuf);
			if (error)
				goto nfsmout;
			error = nfs_gss_token_get(cp->gss_svc_sched, krb5_wrap, tokbuf, 1,
				&toklen, cksum1);
			if (error)
				goto nfsmout;
			nfsm_chain_reverse(nmc, nfsm_pad(toklen));
	
			/* decrypt the 8 byte confounder + seqnum + args */
			start = nfsm_chain_offset(nmc);
			arglen -= toklen;
			nfs_gss_encrypt_chain(cp->gss_svc_skey, nmc, start, arglen, DES_DECRYPT);
	
			/* Compute a checksum over the sequence number + results */
			nfs_gss_cksum_chain(cp->gss_svc_sched, nmc, krb5_wrap, start, arglen, cksum2);
	
			/* Verify that the checksums are the same */
			if (bcmp(cksum1, cksum2, 8) != 0) {
				error = EBADRPC;
				goto nfsmout;
			}

			/*
			 * Get the sequence number prepended to the args
			 * and compare it against the one sent in the
			 * call credential.
			 */
			nfsm_chain_adv(error, nmc, 8);			// skip over the confounder
			nfsm_chain_get_32(error, nmc, seqnum);
			if (seqnum != nd->nd_gss_seqnum) {
				error = EBADRPC;			// returns as GARBAGEARGS
				goto nfsmout;
			}
			break;
		}
	} else {
		/*
		 * If the proc is RPCSEC_GSS_INIT or RPCSEC_GSS_CONTINUE_INIT
		 * then we expect a null verifier.
		 */
		nfsm_chain_get_32(error, nmc, flavor);
		nfsm_chain_get_32(error, nmc, verflen);
		if (error || flavor != RPCAUTH_NULL || verflen > 0)
			error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
		if (error)
			goto nfsmout;
	}

	nd->nd_gss_context = cp;
nfsmout:
	return (error);
}

/*
 * Insert the server's verifier into the RPC reply header.
 * It contains a signed checksum of the sequence number that
 * was received in the RPC call.
 * Then go on to add integrity or privacy if necessary.
 */
int
nfs_gss_svc_verf_put(struct nfsrv_descript *nd, struct nfsm_chain *nmc)
{
	struct nfs_gss_svc_ctx *cp;
	int error = 0;
	u_char tokbuf[KRB5_SZ_TOKEN];
	int toklen;
	u_char cksum[8];

	cp = nd->nd_gss_context;

	if (cp->gss_svc_major != GSS_S_COMPLETE) {
		/*
		 * If the context isn't yet complete
		 * then return a null verifier.
		 */
		nfsm_chain_add_32(error, nmc, RPCAUTH_NULL);
		nfsm_chain_add_32(error, nmc, 0);
		return (error);
	}

	/*
	 * Compute checksum of the request seq number
	 * If it's the final reply of context setup
	 * then return the checksum of the context
	 * window size.
	 */
	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT)
		nfs_gss_cksum_rep(cp->gss_svc_sched, cp->gss_svc_seqwin, cksum);
	else
		nfs_gss_cksum_rep(cp->gss_svc_sched, nd->nd_gss_seqnum, cksum);
	/*
	 * Now wrap it in a token and add
	 * the verifier to the reply.
	 */
	toklen = nfs_gss_token_put(cp->gss_svc_sched, krb5_mic, tokbuf, 0, 0, cksum);
	nfsm_chain_add_32(error, nmc, RPCSEC_GSS);
	nfsm_chain_add_32(error, nmc, toklen);
	nfsm_chain_add_opaque(error, nmc, tokbuf, toklen);

	return (error);
}

/*
 * The results aren't available yet, but if they need to be
 * checksummed for integrity protection or encrypted, then
 * we can record the start offset here, insert a place-holder
 * for the results length, as well as the sequence number.
 * The rest of the work is done later by nfs_gss_svc_protect_reply()
 * when the results are available.
 */
int
nfs_gss_svc_prepare_reply(struct nfsrv_descript *nd, struct nfsm_chain *nmc)
{
	struct nfs_gss_svc_ctx *cp = nd->nd_gss_context;
	int error = 0;

	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT)
		return (0);

	switch (nd->nd_sec) {
	case RPCAUTH_KRB5:
		/* Nothing to do */
		break;
	case RPCAUTH_KRB5I:
		nd->nd_gss_mb = nmc->nmc_mcur;			// record current mbuf
		nfsm_chain_finish_mbuf(error, nmc);		// split the chain here
		nfsm_chain_add_32(error, nmc, nd->nd_gss_seqnum); // req sequence number
		break;
	case RPCAUTH_KRB5P:
		nd->nd_gss_mb = nmc->nmc_mcur;			// record current mbuf
		nfsm_chain_finish_mbuf(error, nmc);		// split the chain here
		nfsm_chain_add_32(error, nmc, random());	// confounder bytes 1-4
		nfsm_chain_add_32(error, nmc, random());	// confounder bytes 5-8
		nfsm_chain_add_32(error, nmc, nd->nd_gss_seqnum); // req sequence number
		break;
	}

	return (error);
}

/*
 * The results are checksummed or encrypted for return to the client
 */
int
nfs_gss_svc_protect_reply(struct nfsrv_descript *nd, mbuf_t mrep)
{
	struct nfs_gss_svc_ctx *cp = nd->nd_gss_context;
	struct nfsm_chain nmrep_res, *nmc_res = &nmrep_res;
	struct nfsm_chain nmrep_pre, *nmc_pre = &nmrep_pre;
	mbuf_t mb, results;
	uint32_t reslen;
	u_char tokbuf[KRB5_SZ_TOKMAX];
	int pad, toklen;
	u_char cksum[8];
	int error = 0;

	/*
	 * Using a reference to the mbuf where we previously split the reply
	 * mbuf chain, we split the mbuf chain argument into two mbuf chains,
	 * one that allows us to prepend a length field or token, (nmc_pre)
	 * and the second which holds just the results that we're going to
	 * checksum and/or encrypt.  When we're done, we join the chains back
	 * together.
	 */
	nfs_gss_nfsm_chain(nmc_res, mrep);		// set up the results chain
	mb = nd->nd_gss_mb;				// the mbuf where we split
	results = mbuf_next(mb);			// first mbuf in the results
	reslen = nfs_gss_mchain_length(results);	// length of results
	error = mbuf_setnext(mb, NULL);			// disconnect the chains
	if (error)
		return (error);
	nfs_gss_nfsm_chain(nmc_pre, mb);		// set up the prepend chain

	if (nd->nd_sec == RPCAUTH_KRB5I) {
		nfsm_chain_add_32(error, nmc_pre, reslen);
		nfsm_chain_build_done(error, nmc_pre);
		if (error)
			return (error);
		nfs_gss_append_chain(nmc_pre, results);	// Append the results mbufs

		/* Now compute the checksum over the results data */
		nfs_gss_cksum_mchain(cp->gss_svc_sched, results, krb5_mic, 0, reslen, cksum);

		/* Put it into a token and append to the request */
		toklen = nfs_gss_token_put(cp->gss_svc_sched, krb5_mic, tokbuf, 0, 0, cksum);
		nfsm_chain_add_32(error, nmc_res, toklen);
		nfsm_chain_add_opaque(error, nmc_res, tokbuf, toklen);
		nfsm_chain_build_done(error, nmc_res);
	} else {
		/* RPCAUTH_KRB5P */
		/*
		 * Append a pad trailer - per RFC 1964 section 1.2.2.3
		 * Since XDR data is always 32-bit aligned, it
		 * needs to be padded either by 4 bytes or 8 bytes.
		 */
		if (reslen % 8 > 0) {
			nfsm_chain_add_32(error, nmc_res, 0x04040404);
			reslen += NFSX_UNSIGNED;
		} else {
			nfsm_chain_add_32(error, nmc_res, 0x08080808);
			nfsm_chain_add_32(error, nmc_res, 0x08080808);
			reslen +=  2 * NFSX_UNSIGNED;
		}
		nfsm_chain_build_done(error, nmc_res);

		/* Now compute the checksum over the results data */
		nfs_gss_cksum_mchain(cp->gss_svc_sched, results, krb5_wrap, 0, reslen, cksum);

		/* Put it into a token and insert in the reply */
		toklen = nfs_gss_token_put(cp->gss_svc_sched, krb5_wrap, tokbuf, 0, reslen, cksum);
		nfsm_chain_add_32(error, nmc_pre, toklen + reslen);
		nfsm_chain_add_opaque_nopad(error, nmc_pre, tokbuf, toklen);
		nfsm_chain_build_done(error, nmc_pre);
		if (error)
			return (error);
		nfs_gss_append_chain(nmc_pre, results);	// Append the results mbufs

		/* Encrypt the confounder + seqnum + results */
		nfs_gss_encrypt_mchain(cp->gss_svc_skey, results, 0, reslen, DES_ENCRYPT);

		/* Add null XDR pad if the ASN.1 token misaligned the data */
		pad = nfsm_pad(toklen + reslen);
		if (pad > 0) {
			nfsm_chain_add_opaque_nopad(error, nmc_pre, iv0, pad);
			nfsm_chain_build_done(error, nmc_pre);
		}
	}

	return (error);
}

/*
 * This function handles the context setup calls from the client.
 * Essentially, it implements the NFS null procedure calls when
 * an RPCSEC_GSS credential is used.
 * This is the context maintenance function.  It creates and
 * destroys server contexts at the whim of the client.
 * During context creation, it receives GSS-API tokens from the
 * client, passes them up to gssd, and returns a received token
 * back to the client in the null procedure reply.
 */
int
nfs_gss_svc_ctx_init(struct nfsrv_descript *nd, struct nfsrv_sock *slp, mbuf_t *mrepp)
{
	struct nfs_gss_svc_ctx *cp = NULL;
	uint32_t handle = 0;
	int error = 0;
	int autherr = 0;
	struct nfsm_chain *nmreq, nmrep;
	int sz;

	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	*mrepp = NULL;
	cp = nd->nd_gss_context;
	nd->nd_repstat = 0;

	switch (cp->gss_svc_proc) {
	case RPCSEC_GSS_INIT:
		/*
		 * Give the client a random handle so that
		 * if we reboot it's unlikely the client
		 * will get a bad context match.
		 * Make sure it's not zero, or already assigned.
		 */
		do {
			handle = random();
		} while (nfs_gss_svc_ctx_find(handle) != NULL || handle == 0);
		cp->gss_svc_handle = handle;
		cp->gss_svc_mtx = lck_mtx_alloc_init(nfs_gss_svc_grp, LCK_ATTR_NULL);
		clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC,
			&cp->gss_svc_expiretime);

		nfs_gss_svc_ctx_insert(cp);

		/* FALLTHRU */

	case RPCSEC_GSS_CONTINUE_INIT:
		/* Get the token from the request */
		nfsm_chain_get_32(error, nmreq, cp->gss_svc_tokenlen);
		if (cp->gss_svc_tokenlen == 0) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			break;
		}
		MALLOC(cp->gss_svc_token, u_char *, cp->gss_svc_tokenlen, M_TEMP, M_WAITOK);
		if (cp->gss_svc_token == NULL) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			break;
		}
		nfsm_chain_get_opaque(error, nmreq, cp->gss_svc_tokenlen, cp->gss_svc_token);

		/* Use the token in a gss_accept_sec_context upcall */
		error = nfs_gss_svc_gssd_upcall(cp);
		if (error) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			if (error == EAUTH)
				error = 0;
			break;
		}

		/*
		 * If the context isn't complete, pass the new token
		 * back to the client for another round.
		 */
		if (cp->gss_svc_major != GSS_S_COMPLETE)
			break;

		/*
		 * Now the server context is complete.
		 * Finish setup.
		 */
		clock_interval_to_deadline(GSS_CTX_EXPIRE, NSEC_PER_SEC,
			&cp->gss_svc_expiretime);
		cp->gss_svc_seqwin = GSS_SVC_SEQWINDOW;
		MALLOC(cp->gss_svc_seqbits, uint32_t *,
			nfsm_rndup((cp->gss_svc_seqwin + 7) / 8), M_TEMP, M_WAITOK|M_ZERO);
		if (cp->gss_svc_seqbits == NULL) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			break;
		}

		/*
		 * Generate a key schedule from our shiny new DES key
		 */
		error = des_key_sched((des_cblock *) cp->gss_svc_skey, cp->gss_svc_sched);
		if (error) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			error = 0;
			break;
		}
		break;

	case RPCSEC_GSS_DATA:
		/* Just a nullproc ping - do nothing */
		break;

	case RPCSEC_GSS_DESTROY:
		/*
		 * Don't destroy the context immediately because
		 * other active requests might still be using it.
		 * Instead, schedule it for destruction after
		 * GSS_CTX_PEND time has elapsed.
		 */
		cp = nfs_gss_svc_ctx_find(cp->gss_svc_handle);
		if (cp != NULL) {
			cp->gss_svc_handle = 0;	// so it can't be found
			lck_mtx_lock(cp->gss_svc_mtx);
			clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC,
				&cp->gss_svc_expiretime);
			lck_mtx_unlock(cp->gss_svc_mtx);
		}
		break;
	default:
		autherr = RPCSEC_GSS_CREDPROBLEM;
		break;
	}

	/* Now build the reply  */

	if (nd->nd_repstat == 0)
		nd->nd_repstat = autherr ? (NFSERR_AUTHERR | autherr) : NFSERR_RETVOID;
	sz = 7 * NFSX_UNSIGNED + nfsm_rndup(cp->gss_svc_tokenlen); // size of results
	error = nfsrv_rephead(nd, slp, &nmrep, sz);
	*mrepp = nmrep.nmc_mhead;
	if (error || autherr)
		goto nfsmout;

	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		nfsm_chain_add_32(error, &nmrep, sizeof(cp->gss_svc_handle));
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_handle);
	
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_major);
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_minor);
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_seqwin);
	
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_tokenlen);
		nfsm_chain_add_opaque(error, &nmrep, cp->gss_svc_token, cp->gss_svc_tokenlen);
		if (cp->gss_svc_token != NULL) {
			FREE(cp->gss_svc_token, M_TEMP);
			cp->gss_svc_token = NULL;
		}
	}

nfsmout:
	if (autherr != 0) {
		LIST_REMOVE(cp, gss_svc_entries);
		if (cp->gss_svc_seqbits != NULL)
			FREE(cp->gss_svc_seqbits, M_TEMP);
		if (cp->gss_svc_token != NULL)
			FREE(cp->gss_svc_token, M_TEMP);
		lck_mtx_destroy(cp->gss_svc_mtx, nfs_gss_svc_grp);
		FREE(cp, M_TEMP);
	}

	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * This is almost a mirror-image of the client side upcall.
 * It passes and receives a token, but invokes gss_accept_sec_context.
 * If it's the final call of the context setup, then gssd also returns
 * the session key and the user's UID.
 */
static int
nfs_gss_svc_gssd_upcall(struct nfs_gss_svc_ctx *cp)
{
	kern_return_t kr;
	mach_port_t mp;
	int retry_cnt = 0;
	byte_buffer okey = NULL;
	uint32_t skeylen = 0;
	vm_map_copy_t itoken = NULL;
	byte_buffer otoken = NULL;
	int error = 0;
	char svcname[] = "nfs";

	kr = task_get_gssd_port(get_threadtask(current_thread()), &mp);
	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_svc_gssd_upcall: can't get gssd port, status 0x%08x\n", kr);
		return (EAUTH);
	}
	if (!IPC_PORT_VALID(mp)) {
		printf("nfs_gss_svc_gssd_upcall: gssd port not valid\n");
		return (EAUTH);
	}

	if (cp->gss_svc_tokenlen > 0)
		nfs_gss_mach_alloc_buffer(cp->gss_svc_token, cp->gss_svc_tokenlen, &itoken);

retry:
	kr = mach_gss_accept_sec_context(
		mp,
		(byte_buffer) itoken, (mach_msg_type_number_t) cp->gss_svc_tokenlen,
		svcname,
		0,
		&cp->gss_svc_gssd_verf,
		&cp->gss_svc_context,
		&cp->gss_svc_cred_handle,
		&cp->gss_svc_uid,
		cp->gss_svc_gids,
		&cp->gss_svc_ngroups,
		&okey, (mach_msg_type_number_t *) &skeylen,
		&otoken, (mach_msg_type_number_t *) &cp->gss_svc_tokenlen,
		&cp->gss_svc_major,
		&cp->gss_svc_minor);

	if (kr != KERN_SUCCESS) { 
		printf("nfs_gss_svc_gssd_upcall failed: %d\n", kr);
		if (kr == MIG_SERVER_DIED && cp->gss_svc_context == 0 &&
			retry_cnt++ < NFS_GSS_MACH_MAX_RETRIES)
			goto retry;
		task_release_special_port(mp);
		return (EAUTH);
	}

	task_release_special_port(mp);
	if (skeylen > 0) {
		if (skeylen != SKEYLEN) {
			printf("nfs_gss_svc_gssd_upcall: bad key length (%d)\n", skeylen);
			return (EAUTH);
		}
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) okey, skeylen, cp->gss_svc_skey);
		if (error)
			return (EAUTH);
	}

	if (cp->gss_svc_tokenlen > 0) {
		MALLOC(cp->gss_svc_token, u_char *, cp->gss_svc_tokenlen, M_TEMP, M_WAITOK);
		if (cp->gss_svc_token == NULL)
			return (ENOMEM);
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) otoken, cp->gss_svc_tokenlen,
			cp->gss_svc_token);
		if (error)
			return (EAUTH);
	}

	return (kr);
}

/*
 * Validate the sequence number in the credential as described
 * in RFC 2203 Section 5.3.3.1
 *
 * Here the window of valid sequence numbers is represented by
 * a bitmap.  As each sequence number is received, its bit is
 * set in the bitmap.  An invalid sequence number lies below
 * the lower bound of the window, or is within the window but
 * has its bit already set.
 */
static int
nfs_gss_svc_seqnum_valid(struct nfs_gss_svc_ctx *cp, uint32_t seq)
{
	uint32_t *bits = cp->gss_svc_seqbits;
	uint32_t win = cp->gss_svc_seqwin;
	uint32_t i;

	lck_mtx_lock(cp->gss_svc_mtx);

	/*
	 * If greater than the window upper bound,
	 * move the window up, and set the bit.
	 */
	if (seq > cp->gss_svc_seqmax) {
		if (seq - cp->gss_svc_seqmax > win)
			bzero(bits, nfsm_rndup((win + 7) / 8));
		else
			for (i = cp->gss_svc_seqmax + 1; i < seq; i++)
				win_resetbit(bits, i % win);
		win_setbit(bits, seq % win);
		cp->gss_svc_seqmax = seq;
		lck_mtx_unlock(cp->gss_svc_mtx);
		return (1);
	}

	/*
	 * Invalid if below the lower bound of the window
	 */
	if (seq <= cp->gss_svc_seqmax - win) {
		lck_mtx_unlock(cp->gss_svc_mtx);
		return (0);
	}

	/*
	 * In the window, invalid if the bit is already set
	 */
	if (win_getbit(bits, seq % win)) {
		lck_mtx_unlock(cp->gss_svc_mtx);
		return (0);
	}
	win_setbit(bits, seq % win);
	lck_mtx_unlock(cp->gss_svc_mtx);
	return (1);
}

/*
 * Called at NFS server shutdown - destroy all contexts
 */
void
nfs_gss_svc_cleanup(void)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *cp, *ncp;
	int i;
	
	lck_mtx_lock(nfs_gss_svc_ctx_mutex);

	/*
	 * Run through all the buckets
	 */
	for (i = 0; i < SVC_CTX_HASHSZ; i++) {
		/*
		 * Remove and free all entries in the bucket
		 */
		head = &nfs_gss_svc_ctx_hashtbl[i];
		LIST_FOREACH_SAFE(cp, head, gss_svc_entries, ncp) {
			LIST_REMOVE(cp, gss_svc_entries);
			if (cp->gss_svc_seqbits)
				FREE(cp->gss_svc_seqbits, M_TEMP);
			lck_mtx_destroy(cp->gss_svc_mtx, nfs_gss_svc_grp);
			FREE(cp, M_TEMP);
		}
	}

	lck_mtx_unlock(nfs_gss_svc_ctx_mutex);
}

#endif /* NFSSERVER */


/*************
 * The following functions are used by both client and server.
 */

/*
 * Release a task special port that was obtained by task_get_special_port
 * or one of its macros (task_get_gssd_port in this case).
 * This really should be in a public kpi. 
 */

/* This should be in a public header if this routine is not */
extern void ipc_port_release_send(ipc_port_t);
extern ipc_port_t ipc_port_copy_send(ipc_port_t);

static void
task_release_special_port(mach_port_t mp)
{

	ipc_port_release_send(mp);
}

static mach_port_t
task_copy_special_port(mach_port_t mp)
{
	return ipc_port_copy_send(mp);
}

/*
 * The token that is sent and received in the gssd upcall
 * has unbounded variable length.  Mach RPC does not pass
 * the token in-line.  Instead it uses page mapping to handle
 * these parameters.  This function allocates a VM buffer
 * to hold the token for an upcall and copies the token
 * (received from the client) into it.  The VM buffer is
 * marked with a src_destroy flag so that the upcall will
 * automatically de-allocate the buffer when the upcall is
 * complete.
 */
static void
nfs_gss_mach_alloc_buffer(u_char *buf, uint32_t buflen, vm_map_copy_t *addr)
{
	kern_return_t kr;
	vm_offset_t kmem_buf;
	vm_size_t tbuflen;

	*addr = NULL;
	if (buf == NULL || buflen == 0)
		return;

	tbuflen = round_page(buflen);
	kr = vm_allocate(ipc_kernel_map, &kmem_buf, tbuflen, VM_FLAGS_ANYWHERE);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_allocate failed\n");
		return;
	}

	kr = vm_map_wire(ipc_kernel_map, vm_map_trunc_page(kmem_buf),
		vm_map_round_page(kmem_buf + tbuflen),
		VM_PROT_READ|VM_PROT_WRITE, FALSE);

	bcopy(buf, (void *) kmem_buf, buflen);

	kr = vm_map_unwire(ipc_kernel_map, vm_map_trunc_page(kmem_buf),
		vm_map_round_page(kmem_buf + tbuflen), FALSE);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_map_unwire failed\n");
		return;
	}

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t) kmem_buf,
		(vm_map_size_t) buflen, TRUE, addr);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_map_copyin failed\n");
		return;
	}

	if (buflen != tbuflen)
		kmem_free(ipc_kernel_map, kmem_buf + buflen, tbuflen - buflen);
}

/*
 * Here we handle a token received from the gssd via an upcall.
 * The received token resides in an allocate VM buffer.
 * We copy the token out of this buffer to a chunk of malloc'ed
 * memory of the right size, then de-allocate the VM buffer.
 */
static int
nfs_gss_mach_vmcopyout(vm_map_copy_t in, uint32_t len, u_char *out)
{
	vm_map_offset_t map_data;
	vm_offset_t data;
	int error;

	error = vm_map_copyout(ipc_kernel_map, &map_data, in);
	if (error)
		return (error);

	data = CAST_DOWN(vm_offset_t, map_data);
	bcopy((void *) data, out, len);
	vm_deallocate(ipc_kernel_map, data, len);

	return (0);
}

/*
 * Encode an ASN.1 token to be wrapped in an RPCSEC_GSS verifier.
 * Returns the size of the token, since it contains a variable
 * length DER encoded size field.
 */
static int
nfs_gss_token_put(
	des_key_schedule sched,
	u_char *alg,
	u_char *p,
	int initiator,
	int datalen,
	u_char *cksum)
{
	static uint32_t seqnum = 0;
	u_char *psave = p;
	u_char plain[8];
	int toklen, i;

	/*
	 * Fill in the token header: 2 octets.
	 * This is 0x06 - an ASN.1 tag for APPLICATION, 0, SEQUENCE
	 * followed by the length of the token: 35 + 0 octets for a
	 * MIC token, or 35 + encrypted octets for a wrap token;
	 */
	*p++ = 0x060;
	toklen = KRB5_SZ_MECH + KRB5_SZ_ALG + KRB5_SZ_SEQ + KRB5_SZ_CKSUM;
	nfs_gss_der_length_put(&p, toklen + datalen);

	/*
	 * Fill in the DER encoded mech OID for Kerberos v5.
	 * This represents the Kerberos OID 1.2.840.113554.1.2.2
	 * described in RFC 2623, section 4.2
	 */
	bcopy(krb5_mech, p, sizeof(krb5_mech));
	p += sizeof(krb5_mech);

	/*
	 * Now at the token described in RFC 1964, section 1.2.1
	 * Fill in the token ID, integrity algorithm indicator,
	 * for DES MAC MD5, and four filler octets.
	 * The alg string encodes the bytes to represent either
	 * a MIC token or a WRAP token for Kerberos.
	 */
	bcopy(alg, p, KRB5_SZ_ALG);
	p += KRB5_SZ_ALG;

	/*
	 * Now encode the sequence number according to
	 * RFC 1964, section 1.2.1.2 which dictates 4 octets
	 * of sequence number followed by 4 bytes of direction
	 * indicator: 0x00 for initiator or 0xff for acceptor.
	 * We DES CBC encrypt the sequence number using the first
	 * 8 octets of the checksum field as an initialization
	 * vector.
	 * Note that this sequence number is not at all related
	 * to the RPCSEC_GSS protocol sequence number.  This
	 * number is private to the ASN.1 token.  The only
	 * requirement is that it not be repeated in case the
	 * server has replay detection on, which normally should
	 * not be the case, since RFC 2203 section 5.2.3 says that
	 * replay detection and sequence checking must be turned off.
	 */
	seqnum++;
	for (i = 0; i < 4; i++)
		plain[i] = (u_char) ((seqnum >> (i * 8)) & 0xff);
	for (i = 4; i < 8; i++)
		plain[i] = initiator ? 0x00 : 0xff;
	des_cbc_encrypt((des_cblock *) plain, (des_cblock *) p, 8,
		sched, (des_cblock *) cksum, NULL, DES_ENCRYPT);
	p += 8;

	/*
	 * Finally, append 8 octets of DES MAC MD5
	 * checksum of the alg + plaintext data.
	 * The plaintext could be an RPC call header,
	 * the window value, or a sequence number.
	 */
	bcopy(cksum, p, 8);
	p += 8;

	return (p - psave);
}

/*
 * Determine size of ASN.1 DER length
 */
static int
nfs_gss_der_length_size(int len)
{
	return
		len < (1 <<  7) ? 1 :
		len < (1 <<  8) ? 2 :
		len < (1 << 16) ? 3 :
		len < (1 << 24) ? 4 : 5;
}

/*
 * Encode an ASN.1 DER length field
 */
static void
nfs_gss_der_length_put(u_char **pp, int len)
{
	int sz = nfs_gss_der_length_size(len);
	u_char *p = *pp;

	if (sz == 1) {
		*p++ = (u_char) len;
	} else {
		*p++ = (u_char) ((sz-1) | 0x80);
		sz -= 1;
		while (sz--)
			*p++ = (u_char) ((len >> (sz * 8)) & 0xff);
	}

	*pp = p;
}

/*
 * Decode an ASN.1 DER length field
 */
static int
nfs_gss_der_length_get(u_char **pp)
{
	u_char *p = *pp;
	uint32_t flen, len = 0;

	flen = *p & 0x7f;

	if ((*p++ & 0x80) == 0)
		len = flen;
	else {
		if (flen > sizeof(uint32_t))
			return (-1);
		while (flen--)
			len = (len << 8) + *p++;
	}
	*pp = p;
	return (len);
}

/*
 * Decode an ASN.1 token from an RPCSEC_GSS verifier.
 */
static int
nfs_gss_token_get(
	des_key_schedule sched,
	u_char *alg,
	u_char *p,
	int initiator,
	uint32_t *len,
	u_char *cksum)
{
	u_char d, plain[8];
	u_char *psave = p;
	int seqnum, i;

	/*
	 * Check that we have a valid token header
	 */
	if (*p++ != 0x60)
		return (AUTH_BADCRED);
	(void) nfs_gss_der_length_get(&p);	// ignore the size

	/*
	 * Check that we have the DER encoded Kerberos v5 mech OID
	 */
	if (bcmp(p, krb5_mech, sizeof(krb5_mech) != 0))
		return (AUTH_BADCRED);
	p += sizeof(krb5_mech);

	/*
	 * Now check the token ID, DES MAC MD5 algorithm
	 * indicator, and filler octets.
	 */
	if (bcmp(p, alg, KRB5_SZ_ALG) != 0)
		return (AUTH_BADCRED);
	p += KRB5_SZ_ALG;

	/*
	 * Now decrypt the sequence number.
	 * Note that the DES CBC decryption uses the first 8 octets
	 * of the checksum field as an initialization vector (p + 8).
	 * Per RFC 2203 section 5.2.2 we don't check the sequence number
	 * in the ASN.1 token because the RPCSEC_GSS protocol has its
	 * own sequence number described in section 5.3.3.1
	 */
	seqnum = 0;
	des_cbc_encrypt((des_cblock *) p, (des_cblock *) plain, 8,
		sched, (des_cblock *) (p + 8), NULL, DES_DECRYPT);
	p += 8;
	for (i = 0; i < 4; i++)
		seqnum |= plain[i] << (i * 8);

	/*
	 * Make sure the direction
	 * indicator octets are correct.
	 */
	d = initiator ? 0x00 : 0xff;
	for (i = 4; i < 8; i++)
		if (plain[i] != d)
			return (AUTH_BADCRED);

	/*
	 * Finally, get the checksum
	 */
	bcopy(p, cksum, 8);
	p += 8;

	if (len != NULL)
		*len = p - psave;

	return (0);
}

/*
 * Return the number of bytes in an mbuf chain.
 */
static int
nfs_gss_mchain_length(mbuf_t mhead)
{
	mbuf_t mb;
	int len = 0;

	for (mb = mhead; mb; mb = mbuf_next(mb))
		len += mbuf_len(mb);

	return (len);
}

/*
 * Append an args or results mbuf chain to the header chain
 */
static int
nfs_gss_append_chain(struct nfsm_chain *nmc, mbuf_t mc)
{
	int error = 0;
	mbuf_t mb, tail;

	/* Connect the mbuf chains */
	error = mbuf_setnext(nmc->nmc_mcur, mc);
	if (error)
		return (error);

	/* Find the last mbuf in the chain */
	tail = NULL;
	for (mb = mc; mb; mb = mbuf_next(mb))
		tail = mb;

	nmc->nmc_mcur = tail;
	nmc->nmc_ptr = (caddr_t) mbuf_data(tail) + mbuf_len(tail);
	nmc->nmc_left = mbuf_trailingspace(tail);

	return (0);
}

/*
 * Convert an mbuf chain to an NFS mbuf chain
 */
static void
nfs_gss_nfsm_chain(struct nfsm_chain *nmc, mbuf_t mc)
{
	mbuf_t mb, tail;

	/* Find the last mbuf in the chain */
	tail = NULL;
	for (mb = mc; mb; mb = mbuf_next(mb))
		tail = mb;

	nmc->nmc_mhead = mc;
	nmc->nmc_mcur = tail;
	nmc->nmc_ptr = (caddr_t) mbuf_data(tail) + mbuf_len(tail);
	nmc->nmc_left = mbuf_trailingspace(tail);
	nmc->nmc_flags = 0;
}


/*
 * Compute a checksum over an mbuf chain.
 * Start building an MD5 digest at the given offset and keep
 * going until the end of data in the current mbuf is reached.
 * Then convert the 16 byte MD5 digest to an 8 byte DES CBC
 * checksum.
 */
static void
nfs_gss_cksum_mchain(
	des_key_schedule sched,
	mbuf_t mhead,
	u_char *alg,
	int offset,
	int len,
	u_char *cksum)
{
	mbuf_t mb;
	u_char *ptr;
	int left, bytes;
	MD5_CTX context;
	u_char digest[16];

	MD5Init(&context);

	/*
	 * Logically prepend the first 8 bytes of the algorithm
	 * field as required by RFC 1964, section 1.2.1.1
	 */
	MD5Update(&context, alg, KRB5_SZ_ALG);

	/*
	 * Move down the mbuf chain until we reach the given
	 * byte offset, then start MD5 on the mbuf data until
	 * we've done len bytes.
	 */

	for (mb = mhead; mb && len > 0; mb = mbuf_next(mb)) {
		ptr  = mbuf_data(mb);
		left = mbuf_len(mb);
		if (offset >= left) {
			/* Offset not yet reached */
			offset -= left;
			continue;
		}
		/* At or beyond offset - checksum data */
		ptr += offset;
		left -= offset;
		offset = 0;
			
		bytes = left < len ? left : len;
		if (bytes > 0)
			MD5Update(&context, ptr, bytes);
		len -= bytes;
	}

	MD5Final(digest, &context);

	/*
	 * Now get the DES CBC checksum for the digest.
	 */
	(void) des_cbc_cksum((des_cblock *) digest, (des_cblock *) cksum,
		sizeof(digest), sched, (des_cblock *) iv0);
}

/*
 * Compute a checksum over an NFS mbuf chain.
 * Start building an MD5 digest at the given offset and keep
 * going until the end of data in the current mbuf is reached.
 * Then convert the 16 byte MD5 digest to an 8 byte DES CBC
 * checksum.
 */
static void
nfs_gss_cksum_chain(
	des_key_schedule sched,
	struct nfsm_chain *nmc,
	u_char *alg,
	int offset,
	int len,
	u_char *cksum)
{
	/*
	 * If the length parameter is zero, then we need
	 * to use the length from the offset to the current
	 * encode/decode offset.
	 */
	if (len == 0)
		len = nfsm_chain_offset(nmc) - offset;

	return (nfs_gss_cksum_mchain(sched, nmc->nmc_mhead, alg, offset, len, cksum));
}

/*
 * Compute a checksum of the sequence number (or sequence window)
 * of an RPCSEC_GSS reply.
 */
static void
nfs_gss_cksum_rep(des_key_schedule sched, uint32_t seqnum, u_char *cksum)
{
	MD5_CTX context;
	u_char digest[16];
	uint32_t val = htonl(seqnum);

	MD5Init(&context);

	/*
	 * Logically prepend the first 8 bytes of the MIC
	 * token as required by RFC 1964, section 1.2.1.1
	 */
	MD5Update(&context, krb5_mic, KRB5_SZ_ALG);

	/*
	 * Compute the digest of the seqnum in network order
	 */
	MD5Update(&context, (u_char *) &val, 4);
	MD5Final(digest, &context);

	/*
	 * Now get the DES CBC checksum for the digest.
	 */
	(void) des_cbc_cksum((des_cblock *) digest, (des_cblock *) cksum,
		sizeof(digest), sched, (des_cblock *) iv0);
}

/*
 * Encrypt or decrypt data in an mbuf chain with des-cbc.
 */
static void
nfs_gss_encrypt_mchain(
	u_char *key,
	mbuf_t mhead,
	int offset,
	int len,
	int encrypt)
{
	des_key_schedule sched;
	mbuf_t mb, mbn;
	u_char *ptr, *nptr;
	u_char tmp[8], ivec[8];
	int i, left, left8, remain;

	/*
	 * Make the key schedule per RFC 1964 section 1.2.2.3
	 */
	for (i = 0; i < 8; i++)
		tmp[i] = key[i] ^ 0xf0;
	bzero(ivec, 8);

	(void) des_key_sched((des_cblock *) tmp, sched);

	/*
	 * Move down the mbuf chain until we reach the given
	 * byte offset, then start encrypting the mbuf data until
	 * we've done len bytes.
	 */

	for (mb = mhead; mb && len > 0; mb = mbn) {
		mbn  = mbuf_next(mb);
		ptr  = mbuf_data(mb);
		left = mbuf_len(mb);
		if (offset >= left) {
			/* Offset not yet reached */
			offset -= left;
			continue;
		}
		/* At or beyond offset - encrypt data */
		ptr += offset;
		left -= offset;
		offset = 0;
			
		/*
		 * DES CBC has to encrypt 8 bytes at a time.
		 * If the number of bytes to be encrypted in this
		 * mbuf isn't some multiple of 8 bytes, encrypt all
		 * the 8 byte blocks, then combine the remaining
		 * bytes with enough from the next mbuf to make up
		 * an 8 byte block and encrypt that block separately,
		 * i.e. that block is split across two mbufs.
		 */
		remain = left % 8;
		left8 = left - remain;
		left = left8 < len ? left8 : len;
		if (left > 0) {
			des_cbc_encrypt((des_cblock *) ptr, (des_cblock *) ptr, left, sched,
				(des_cblock *) ivec, (des_cblock *) ivec, encrypt);
			len -= left;
		}

		if (mbn && remain > 0) {
			nptr = mbuf_data(mbn);
			offset = 8 - remain;
			bcopy(ptr + left, tmp, remain);		// grab from this mbuf
			bcopy(nptr, tmp + remain, offset);	// grab from next mbuf
			des_cbc_encrypt((des_cblock *) tmp, (des_cblock *) tmp, 8, sched,
				(des_cblock *) ivec, (des_cblock *) ivec, encrypt);
			bcopy(tmp, ptr + left, remain);		// return to this mbuf
			bcopy(tmp + remain, nptr, offset);	// return to next mbuf
			len -= 8;
		}
	}
}

/*
 * Encrypt or decrypt data in an NFS mbuf chain with des-cbc.
 */
static void
nfs_gss_encrypt_chain(
	u_char *key,
	struct nfsm_chain *nmc,
	int offset,
	int len,
	int encrypt)
{
	/*
	 * If the length parameter is zero, then we need
	 * to use the length from the offset to the current
	 * encode/decode offset.
	 */
	if (len == 0)
		len = nfsm_chain_offset(nmc) - offset;

	return (nfs_gss_encrypt_mchain(key, nmc->nmc_mhead, offset, len, encrypt));
}

/*
 * XXX This function borrowed from OpenBSD.
 * It will likely be moved into kernel crypto.
 */
static DES_LONG
des_cbc_cksum(input, output, length, schedule, ivec)
	des_cblock (*input);
	des_cblock (*output);
	long length;
	des_key_schedule schedule;
	des_cblock (*ivec);
{
	register unsigned long tout0,tout1,tin0,tin1;
	register long l=length;
	unsigned long tin[2];
	unsigned char *in,*out,*iv;

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	iv=(unsigned char *)ivec;

	c2l(iv,tout0);
	c2l(iv,tout1);
	for (; l>0; l-=8) {
		if (l >= 8) {
			c2l(in,tin0);
			c2l(in,tin1);
		} else
			c2ln(in,tin0,tin1,l);
			
		tin0^=tout0; tin[0]=tin0;
		tin1^=tout1; tin[1]=tin1;
		des_encrypt1((DES_LONG *)tin,schedule,DES_ENCRYPT);
		/* fix 15/10/91 eay - thanks to keithr@sco.COM */
		tout0=tin[0];
		tout1=tin[1];
	}
	if (out != NULL) {
		l2c(tout0,out);
		l2c(tout1,out);
	}
	tout0=tin0=tin1=tin[0]=tin[1]=0;
	return(tout1);
}

/*
 * XXX This function borrowed from OpenBSD.
 * It will likely be moved into kernel crypto.
 */
static void
des_cbc_encrypt(input, output, length, schedule, ivec, retvec, encrypt)
	des_cblock (*input);
	des_cblock (*output);
	long length;
	des_key_schedule schedule;
	des_cblock (*ivec);
	des_cblock (*retvec);
	int encrypt;
{
	register unsigned long tin0,tin1;
	register unsigned long tout0,tout1,xor0,xor1;
	register unsigned char *in,*out,*retval;
	register long l=length;
	unsigned long tin[2];
	unsigned char *iv;
	tin0 = tin1 = 0;

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	retval=(unsigned char *)retvec;
	iv=(unsigned char *)ivec;

	if (encrypt) {
		c2l(iv,tout0);
		c2l(iv,tout1);
		for (l-=8; l>=0; l-=8) {
			c2l(in,tin0);
			c2l(in,tin1);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (l != -8) {
			c2ln(in,tin0,tin1,l+8);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (retval) {
			l2c(tout0,retval);
			l2c(tout1,retval);
		}
	} else {
		c2l(iv,xor0);
		c2l(iv,xor1);
		for (l-=8; l>=0; l-=8) {
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2c(tout0,out);
			l2c(tout1,out);
			xor0=tin0;
			xor1=tin1;
		}
		if (l != -8) {
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt1((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2cn(tout0,tout1,out,l+8);
		/*	xor0=tin0;
			xor1=tin1; */
		}
		if (retval) {
			l2c(tin0,retval);
			l2c(tin1,retval);
		}
	}
	tin0=tin1=tout0=tout1=xor0=xor1=0;
	tin[0]=tin[1]=0;
}
