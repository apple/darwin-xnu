/*
 * Copyright (c) 2007-2015 Apple Inc. All rights reserved.
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

#include <nfs/nfs_conf.h>
#if CONFIG_NFS

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
#include <sys/ucred.h>

#include <kern/host.h>
#include <kern/task.h>
#include <libkern/libkern.h>

#include <mach/task.h>
#include <mach/host_special_ports.h>
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
#include <mach_assert.h>
#include <kern/assert.h>

#define ASSERT(EX) assert(EX)

#define NFS_GSS_MACH_MAX_RETRIES 3

#define NFS_GSS_DBG(...) NFS_DBG(NFS_FAC_GSS, 7, ## __VA_ARGS__)
#define NFS_GSS_ISDBG  (NFS_DEBUG_FACILITY &  NFS_FAC_GSS)


#if CONFIG_NFS_SERVER
u_long nfs_gss_svc_ctx_hash;
struct nfs_gss_svc_ctx_hashhead *nfs_gss_svc_ctx_hashtbl;
lck_mtx_t *nfs_gss_svc_ctx_mutex;
lck_grp_t *nfs_gss_svc_grp;
uint32_t nfsrv_gss_context_ttl = GSS_CTX_EXPIRE;
#define GSS_SVC_CTX_TTL ((uint64_t)max(2*GSS_CTX_PEND, nfsrv_gss_context_ttl) * NSEC_PER_SEC)
#endif /* CONFIG_NFS_SERVER */

#if CONFIG_NFS_CLIENT
lck_grp_t *nfs_gss_clnt_grp;
#endif /* CONFIG_NFS_CLIENT */

#define KRB5_MAX_MIC_SIZE 128
uint8_t krb5_mech_oid[11] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
static uint8_t xdrpad[] = { 0x00, 0x00, 0x00, 0x00};

#if CONFIG_NFS_CLIENT
static int      nfs_gss_clnt_ctx_find(struct nfsreq *);
static int      nfs_gss_clnt_ctx_init(struct nfsreq *, struct nfs_gss_clnt_ctx *);
static int      nfs_gss_clnt_ctx_init_retry(struct nfsreq *, struct nfs_gss_clnt_ctx *);
static int      nfs_gss_clnt_ctx_callserver(struct nfsreq *, struct nfs_gss_clnt_ctx *);
static uint8_t  *nfs_gss_clnt_svcname(struct nfsmount *, gssd_nametype *, uint32_t *);
static int      nfs_gss_clnt_gssd_upcall(struct nfsreq *, struct nfs_gss_clnt_ctx *, uint32_t);
void            nfs_gss_clnt_ctx_neg_cache_reap(struct nfsmount *);
static void     nfs_gss_clnt_ctx_clean(struct nfs_gss_clnt_ctx *);
static int      nfs_gss_clnt_ctx_copy(struct nfs_gss_clnt_ctx *, struct nfs_gss_clnt_ctx **);
static void     nfs_gss_clnt_ctx_destroy(struct nfs_gss_clnt_ctx *);
static void     nfs_gss_clnt_log_error(struct nfsreq *, struct nfs_gss_clnt_ctx *, uint32_t, uint32_t);
#endif /* CONFIG_NFS_CLIENT */

#if CONFIG_NFS_SERVER
static struct nfs_gss_svc_ctx *nfs_gss_svc_ctx_find(uint32_t);
static void     nfs_gss_svc_ctx_insert(struct nfs_gss_svc_ctx *);
static void     nfs_gss_svc_ctx_timer(void *, void *);
static int      nfs_gss_svc_gssd_upcall(struct nfs_gss_svc_ctx *);
static int      nfs_gss_svc_seqnum_valid(struct nfs_gss_svc_ctx *, uint32_t);

/* This is only used by server code */
static void     nfs_gss_nfsm_chain(struct nfsm_chain *, mbuf_t);
#endif /* CONFIG_NFS_SERVER */

static void     host_release_special_port(mach_port_t);
static mach_port_t host_copy_special_port(mach_port_t);
static void     nfs_gss_mach_alloc_buffer(u_char *, uint32_t, vm_map_copy_t *);
static int      nfs_gss_mach_vmcopyout(vm_map_copy_t, uint32_t, u_char *);

static int      nfs_gss_mchain_length(mbuf_t);
static int      nfs_gss_append_chain(struct nfsm_chain *, mbuf_t);

#if CONFIG_NFS_SERVER
thread_call_t nfs_gss_svc_ctx_timer_call;
int nfs_gss_timer_on = 0;
uint32_t nfs_gss_ctx_count = 0;
const uint32_t nfs_gss_ctx_max = GSS_SVC_MAXCONTEXTS;
#endif /* CONFIG_NFS_SERVER */

/*
 * Initialization when NFS starts
 */
void
nfs_gss_init(void)
{
#if CONFIG_NFS_CLIENT
	nfs_gss_clnt_grp = lck_grp_alloc_init("rpcsec_gss_clnt", LCK_GRP_ATTR_NULL);
#endif /* CONFIG_NFS_CLIENT */

#if CONFIG_NFS_SERVER
	nfs_gss_svc_grp  = lck_grp_alloc_init("rpcsec_gss_svc", LCK_GRP_ATTR_NULL);

	nfs_gss_svc_ctx_hashtbl = hashinit(SVC_CTX_HASHSZ, M_TEMP, &nfs_gss_svc_ctx_hash);
	nfs_gss_svc_ctx_mutex = lck_mtx_alloc_init(nfs_gss_svc_grp, LCK_ATTR_NULL);

	nfs_gss_svc_ctx_timer_call = thread_call_allocate(nfs_gss_svc_ctx_timer, NULL);
#endif /* CONFIG_NFS_SERVER */
}

/*
 * Common RPCSEC_GSS support routines
 */

static errno_t
rpc_gss_prepend_32(mbuf_t *mb, uint32_t value)
{
	int error;
	uint32_t *data;

#if 0
	data = mbuf_data(*mb);
	/*
	 * If a wap token comes back and is not aligned
	 * get a new buffer (which should be aligned) to put the
	 * length in.
	 */
	if ((uintptr_t)data & 0x3) {
		mbuf_t nmb;

		error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &nmb);
		if (error) {
			return error;
		}
		mbuf_setnext(nmb, *mb);
		*mb = nmb;
	}
#endif
	error = mbuf_prepend(mb, sizeof(uint32_t), MBUF_WAITOK);
	if (error) {
		return error;
	}

	data = mbuf_data(*mb);
	*data = txdr_unsigned(value);

	return 0;
}

/*
 * Prepend the sequence number to the xdr encode argumen or result
 * Sequence number is prepended in its own mbuf.
 *
 * On successful return mbp_head will point to the old mbuf chain
 * prepended  with a new mbuf that has the sequence number.
 */

static errno_t
rpc_gss_data_create(mbuf_t *mbp_head, uint32_t seqnum)
{
	int error;
	mbuf_t mb;
	struct nfsm_chain nmc;
	struct nfsm_chain *nmcp = &nmc;
	uint8_t *data;

	error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mb);
	if (error) {
		return error;
	}
	data = mbuf_data(mb);
#if 0
	/* Reserve space for prepending */
	len = mbuf_maxlen(mb);
	len = (len & ~0x3) - NFSX_UNSIGNED;
	printf("%s: data = %p, len = %d\n", __func__, data, (int)len);
	error = mbuf_setdata(mb, data + len, 0);
	if (error || mbuf_trailingspace(mb)) {
		printf("%s: data = %p trailingspace = %d error = %d\n", __func__, mbuf_data(mb), (int)mbuf_trailingspace(mb), error);
	}
#endif
	/* Reserve 16 words for prepending */
	error = mbuf_setdata(mb, data + 16 * sizeof(uint32_t), 0);
	nfsm_chain_init(nmcp, mb);
	nfsm_chain_add_32(error, nmcp, seqnum);
	nfsm_chain_build_done(error, nmcp);
	if (error) {
		return EINVAL;
	}
	mbuf_setnext(nmcp->nmc_mcur, *mbp_head);
	*mbp_head = nmcp->nmc_mhead;

	return 0;
}

/*
 * Create an rpc_gss_integ_data_t given an argument or result in mb_head.
 * On successful return mb_head will point to the rpc_gss_integ_data_t of length len.
 *      Note mb_head will now point to a 4 byte sequence number. len does not include
 *	any extra xdr padding.
 * Returns 0 on success, else an errno_t
 */

static errno_t
rpc_gss_integ_data_create(gss_ctx_id_t ctx, mbuf_t *mb_head, uint32_t seqnum, uint32_t *len)
{
	uint32_t error;
	uint32_t major;
	uint32_t length;
	gss_buffer_desc mic;
	struct nfsm_chain nmc;

	/* Length of the argument or result */
	length = nfs_gss_mchain_length(*mb_head);
	if (len) {
		*len = length;
	}
	error = rpc_gss_data_create(mb_head, seqnum);
	if (error) {
		return error;
	}

	/*
	 * length is the length of the rpc_gss_data
	 */
	length += NFSX_UNSIGNED;  /* Add the sequence number to the length */
	major = gss_krb5_get_mic_mbuf(&error, ctx, 0, *mb_head, 0, length, &mic);
	if (major != GSS_S_COMPLETE) {
		printf("gss_krb5_get_mic_mbuf failed %d\n", error);
		return error;
	}

	error = rpc_gss_prepend_32(mb_head, length);
	if (error) {
		return error;
	}

	nfsm_chain_dissect_init(error, &nmc, *mb_head);
	/* Append GSS mic token by advancing rpc_gss_data_t length + NFSX_UNSIGNED (size of the length field) */
	nfsm_chain_adv(error, &nmc, length + NFSX_UNSIGNED);
	nfsm_chain_finish_mbuf(error, &nmc); // Force the mic into its own sub chain.
	nfsm_chain_add_32(error, &nmc, mic.length);
	nfsm_chain_add_opaque(error, &nmc, mic.value, mic.length);
	nfsm_chain_build_done(error, &nmc);
	gss_release_buffer(NULL, &mic);

//	printmbuf("rpc_gss_integ_data_create done", *mb_head, 0, 0);
	assert(nmc.nmc_mhead == *mb_head);

	return error;
}

/*
 * Create an rpc_gss_priv_data_t out of the supplied raw arguments or results in mb_head.
 * On successful return mb_head will point to a wrap token of lenght len.
 *	Note len does not include any xdr padding
 * Returns 0 on success, else an errno_t
 */
static errno_t
rpc_gss_priv_data_create(gss_ctx_id_t ctx, mbuf_t *mb_head, uint32_t seqnum, uint32_t *len)
{
	uint32_t error;
	uint32_t major;
	struct nfsm_chain nmc;
	uint32_t pad;
	uint32_t length;

	error = rpc_gss_data_create(mb_head, seqnum);
	if (error) {
		return error;
	}

	length = nfs_gss_mchain_length(*mb_head);
	major = gss_krb5_wrap_mbuf(&error, ctx, 1, 0, mb_head, 0, length, NULL);
	if (major != GSS_S_COMPLETE) {
		return error;
	}

	length = nfs_gss_mchain_length(*mb_head);
	if (len) {
		*len = length;
	}
	pad = nfsm_pad(length);

	/* Prepend the opaque length of rep rpc_gss_priv_data */
	error = rpc_gss_prepend_32(mb_head, length);

	if (error) {
		return error;
	}
	if (pad) {
		nfsm_chain_dissect_init(error, &nmc, *mb_head);
		/* Advance the opauque size of length and length data */
		nfsm_chain_adv(error, &nmc, NFSX_UNSIGNED + length);
		nfsm_chain_finish_mbuf(error, &nmc);
		nfsm_chain_add_opaque_nopad(error, &nmc, xdrpad, pad);
		nfsm_chain_build_done(error, &nmc);
	}

	return error;
}

#if CONFIG_NFS_CLIENT

/*
 * Restore the argument or result from an rpc_gss_integ_data mbuf chain
 * We have a four byte seqence number, len arguments, and an opaque
 * encoded mic, possibly followed by some pad bytes. The mic and possible
 * pad bytes are on their own sub mbuf chains.
 *
 * On successful return mb_head is the chain of the xdr args or results sans
 * the sequence number and mic and return 0. Otherwise return an errno.
 *
 */
static errno_t
rpc_gss_integ_data_restore(gss_ctx_id_t ctx __unused, mbuf_t *mb_head, size_t len)
{
	mbuf_t mb = *mb_head;
	mbuf_t tail = NULL, next;

	/* Chop of the opaque length and seq number */
	mbuf_adj(mb, 2 * NFSX_UNSIGNED);

	/* should only be one, ... but */
	for (; mb; mb = next) {
		next = mbuf_next(mb);
		if (mbuf_len(mb) == 0) {
			mbuf_free(mb);
		} else {
			break;
		}
	}
	*mb_head = mb;

	for (; mb && len; mb = mbuf_next(mb)) {
		tail = mb;
		if (mbuf_len(mb) <= len) {
			len -= mbuf_len(mb);
		} else {
			return EBADRPC;
		}
	}
	/* drop the mic */
	if (tail) {
		mbuf_setnext(tail, NULL);
		mbuf_freem(mb);
	}

	return 0;
}

/*
 * Restore the argument or result rfom an rpc_gss_priv_data mbuf chain
 * mb_head points to the wrap token of length len.
 *
 * On successful return mb_head is our original xdr arg or result an
 * the return value is 0. Otherise return an errno
 */
static errno_t
rpc_gss_priv_data_restore(gss_ctx_id_t ctx, mbuf_t *mb_head, size_t len)
{
	uint32_t major, error;
	mbuf_t mb = *mb_head, next;
	uint32_t plen;
	size_t length;
	gss_qop_t qop = GSS_C_QOP_REVERSE;

	/* Chop of the opaque length */
	mbuf_adj(mb, NFSX_UNSIGNED);
	/* If we have padding, drop it */
	plen = nfsm_pad(len);
	if (plen) {
		mbuf_t tail = NULL;

		for (length = 0; length < len && mb; mb = mbuf_next(mb)) {
			tail = mb;
			length += mbuf_len(mb);
		}
		if ((length != len) || (mb == NULL) || (tail == NULL)) {
			return EBADRPC;
		}

		mbuf_freem(mb);
		mbuf_setnext(tail, NULL);
	}

	major = gss_krb5_unwrap_mbuf(&error, ctx, mb_head, 0, len, NULL, &qop);
	if (major != GSS_S_COMPLETE) {
		printf("gss_krb5_unwrap_mbuf failed. major = %d minor = %d\n", (int)major, error);
		return error;
	}
	mb = *mb_head;

	/* Drop the seqence number */
	mbuf_adj(mb, NFSX_UNSIGNED);
	assert(mbuf_len(mb) == 0);

	/* Chop of any empty mbufs */
	for (mb = *mb_head; mb; mb = next) {
		next = mbuf_next(mb);
		if (mbuf_len(mb) == 0) {
			mbuf_free(mb);
		} else {
			break;
		}
	}
	*mb_head = mb;

	return 0;
}

/*
 * Find the context for a particular user.
 *
 * If the context doesn't already exist
 * then create a new context for this user.
 *
 * Note that the code allows superuser (uid == 0)
 * to adopt the context of another user.
 *
 * We'll match on the audit session ids, since those
 * processes will have acccess to the same credential cache.
 */

#define kauth_cred_getasid(cred) ((cred)->cr_audit.as_aia_p->ai_asid)
#define kauth_cred_getauid(cred) ((cred)->cr_audit.as_aia_p->ai_auid)

#define SAFE_CAST_INTTYPE( type, intval ) \
	( (type)(intval)/(sizeof(type) < sizeof(intval) ? 0 : 1) )

uid_t
nfs_cred_getasid2uid(kauth_cred_t cred)
{
	uid_t result = SAFE_CAST_INTTYPE(uid_t, kauth_cred_getasid(cred));
	return result;
}

/*
 * Debugging
 */
static void
nfs_gss_clnt_ctx_dump(struct nfsmount *nmp)
{
	struct nfs_gss_clnt_ctx *cp;

	lck_mtx_lock(&nmp->nm_lock);
	NFS_GSS_DBG("Enter\n");
	TAILQ_FOREACH(cp, &nmp->nm_gsscl, gss_clnt_entries) {
		lck_mtx_lock(cp->gss_clnt_mtx);
		printf("context %d/%d: refcnt = %d, flags = %x\n",
		    kauth_cred_getasid(cp->gss_clnt_cred),
		    kauth_cred_getauid(cp->gss_clnt_cred),
		    cp->gss_clnt_refcnt, cp->gss_clnt_flags);
		lck_mtx_unlock(cp->gss_clnt_mtx);
	}
	NFS_GSS_DBG("Exit\n");
	lck_mtx_unlock(&nmp->nm_lock);
}

static char *
nfs_gss_clnt_ctx_name(struct nfsmount *nmp, struct nfs_gss_clnt_ctx *cp, char *buf, int len)
{
	char *np;
	int nlen;
	const char *server = "";

	if (nmp && nmp->nm_mountp) {
		server = vfs_statfs(nmp->nm_mountp)->f_mntfromname;
	}

	if (cp == NULL) {
		snprintf(buf, len, "[%s] NULL context", server);
		return buf;
	}

	if (cp->gss_clnt_principal && !cp->gss_clnt_display) {
		np = (char *)cp->gss_clnt_principal;
		nlen = cp->gss_clnt_prinlen;
	} else {
		np = cp->gss_clnt_display;
		nlen = np ? strlen(cp->gss_clnt_display) : 0;
	}
	if (nlen) {
		snprintf(buf, len, "[%s] %.*s %d/%d %s", server, nlen, np,
		    kauth_cred_getasid(cp->gss_clnt_cred),
		    kauth_cred_getuid(cp->gss_clnt_cred),
		    cp->gss_clnt_principal ? "" : "[from default cred] ");
	} else {
		snprintf(buf, len, "[%s] using default %d/%d ", server,
		    kauth_cred_getasid(cp->gss_clnt_cred),
		    kauth_cred_getuid(cp->gss_clnt_cred));
	}
	return buf;
}

#define NFS_CTXBUFSZ 80
#define NFS_GSS_CTX(req, cp) nfs_gss_clnt_ctx_name((req)->r_nmp, cp ? cp : (req)->r_gss_ctx, CTXBUF, sizeof(CTXBUF))

#define NFS_GSS_CLNT_CTX_DUMP(nmp)              \
	do {                  \
	        if (NFS_GSS_ISDBG && (NFS_DEBUG_FLAGS & 0x2))   \
	                nfs_gss_clnt_ctx_dump((nmp));   \
	} while (0)

static int
nfs_gss_clnt_ctx_cred_match(kauth_cred_t cred1, kauth_cred_t cred2)
{
	if (kauth_cred_getasid(cred1) == kauth_cred_getasid(cred2)) {
		return 1;
	}
	return 0;
}

/*
 * Busy the mount for each principal set on the mount
 * so that the automounter will not unmount the file
 * system underneath us. With out this, if an unmount
 * occurs the principal that is set for an audit session
 * will be lost and we may end up with a different identity.
 *
 * Note setting principals on the mount is a bad idea. This
 * really should be handle by KIM (Kerberos Identity Management)
 * so that defaults can be set by service identities.
 */

static void
nfs_gss_clnt_mnt_ref(struct nfsmount *nmp)
{
	int error;
	vnode_t rvp;

	if (nmp == NULL ||
	    !(vfs_flags(nmp->nm_mountp) & MNT_AUTOMOUNTED)) {
		return;
	}

	error = VFS_ROOT(nmp->nm_mountp, &rvp, NULL);
	if (!error) {
		vnode_ref(rvp);
		vnode_put(rvp);
	}
}

/*
 * Unbusy the mout. See above comment,
 */

static void
nfs_gss_clnt_mnt_rele(struct nfsmount *nmp)
{
	int error;
	vnode_t rvp;

	if (nmp == NULL ||
	    !(vfs_flags(nmp->nm_mountp) & MNT_AUTOMOUNTED)) {
		return;
	}

	error = VFS_ROOT(nmp->nm_mountp, &rvp, NULL);
	if (!error) {
		vnode_rele(rvp);
		vnode_put(rvp);
	}
}

int nfs_root_steals_ctx = 0;

static int
nfs_gss_clnt_ctx_find_principal(struct nfsreq *req, uint8_t *principal, uint32_t plen, uint32_t nt)
{
	struct nfsmount *nmp = req->r_nmp;
	struct nfs_gss_clnt_ctx *cp;
	struct nfsreq treq;
	int error = 0;
	struct timeval now;
	char CTXBUF[NFS_CTXBUFSZ];

	bzero(&treq, sizeof(struct nfsreq));
	treq.r_nmp = nmp;

	microuptime(&now);
	lck_mtx_lock(&nmp->nm_lock);
	TAILQ_FOREACH(cp, &nmp->nm_gsscl, gss_clnt_entries) {
		lck_mtx_lock(cp->gss_clnt_mtx);
		if (cp->gss_clnt_flags & GSS_CTX_DESTROY) {
			NFS_GSS_DBG("Found destroyed context %s refcnt = %d continuing\n",
			    NFS_GSS_CTX(req, cp),
			    cp->gss_clnt_refcnt);
			lck_mtx_unlock(cp->gss_clnt_mtx);
			continue;
		}
		if (nfs_gss_clnt_ctx_cred_match(cp->gss_clnt_cred, req->r_cred)) {
			if (nmp->nm_gsscl.tqh_first != cp) {
				TAILQ_REMOVE(&nmp->nm_gsscl, cp, gss_clnt_entries);
				TAILQ_INSERT_HEAD(&nmp->nm_gsscl, cp, gss_clnt_entries);
			}
			if (principal) {
				/*
				 * If we have a principal, but it does not match the current cred
				 * mark it for removal
				 */
				if (cp->gss_clnt_prinlen != plen || cp->gss_clnt_prinnt != nt ||
				    bcmp(cp->gss_clnt_principal, principal, plen) != 0) {
					cp->gss_clnt_flags |= (GSS_CTX_INVAL | GSS_CTX_DESTROY);
					cp->gss_clnt_refcnt++;
					lck_mtx_unlock(cp->gss_clnt_mtx);
					NFS_GSS_DBG("Marking %s for deletion because %s does not match\n",
					    NFS_GSS_CTX(req, cp), principal);
					NFS_GSS_DBG("len = (%d,%d), nt = (%d,%d)\n", cp->gss_clnt_prinlen, plen,
					    cp->gss_clnt_prinnt, nt);
					treq.r_gss_ctx  = cp;
					cp = NULL;
					break;
				}
			}
			if (cp->gss_clnt_flags & GSS_CTX_INVAL) {
				/*
				 * If we're still being used and we're not expired
				 * just return and don't bother gssd again. Note if
				 * gss_clnt_nctime is zero it is about to be set to now.
				 */
				if (cp->gss_clnt_nctime + GSS_NEG_CACHE_TO >= now.tv_sec || cp->gss_clnt_nctime == 0) {
					NFS_GSS_DBG("Context %s (refcnt = %d) not expired returning EAUTH nctime = %ld now = %ld\n",
					    NFS_GSS_CTX(req, cp), cp->gss_clnt_refcnt, cp->gss_clnt_nctime, now.tv_sec);
					lck_mtx_unlock(cp->gss_clnt_mtx);
					lck_mtx_unlock(&nmp->nm_lock);
					return NFSERR_EAUTH;
				}
				if (cp->gss_clnt_refcnt) {
					struct nfs_gss_clnt_ctx *ncp;
					/*
					 * If this context has references, we can't use it so we mark if for
					 * destruction and create a new context based on this one in the
					 * same manner as renewing one.
					 */
					cp->gss_clnt_flags |= GSS_CTX_DESTROY;
					NFS_GSS_DBG("Context %s has expired but we still have %d references\n",
					    NFS_GSS_CTX(req, cp), cp->gss_clnt_refcnt);
					error = nfs_gss_clnt_ctx_copy(cp, &ncp);
					lck_mtx_unlock(cp->gss_clnt_mtx);
					if (error) {
						lck_mtx_unlock(&nmp->nm_lock);
						return error;
					}
					cp = ncp;
					break;
				} else {
					if (cp->gss_clnt_nctime) {
						nmp->nm_ncentries--;
					}
					lck_mtx_unlock(cp->gss_clnt_mtx);
					TAILQ_REMOVE(&nmp->nm_gsscl, cp, gss_clnt_entries);
					break;
				}
			}
			/* Found a valid context to return */
			cp->gss_clnt_refcnt++;
			req->r_gss_ctx = cp;
			lck_mtx_unlock(cp->gss_clnt_mtx);
			lck_mtx_unlock(&nmp->nm_lock);
			return 0;
		}
		lck_mtx_unlock(cp->gss_clnt_mtx);
	}

	if (!cp && nfs_root_steals_ctx && principal == NULL && kauth_cred_getuid(req->r_cred) == 0) {
		/*
		 * If superuser is trying to get access, then co-opt
		 * the first valid context in the list.
		 * XXX Ultimately, we need to allow superuser to
		 * go ahead and attempt to set up its own context
		 * in case one is set up for it.
		 */
		TAILQ_FOREACH(cp, &nmp->nm_gsscl, gss_clnt_entries) {
			if (!(cp->gss_clnt_flags & (GSS_CTX_INVAL | GSS_CTX_DESTROY))) {
				nfs_gss_clnt_ctx_ref(req, cp);
				lck_mtx_unlock(&nmp->nm_lock);
				NFS_GSS_DBG("Root stole context %s\n", NFS_GSS_CTX(req, NULL));
				return 0;
			}
		}
	}

	NFS_GSS_DBG("Context %s%sfound in Neg Cache @  %ld\n",
	    NFS_GSS_CTX(req, cp),
	    cp == NULL ? " not " : "",
	    cp == NULL ? 0L : cp->gss_clnt_nctime);

	/*
	 * Not found - create a new context
	 */

	if (cp == NULL) {
		MALLOC(cp, struct nfs_gss_clnt_ctx *, sizeof(*cp), M_TEMP, M_WAITOK | M_ZERO);
		if (cp == NULL) {
			lck_mtx_unlock(&nmp->nm_lock);
			return ENOMEM;
		}
		cp->gss_clnt_cred = req->r_cred;
		kauth_cred_ref(cp->gss_clnt_cred);
		cp->gss_clnt_mtx = lck_mtx_alloc_init(nfs_gss_clnt_grp, LCK_ATTR_NULL);
		cp->gss_clnt_ptime = now.tv_sec - GSS_PRINT_DELAY;
		if (principal) {
			MALLOC(cp->gss_clnt_principal, uint8_t *, plen + 1, M_TEMP, M_WAITOK | M_ZERO);
			memcpy(cp->gss_clnt_principal, principal, plen);
			cp->gss_clnt_prinlen = plen;
			cp->gss_clnt_prinnt = nt;
			cp->gss_clnt_flags |= GSS_CTX_STICKY;
			nfs_gss_clnt_mnt_ref(nmp);
		}
	} else {
		nfs_gss_clnt_ctx_clean(cp);
		if (principal) {
			/*
			 * If we have a principal and we found a matching audit
			 * session, then to get here, the principal had to match.
			 * In walking the context list if it has a principal
			 * or the principal is not set then we mark the context
			 * for destruction and set cp to NULL and we fall to the
			 * if clause above. If the context still has references
			 * again we copy the context which will preserve the principal
			 * and we end up here with the correct principal set.
			 * If we don't have references the the principal must have
			 * match and we will fall through here.
			 */
			cp->gss_clnt_flags |= GSS_CTX_STICKY;
		}
	}

	cp->gss_clnt_thread = current_thread();
	nfs_gss_clnt_ctx_ref(req, cp);
	TAILQ_INSERT_HEAD(&nmp->nm_gsscl, cp, gss_clnt_entries);
	lck_mtx_unlock(&nmp->nm_lock);

	error = nfs_gss_clnt_ctx_init_retry(req, cp); // Initialize new context
	if (error) {
		NFS_GSS_DBG("nfs_gss_clnt_ctx_init_retry returned %d for %s\n", error, NFS_GSS_CTX(req, cp));
		nfs_gss_clnt_ctx_unref(req);
	}

	/* Remove any old matching contex that had a different principal */
	nfs_gss_clnt_ctx_unref(&treq);

	return error;
}

static int
nfs_gss_clnt_ctx_find(struct nfsreq *req)
{
	return nfs_gss_clnt_ctx_find_principal(req, NULL, 0, 0);
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
	struct nfs_gss_clnt_ctx *cp;
	uint32_t seqnum = 0;
	uint32_t major;
	uint32_t error = 0;
	int slpflag, recordmark = 0, offset;
	struct gss_seq *gsp;
	gss_buffer_desc mic;

	slpflag = (PZERO - 1);
	if (req->r_nmp) {
		slpflag |= (NMFLAG(req->r_nmp, INTR) && req->r_thread && !(req->r_flags & R_NOINTR)) ? PCATCH : 0;
		recordmark = (req->r_nmp->nm_sotype == SOCK_STREAM);
	}

retry:
	if (req->r_gss_ctx == NULL) {
		/*
		 * Find the context for this user.
		 * If no context is found, one will
		 * be created.
		 */
		error = nfs_gss_clnt_ctx_find(req);
		if (error) {
			return error;
		}
	}
	cp = req->r_gss_ctx;

	/*
	 * If the context thread isn't null, then the context isn't
	 * yet complete and is for the exclusive use of the thread
	 * doing the context setup. Wait until the context thread
	 * is null.
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	if (cp->gss_clnt_thread && cp->gss_clnt_thread != current_thread()) {
		cp->gss_clnt_flags |= GSS_NEEDCTX;
		msleep(cp, cp->gss_clnt_mtx, slpflag | PDROP, "ctxwait", NULL);
		slpflag &= ~PCATCH;
		if ((error = nfs_sigintr(req->r_nmp, req, req->r_thread, 0))) {
			return error;
		}
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
			msleep(cp, cp->gss_clnt_mtx, slpflag | PDROP, "seqwin", NULL);
			slpflag &= ~PCATCH;
			if ((error = nfs_sigintr(req->r_nmp, req, req->r_thread, 0))) {
				return error;
			}
			lck_mtx_lock(cp->gss_clnt_mtx);
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

		MALLOC(gsp, struct gss_seq *, sizeof(*gsp), M_TEMP, M_WAITOK | M_ZERO);
		if (gsp == NULL) {
			return ENOMEM;
		}
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
	if (cp->gss_clnt_handle_len > 0) {
		if (cp->gss_clnt_handle == NULL) {
			return EBADRPC;
		}
		nfsm_chain_add_opaque(error, nmc, cp->gss_clnt_handle, cp->gss_clnt_handle_len);
	}
	if (error) {
		return error;
	}
	/*
	 * Now add the verifier
	 */
	if (cp->gss_clnt_proc == RPCSEC_GSS_INIT ||
	    cp->gss_clnt_proc == RPCSEC_GSS_CONTINUE_INIT) {
		/*
		 * If the context is still being created
		 * then use a null verifier.
		 */
		nfsm_chain_add_32(error, nmc, RPCAUTH_NULL);    // flavor
		nfsm_chain_add_32(error, nmc, 0);               // length
		nfsm_chain_build_done(error, nmc);
		if (!error) {
			nfs_gss_append_chain(nmc, args);
		}
		return error;
	}

	offset = recordmark ? NFSX_UNSIGNED : 0; // record mark
	nfsm_chain_build_done(error, nmc);

	major = gss_krb5_get_mic_mbuf((uint32_t *)&error, cp->gss_clnt_ctx_id, 0, nmc->nmc_mhead, offset, 0, &mic);
	if (major != GSS_S_COMPLETE) {
		printf("gss_krb5_get_mic_buf failed %d\n", error);
		return error;
	}

	nfsm_chain_add_32(error, nmc, RPCSEC_GSS);      // flavor
	nfsm_chain_add_32(error, nmc, mic.length);              // length
	nfsm_chain_add_opaque(error, nmc, mic.value, mic.length);
	(void)gss_release_buffer(NULL, &mic);
	nfsm_chain_build_done(error, nmc);
	if (error) {
		return error;
	}

	/*
	 * Now we may have to compute integrity or encrypt the call args
	 * per RFC 2203 Section 5.3.2
	 */
	switch (cp->gss_clnt_service) {
	case RPCSEC_GSS_SVC_NONE:
		if (args) {
			nfs_gss_append_chain(nmc, args);
		}
		break;
	case RPCSEC_GSS_SVC_INTEGRITY:
		/*
		 * r_gss_arglen is the length of args mbuf going into the routine.
		 * Its used to find the mic if we need to restore the args.
		 */
		/* Note the mbufs that were used in r_mrest are being encapsulated in the rpc_gss_integ_data_t */
		assert(req->r_mrest == args);
		nfsm_chain_finish_mbuf(error, nmc);
		if (error) {
			return error;
		}
		error = rpc_gss_integ_data_create(cp->gss_clnt_ctx_id, &args, seqnum, &req->r_gss_arglen);
		if (error) {
			break;
		}
		req->r_mrest = args;
		req->r_gss_argoff = nfsm_chain_offset(nmc);
		nfs_gss_append_chain(nmc, args);
		break;
	case RPCSEC_GSS_SVC_PRIVACY:
		/*
		 * r_gss_arglen is the length of the wrap token sans any padding length.
		 * Its used to find any XDR padding of the wrap token.
		 */
		/* Note the mbufs that were used in r_mrest are being encapsulated in the rpc_gss_priv_data_t */
		assert(req->r_mrest == args);
		nfsm_chain_finish_mbuf(error, nmc);
		if (error) {
			return error;
		}
		error = rpc_gss_priv_data_create(cp->gss_clnt_ctx_id, &args, seqnum, &req->r_gss_arglen);
		if (error) {
			break;
		}
		req->r_mrest = args;
		req->r_gss_argoff = nfsm_chain_offset(nmc);
		nfs_gss_append_chain(nmc, args);
		break;
	default:
		return EINVAL;
	}

	return error;
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
	gss_buffer_desc cksum;
	uint32_t seqnum = 0;
	uint32_t major;
	struct nfs_gss_clnt_ctx *cp = req->r_gss_ctx;
	struct nfsm_chain nmc_tmp;
	struct gss_seq *gsp;
	uint32_t reslen, offset;
	int error = 0;
	mbuf_t results_mbuf, prev_mbuf, pad_mbuf;
	size_t ressize;

	reslen = 0;
	*accepted_statusp = 0;

	if (cp == NULL) {
		return NFSERR_EAUTH;
	}
	/*
	 * If it's not an RPCSEC_GSS verifier, then it has to
	 * be a null verifier that resulted from either
	 * a CONTINUE_NEEDED reply during context setup or
	 * from the reply to an AUTH_UNIX call from a dummy
	 * context that resulted from a fallback to sec=sys.
	 */
	if (verftype != RPCSEC_GSS) {
		if (verftype != RPCAUTH_NULL) {
			return NFSERR_EAUTH;
		}
		if (cp->gss_clnt_flags & GSS_CTX_COMPLETE) {
			return NFSERR_EAUTH;
		}
		if (verflen > 0) {
			nfsm_chain_adv(error, nmc, nfsm_rndup(verflen));
		}
		nfsm_chain_get_32(error, nmc, *accepted_statusp);
		return error;
	}

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
		if (verflen > KRB5_MAX_MIC_SIZE) {
			return EBADRPC;
		}
		MALLOC(cp->gss_clnt_verf, u_char *, verflen, M_TEMP, M_WAITOK | M_ZERO);
		if (cp->gss_clnt_verf == NULL) {
			return ENOMEM;
		}
		cp->gss_clnt_verflen = verflen;
		nfsm_chain_get_opaque(error, nmc, verflen, cp->gss_clnt_verf);
		nfsm_chain_get_32(error, nmc, *accepted_statusp);
		return error;
	}

	if (verflen > KRB5_MAX_MIC_SIZE) {
		return EBADRPC;
	}
	cksum.length = verflen;
	MALLOC(cksum.value, void *, verflen, M_TEMP, M_WAITOK);

	/*
	 * Get the gss mic
	 */
	nfsm_chain_get_opaque(error, nmc, verflen, cksum.value);
	if (error) {
		FREE(cksum.value, M_TEMP);
		goto nfsmout;
	}

	/*
	 * Search the request sequence numbers for this reply, starting
	 * with the most recent, looking for a checksum that matches
	 * the one in the verifier returned by the server.
	 */
	SLIST_FOREACH(gsp, &req->r_gss_seqlist, gss_seqnext) {
		gss_buffer_desc seqnum_buf;
		uint32_t network_seqnum = htonl(gsp->gss_seqnum);

		seqnum_buf.length = sizeof(network_seqnum);
		seqnum_buf.value = &network_seqnum;
		major = gss_krb5_verify_mic(NULL, cp->gss_clnt_ctx_id, &seqnum_buf, &cksum, NULL);
		if (major == GSS_S_COMPLETE) {
			break;
		}
	}
	FREE(cksum.value, M_TEMP);
	if (gsp == NULL) {
		return NFSERR_EAUTH;
	}

	/*
	 * Get the RPC accepted status
	 */
	nfsm_chain_get_32(error, nmc, *accepted_statusp);
	if (*accepted_statusp != RPC_SUCCESS) {
		return 0;
	}

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
		 * Here's what we expect in the integrity results from RFC 2203:
		 *
		 * - length of seq num + results (4 bytes)
		 * - sequence number (4 bytes)
		 * - results (variable bytes)
		 * - length of checksum token
		 * - checksum of seqnum + results
		 */

		nfsm_chain_get_32(error, nmc, reslen);          // length of results
		if (reslen > NFS_MAXPACKET) {
			error = EBADRPC;
			goto nfsmout;
		}

		/* Advance and fetch the mic */
		nmc_tmp = *nmc;
		nfsm_chain_adv(error, &nmc_tmp, reslen);        // skip over the results
		nfsm_chain_get_32(error, &nmc_tmp, cksum.length);
		if (cksum.length > KRB5_MAX_MIC_SIZE) {
			error = EBADRPC;
			goto nfsmout;
		}
		MALLOC(cksum.value, void *, cksum.length, M_TEMP, M_WAITOK);
		nfsm_chain_get_opaque(error, &nmc_tmp, cksum.length, cksum.value);
		//XXX chop offf the cksum?

		/* Call verify mic */
		offset = nfsm_chain_offset(nmc);
		major = gss_krb5_verify_mic_mbuf((uint32_t *)&error, cp->gss_clnt_ctx_id, nmc->nmc_mhead, offset, reslen, &cksum, NULL);
		FREE(cksum.value, M_TEMP);
		if (major != GSS_S_COMPLETE) {
			printf("client results: gss_krb5_verify_mic_mbuf failed %d\n", error);
			error = EBADRPC;
			goto nfsmout;
		}

		/*
		 * Get the sequence number prepended to the results
		 * and compare it against the header.
		 */
		nfsm_chain_get_32(error, nmc, seqnum);
		if (gsp->gss_seqnum != seqnum) {
			error = EBADRPC;
			goto nfsmout;
		}
#if 0
		SLIST_FOREACH(gsp, &req->r_gss_seqlist, gss_seqnext) {
			if (seqnum == gsp->gss_seqnum) {
				break;
			}
		}
		if (gsp == NULL) {
			error = EBADRPC;
			goto nfsmout;
		}
#endif
		break;
	case RPCSEC_GSS_SVC_PRIVACY:
		/*
		 * Here's what we expect in the privacy results:
		 *
		 * opaque encodeing of the wrap token
		 * - length of wrap token
		 * - wrap token
		 */
		prev_mbuf = nmc->nmc_mcur;
		nfsm_chain_get_32(error, nmc, reslen);          // length of results
		if (reslen == 0 || reslen > NFS_MAXPACKET) {
			error = EBADRPC;
			goto nfsmout;
		}

		/* Get the wrap token (current mbuf in the chain starting at the current offset) */
		offset = nmc->nmc_ptr - (caddr_t)mbuf_data(nmc->nmc_mcur);

		/* split out the wrap token */
		ressize = reslen;
		error = gss_normalize_mbuf(nmc->nmc_mcur, offset, &ressize, &results_mbuf, &pad_mbuf, 0);
		if (error) {
			goto nfsmout;
		}

		if (pad_mbuf) {
			assert(nfsm_pad(reslen) == mbuf_len(pad_mbuf));
			mbuf_free(pad_mbuf);
		}

		major = gss_krb5_unwrap_mbuf((uint32_t *)&error, cp->gss_clnt_ctx_id, &results_mbuf, 0, ressize, NULL, NULL);
		if (major) {
			printf("%s unwraped failed %d\n", __func__, error);
			goto nfsmout;
		}

		/* Now replace the wrapped arguments with the unwrapped ones */
		mbuf_setnext(prev_mbuf, results_mbuf);
		nmc->nmc_mcur = results_mbuf;
		nmc->nmc_ptr = mbuf_data(results_mbuf);
		nmc->nmc_left = mbuf_len(results_mbuf);

		/*
		 * Get the sequence number prepended to the results
		 * and compare it against the header
		 */
		nfsm_chain_get_32(error, nmc, seqnum);
		if (gsp->gss_seqnum != seqnum) {
			printf("%s bad seqnum\n", __func__);
			error = EBADRPC;
			goto nfsmout;
		}
#if 0
		SLIST_FOREACH(gsp, &req->r_gss_seqlist, gss_seqnext) {
			if (seqnum == gsp->gss_seqnum) {
				break;
			}
		}
		if (gsp == NULL) {
			error = EBADRPC;
			goto nfsmout;
		}
#endif
		break;
	}
nfsmout:
	return error;
}

/*
 * An RPCSEC_GSS request with no integrity or privacy consists
 * of just the header mbufs followed by the arg mbufs.
 *
 * However, integrity or privacy the original mbufs have mbufs
 * prepended and appended to, which means we have to do some work to
 * restore the arg mbuf chain to its previous state in case we need to
 * retransmit.
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
	int error = 0, merr;

	if (cp == NULL) {
		return NFSERR_EAUTH;
	}

	if ((cp->gss_clnt_flags & GSS_CTX_COMPLETE) == 0) {
		return ENEEDAUTH;
	}

	/* Nothing to restore for SVC_NONE */
	if (cp->gss_clnt_service == RPCSEC_GSS_SVC_NONE) {
		return 0;
	}

	nfsm_chain_dissect_init(error, nmc, req->r_mhead);      // start at RPC header
	nfsm_chain_adv(error, nmc, req->r_gss_argoff);          // advance to args
	if (error) {
		return error;
	}

	if (cp->gss_clnt_service == RPCSEC_GSS_SVC_INTEGRITY) {
		error = rpc_gss_integ_data_restore(cp->gss_clnt_ctx_id, &req->r_mrest, req->r_gss_arglen);
	} else {
		error = rpc_gss_priv_data_restore(cp->gss_clnt_ctx_id, &req->r_mrest, req->r_gss_arglen);
	}

	merr = mbuf_setnext(nmc->nmc_mcur, req->r_mrest);  /* Should always succeed */
	assert(merr == 0);

	return error ? error : merr;
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
	gss_buffer_desc cksum, window;
	uint32_t network_seqnum;
	int client_complete = 0;
	int server_complete = 0;
	int error = 0;
	int retrycnt = 0;
	uint32_t major;

	/* Initialize a new client context */

	if (cp->gss_clnt_svcname == NULL) {
		cp->gss_clnt_svcname = nfs_gss_clnt_svcname(nmp, &cp->gss_clnt_svcnt, &cp->gss_clnt_svcnamlen);
		if (cp->gss_clnt_svcname == NULL) {
			error = NFSERR_EAUTH;
			goto nfsmout;
		}
	}

	cp->gss_clnt_proc = RPCSEC_GSS_INIT;

	cp->gss_clnt_service =
	    req->r_auth == RPCAUTH_KRB5  ? RPCSEC_GSS_SVC_NONE :
	    req->r_auth == RPCAUTH_KRB5I ? RPCSEC_GSS_SVC_INTEGRITY :
	    req->r_auth == RPCAUTH_KRB5P ? RPCSEC_GSS_SVC_PRIVACY : 0;

	/*
	 * Now loop around alternating gss_init_sec_context and
	 * gss_accept_sec_context upcalls to the gssd on the client
	 * and server side until the context is complete - or fails.
	 */
	for (;;) {
retry:
		/* Upcall to the gss_init_sec_context in the gssd */
		error = nfs_gss_clnt_gssd_upcall(req, cp, retrycnt);
		if (error) {
			goto nfsmout;
		}

		if (cp->gss_clnt_major == GSS_S_COMPLETE) {
			client_complete = 1;
			NFS_GSS_DBG("Client complete\n");
			if (server_complete) {
				break;
			}
		} else if (cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
			/*
			 * We may have gotten here because the accept sec context
			 * from the server failed and sent back a GSS token that
			 * encapsulates a kerberos error token per RFC 1964/4121
			 * with a status of GSS_S_CONTINUE_NEEDED. That caused us
			 * to loop to the above up call and received the now
			 * decoded errors.
			 */
			retrycnt++;
			cp->gss_clnt_gssd_flags |= GSSD_RESTART;
			NFS_GSS_DBG("Retrying major = %x minor = %d\n", cp->gss_clnt_major, (int)cp->gss_clnt_minor);
			goto retry;
		}

		/*
		 * Pass the token to the server.
		 */
		error = nfs_gss_clnt_ctx_callserver(req, cp);
		if (error) {
			if (error == ENEEDAUTH &&
			    (cp->gss_clnt_proc == RPCSEC_GSS_INIT ||
			    cp->gss_clnt_proc == RPCSEC_GSS_CONTINUE_INIT)) {
				/*
				 * We got here because the server had a problem
				 * trying to establish a context and sent that there
				 * was a context problem at the rpc sec layer. Perhaps
				 * gss_accept_sec_context succeeded  in user space,
				 * but the kernel could not handle the etype
				 * to generate the mic for the verifier of the rpc_sec
				 * window size.
				 */
				retrycnt++;
				cp->gss_clnt_gssd_flags |= GSSD_RESTART;
				NFS_GSS_DBG("Retrying major = %x minor = %d\n", cp->gss_clnt_major, (int)cp->gss_clnt_minor);
				goto retry;
			}
			goto nfsmout;
		}
		if (cp->gss_clnt_major == GSS_S_COMPLETE) {
			NFS_GSS_DBG("Server complete\n");
			server_complete = 1;
			if (client_complete) {
				break;
			}
		} else if (cp->gss_clnt_major == GSS_S_CONTINUE_NEEDED) {
			cp->gss_clnt_proc = RPCSEC_GSS_CONTINUE_INIT;
		} else {
			/* Server didn't like us. Try something else */
			retrycnt++;
			cp->gss_clnt_gssd_flags |= GSSD_RESTART;
			NFS_GSS_DBG("Retrying major = %x minor = %d\n", cp->gss_clnt_major, (int)cp->gss_clnt_minor);
		}
	}

	/*
	 * The context is apparently established successfully
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	cp->gss_clnt_flags |= GSS_CTX_COMPLETE;
	lck_mtx_unlock(cp->gss_clnt_mtx);
	cp->gss_clnt_proc = RPCSEC_GSS_DATA;

	network_seqnum = htonl(cp->gss_clnt_seqwin);
	window.length = sizeof(cp->gss_clnt_seqwin);
	window.value = &network_seqnum;
	cksum.value = cp->gss_clnt_verf;
	cksum.length = cp->gss_clnt_verflen;
	major = gss_krb5_verify_mic((uint32_t *)&error, cp->gss_clnt_ctx_id, &window, &cksum, NULL);
	cp->gss_clnt_verflen = 0;
	FREE(cp->gss_clnt_verf, M_TEMP);
	cp->gss_clnt_verf = NULL;
	if (major != GSS_S_COMPLETE) {
		printf("%s: could not verify window\n", __func__);
		error = NFSERR_EAUTH;
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
	    nfsm_rndup((cp->gss_clnt_seqwin + 7) / 8), M_TEMP, M_WAITOK | M_ZERO);
	if (cp->gss_clnt_seqbits == NULL) {
		error = NFSERR_EAUTH;
	}

nfsmout:
	/*
	 * If the error is ENEEDAUTH we're not done, so no need
	 * to wake up other threads again. This thread will retry in
	 * the find or renew routines.
	 */
	if (error == ENEEDAUTH) {
		NFS_GSS_DBG("Returning ENEEDAUTH\n");
		return error;
	}

	/*
	 * If there's an error, just mark it as invalid.
	 * It will be removed when the reference count
	 * drops to zero.
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	if (error) {
		cp->gss_clnt_flags |= GSS_CTX_INVAL;
	}

	/*
	 * Wake any threads waiting to use the context
	 */
	cp->gss_clnt_thread = NULL;
	if (cp->gss_clnt_flags & GSS_NEEDCTX) {
		cp->gss_clnt_flags &= ~GSS_NEEDCTX;
		wakeup(cp);
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);

	NFS_GSS_DBG("Returning error = %d\n", error);
	return error;
}

/*
 * This function calls nfs_gss_clnt_ctx_init() to set up a new context.
 * But if there's a failure in trying to establish the context it keeps
 * retrying at progressively longer intervals in case the failure is
 * due to some transient condition.  For instance, the server might be
 * failing the context setup because directory services is not coming
 * up in a timely fashion.
 */
static int
nfs_gss_clnt_ctx_init_retry(struct nfsreq *req, struct nfs_gss_clnt_ctx *cp)
{
	struct nfsmount *nmp = req->r_nmp;
	struct timeval now;
	time_t waituntil;
	int error, slpflag;
	int retries = 0;
	int timeo = NFS_TRYLATERDEL;

	if (nfs_mount_gone(nmp)) {
		error = ENXIO;
		goto bad;
	}

	/* For an "intr" mount allow a signal to interrupt the retries */
	slpflag = (NMFLAG(nmp, INTR) && !(req->r_flags & R_NOINTR)) ? PCATCH : 0;

	while ((error = nfs_gss_clnt_ctx_init(req, cp)) == ENEEDAUTH) {
		microuptime(&now);
		waituntil = now.tv_sec + timeo;
		while (now.tv_sec < waituntil) {
			tsleep(NULL, PSOCK | slpflag, "nfs_gss_clnt_ctx_init_retry", hz);
			slpflag = 0;
			error = nfs_sigintr(req->r_nmp, req, current_thread(), 0);
			if (error) {
				goto bad;
			}
			microuptime(&now);
		}

		retries++;
		/* If it's a soft mount just give up after a while */
		if ((NMFLAG(nmp, SOFT) || (req->r_flags & R_SOFT)) && (retries > nmp->nm_retry)) {
			error = ETIMEDOUT;
			goto bad;
		}
		timeo *= 2;
		if (timeo > 60) {
			timeo = 60;
		}
	}

	if (error == 0) {
		return 0;       // success
	}
bad:
	/*
	 * Give up on this context
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	cp->gss_clnt_flags |= GSS_CTX_INVAL;

	/*
	 * Wake any threads waiting to use the context
	 */
	cp->gss_clnt_thread = NULL;
	if (cp->gss_clnt_flags & GSS_NEEDCTX) {
		cp->gss_clnt_flags &= ~GSS_NEEDCTX;
		wakeup(cp);
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);

	return error;
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
	struct nfsm_chain nmreq, nmrep;
	int error = 0, status;
	uint32_t major = cp->gss_clnt_major, minor = cp->gss_clnt_minor;
	int sz;

	if (nfs_mount_gone(req->r_nmp)) {
		return ENXIO;
	}
	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);
	sz = NFSX_UNSIGNED + nfsm_rndup(cp->gss_clnt_tokenlen);
	nfsm_chain_build_alloc_init(error, &nmreq, sz);
	nfsm_chain_add_32(error, &nmreq, cp->gss_clnt_tokenlen);
	if (cp->gss_clnt_tokenlen > 0) {
		nfsm_chain_add_opaque(error, &nmreq, cp->gss_clnt_token, cp->gss_clnt_tokenlen);
	}
	nfsm_chain_build_done(error, &nmreq);
	if (error) {
		goto nfsmout;
	}

	/* Call the server */
	error = nfs_request_gss(req->r_nmp->nm_mountp, &nmreq, req->r_thread, req->r_cred,
	    (req->r_flags & R_OPTMASK), cp, &nmrep, &status);
	if (cp->gss_clnt_token != NULL) {
		FREE(cp->gss_clnt_token, M_TEMP);
		cp->gss_clnt_token = NULL;
	}
	if (!error) {
		error = status;
	}
	if (error) {
		goto nfsmout;
	}

	/* Get the server's reply */

	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_handle_len);
	if (cp->gss_clnt_handle != NULL) {
		FREE(cp->gss_clnt_handle, M_TEMP);
		cp->gss_clnt_handle = NULL;
	}
	if (cp->gss_clnt_handle_len > 0 && cp->gss_clnt_handle_len < GSS_MAX_CTX_HANDLE_LEN) {
		MALLOC(cp->gss_clnt_handle, u_char *, cp->gss_clnt_handle_len, M_TEMP, M_WAITOK);
		if (cp->gss_clnt_handle == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		nfsm_chain_get_opaque(error, &nmrep, cp->gss_clnt_handle_len, cp->gss_clnt_handle);
	} else {
		error = EBADRPC;
	}
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_major);
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_minor);
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_seqwin);
	nfsm_chain_get_32(error, &nmrep, cp->gss_clnt_tokenlen);
	if (error) {
		goto nfsmout;
	}
	if (cp->gss_clnt_tokenlen > 0 && cp->gss_clnt_tokenlen < GSS_MAX_TOKEN_LEN) {
		MALLOC(cp->gss_clnt_token, u_char *, cp->gss_clnt_tokenlen, M_TEMP, M_WAITOK);
		if (cp->gss_clnt_token == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		nfsm_chain_get_opaque(error, &nmrep, cp->gss_clnt_tokenlen, cp->gss_clnt_token);
	} else {
		error = EBADRPC;
	}

	/*
	 * Make sure any unusual errors are expanded and logged by gssd
	 */
	if (cp->gss_clnt_major != GSS_S_COMPLETE &&
	    cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
		printf("nfs_gss_clnt_ctx_callserver: gss_clnt_major = %d\n", cp->gss_clnt_major);
		nfs_gss_clnt_log_error(req, cp, major, minor);
	}

nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	return error;
}

/*
 * We construct the service principal as a gss hostbased service principal of
 * the form nfs@<server>, unless the servers principal was passed down in the
 * mount arguments. If the arguments don't specify the service principal, the
 * server name is extracted the location passed in the mount argument if
 * available.  Otherwise assume a format of <server>:<path> in the
 * mntfromname. We don't currently support url's or other bizarre formats like
 * path@server. Mount_url will convert the nfs url into <server>:<path> when
 * calling mount, so this works out well in practice.
 *
 */

static uint8_t *
nfs_gss_clnt_svcname(struct nfsmount *nmp, gssd_nametype *nt, uint32_t *len)
{
	char *svcname, *d, *server;
	int lindx, sindx;

	if (nfs_mount_gone(nmp)) {
		return NULL;
	}

	if (nmp->nm_sprinc) {
		*len = strlen(nmp->nm_sprinc) + 1;
		MALLOC(svcname, char *, *len, M_TEMP, M_WAITOK);
		*nt = GSSD_HOSTBASED;
		if (svcname == NULL) {
			return NULL;
		}
		strlcpy(svcname, nmp->nm_sprinc, *len);

		return (uint8_t *)svcname;
	}

	*nt = GSSD_HOSTBASED;
	if (nmp->nm_locations.nl_numlocs && !(NFS_GSS_ISDBG && (NFS_DEBUG_FLAGS & 0x1))) {
		lindx = nmp->nm_locations.nl_current.nli_loc;
		sindx = nmp->nm_locations.nl_current.nli_serv;
		server = nmp->nm_locations.nl_locations[lindx]->nl_servers[sindx]->ns_name;
		*len = (uint32_t)strlen(server);
	} else {
		/* Older binaries using older mount args end up here */
		server = vfs_statfs(nmp->nm_mountp)->f_mntfromname;
		NFS_GSS_DBG("nfs getting gss svcname from %s\n", server);
		d = strchr(server, ':');
		*len = (uint32_t)(d ? (d - server) : strlen(server));
	}

	*len +=  5; /* "nfs@" plus null */
	MALLOC(svcname, char *, *len, M_TEMP, M_WAITOK);
	strlcpy(svcname, "nfs", *len);
	strlcat(svcname, "@", *len);
	strlcat(svcname, server, *len);
	NFS_GSS_DBG("nfs svcname = %s\n", svcname);

	return (uint8_t *)svcname;
}

/*
 * Get a mach port to talk to gssd.
 * gssd lives in the root bootstrap, so we call gssd's lookup routine
 * to get a send right to talk to a new gssd instance that launchd has launched
 * based on the cred's uid and audit session id.
 */

static mach_port_t
nfs_gss_clnt_get_upcall_port(kauth_cred_t credp)
{
	mach_port_t gssd_host_port, uc_port = IPC_PORT_NULL;
	kern_return_t kr;
	au_asid_t asid;
	uid_t uid;

	kr = host_get_gssd_port(host_priv_self(), &gssd_host_port);
	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_get_upcall_port: can't get gssd port, status %x (%d)\n", kr, kr);
		return IPC_PORT_NULL;
	}
	if (!IPC_PORT_VALID(gssd_host_port)) {
		printf("nfs_gss_get_upcall_port: gssd port not valid\n");
		return IPC_PORT_NULL;
	}

	asid = kauth_cred_getasid(credp);
	uid = kauth_cred_getauid(credp);
	if (uid == AU_DEFAUDITID) {
		uid = kauth_cred_getuid(credp);
	}
	kr = mach_gss_lookup(gssd_host_port, uid, asid, &uc_port);
	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_clnt_get_upcall_port: mach_gssd_lookup failed: status %x (%d)\n", kr, kr);
	}
	host_release_special_port(gssd_host_port);

	return uc_port;
}


static void
nfs_gss_clnt_log_error(struct nfsreq *req, struct nfs_gss_clnt_ctx *cp, uint32_t major, uint32_t minor)
{
#define GETMAJERROR(x) (((x) >> GSS_C_ROUTINE_ERROR_OFFSET) & GSS_C_ROUTINE_ERROR_MASK)
	struct nfsmount *nmp = req->r_nmp;
	char who[] = "client";
	uint32_t gss_error = GETMAJERROR(cp->gss_clnt_major);
	const char *procn = "unkown";
	proc_t proc;
	pid_t pid = -1;
	struct timeval now;

	if (req->r_thread) {
		proc = (proc_t)get_bsdthreadtask_info(req->r_thread);
		if (proc != NULL && (proc->p_fd == NULL || (proc->p_lflag & P_LVFORK))) {
			proc = NULL;
		}
		if (proc) {
			if (*proc->p_comm) {
				procn = proc->p_comm;
			}
			pid = proc->p_pid;
		}
	} else {
		procn = "kernproc";
		pid = 0;
	}

	microuptime(&now);
	if ((cp->gss_clnt_major != major || cp->gss_clnt_minor != minor ||
	    cp->gss_clnt_ptime + GSS_PRINT_DELAY < now.tv_sec) &&
	    (nmp->nm_state & NFSSTA_MOUNTED)) {
		/*
		 * Will let gssd do some logging in hopes that it can translate
		 * the minor code.
		 */
		if (cp->gss_clnt_minor && cp->gss_clnt_minor != minor) {
			(void) mach_gss_log_error(
				cp->gss_clnt_mport,
				vfs_statfs(nmp->nm_mountp)->f_mntfromname,
				kauth_cred_getuid(cp->gss_clnt_cred),
				who,
				cp->gss_clnt_major,
				cp->gss_clnt_minor);
		}
		gss_error = gss_error ? gss_error : cp->gss_clnt_major;

		/*
		 *%%% It would be really nice to get the terminal from the proc or auditinfo_addr struct and print that here.
		 */
		printf("NFS: gssd auth failure by %s on audit session %d uid %d proc %s/%d for mount %s. Error: major = %d minor = %d\n",
		    cp->gss_clnt_display ? cp->gss_clnt_display : who, kauth_cred_getasid(req->r_cred), kauth_cred_getuid(req->r_cred),
		    procn, pid, vfs_statfs(nmp->nm_mountp)->f_mntfromname, gss_error, (int32_t)cp->gss_clnt_minor);
		cp->gss_clnt_ptime = now.tv_sec;
		switch (gss_error) {
		case 7: printf("NFS: gssd does not have credentials for session %d/%d, (kinit)?\n",
			    kauth_cred_getasid(req->r_cred), kauth_cred_getauid(req->r_cred));
			break;
		case 11: printf("NFS: gssd has expired credentals for session %d/%d, (kinit)?\n",
			    kauth_cred_getasid(req->r_cred), kauth_cred_getauid(req->r_cred));
			break;
		}
	} else {
		NFS_GSS_DBG("NFS: gssd auth failure by %s on audit session %d uid %d proc %s/%d for mount %s. Error: major = %d minor = %d\n",
		    cp->gss_clnt_display ? cp->gss_clnt_display : who, kauth_cred_getasid(req->r_cred), kauth_cred_getuid(req->r_cred),
		    procn, pid, vfs_statfs(nmp->nm_mountp)->f_mntfromname, gss_error, (int32_t)cp->gss_clnt_minor);
	}
}

/*
 * Make an upcall to the gssd using Mach RPC
 * The upcall is made using a host special port.
 * This allows launchd to fire up the gssd in the
 * user's session.  This is important, since gssd
 * must have access to the user's credential cache.
 */
static int
nfs_gss_clnt_gssd_upcall(struct nfsreq *req, struct nfs_gss_clnt_ctx *cp, uint32_t retrycnt)
{
	kern_return_t kr;
	gssd_byte_buffer octx = NULL;
	uint32_t lucidlen = 0;
	void *lucid_ctx_buffer;
	int retry_cnt = 0;
	vm_map_copy_t itoken = NULL;
	gssd_byte_buffer otoken = NULL;
	mach_msg_type_number_t otokenlen;
	int error = 0;
	uint8_t *principal = NULL;
	uint32_t plen = 0;
	int32_t nt = GSSD_STRING_NAME;
	vm_map_copy_t pname = NULL;
	vm_map_copy_t svcname = NULL;
	char display_name[MAX_DISPLAY_STR] = "";
	uint32_t ret_flags;
	struct nfsmount *nmp = req->r_nmp;
	uint32_t major = cp->gss_clnt_major, minor = cp->gss_clnt_minor;
	uint32_t selected = (uint32_t)-1;
	struct nfs_etype etype;

	if (nmp == NULL || vfs_isforce(nmp->nm_mountp) || (nmp->nm_state & (NFSSTA_FORCE | NFSSTA_DEAD))) {
		return ENXIO;
	}

	if (cp->gss_clnt_gssd_flags & GSSD_RESTART) {
		if (cp->gss_clnt_token) {
			FREE(cp->gss_clnt_token, M_TEMP);
		}
		cp->gss_clnt_token = NULL;
		cp->gss_clnt_tokenlen = 0;
		cp->gss_clnt_proc = RPCSEC_GSS_INIT;
		/* Server's handle isn't valid. Don't reuse */
		cp->gss_clnt_handle_len = 0;
		if (cp->gss_clnt_handle != NULL) {
			FREE(cp->gss_clnt_handle, M_TEMP);
			cp->gss_clnt_handle = NULL;
		}
	}

	NFS_GSS_DBG("Retrycnt = %d nm_etype.count = %d\n", retrycnt, nmp->nm_etype.count);
	if (retrycnt >= nmp->nm_etype.count) {
		return EACCES;
	}

	/* Copy the mount etypes to an order set of etypes to try */
	etype = nmp->nm_etype;

	/*
	 * If we've already selected an etype, lets put that first in our
	 * array of etypes to try, since overwhelmingly, that is likely
	 * to be the etype we want.
	 */
	if (etype.selected < etype.count) {
		etype.etypes[0] = nmp->nm_etype.etypes[etype.selected];
		for (uint32_t i = 0; i < etype.selected; i++) {
			etype.etypes[i + 1] = nmp->nm_etype.etypes[i];
		}
		for (uint32_t i = etype.selected + 1; i < etype.count; i++) {
			etype.etypes[i] = nmp->nm_etype.etypes[i];
		}
	}

	/* Remove the ones we've already have tried */
	for (uint32_t i = retrycnt; i < etype.count; i++) {
		etype.etypes[i - retrycnt] = etype.etypes[i];
	}
	etype.count = etype.count - retrycnt;

	NFS_GSS_DBG("etype count = %d preferred etype = %d\n", etype.count, etype.etypes[0]);

	/*
	 * NFS currently only supports default principals or
	 * principals based on the uid of the caller, unless
	 * the principal to use for the mounting cred was specified
	 * in the mount argmuments. If the realm to use was specified
	 * then will send that up as the principal since the realm is
	 * preceed by an "@" gssd that will try and select the default
	 * principal for that realm.
	 */

	if (cp->gss_clnt_principal && cp->gss_clnt_prinlen) {
		principal = cp->gss_clnt_principal;
		plen = cp->gss_clnt_prinlen;
		nt = cp->gss_clnt_prinnt;
	} else if (nmp->nm_principal && IS_VALID_CRED(nmp->nm_mcred) && req->r_cred == nmp->nm_mcred) {
		plen = (uint32_t)strlen(nmp->nm_principal);
		principal = (uint8_t *)nmp->nm_principal;
		cp->gss_clnt_prinnt = nt = GSSD_USER;
	} else if (nmp->nm_realm) {
		plen = (uint32_t)strlen(nmp->nm_realm);
		principal = (uint8_t *)nmp->nm_realm;
		nt = GSSD_USER;
	}

	if (!IPC_PORT_VALID(cp->gss_clnt_mport)) {
		cp->gss_clnt_mport = nfs_gss_clnt_get_upcall_port(req->r_cred);
		if (cp->gss_clnt_mport == IPC_PORT_NULL) {
			goto out;
		}
	}

	if (plen) {
		nfs_gss_mach_alloc_buffer(principal, plen, &pname);
	}
	if (cp->gss_clnt_svcnamlen) {
		nfs_gss_mach_alloc_buffer(cp->gss_clnt_svcname, cp->gss_clnt_svcnamlen, &svcname);
	}
	if (cp->gss_clnt_tokenlen) {
		nfs_gss_mach_alloc_buffer(cp->gss_clnt_token, cp->gss_clnt_tokenlen, &itoken);
	}

	/* Always want to export the lucid context */
	cp->gss_clnt_gssd_flags |= GSSD_LUCID_CONTEXT;

retry:
	kr = mach_gss_init_sec_context_v3(
		cp->gss_clnt_mport,
		GSSD_KRB5_MECH,
		(gssd_byte_buffer) itoken, (mach_msg_type_number_t) cp->gss_clnt_tokenlen,
		kauth_cred_getuid(cp->gss_clnt_cred),
		nt,
		(gssd_byte_buffer)pname, (mach_msg_type_number_t) plen,
		cp->gss_clnt_svcnt,
		(gssd_byte_buffer)svcname, (mach_msg_type_number_t) cp->gss_clnt_svcnamlen,
		GSSD_MUTUAL_FLAG,
		(gssd_etype_list)etype.etypes, (mach_msg_type_number_t)etype.count,
		&cp->gss_clnt_gssd_flags,
		&cp->gss_clnt_context,
		&cp->gss_clnt_cred_handle,
		&ret_flags,
		&octx, (mach_msg_type_number_t *) &lucidlen,
		&otoken, &otokenlen,
		cp->gss_clnt_display ? NULL : display_name,
		&cp->gss_clnt_major,
		&cp->gss_clnt_minor);

	/* Clear the RESTART flag */
	cp->gss_clnt_gssd_flags &= ~GSSD_RESTART;
	if (cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
		/* We're done with the gssd handles */
		cp->gss_clnt_context = 0;
		cp->gss_clnt_cred_handle = 0;
	}

	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_clnt_gssd_upcall: mach_gss_init_sec_context failed: %x (%d)\n", kr, kr);
		if (kr == MIG_SERVER_DIED && cp->gss_clnt_cred_handle == 0 &&
		    retry_cnt++ < NFS_GSS_MACH_MAX_RETRIES &&
		    !vfs_isforce(nmp->nm_mountp) && (nmp->nm_state & (NFSSTA_FORCE | NFSSTA_DEAD)) == 0) {
			if (plen) {
				nfs_gss_mach_alloc_buffer(principal, plen, &pname);
			}
			if (cp->gss_clnt_svcnamlen) {
				nfs_gss_mach_alloc_buffer(cp->gss_clnt_svcname, cp->gss_clnt_svcnamlen, &svcname);
			}
			if (cp->gss_clnt_tokenlen > 0) {
				nfs_gss_mach_alloc_buffer(cp->gss_clnt_token, cp->gss_clnt_tokenlen, &itoken);
			}
			goto retry;
		}

		host_release_special_port(cp->gss_clnt_mport);
		cp->gss_clnt_mport = IPC_PORT_NULL;
		goto out;
	}

	if (cp->gss_clnt_display == NULL && *display_name != '\0') {
		int dlen = strnlen(display_name, MAX_DISPLAY_STR) + 1;  /* Add extra byte to include '\0' */

		if (dlen < MAX_DISPLAY_STR) {
			MALLOC(cp->gss_clnt_display, char *, dlen, M_TEMP, M_WAITOK);
			if (cp->gss_clnt_display == NULL) {
				goto skip;
			}
			bcopy(display_name, cp->gss_clnt_display, dlen);
		} else {
			goto skip;
		}
	}
skip:
	/*
	 * Make sure any unusual errors are expanded and logged by gssd
	 *
	 * XXXX, we need to rethink this and just have gssd return a string for the major and minor codes.
	 */
	if (cp->gss_clnt_major != GSS_S_COMPLETE &&
	    cp->gss_clnt_major != GSS_S_CONTINUE_NEEDED) {
		NFS_GSS_DBG("Up call returned error\n");
		nfs_gss_clnt_log_error(req, cp, major, minor);
		/* Server's handle isn't valid. Don't reuse */
		cp->gss_clnt_handle_len = 0;
		if (cp->gss_clnt_handle != NULL) {
			FREE(cp->gss_clnt_handle, M_TEMP);
			cp->gss_clnt_handle = NULL;
		}
	}

	if (lucidlen > 0) {
		if (lucidlen > MAX_LUCIDLEN) {
			printf("nfs_gss_clnt_gssd_upcall: bad context length (%d)\n", lucidlen);
			vm_map_copy_discard((vm_map_copy_t) octx);
			vm_map_copy_discard((vm_map_copy_t) otoken);
			goto out;
		}
		MALLOC(lucid_ctx_buffer, void *, lucidlen, M_TEMP, M_WAITOK | M_ZERO);
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) octx, lucidlen, lucid_ctx_buffer);
		if (error) {
			vm_map_copy_discard((vm_map_copy_t) otoken);
			goto out;
		}

		if (cp->gss_clnt_ctx_id) {
			gss_krb5_destroy_context(cp->gss_clnt_ctx_id);
		}
		cp->gss_clnt_ctx_id = gss_krb5_make_context(lucid_ctx_buffer, lucidlen);
		if (cp->gss_clnt_ctx_id == NULL) {
			printf("Failed to make context from lucid_ctx_buffer\n");
			goto out;
		}
		for (uint32_t i = 0; i < nmp->nm_etype.count; i++) {
			if (nmp->nm_etype.etypes[i] == cp->gss_clnt_ctx_id->gss_cryptor.etype) {
				selected = i;
				break;
			}
		}
	}

	/* Free context token used as input */
	if (cp->gss_clnt_token) {
		FREE(cp->gss_clnt_token, M_TEMP);
	}
	cp->gss_clnt_token = NULL;
	cp->gss_clnt_tokenlen = 0;

	if (otokenlen > 0) {
		/* Set context token to gss output token */
		MALLOC(cp->gss_clnt_token, u_char *, otokenlen, M_TEMP, M_WAITOK);
		if (cp->gss_clnt_token == NULL) {
			printf("nfs_gss_clnt_gssd_upcall: could not allocate %d bytes\n", otokenlen);
			vm_map_copy_discard((vm_map_copy_t) otoken);
			return ENOMEM;
		}
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) otoken, otokenlen, cp->gss_clnt_token);
		if (error) {
			printf("Could not copyout gss token\n");
			FREE(cp->gss_clnt_token, M_TEMP);
			cp->gss_clnt_token = NULL;
			return NFSERR_EAUTH;
		}
		cp->gss_clnt_tokenlen = otokenlen;
	}

	if (selected != (uint32_t)-1) {
		nmp->nm_etype.selected = selected;
		NFS_GSS_DBG("etype selected = %d\n", nmp->nm_etype.etypes[selected]);
	}
	NFS_GSS_DBG("Up call succeeded major = %d\n", cp->gss_clnt_major);
	return 0;

out:
	if (cp->gss_clnt_token) {
		FREE(cp->gss_clnt_token, M_TEMP);
	}
	cp->gss_clnt_token = NULL;
	cp->gss_clnt_tokenlen = 0;
	/* Server's handle isn't valid. Don't reuse */
	cp->gss_clnt_handle_len = 0;
	if (cp->gss_clnt_handle != NULL) {
		FREE(cp->gss_clnt_handle, M_TEMP);
		cp->gss_clnt_handle = NULL;
	}

	NFS_GSS_DBG("Up call returned NFSERR_EAUTH");
	return NFSERR_EAUTH;
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

	if (cp == NULL || !(cp->gss_clnt_flags & GSS_CTX_COMPLETE)) {
		return; // no context - don't bother
	}
	/*
	 * Reset the bit for this request in the
	 * sequence number window to indicate it's done.
	 * We do this even if the request timed out.
	 */
	lck_mtx_lock(cp->gss_clnt_mtx);
	gsp = SLIST_FIRST(&req->r_gss_seqlist);
	if (gsp && gsp->gss_seqnum > (cp->gss_clnt_seqnum - cp->gss_clnt_seqwin)) {
		win_resetbit(cp->gss_clnt_seqbits,
		    gsp->gss_seqnum % cp->gss_clnt_seqwin);
	}

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
	int on_neg_cache = 0;
	int neg_cache = 0;
	int destroy = 0;
	struct timeval now;
	char CTXBUF[NFS_CTXBUFSZ];

	if (cp == NULL) {
		return;
	}

	req->r_gss_ctx = NULL;

	lck_mtx_lock(cp->gss_clnt_mtx);
	if (--cp->gss_clnt_refcnt < 0) {
		panic("Over release of gss context!\n");
	}

	if (cp->gss_clnt_refcnt == 0) {
		if ((cp->gss_clnt_flags & GSS_CTX_INVAL) &&
		    cp->gss_clnt_ctx_id) {
			gss_krb5_destroy_context(cp->gss_clnt_ctx_id);
			cp->gss_clnt_ctx_id = NULL;
		}
		if (cp->gss_clnt_flags & GSS_CTX_DESTROY) {
			destroy = 1;
			if (cp->gss_clnt_flags & GSS_CTX_STICKY) {
				nfs_gss_clnt_mnt_rele(nmp);
			}
			if (cp->gss_clnt_nctime) {
				on_neg_cache = 1;
			}
		}
	}
	if (!destroy && cp->gss_clnt_nctime == 0 &&
	    (cp->gss_clnt_flags & GSS_CTX_INVAL)) {
		microuptime(&now);
		cp->gss_clnt_nctime = now.tv_sec;
		neg_cache = 1;
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);
	if (destroy) {
		NFS_GSS_DBG("Destroying context %s\n", NFS_GSS_CTX(req, cp));
		if (nmp) {
			lck_mtx_lock(&nmp->nm_lock);
			if (cp->gss_clnt_entries.tqe_next != NFSNOLIST) {
				TAILQ_REMOVE(&nmp->nm_gsscl, cp, gss_clnt_entries);
			}
			if (on_neg_cache) {
				nmp->nm_ncentries--;
			}
			lck_mtx_unlock(&nmp->nm_lock);
		}
		nfs_gss_clnt_ctx_destroy(cp);
	} else if (neg_cache) {
		NFS_GSS_DBG("Entering context %s into negative cache\n", NFS_GSS_CTX(req, cp));
		if (nmp) {
			lck_mtx_lock(&nmp->nm_lock);
			nmp->nm_ncentries++;
			nfs_gss_clnt_ctx_neg_cache_reap(nmp);
			lck_mtx_unlock(&nmp->nm_lock);
		}
	}
	NFS_GSS_CLNT_CTX_DUMP(nmp);
}

/*
 * Try and reap any old negative cache entries.
 * cache queue.
 */
void
nfs_gss_clnt_ctx_neg_cache_reap(struct nfsmount *nmp)
{
	struct nfs_gss_clnt_ctx *cp, *tcp;
	struct timeval now;
	int reaped = 0;

	/* Try and reap old, unreferenced, expired contexts */
	microuptime(&now);

	NFS_GSS_DBG("Reaping contexts ncentries = %d\n", nmp->nm_ncentries);

	TAILQ_FOREACH_SAFE(cp, &nmp->nm_gsscl, gss_clnt_entries, tcp) {
		int destroy = 0;

		/* Don't reap STICKY contexts */
		if ((cp->gss_clnt_flags & GSS_CTX_STICKY) ||
		    !(cp->gss_clnt_flags & GSS_CTX_INVAL)) {
			continue;
		}
		/* Keep up to GSS_MAX_NEG_CACHE_ENTRIES */
		if (nmp->nm_ncentries <= GSS_MAX_NEG_CACHE_ENTRIES) {
			break;
		}
		/* Contexts too young */
		if (cp->gss_clnt_nctime + GSS_NEG_CACHE_TO >= now.tv_sec) {
			continue;
		}
		/* Not referenced, remove it. */
		lck_mtx_lock(cp->gss_clnt_mtx);
		if (cp->gss_clnt_refcnt == 0) {
			cp->gss_clnt_flags |= GSS_CTX_DESTROY;
			destroy = 1;
		}
		lck_mtx_unlock(cp->gss_clnt_mtx);
		if (destroy) {
			TAILQ_REMOVE(&nmp->nm_gsscl, cp, gss_clnt_entries);
			nmp->nm_ncentries++;
			reaped++;
			nfs_gss_clnt_ctx_destroy(cp);
		}
	}
	NFS_GSS_DBG("Reaped %d contexts ncentries = %d\n", reaped, nmp->nm_ncentries);
}

/*
 * Clean a context to be cached
 */
static void
nfs_gss_clnt_ctx_clean(struct nfs_gss_clnt_ctx *cp)
{
	/* Preserve gss_clnt_mtx */
	assert(cp->gss_clnt_thread == NULL);  /* Will be set to this thread */
	/* gss_clnt_entries  we should not be on any list at this point */
	cp->gss_clnt_flags = 0;
	/* gss_clnt_refcnt should be zero */
	assert(cp->gss_clnt_refcnt == 0);
	/*
	 * We are who we are preserve:
	 * gss_clnt_cred
	 * gss_clnt_principal
	 * gss_clnt_prinlen
	 * gss_clnt_prinnt
	 * gss_clnt_desplay
	 */
	/* gss_clnt_proc will be set in nfs_gss_clnt_ctx_init */
	cp->gss_clnt_seqnum = 0;
	/* Preserve gss_clnt_service, we're not changing flavors */
	if (cp->gss_clnt_handle) {
		FREE(cp->gss_clnt_handle, M_TEMP);
		cp->gss_clnt_handle = NULL;
	}
	cp->gss_clnt_handle_len = 0;
	cp->gss_clnt_nctime = 0;
	cp->gss_clnt_seqwin = 0;
	if (cp->gss_clnt_seqbits) {
		FREE(cp->gss_clnt_seqbits, M_TEMP);
		cp->gss_clnt_seqbits = NULL;
	}
	/* Preserve gss_clnt_mport. Still talking to the same gssd */
	if (cp->gss_clnt_verf) {
		FREE(cp->gss_clnt_verf, M_TEMP);
		cp->gss_clnt_verf = NULL;
	}
	/* Service name might change on failover, so reset it */
	if (cp->gss_clnt_svcname) {
		FREE(cp->gss_clnt_svcname, M_TEMP);
		cp->gss_clnt_svcname = NULL;
		cp->gss_clnt_svcnt = 0;
	}
	cp->gss_clnt_svcnamlen = 0;
	cp->gss_clnt_cred_handle = 0;
	cp->gss_clnt_context = 0;
	if (cp->gss_clnt_token) {
		FREE(cp->gss_clnt_token, M_TEMP);
		cp->gss_clnt_token = NULL;
	}
	cp->gss_clnt_tokenlen = 0;
	/* XXX gss_clnt_ctx_id ??? */
	/*
	 * Preserve:
	 * gss_clnt_gssd_flags
	 * gss_clnt_major
	 * gss_clnt_minor
	 * gss_clnt_ptime
	 */
}

/*
 * Copy a source context to a new context. This is used to create a new context
 * with the identity of the old context for renewal. The old context is invalid
 * at this point but may have reference still to it, so it is not safe to use that
 * context.
 */
static int
nfs_gss_clnt_ctx_copy(struct nfs_gss_clnt_ctx *scp, struct nfs_gss_clnt_ctx **dcpp)
{
	struct nfs_gss_clnt_ctx *dcp;

	*dcpp = (struct nfs_gss_clnt_ctx *)NULL;
	MALLOC(dcp, struct nfs_gss_clnt_ctx *, sizeof(struct nfs_gss_clnt_ctx), M_TEMP, M_WAITOK);
	if (dcp == NULL) {
		return ENOMEM;
	}
	bzero(dcp, sizeof(struct nfs_gss_clnt_ctx));
	dcp->gss_clnt_mtx = lck_mtx_alloc_init(nfs_gss_clnt_grp, LCK_ATTR_NULL);
	dcp->gss_clnt_cred = scp->gss_clnt_cred;
	kauth_cred_ref(dcp->gss_clnt_cred);
	dcp->gss_clnt_prinlen = scp->gss_clnt_prinlen;
	dcp->gss_clnt_prinnt = scp->gss_clnt_prinnt;
	if (scp->gss_clnt_principal) {
		MALLOC(dcp->gss_clnt_principal, uint8_t *, dcp->gss_clnt_prinlen, M_TEMP, M_WAITOK | M_ZERO);
		if (dcp->gss_clnt_principal == NULL) {
			FREE(dcp, M_TEMP);
			return ENOMEM;
		}
		bcopy(scp->gss_clnt_principal, dcp->gss_clnt_principal, dcp->gss_clnt_prinlen);
	}
	/* Note we don't preserve the display name, that will be set by a successful up call */
	dcp->gss_clnt_service = scp->gss_clnt_service;
	dcp->gss_clnt_mport = host_copy_special_port(scp->gss_clnt_mport);
	dcp->gss_clnt_ctx_id = NULL;   /* Will be set from successful upcall */
	dcp->gss_clnt_gssd_flags = scp->gss_clnt_gssd_flags;
	dcp->gss_clnt_major = scp->gss_clnt_major;
	dcp->gss_clnt_minor = scp->gss_clnt_minor;
	dcp->gss_clnt_ptime = scp->gss_clnt_ptime;

	*dcpp = dcp;

	return 0;
}

/*
 * Remove a context
 */
static void
nfs_gss_clnt_ctx_destroy(struct nfs_gss_clnt_ctx *cp)
{
	NFS_GSS_DBG("Destroying context %d/%d\n",
	    kauth_cred_getasid(cp->gss_clnt_cred),
	    kauth_cred_getauid(cp->gss_clnt_cred));

	host_release_special_port(cp->gss_clnt_mport);
	cp->gss_clnt_mport = IPC_PORT_NULL;

	if (cp->gss_clnt_mtx) {
		lck_mtx_destroy(cp->gss_clnt_mtx, nfs_gss_clnt_grp);
		cp->gss_clnt_mtx = (lck_mtx_t *)NULL;
	}
	if (IS_VALID_CRED(cp->gss_clnt_cred)) {
		kauth_cred_unref(&cp->gss_clnt_cred);
	}
	cp->gss_clnt_entries.tqe_next = NFSNOLIST;
	cp->gss_clnt_entries.tqe_prev = NFSNOLIST;
	if (cp->gss_clnt_principal) {
		FREE(cp->gss_clnt_principal, M_TEMP);
		cp->gss_clnt_principal = NULL;
	}
	if (cp->gss_clnt_display) {
		FREE(cp->gss_clnt_display, M_TEMP);
		cp->gss_clnt_display = NULL;
	}
	if (cp->gss_clnt_ctx_id) {
		gss_krb5_destroy_context(cp->gss_clnt_ctx_id);
		cp->gss_clnt_ctx_id = NULL;
	}

	nfs_gss_clnt_ctx_clean(cp);

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
	struct nfs_gss_clnt_ctx *ncp;
	struct nfsmount *nmp;
	int error = 0;
	char CTXBUF[NFS_CTXBUFSZ];

	if (cp == NULL) {
		return 0;
	}

	if (req->r_nmp == NULL) {
		return ENXIO;
	}
	nmp = req->r_nmp;

	lck_mtx_lock(cp->gss_clnt_mtx);
	if (cp->gss_clnt_flags & GSS_CTX_INVAL) {
		lck_mtx_unlock(cp->gss_clnt_mtx);
		nfs_gss_clnt_ctx_unref(req);
		return 0;     // already being renewed
	}

	cp->gss_clnt_flags |= (GSS_CTX_INVAL | GSS_CTX_DESTROY);

	if (cp->gss_clnt_flags & (GSS_NEEDCTX | GSS_NEEDSEQ)) {
		cp->gss_clnt_flags &= ~GSS_NEEDSEQ;
		wakeup(cp);
	}
	lck_mtx_unlock(cp->gss_clnt_mtx);

	if (cp->gss_clnt_proc == RPCSEC_GSS_DESTROY) {
		return EACCES;  /* Destroying a context is best effort. Don't renew. */
	}
	/*
	 * If we're setting up a context let nfs_gss_clnt_ctx_init know this is not working
	 * and to try some other etype.
	 */
	if (cp->gss_clnt_proc != RPCSEC_GSS_DATA) {
		return ENEEDAUTH;
	}
	error =  nfs_gss_clnt_ctx_copy(cp, &ncp);
	NFS_GSS_DBG("Renewing context %s\n", NFS_GSS_CTX(req, ncp));
	nfs_gss_clnt_ctx_unref(req);
	if (error) {
		return error;
	}

	lck_mtx_lock(&nmp->nm_lock);
	/*
	 * Note we don't bother taking the new context mutex as we're
	 * not findable at the moment.
	 */
	ncp->gss_clnt_thread = current_thread();
	nfs_gss_clnt_ctx_ref(req, ncp);
	TAILQ_INSERT_HEAD(&nmp->nm_gsscl, ncp, gss_clnt_entries);
	lck_mtx_unlock(&nmp->nm_lock);

	error = nfs_gss_clnt_ctx_init_retry(req, ncp); // Initialize new context
	if (error) {
		nfs_gss_clnt_ctx_unref(req);
	}

	return error;
}


/*
 * Destroy all the contexts associated with a mount.
 * The contexts are also destroyed by the server.
 */
void
nfs_gss_clnt_ctx_unmount(struct nfsmount *nmp)
{
	struct nfs_gss_clnt_ctx *cp;
	struct nfsm_chain nmreq, nmrep;
	int error, status;
	struct nfsreq req;
	req.r_nmp = nmp;

	if (!nmp) {
		return;
	}


	lck_mtx_lock(&nmp->nm_lock);
	while ((cp = TAILQ_FIRST(&nmp->nm_gsscl))) {
		TAILQ_REMOVE(&nmp->nm_gsscl, cp, gss_clnt_entries);
		cp->gss_clnt_entries.tqe_next = NFSNOLIST;
		lck_mtx_lock(cp->gss_clnt_mtx);
		if (cp->gss_clnt_flags & GSS_CTX_DESTROY) {
			lck_mtx_unlock(cp->gss_clnt_mtx);
			continue;
		}
		cp->gss_clnt_refcnt++;
		lck_mtx_unlock(cp->gss_clnt_mtx);
		req.r_gss_ctx = cp;

		lck_mtx_unlock(&nmp->nm_lock);
		/*
		 * Tell the server to destroy its context.
		 * But don't bother if it's a forced unmount.
		 */
		if (!nfs_mount_gone(nmp) &&
		    (cp->gss_clnt_flags & (GSS_CTX_INVAL | GSS_CTX_DESTROY | GSS_CTX_COMPLETE)) == GSS_CTX_COMPLETE) {
			cp->gss_clnt_proc = RPCSEC_GSS_DESTROY;

			error = 0;
			nfsm_chain_null(&nmreq);
			nfsm_chain_null(&nmrep);
			nfsm_chain_build_alloc_init(error, &nmreq, 0);
			nfsm_chain_build_done(error, &nmreq);
			if (!error) {
				nfs_request_gss(nmp->nm_mountp, &nmreq,
				    current_thread(), cp->gss_clnt_cred, 0, cp, &nmrep, &status);
			}
			nfsm_chain_cleanup(&nmreq);
			nfsm_chain_cleanup(&nmrep);
		}

		/*
		 * Mark the context invalid then drop
		 * the reference to remove it if its
		 * refcount is zero.
		 */
		lck_mtx_lock(cp->gss_clnt_mtx);
		cp->gss_clnt_flags |= (GSS_CTX_INVAL | GSS_CTX_DESTROY);
		lck_mtx_unlock(cp->gss_clnt_mtx);
		nfs_gss_clnt_ctx_unref(&req);
		lck_mtx_lock(&nmp->nm_lock);
	}
	lck_mtx_unlock(&nmp->nm_lock);
	assert(TAILQ_EMPTY(&nmp->nm_gsscl));
}


/*
 * Removes a mounts context for a credential
 */
int
nfs_gss_clnt_ctx_remove(struct nfsmount *nmp, kauth_cred_t cred)
{
	struct nfs_gss_clnt_ctx *cp;
	struct nfsreq req;

	req.r_nmp = nmp;

	NFS_GSS_DBG("Enter\n");
	NFS_GSS_CLNT_CTX_DUMP(nmp);
	lck_mtx_lock(&nmp->nm_lock);
	TAILQ_FOREACH(cp, &nmp->nm_gsscl, gss_clnt_entries) {
		lck_mtx_lock(cp->gss_clnt_mtx);
		if (nfs_gss_clnt_ctx_cred_match(cp->gss_clnt_cred, cred)) {
			if (cp->gss_clnt_flags & GSS_CTX_DESTROY) {
				NFS_GSS_DBG("Found destroyed context %d/%d. refcnt = %d continuing\n",
				    kauth_cred_getasid(cp->gss_clnt_cred),
				    kauth_cred_getauid(cp->gss_clnt_cred),
				    cp->gss_clnt_refcnt);
				lck_mtx_unlock(cp->gss_clnt_mtx);
				continue;
			}
			cp->gss_clnt_refcnt++;
			cp->gss_clnt_flags |= (GSS_CTX_INVAL | GSS_CTX_DESTROY);
			lck_mtx_unlock(cp->gss_clnt_mtx);
			req.r_gss_ctx = cp;
			lck_mtx_unlock(&nmp->nm_lock);
			/*
			 * Drop the reference to remove it if its
			 * refcount is zero.
			 */
			NFS_GSS_DBG("Removed context %d/%d refcnt = %d\n",
			    kauth_cred_getasid(cp->gss_clnt_cred),
			    kauth_cred_getuid(cp->gss_clnt_cred),
			    cp->gss_clnt_refcnt);
			nfs_gss_clnt_ctx_unref(&req);
			return 0;
		}
		lck_mtx_unlock(cp->gss_clnt_mtx);
	}

	lck_mtx_unlock(&nmp->nm_lock);

	NFS_GSS_DBG("Returning ENOENT\n");
	return ENOENT;
}

/*
 * Sets a mounts principal for a session associated with cred.
 */
int
nfs_gss_clnt_ctx_set_principal(struct nfsmount *nmp, vfs_context_t ctx,
    uint8_t *principal, uint32_t princlen, uint32_t nametype)
{
	struct nfsreq req;
	int error;

	NFS_GSS_DBG("Enter:\n");

	bzero(&req, sizeof(struct nfsreq));
	req.r_nmp = nmp;
	req.r_gss_ctx = NULL;
	req.r_auth = nmp->nm_auth;
	req.r_thread = vfs_context_thread(ctx);
	req.r_cred = vfs_context_ucred(ctx);

	error = nfs_gss_clnt_ctx_find_principal(&req, principal, princlen, nametype);
	NFS_GSS_DBG("nfs_gss_clnt_ctx_find_principal returned %d\n", error);
	/*
	 * We don't care about auth errors. Those would indicate that the context is in the
	 * neagative cache and if and when the user has credentials for the principal
	 * we should be good to go in that we will select those credentials for this principal.
	 */
	if (error == EACCES || error == EAUTH || error == ENEEDAUTH) {
		error = 0;
	}

	/* We're done with this request */
	nfs_gss_clnt_ctx_unref(&req);

	return error;
}

/*
 * Gets a mounts principal from a session associated with cred
 */
int
nfs_gss_clnt_ctx_get_principal(struct nfsmount *nmp, vfs_context_t ctx,
    struct user_nfs_gss_principal *p)
{
	struct nfsreq req;
	int error = 0;
	struct nfs_gss_clnt_ctx *cp;
	kauth_cred_t cred = vfs_context_ucred(ctx);
	const char *princ = NULL;
	char CTXBUF[NFS_CTXBUFSZ];

	/* Make sure the the members of the struct user_nfs_gss_principal are initialized */
	p->nametype = GSSD_STRING_NAME;
	p->principal = USER_ADDR_NULL;
	p->princlen = 0;
	p->flags = 0;

	req.r_nmp = nmp;
	lck_mtx_lock(&nmp->nm_lock);
	TAILQ_FOREACH(cp, &nmp->nm_gsscl, gss_clnt_entries) {
		lck_mtx_lock(cp->gss_clnt_mtx);
		if (cp->gss_clnt_flags & GSS_CTX_DESTROY) {
			NFS_GSS_DBG("Found destroyed context %s refcnt = %d continuing\n",
			    NFS_GSS_CTX(&req, cp),
			    cp->gss_clnt_refcnt);
			lck_mtx_unlock(cp->gss_clnt_mtx);
			continue;
		}
		if (nfs_gss_clnt_ctx_cred_match(cp->gss_clnt_cred, cred)) {
			cp->gss_clnt_refcnt++;
			lck_mtx_unlock(cp->gss_clnt_mtx);
			goto out;
		}
		lck_mtx_unlock(cp->gss_clnt_mtx);
	}

out:
	if (cp == NULL) {
		lck_mtx_unlock(&nmp->nm_lock);
		p->flags |= NFS_IOC_NO_CRED_FLAG;  /* No credentials, valid or invalid on this mount */
		NFS_GSS_DBG("No context found for session %d by uid %d\n",
		    kauth_cred_getasid(cred), kauth_cred_getuid(cred));
		return 0;
	}

	/* Indicate if the cred is INVALID */
	if (cp->gss_clnt_flags & GSS_CTX_INVAL) {
		p->flags |= NFS_IOC_INVALID_CRED_FLAG;
	}

	/* We have set a principal on the mount */
	if (cp->gss_clnt_principal) {
		princ = (char *)cp->gss_clnt_principal;
		p->princlen = cp->gss_clnt_prinlen;
		p->nametype = cp->gss_clnt_prinnt;
	} else if (cp->gss_clnt_display) {
		/* We have a successful use the the default credential */
		princ = cp->gss_clnt_display;
		p->princlen = strlen(cp->gss_clnt_display);
	}

	/*
	 * If neither of the above is true we have an invalid default credential
	 * So from above p->principal is USER_ADDR_NULL and princ is NULL
	 */

	if (princ) {
		char *pp;

		MALLOC(pp, char *, p->princlen, M_TEMP, M_WAITOK);
		bcopy(princ, pp, p->princlen);
		p->principal = CAST_USER_ADDR_T(pp);
	}

	lck_mtx_unlock(&nmp->nm_lock);

	req.r_gss_ctx = cp;
	NFS_GSS_DBG("Found context %s\n", NFS_GSS_CTX(&req, NULL));
	nfs_gss_clnt_ctx_unref(&req);
	return error;
}
#endif /* CONFIG_NFS_CLIENT */

/*************
 *
 * Server functions
 */

#if CONFIG_NFS_SERVER

/*
 * Find a server context based on a handle value received
 * in an RPCSEC_GSS credential.
 */
static struct nfs_gss_svc_ctx *
nfs_gss_svc_ctx_find(uint32_t handle)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *cp;
	uint64_t timenow;

	if (handle == 0) {
		return NULL;
	}

	head = &nfs_gss_svc_ctx_hashtbl[SVC_CTX_HASH(handle)];
	/*
	 * Don't return a context that is going to expire in GSS_CTX_PEND seconds
	 */
	clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC, &timenow);

	lck_mtx_lock(nfs_gss_svc_ctx_mutex);

	LIST_FOREACH(cp, head, gss_svc_entries) {
		if (cp->gss_svc_handle == handle) {
			if (timenow > cp->gss_svc_incarnation + GSS_SVC_CTX_TTL) {
				/*
				 * Context has or is about to expire. Don't use.
				 * We'll return null and the client will have to create
				 * a new context.
				 */
				cp->gss_svc_handle = 0;
				/*
				 * Make sure though that we stay around for GSS_CTX_PEND seconds
				 * for other threads that might be using the context.
				 */
				cp->gss_svc_incarnation = timenow;

				cp = NULL;
				break;
			}
			lck_mtx_lock(cp->gss_svc_mtx);
			cp->gss_svc_refcnt++;
			lck_mtx_unlock(cp->gss_svc_mtx);
			break;
		}
	}

	lck_mtx_unlock(nfs_gss_svc_ctx_mutex);

	return cp;
}

/*
 * Insert a new server context into the hash table
 * and start the context reap thread if necessary.
 */
static void
nfs_gss_svc_ctx_insert(struct nfs_gss_svc_ctx *cp)
{
	struct nfs_gss_svc_ctx_hashhead *head;
	struct nfs_gss_svc_ctx *p;

	lck_mtx_lock(nfs_gss_svc_ctx_mutex);

	/*
	 * Give the client a random handle so that if we reboot
	 * it's unlikely the client will get a bad context match.
	 * Make sure it's not zero or already assigned.
	 */
retry:
	cp->gss_svc_handle = random();
	if (cp->gss_svc_handle == 0) {
		goto retry;
	}
	head = &nfs_gss_svc_ctx_hashtbl[SVC_CTX_HASH(cp->gss_svc_handle)];
	LIST_FOREACH(p, head, gss_svc_entries)
	if (p->gss_svc_handle == cp->gss_svc_handle) {
		goto retry;
	}

	clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC,
	    &cp->gss_svc_incarnation);
	LIST_INSERT_HEAD(head, cp, gss_svc_entries);
	nfs_gss_ctx_count++;

	if (!nfs_gss_timer_on) {
		nfs_gss_timer_on = 1;

		nfs_interval_timer_start(nfs_gss_svc_ctx_timer_call,
		    min(GSS_TIMER_PERIOD, max(GSS_CTX_TTL_MIN, nfsrv_gss_context_ttl)) * MSECS_PER_SEC);
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
	struct nfs_gss_svc_ctx *cp, *next;
	uint64_t timenow;
	int contexts = 0;
	int i;

	lck_mtx_lock(nfs_gss_svc_ctx_mutex);
	clock_get_uptime(&timenow);

	NFS_GSS_DBG("is running\n");

	/*
	 * Scan all the hash chains
	 */
	for (i = 0; i < SVC_CTX_HASHSZ; i++) {
		/*
		 * For each hash chain, look for entries
		 * that haven't been used in a while.
		 */
		LIST_FOREACH_SAFE(cp, &nfs_gss_svc_ctx_hashtbl[i], gss_svc_entries, next) {
			contexts++;
			if (timenow > cp->gss_svc_incarnation +
			    (cp->gss_svc_handle ? GSS_SVC_CTX_TTL : 0)
			    && cp->gss_svc_refcnt == 0) {
				/*
				 * A stale context - remove it
				 */
				LIST_REMOVE(cp, gss_svc_entries);
				NFS_GSS_DBG("Removing contex for %d\n", cp->gss_svc_uid);
				if (cp->gss_svc_seqbits) {
					FREE(cp->gss_svc_seqbits, M_TEMP);
				}
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
	if (nfs_gss_timer_on) {
		nfs_interval_timer_start(nfs_gss_svc_ctx_timer_call,
		    min(GSS_TIMER_PERIOD, max(GSS_CTX_TTL_MIN, nfsrv_gss_context_ttl)) * MSECS_PER_SEC);
	}

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
	uint32_t major;
	struct nfs_gss_svc_ctx *cp = NULL;
	uint32_t flavor = 0, header_len;
	int error = 0;
	uint32_t arglen, start;
	size_t argsize;
	gss_buffer_desc cksum;
	struct nfsm_chain nmc_tmp;
	mbuf_t reply_mbuf, prev_mbuf, pad_mbuf;

	vers = proc = seqnum = service = handle_len = 0;
	arglen = 0;

	nfsm_chain_get_32(error, nmc, vers);
	if (vers != RPCSEC_GSS_VERS_1) {
		error = NFSERR_AUTHERR | AUTH_REJECTCRED;
		goto nfsmout;
	}

	nfsm_chain_get_32(error, nmc, proc);
	nfsm_chain_get_32(error, nmc, seqnum);
	nfsm_chain_get_32(error, nmc, service);
	nfsm_chain_get_32(error, nmc, handle_len);
	if (error) {
		goto nfsmout;
	}

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
		MALLOC(cp, struct nfs_gss_svc_ctx *, sizeof(*cp), M_TEMP, M_WAITOK | M_ZERO);
		if (cp == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		cp->gss_svc_mtx = lck_mtx_alloc_init(nfs_gss_svc_grp, LCK_ATTR_NULL);
		cp->gss_svc_refcnt = 1;
	} else {
		/*
		 * Use the handle to find the context
		 */
		if (handle_len != sizeof(handle)) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
			goto nfsmout;
		}
		nfsm_chain_get_32(error, nmc, handle);
		if (error) {
			goto nfsmout;
		}
		cp = nfs_gss_svc_ctx_find(handle);
		if (cp == NULL) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}
	}

	cp->gss_svc_proc = proc;

	if (proc == RPCSEC_GSS_DATA || proc == RPCSEC_GSS_DESTROY) {
		struct posix_cred temp_pcred;

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
			error = EINVAL; // drop the request
			goto nfsmout;
		}

		/*
		 * Validate the verifier.
		 * The verifier contains an encrypted checksum
		 * of the call header from the XID up to and
		 * including the credential.  We compute the
		 * checksum and compare it with what came in
		 * the verifier.
		 */
		header_len = nfsm_chain_offset(nmc);
		nfsm_chain_get_32(error, nmc, flavor);
		nfsm_chain_get_32(error, nmc, cksum.length);
		if (error) {
			goto nfsmout;
		}
		if (flavor != RPCSEC_GSS || cksum.length > KRB5_MAX_MIC_SIZE) {
			error = NFSERR_AUTHERR | AUTH_BADVERF;
		} else {
			MALLOC(cksum.value, void *, cksum.length, M_TEMP, M_WAITOK);
			nfsm_chain_get_opaque(error, nmc, cksum.length, cksum.value);
		}
		if (error) {
			goto nfsmout;
		}

		/* Now verify the client's call header checksum */
		major = gss_krb5_verify_mic_mbuf((uint32_t *)&error, cp->gss_svc_ctx_id, nmc->nmc_mhead, 0, header_len, &cksum, NULL);
		(void)gss_release_buffer(NULL, &cksum);
		if (major != GSS_S_COMPLETE) {
			printf("Server header: gss_krb5_verify_mic_mbuf failed %d\n", error);
			error = NFSERR_AUTHERR | RPCSEC_GSS_CTXPROBLEM;
			goto nfsmout;
		}

		nd->nd_gss_seqnum = seqnum;

		/*
		 * Set up the user's cred
		 */
		bzero(&temp_pcred, sizeof(temp_pcred));
		temp_pcred.cr_uid = cp->gss_svc_uid;
		bcopy(cp->gss_svc_gids, temp_pcred.cr_groups,
		    sizeof(gid_t) * cp->gss_svc_ngroups);
		temp_pcred.cr_ngroups = cp->gss_svc_ngroups;

		nd->nd_cr = posix_cred_create(&temp_pcred);
		if (nd->nd_cr == NULL) {
			error = ENOMEM;
			goto nfsmout;
		}
		clock_get_uptime(&cp->gss_svc_incarnation);

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
			 * - length of checksum token
			 * - checksum of seqnum + call args
			 */
			nfsm_chain_get_32(error, nmc, arglen);          // length of args
			if (arglen > NFS_MAXPACKET) {
				error = EBADRPC;
				goto nfsmout;
			}

			nmc_tmp = *nmc;
			nfsm_chain_adv(error, &nmc_tmp, arglen);
			nfsm_chain_get_32(error, &nmc_tmp, cksum.length);
			cksum.value = NULL;
			if (cksum.length > 0 && cksum.length < GSS_MAX_MIC_LEN) {
				MALLOC(cksum.value, void *, cksum.length, M_TEMP, M_WAITOK);
			}

			if (cksum.value == NULL) {
				error = EBADRPC;
				goto nfsmout;
			}
			nfsm_chain_get_opaque(error, &nmc_tmp, cksum.length, cksum.value);

			/* Verify the checksum over the call args */
			start = nfsm_chain_offset(nmc);

			major = gss_krb5_verify_mic_mbuf((uint32_t *)&error, cp->gss_svc_ctx_id,
			    nmc->nmc_mhead, start, arglen, &cksum, NULL);
			FREE(cksum.value, M_TEMP);
			if (major != GSS_S_COMPLETE) {
				printf("Server args: gss_krb5_verify_mic_mbuf failed %d\n", error);
				error = EBADRPC;
				goto nfsmout;
			}

			/*
			 * Get the sequence number prepended to the args
			 * and compare it against the one sent in the
			 * call credential.
			 */
			nfsm_chain_get_32(error, nmc, seqnum);
			if (seqnum != nd->nd_gss_seqnum) {
				error = EBADRPC;                        // returns as GARBAGEARGS
				goto nfsmout;
			}
			break;
		case RPCSEC_GSS_SVC_PRIVACY:
			/*
			 * Here's what we expect in the privacy call args:
			 *
			 * - length of wrap token
			 * - wrap token (37-40 bytes)
			 */
			prev_mbuf = nmc->nmc_mcur;
			nfsm_chain_get_32(error, nmc, arglen);          // length of args
			if (arglen > NFS_MAXPACKET) {
				error = EBADRPC;
				goto nfsmout;
			}

			/* Get the wrap token (current mbuf in the chain starting at the current offset) */
			start = nmc->nmc_ptr - (caddr_t)mbuf_data(nmc->nmc_mcur);

			/* split out the wrap token */
			argsize = arglen;
			error = gss_normalize_mbuf(nmc->nmc_mcur, start, &argsize, &reply_mbuf, &pad_mbuf, 0);
			if (error) {
				goto nfsmout;
			}

			assert(argsize == arglen);
			if (pad_mbuf) {
				assert(nfsm_pad(arglen) == mbuf_len(pad_mbuf));
				mbuf_free(pad_mbuf);
			} else {
				assert(nfsm_pad(arglen) == 0);
			}

			major = gss_krb5_unwrap_mbuf((uint32_t *)&error, cp->gss_svc_ctx_id, &reply_mbuf, 0, arglen, NULL, NULL);
			if (major != GSS_S_COMPLETE) {
				printf("%s: gss_krb5_unwrap_mbuf failes %d\n", __func__, error);
				goto nfsmout;
			}

			/* Now replace the wrapped arguments with the unwrapped ones */
			mbuf_setnext(prev_mbuf, reply_mbuf);
			nmc->nmc_mcur = reply_mbuf;
			nmc->nmc_ptr = mbuf_data(reply_mbuf);
			nmc->nmc_left = mbuf_len(reply_mbuf);

			/*
			 * - sequence number (4 bytes)
			 * - call args
			 */

			// nfsm_chain_reverse(nmc, nfsm_pad(toklen));

			/*
			 * Get the sequence number prepended to the args
			 * and compare it against the one sent in the
			 * call credential.
			 */
			nfsm_chain_get_32(error, nmc, seqnum);
			if (seqnum != nd->nd_gss_seqnum) {
				printf("%s: Sequence number mismatch seqnum = %d nd->nd_gss_seqnum = %d\n",
				    __func__, seqnum, nd->nd_gss_seqnum);
				printmbuf("reply_mbuf", nmc->nmc_mhead, 0, 0);
				printf("reply_mbuf %p nmc_head %p\n", reply_mbuf, nmc->nmc_mhead);
				error = EBADRPC;                        // returns as GARBAGEARGS
				goto nfsmout;
			}
			break;
		}
	} else {
		uint32_t verflen;
		/*
		 * If the proc is RPCSEC_GSS_INIT or RPCSEC_GSS_CONTINUE_INIT
		 * then we expect a null verifier.
		 */
		nfsm_chain_get_32(error, nmc, flavor);
		nfsm_chain_get_32(error, nmc, verflen);
		if (error || flavor != RPCAUTH_NULL || verflen > 0) {
			error = NFSERR_AUTHERR | RPCSEC_GSS_CREDPROBLEM;
		}
		if (error) {
			if (proc == RPCSEC_GSS_INIT) {
				lck_mtx_destroy(cp->gss_svc_mtx, nfs_gss_svc_grp);
				FREE(cp, M_TEMP);
				cp = NULL;
			}
			goto nfsmout;
		}
	}

	nd->nd_gss_context = cp;
	return 0;
nfsmout:
	if (cp) {
		nfs_gss_svc_ctx_deref(cp);
	}
	return error;
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
	gss_buffer_desc cksum, seqbuf;
	uint32_t network_seqnum;
	cp = nd->nd_gss_context;
	uint32_t major;

	if (cp->gss_svc_major != GSS_S_COMPLETE) {
		/*
		 * If the context isn't yet complete
		 * then return a null verifier.
		 */
		nfsm_chain_add_32(error, nmc, RPCAUTH_NULL);
		nfsm_chain_add_32(error, nmc, 0);
		return error;
	}

	/*
	 * Compute checksum of the request seq number
	 * If it's the final reply of context setup
	 * then return the checksum of the context
	 * window size.
	 */
	seqbuf.length = NFSX_UNSIGNED;
	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		network_seqnum = htonl(cp->gss_svc_seqwin);
	} else {
		network_seqnum = htonl(nd->nd_gss_seqnum);
	}
	seqbuf.value = &network_seqnum;

	major = gss_krb5_get_mic((uint32_t *)&error, cp->gss_svc_ctx_id, 0, &seqbuf, &cksum);
	if (major != GSS_S_COMPLETE) {
		return error;
	}

	/*
	 * Now wrap it in a token and add
	 * the verifier to the reply.
	 */
	nfsm_chain_add_32(error, nmc, RPCSEC_GSS);
	nfsm_chain_add_32(error, nmc, cksum.length);
	nfsm_chain_add_opaque(error, nmc, cksum.value, cksum.length);
	gss_release_buffer(NULL, &cksum);

	return error;
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
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		return 0;
	}

	switch (nd->nd_sec) {
	case RPCAUTH_KRB5:
		/* Nothing to do */
		break;
	case RPCAUTH_KRB5I:
	case RPCAUTH_KRB5P:
		nd->nd_gss_mb = nmc->nmc_mcur;                  // record current mbuf
		nfsm_chain_finish_mbuf(error, nmc);             // split the chain here
		break;
	}

	return error;
}

/*
 * The results are checksummed or encrypted for return to the client
 */
int
nfs_gss_svc_protect_reply(struct nfsrv_descript *nd, mbuf_t mrep __unused)
{
	struct nfs_gss_svc_ctx *cp = nd->nd_gss_context;
	struct nfsm_chain nmrep_res, *nmc_res = &nmrep_res;
	mbuf_t mb, results;
	uint32_t reslen;
	int error = 0;

	/* XXX
	 * Using a reference to the mbuf where we previously split the reply
	 * mbuf chain, we split the mbuf chain argument into two mbuf chains,
	 * one that allows us to prepend a length field or token, (nmc_pre)
	 * and the second which holds just the results that we're going to
	 * checksum and/or encrypt.  When we're done, we join the chains back
	 * together.
	 */

	mb = nd->nd_gss_mb;                             // the mbuf where we split
	results = mbuf_next(mb);                        // first mbuf in the results
	error = mbuf_setnext(mb, NULL);                 // disconnect the chains
	if (error) {
		return error;
	}
	nfs_gss_nfsm_chain(nmc_res, mb);                // set up the prepend chain
	nfsm_chain_build_done(error, nmc_res);
	if (error) {
		return error;
	}

	if (nd->nd_sec == RPCAUTH_KRB5I) {
		error = rpc_gss_integ_data_create(cp->gss_svc_ctx_id, &results, nd->nd_gss_seqnum, &reslen);
	} else {
		/* RPCAUTH_KRB5P */
		error = rpc_gss_priv_data_create(cp->gss_svc_ctx_id, &results, nd->nd_gss_seqnum, &reslen);
	}
	nfs_gss_append_chain(nmc_res, results); // Append the results mbufs
	nfsm_chain_build_done(error, nmc_res);

	return error;
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
		nfs_gss_svc_ctx_insert(cp);
	/* FALLTHRU */

	case RPCSEC_GSS_CONTINUE_INIT:
		/* Get the token from the request */
		nfsm_chain_get_32(error, nmreq, cp->gss_svc_tokenlen);
		cp->gss_svc_token = NULL;
		if (cp->gss_svc_tokenlen > 0 && cp->gss_svc_tokenlen < GSS_MAX_TOKEN_LEN) {
			MALLOC(cp->gss_svc_token, u_char *, cp->gss_svc_tokenlen, M_TEMP, M_WAITOK);
		}
		if (cp->gss_svc_token == NULL) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			break;
		}
		nfsm_chain_get_opaque(error, nmreq, cp->gss_svc_tokenlen, cp->gss_svc_token);

		/* Use the token in a gss_accept_sec_context upcall */
		error = nfs_gss_svc_gssd_upcall(cp);
		if (error) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
			if (error == NFSERR_EAUTH) {
				error = 0;
			}
			break;
		}

		/*
		 * If the context isn't complete, pass the new token
		 * back to the client for another round.
		 */
		if (cp->gss_svc_major != GSS_S_COMPLETE) {
			break;
		}

		/*
		 * Now the server context is complete.
		 * Finish setup.
		 */
		clock_get_uptime(&cp->gss_svc_incarnation);

		cp->gss_svc_seqwin = GSS_SVC_SEQWINDOW;
		MALLOC(cp->gss_svc_seqbits, uint32_t *,
		    nfsm_rndup((cp->gss_svc_seqwin + 7) / 8), M_TEMP, M_WAITOK | M_ZERO);
		if (cp->gss_svc_seqbits == NULL) {
			autherr = RPCSEC_GSS_CREDPROBLEM;
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
			cp->gss_svc_handle = 0; // so it can't be found
			lck_mtx_lock(cp->gss_svc_mtx);
			clock_interval_to_deadline(GSS_CTX_PEND, NSEC_PER_SEC,
			    &cp->gss_svc_incarnation);
			lck_mtx_unlock(cp->gss_svc_mtx);
		}
		break;
	default:
		autherr = RPCSEC_GSS_CREDPROBLEM;
		break;
	}

	/* Now build the reply  */

	if (nd->nd_repstat == 0) {
		nd->nd_repstat = autherr ? (NFSERR_AUTHERR | autherr) : NFSERR_RETVOID;
	}
	sz = 7 * NFSX_UNSIGNED + nfsm_rndup(cp->gss_svc_tokenlen); // size of results
	error = nfsrv_rephead(nd, slp, &nmrep, sz);
	*mrepp = nmrep.nmc_mhead;
	if (error || autherr) {
		goto nfsmout;
	}

	if (cp->gss_svc_proc == RPCSEC_GSS_INIT ||
	    cp->gss_svc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		nfsm_chain_add_32(error, &nmrep, sizeof(cp->gss_svc_handle));
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_handle);

		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_major);
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_minor);
		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_seqwin);

		nfsm_chain_add_32(error, &nmrep, cp->gss_svc_tokenlen);
		if (cp->gss_svc_token != NULL) {
			nfsm_chain_add_opaque(error, &nmrep, cp->gss_svc_token, cp->gss_svc_tokenlen);
			FREE(cp->gss_svc_token, M_TEMP);
			cp->gss_svc_token = NULL;
		}
	}

nfsmout:
	if (autherr != 0) {
		nd->nd_gss_context = NULL;
		LIST_REMOVE(cp, gss_svc_entries);
		if (cp->gss_svc_seqbits != NULL) {
			FREE(cp->gss_svc_seqbits, M_TEMP);
		}
		if (cp->gss_svc_token != NULL) {
			FREE(cp->gss_svc_token, M_TEMP);
		}
		lck_mtx_destroy(cp->gss_svc_mtx, nfs_gss_svc_grp);
		FREE(cp, M_TEMP);
	}

	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return error;
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
	gssd_byte_buffer octx = NULL;
	uint32_t lucidlen = 0;
	void *lucid_ctx_buffer;
	uint32_t ret_flags;
	vm_map_copy_t itoken = NULL;
	gssd_byte_buffer otoken = NULL;
	mach_msg_type_number_t otokenlen;
	int error = 0;
	char svcname[] = "nfs";

	kr = host_get_gssd_port(host_priv_self(), &mp);
	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_svc_gssd_upcall: can't get gssd port, status %x (%d)\n", kr, kr);
		goto out;
	}
	if (!IPC_PORT_VALID(mp)) {
		printf("nfs_gss_svc_gssd_upcall: gssd port not valid\n");
		goto out;
	}

	if (cp->gss_svc_tokenlen > 0) {
		nfs_gss_mach_alloc_buffer(cp->gss_svc_token, cp->gss_svc_tokenlen, &itoken);
	}

retry:
	printf("Calling mach_gss_accept_sec_context\n");
	kr = mach_gss_accept_sec_context(
		mp,
		(gssd_byte_buffer) itoken, (mach_msg_type_number_t) cp->gss_svc_tokenlen,
		svcname,
		0,
		&cp->gss_svc_context,
		&cp->gss_svc_cred_handle,
		&ret_flags,
		&cp->gss_svc_uid,
		cp->gss_svc_gids,
		&cp->gss_svc_ngroups,
		&octx, (mach_msg_type_number_t *) &lucidlen,
		&otoken, &otokenlen,
		&cp->gss_svc_major,
		&cp->gss_svc_minor);

	printf("mach_gss_accept_sec_context returned %d\n", kr);
	if (kr != KERN_SUCCESS) {
		printf("nfs_gss_svc_gssd_upcall failed: %x (%d)\n", kr, kr);
		if (kr == MIG_SERVER_DIED && cp->gss_svc_context == 0 &&
		    retry_cnt++ < NFS_GSS_MACH_MAX_RETRIES) {
			if (cp->gss_svc_tokenlen > 0) {
				nfs_gss_mach_alloc_buffer(cp->gss_svc_token, cp->gss_svc_tokenlen, &itoken);
			}
			goto retry;
		}
		host_release_special_port(mp);
		goto out;
	}

	host_release_special_port(mp);

	if (lucidlen > 0) {
		if (lucidlen > MAX_LUCIDLEN) {
			printf("nfs_gss_svc_gssd_upcall: bad context length (%d)\n", lucidlen);
			vm_map_copy_discard((vm_map_copy_t) octx);
			vm_map_copy_discard((vm_map_copy_t) otoken);
			goto out;
		}
		MALLOC(lucid_ctx_buffer, void *, lucidlen, M_TEMP, M_WAITOK | M_ZERO);
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) octx, lucidlen, lucid_ctx_buffer);
		if (error) {
			vm_map_copy_discard((vm_map_copy_t) otoken);
			FREE(lucid_ctx_buffer, M_TEMP);
			goto out;
		}
		if (cp->gss_svc_ctx_id) {
			gss_krb5_destroy_context(cp->gss_svc_ctx_id);
		}
		cp->gss_svc_ctx_id = gss_krb5_make_context(lucid_ctx_buffer, lucidlen);
		if (cp->gss_svc_ctx_id == NULL) {
			printf("Failed to make context from lucid_ctx_buffer\n");
			goto out;
		}
	}

	/* Free context token used as input */
	if (cp->gss_svc_token) {
		FREE(cp->gss_svc_token, M_TEMP);
	}
	cp->gss_svc_token = NULL;
	cp->gss_svc_tokenlen = 0;

	if (otokenlen > 0) {
		/* Set context token to gss output token */
		MALLOC(cp->gss_svc_token, u_char *, otokenlen, M_TEMP, M_WAITOK);
		if (cp->gss_svc_token == NULL) {
			printf("nfs_gss_svc_gssd_upcall: could not allocate %d bytes\n", otokenlen);
			vm_map_copy_discard((vm_map_copy_t) otoken);
			return ENOMEM;
		}
		error = nfs_gss_mach_vmcopyout((vm_map_copy_t) otoken, otokenlen, cp->gss_svc_token);
		if (error) {
			FREE(cp->gss_svc_token, M_TEMP);
			cp->gss_svc_token = NULL;
			return NFSERR_EAUTH;
		}
		cp->gss_svc_tokenlen = otokenlen;
	}

	return 0;

out:
	FREE(cp->gss_svc_token, M_TEMP);
	cp->gss_svc_tokenlen = 0;
	cp->gss_svc_token = NULL;

	return NFSERR_EAUTH;
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
		if (seq - cp->gss_svc_seqmax > win) {
			bzero(bits, nfsm_rndup((win + 7) / 8));
		} else {
			for (i = cp->gss_svc_seqmax + 1; i < seq; i++) {
				win_resetbit(bits, i % win);
			}
		}
		win_setbit(bits, seq % win);
		cp->gss_svc_seqmax = seq;
		lck_mtx_unlock(cp->gss_svc_mtx);
		return 1;
	}

	/*
	 * Invalid if below the lower bound of the window
	 */
	if (seq <= cp->gss_svc_seqmax - win) {
		lck_mtx_unlock(cp->gss_svc_mtx);
		return 0;
	}

	/*
	 * In the window, invalid if the bit is already set
	 */
	if (win_getbit(bits, seq % win)) {
		lck_mtx_unlock(cp->gss_svc_mtx);
		return 0;
	}
	win_setbit(bits, seq % win);
	lck_mtx_unlock(cp->gss_svc_mtx);
	return 1;
}

/*
 * Drop a reference to a context
 *
 * Note that it's OK for the context to exist
 * with a refcount of zero.  The refcount isn't
 * checked until we're about to reap an expired one.
 */
void
nfs_gss_svc_ctx_deref(struct nfs_gss_svc_ctx *cp)
{
	lck_mtx_lock(cp->gss_svc_mtx);
	if (cp->gss_svc_refcnt > 0) {
		cp->gss_svc_refcnt--;
	} else {
		printf("nfs_gss_ctx_deref: zero refcount\n");
	}
	lck_mtx_unlock(cp->gss_svc_mtx);
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
			if (cp->gss_svc_seqbits) {
				FREE(cp->gss_svc_seqbits, M_TEMP);
			}
			lck_mtx_destroy(cp->gss_svc_mtx, nfs_gss_svc_grp);
			FREE(cp, M_TEMP);
		}
	}

	lck_mtx_unlock(nfs_gss_svc_ctx_mutex);
}

#endif /* CONFIG_NFS_SERVER */


/*************
 * The following functions are used by both client and server.
 */

/*
 * Release a host special port that was obtained by host_get_special_port
 * or one of its macros (host_get_gssd_port in this case).
 * This really should be in a public kpi.
 */

/* This should be in a public header if this routine is not */
extern void ipc_port_release_send(ipc_port_t);
extern ipc_port_t ipc_port_copy_send(ipc_port_t);

static void
host_release_special_port(mach_port_t mp)
{
	if (IPC_PORT_VALID(mp)) {
		ipc_port_release_send(mp);
	}
}

static mach_port_t
host_copy_special_port(mach_port_t mp)
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
	if (buf == NULL || buflen == 0) {
		return;
	}

	tbuflen = vm_map_round_page(buflen,
	    vm_map_page_mask(ipc_kernel_map));

	if (tbuflen < buflen) {
		printf("nfs_gss_mach_alloc_buffer: vm_map_round_page failed\n");
		return;
	}

	kr = vm_allocate_kernel(ipc_kernel_map, &kmem_buf, tbuflen, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_FILE);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_allocate failed\n");
		return;
	}

	kr = vm_map_wire_kernel(ipc_kernel_map,
	    vm_map_trunc_page(kmem_buf,
	    vm_map_page_mask(ipc_kernel_map)),
	    vm_map_round_page(kmem_buf + tbuflen,
	    vm_map_page_mask(ipc_kernel_map)),
	    VM_PROT_READ | VM_PROT_WRITE, VM_KERN_MEMORY_FILE, FALSE);
	if (kr != 0) {
		printf("nfs_gss_mach_alloc_buffer: vm_map_wire failed\n");
		return;
	}

	bcopy(buf, (void *) kmem_buf, buflen);
	// Shouldn't need to bzero below since vm_allocate returns zeroed pages
	// bzero(kmem_buf + buflen, tbuflen - buflen);

	kr = vm_map_unwire(ipc_kernel_map,
	    vm_map_trunc_page(kmem_buf,
	    vm_map_page_mask(ipc_kernel_map)),
	    vm_map_round_page(kmem_buf + tbuflen,
	    vm_map_page_mask(ipc_kernel_map)),
	    FALSE);
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
	if (error) {
		return error;
	}

	data = CAST_DOWN(vm_offset_t, map_data);
	bcopy((void *) data, out, len);
	vm_deallocate(ipc_kernel_map, data, len);

	return 0;
}

/*
 * Return the number of bytes in an mbuf chain.
 */
static int
nfs_gss_mchain_length(mbuf_t mhead)
{
	mbuf_t mb;
	int len = 0;

	for (mb = mhead; mb; mb = mbuf_next(mb)) {
		len += mbuf_len(mb);
	}

	return len;
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
	if (error) {
		return error;
	}

	/* Find the last mbuf in the chain */
	tail = NULL;
	for (mb = mc; mb; mb = mbuf_next(mb)) {
		tail = mb;
	}

	nmc->nmc_mcur = tail;
	nmc->nmc_ptr = (caddr_t) mbuf_data(tail) + mbuf_len(tail);
	nmc->nmc_left = mbuf_trailingspace(tail);

	return 0;
}

#if CONFIG_NFS_SERVER /* Only used by CONFIG_NFS_SERVER */
/*
 * Convert an mbuf chain to an NFS mbuf chain
 */
static void
nfs_gss_nfsm_chain(struct nfsm_chain *nmc, mbuf_t mc)
{
	mbuf_t mb, tail;

	/* Find the last mbuf in the chain */
	tail = NULL;
	for (mb = mc; mb; mb = mbuf_next(mb)) {
		tail = mb;
	}

	nmc->nmc_mhead = mc;
	nmc->nmc_mcur = tail;
	nmc->nmc_ptr = (caddr_t) mbuf_data(tail) + mbuf_len(tail);
	nmc->nmc_left = mbuf_trailingspace(tail);
	nmc->nmc_flags = 0;
}
#endif /* CONFIG_NFS_SERVER */


#if 0
#define DISPLAYLEN 16
#define MAXDISPLAYLEN 256

static void
hexdump(const char *msg, void *data, size_t len)
{
	size_t i, j;
	u_char *d = data;
	char *p, disbuf[3 * DISPLAYLEN + 1];

	printf("NFS DEBUG %s len=%d:\n", msg, (uint32_t)len);
	if (len > MAXDISPLAYLEN) {
		len = MAXDISPLAYLEN;
	}

	for (i = 0; i < len; i += DISPLAYLEN) {
		for (p = disbuf, j = 0; (j + i) < len && j < DISPLAYLEN; j++, p += 3) {
			snprintf(p, 4, "%02x ", d[i + j]);
		}
		printf("\t%s\n", disbuf);
	}
}
#endif

#endif /* CONFIG_NFS */
