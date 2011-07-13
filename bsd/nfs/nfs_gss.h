/*
 * Copyright (c) 2007-2010 Apple Inc. All rights reserved.
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

#ifndef _NFS_NFS_GSS_H_
#define _NFS_NFS_GSS_H_

#include <gssd/gssd_mach.h>
#include <sys/param.h>
#include <crypto/des/des.h>

#define RPCSEC_GSS			6
#define	RPCSEC_GSS_VERS_1		1

enum rpcsec_gss_proc {
	RPCSEC_GSS_DATA			= 0,
	RPCSEC_GSS_INIT			= 1,
	RPCSEC_GSS_CONTINUE_INIT	= 2,
	RPCSEC_GSS_DESTROY		= 3
};

enum rpcsec_gss_service {
	RPCSEC_GSS_SVC_NONE		= 1,	// sec=krb5
	RPCSEC_GSS_SVC_INTEGRITY	= 2,	// sec=krb5i
	RPCSEC_GSS_SVC_PRIVACY		= 3,	// sec=krb5p
	RPCSEC_GSS_SVC_SYS		= 4	// sec=sys (fallback)
};

/* encoded krb5 OID */
extern u_char krb5_mech[11];

/*
 * GSS-API things
 */
#define GSS_S_COMPLETE			0
#define GSS_S_CONTINUE_NEEDED		1

#define GSS_MAXSEQ			0x80000000	// The biggest sequence number
#define GSS_SVC_MAXCONTEXTS		500000		// Max contexts supported
#define GSS_SVC_SEQWINDOW		256		// Server's sequence window
#define GSS_CLNT_SEQLISTMAX		32		// Max length of req seq num list
#define GSS_CLNT_SYS_VALID		300		// Valid time (sec) for failover ctx


#define SKEYLEN	8			// length of DES key
#define SKEYLEN3 24			// length of DES3 keyboard
#define MAX_SKEYLEN	SKEYLEN3

typedef struct {
	uint32_t type; 		// See defines below
	uint32_t keybytes; 	// Session key length bytes;
	uint32_t hash_len;
	u_char   skey[MAX_SKEYLEN];	   	// Session key;
	union {
		struct {
			des_cblock  *key;
			des_key_schedule gss_sched;
			des_key_schedule gss_sched_Ke;
		} des;
		struct {
			des_cblock		(*key)[3];
			des_cblock		ckey[3];
			des_key_schedule	gss_sched[3];
		} des3;
	} ks_u;
} gss_key_info;

#define NFS_GSS_0DES	0 // Not DES or uninitialized
#define NFS_GSS_1DES	1 // Single DES with DES_MAC_MD5
#define NFS_GSS_3DES	2 // Triple EDE DES KD with SHA1

/*
 * The client's RPCSEC_GSS context information
 */
struct nfs_gss_clnt_ctx {
	lck_mtx_t		*gss_clnt_mtx;
	thread_t		gss_clnt_thread;	// Thread creating context
	TAILQ_ENTRY(nfs_gss_clnt_ctx)	gss_clnt_entries;
	uint32_t		gss_clnt_flags;		// Flag bits - see below
	uint32_t		gss_clnt_refcnt;	// Reference count
	uid_t			gss_clnt_uid;		// Owner of this context
	uint32_t		gss_clnt_proc;		// Current GSS proc for cred
	uint32_t		gss_clnt_seqnum;	// GSS sequence number
	uint32_t		gss_clnt_service;	// Indicates krb5, krb5i or krb5p
	u_char			*gss_clnt_handle;	// Identifies server context
	uint32_t		gss_clnt_handle_len;	// Size of server's ctx handle
	time_t			gss_clnt_ctime;		// When context was created
	uint32_t		gss_clnt_seqwin;	// Server's seq num window
	uint32_t		*gss_clnt_seqbits;	// Bitmap to track seq numbers in use
	mach_port_t		gss_clnt_mport;		// Mach port for gssd upcall
	u_char			*gss_clnt_verf;		// RPC verifier from server
	char			*gss_clnt_svcname;	// Service name e.g. "nfs/big.apple.com"
	gssd_cred		gss_clnt_cred_handle;	// Opaque cred handle from gssd
	gssd_ctx		gss_clnt_context;	// Opaque context handle from gssd
	u_char			*gss_clnt_token;	// GSS token exchanged via gssd & server
	uint32_t		gss_clnt_tokenlen;	// Length of token
	gss_key_info		gss_clnt_kinfo;		// GSS key info
	uint32_t		gss_clnt_gssd_flags;	// Special flag bits to gssd
	uint32_t		gss_clnt_major;		// GSS major result from gssd or server
	uint32_t		gss_clnt_minor;		// GSS minor result from gssd or server
};

/*
 * gss_clnt_flags
 */
#define GSS_CTX_COMPLETE	0x00000001	// Context is complete
#define GSS_CTX_INVAL		0x00000002	// Context is invalid
#define GSS_NEEDSEQ		0x00000004	// Need a sequence number
#define GSS_NEEDCTX		0x00000008	// Need the context

/*
 * The server's RPCSEC_GSS context information
 */
struct nfs_gss_svc_ctx {
	lck_mtx_t		*gss_svc_mtx;
	LIST_ENTRY(nfs_gss_svc_ctx)	gss_svc_entries;
	uint32_t		gss_svc_handle;		// Identifies server context to client
	uint32_t		gss_svc_refcnt;		// Reference count
	uint32_t		gss_svc_proc;		// Current GSS proc from cred
	uid_t			gss_svc_uid;		// UID of this user
	gid_t			gss_svc_gids[NGROUPS];	// GIDs of this user
	uint32_t		gss_svc_ngroups;	// Count of gids
	uint64_t		gss_svc_incarnation;	// Delete ctx if we exceed this + ttl value
	uint32_t		gss_svc_seqmax;		// Current max GSS sequence number
	uint32_t		gss_svc_seqwin;		// GSS sequence number window
	uint32_t		*gss_svc_seqbits;	// Bitmap to track seq numbers
	gssd_cred		gss_svc_cred_handle;	// Opaque cred handle from gssd
	gssd_ctx			gss_svc_context;	// Opaque context handle from gssd
	u_char			*gss_svc_token;		// GSS token exchanged via gssd & client
	uint32_t		gss_svc_tokenlen;	// Length of token
	gss_key_info		gss_svc_kinfo;		// Session key info
	uint32_t		gss_svc_major;		// GSS major result from gssd
	uint32_t		gss_svc_minor;		// GSS minor result from gssd
};

#define SVC_CTX_HASHSZ	64
#define SVC_CTX_HASH(handle)	((handle) % SVC_CTX_HASHSZ)
LIST_HEAD(nfs_gss_svc_ctx_hashhead, nfs_gss_svc_ctx);

/*
 * Macros to manipulate bits in the sequence window
 */
#define win_getbit(bits, bit)      ((bits[(bit) / 32] &   (1 << (bit) % 32)) != 0)
#define win_setbit(bits, bit)   do { bits[(bit) / 32] |=  (1 << (bit) % 32); } while (0)
#define win_resetbit(bits, bit) do { bits[(bit) / 32] &= ~(1 << (bit) % 32); } while (0)

/*
 * Server context stale times
 */
#define GSS_CTX_PEND		5 		// seconds
#define GSS_CTX_EXPIRE		(8 * 3600)	// seconds
#define GSS_CTX_TTL_MIN		1		// seconds
#define GSS_TIMER_PERIOD	300		// seconds
#define MSECS_PER_SEC		1000

__BEGIN_DECLS

void	nfs_gss_init(void);
int	nfs_gss_clnt_cred_put(struct nfsreq *, struct nfsm_chain *, mbuf_t);
int	nfs_gss_clnt_verf_get(struct nfsreq *, struct nfsm_chain *,
		uint32_t, uint32_t, uint32_t *);
void	nfs_gss_clnt_rpcdone(struct nfsreq *);
int	nfs_gss_clnt_args_restore(struct nfsreq *);
int	nfs_gss_clnt_ctx_renew(struct nfsreq *);
void	nfs_gss_clnt_ctx_ref(struct nfsreq *, struct nfs_gss_clnt_ctx *);
void	nfs_gss_clnt_ctx_unref(struct nfsreq *);
void	nfs_gss_clnt_ctx_unmount(struct nfsmount *);
int	nfs_gss_svc_cred_get(struct nfsrv_descript *, struct nfsm_chain *);
int	nfs_gss_svc_verf_put(struct nfsrv_descript *, struct nfsm_chain *);
int	nfs_gss_svc_ctx_init(struct nfsrv_descript *, struct nfsrv_sock *, mbuf_t *);
int	nfs_gss_svc_prepare_reply(struct nfsrv_descript *, struct nfsm_chain *);
int	nfs_gss_svc_protect_reply(struct nfsrv_descript *, mbuf_t);
void	nfs_gss_svc_ctx_deref(struct nfs_gss_svc_ctx *);
void	nfs_gss_svc_cleanup(void);

__END_DECLS
#endif /* _NFS_NFS_GSS_H_ */
