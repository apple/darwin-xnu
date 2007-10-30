/*
 * Copyright (c) 2006-2007 Apple Inc. All rights reserved.
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

/*
 * miscellaneous support functions for NFSv4
 */
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/syscall.h>
#include <sys/ubc_internal.h>
#include <sys/fcntl.h>
#include <sys/quota.h>
#include <sys/uio_internal.h>
#include <sys/domain.h>
#include <libkern/OSAtomic.h>
#include <kern/thread_call.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#include <sys/time.h>
#include <kern/clock.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfs_lock.h>

#include <miscfs/specfs/specdev.h>

#include <netinet/in.h>
#include <net/kpi_interface.h>


/*
 * NFSv4 SETCLIENTID
 */
int
nfs4_setclientid(struct nfsmount *nmp)
{
	struct sockaddr *saddr;
	uint64_t verifier;
	char id[128];
	int idlen, len, error = 0, status, numops;
	u_int64_t xid;
	vfs_context_t ctx;
	thread_t thd;
	kauth_cred_t cred;
	struct nfsm_chain nmreq, nmrep;

	static uint8_t en0addr[6];
	static uint8_t en0addr_set = 0;

	lck_mtx_lock(nfs_request_mutex);
	if (!en0addr_set) {
		ifnet_t interface = NULL;
		error = ifnet_find_by_name("en0", &interface);
		if (!error)
			error = ifnet_lladdr_copy_bytes(interface, en0addr, sizeof(en0addr));
		if (error)
			printf("nfs4_setclientid: error getting en0 address, %d\n", error);
		if (!error)
			en0addr_set = 1;
		error = 0;
		if (interface)
			ifnet_release(interface);
	}
	lck_mtx_unlock(nfs_request_mutex);

	ctx = vfs_context_kernel(); /* XXX */
	thd = vfs_context_thread(ctx);
	cred = vfs_context_ucred(ctx);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	/* ID: en0_address + server_address */
	idlen = len = sizeof(en0addr);
	bcopy(en0addr, &id[0], len);
	saddr = mbuf_data(nmp->nm_nam);
	len = min(saddr->sa_len, sizeof(id)-idlen);
	bcopy(saddr, &id[idlen], len);
	idlen += len;

	// SETCLIENTID
	numops = 1;
	nfsm_chain_build_alloc_init(error, &nmreq, 14 * NFSX_UNSIGNED + idlen);
	nfsm_chain_add_compound_header(error, &nmreq, "setclientid", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SETCLIENTID);
	/* nfs_client_id4  client; */
	nfsm_chain_add_64(error, &nmreq, nmp->nm_mounttime);
	nfsm_chain_add_32(error, &nmreq, idlen);
	nfsm_chain_add_opaque(error, &nmreq, id, idlen);
	/* cb_client4      callback; */
	/* We don't provide callback info yet */
	nfsm_chain_add_32(error, &nmreq, 0); /* callback program */
	nfsm_chain_add_string(error, &nmreq, "", 0); /* callback r_netid */
	nfsm_chain_add_string(error, &nmreq, "", 0); /* callback r_addr */
	nfsm_chain_add_32(error, &nmreq, 0); /* callback_ident */
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND, thd, cred, R_SETUP, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SETCLIENTID);
	if (error == NFSERR_CLID_INUSE)
		printf("nfs4_setclientid: client ID in use?\n");
	nfsmout_if(error);
	nfsm_chain_get_64(error, &nmrep, nmp->nm_clientid);
	nfsm_chain_get_64(error, &nmrep, verifier);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	// SETCLIENTID_CONFIRM
	numops = 1;
	nfsm_chain_build_alloc_init(error, &nmreq, 13 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "setclientid_confirm", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SETCLIENTID_CONFIRM);
	nfsm_chain_add_64(error, &nmreq, nmp->nm_clientid);
	nfsm_chain_add_64(error, &nmreq, verifier);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND, thd, cred, R_SETUP, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SETCLIENTID_CONFIRM);
	if (error)
		printf("nfs4_setclientid: confirm error %d\n", error);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	if (error)
		printf("nfs4_setclientid failed, %d\n", error);
	return (error);
}

/*
 * periodic timer to renew lease state on server
 */
void
nfs4_renew_timer(void *param0, __unused void *param1)
{
	struct nfsmount *nmp = param0;
	int error = 0, status, numops, interval;
	u_int64_t xid;
	vfs_context_t ctx;
	struct nfsm_chain nmreq, nmrep;

	ctx = vfs_context_kernel(); /* XXX */

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// RENEW
	numops = 1;
	nfsm_chain_build_alloc_init(error, &nmreq, 8 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "renew", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_RENEW);
	nfsm_chain_add_64(error, &nmreq, nmp->nm_clientid);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(NULL, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RENEW);
nfsmout:
	if (error)
		printf("nfs4_renew_timer: error %d\n", error);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	interval = nmp->nm_fsattr.nfsa_lease / (error ? 4 : 2);
	if (interval < 1)
		interval = 1;
	nfs_interval_timer_start(nmp->nm_renew_timer, interval * 1000);
}

/*
 * Set a vnode attr's supported bits according to the given bitmap
 */
void
nfs_vattr_set_supported(uint32_t *bitmap, struct vnode_attr *vap)
{
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TYPE))
		VATTR_SET_SUPPORTED(vap, va_type);
	// if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_CHANGE))
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SIZE))
		VATTR_SET_SUPPORTED(vap, va_data_size);
	// if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_NAMED_ATTR))
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FSID))
		VATTR_SET_SUPPORTED(vap, va_fsid);
//	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_ACL))
//		VATTR_SET_SUPPORTED(vap, va_acl);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_ARCHIVE))
		VATTR_SET_SUPPORTED(vap, va_flags);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FILEID))
		VATTR_SET_SUPPORTED(vap, va_fileid);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_HIDDEN))
		VATTR_SET_SUPPORTED(vap, va_flags);
	// if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MIMETYPE))
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MODE))
		VATTR_SET_SUPPORTED(vap, va_mode);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_NUMLINKS))
		VATTR_SET_SUPPORTED(vap, va_nlink);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER))
		VATTR_SET_SUPPORTED(vap, va_uid);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER_GROUP))
		VATTR_SET_SUPPORTED(vap, va_gid);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_RAWDEV))
		VATTR_SET_SUPPORTED(vap, va_rdev);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SPACE_USED))
		VATTR_SET_SUPPORTED(vap, va_total_alloc);
	// if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SYSTEM))
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_ACCESS))
		VATTR_SET_SUPPORTED(vap, va_access_time);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_BACKUP))
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_CREATE))
		VATTR_SET_SUPPORTED(vap, va_create_time);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_METADATA))
		VATTR_SET_SUPPORTED(vap, va_change_time);
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_MODIFY))
		VATTR_SET_SUPPORTED(vap, va_modify_time);
}

/*
 * Parse the attributes that are in the mbuf list and store them in
 * the given structures.
 */
int
nfs4_parsefattr(
	struct nfsm_chain *nmc,
	struct nfs_fsattr *nfsap,
	struct nfs_vattr *nvap,
	fhandle_t *fhp,
	struct dqblk *dqbp)
{
	int error = 0, attrbytes;
	uint32_t val, val2, val3, i, j;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN], len;
	char *s;
	struct nfs_fsattr nfsa_dummy;
	struct nfs_vattr nva_dummy;
	struct dqblk dqb_dummy;

	/* if not interested in some values... throw 'em into a local dummy variable */
	if (!nfsap)
		nfsap = &nfsa_dummy;
	if (!nvap)
		nvap = &nva_dummy;
	if (!dqbp)
		dqbp = &dqb_dummy;

	attrbytes = val = val2 = val3 = 0;

	len = NFS_ATTR_BITMAP_LEN;
	nfsm_chain_get_bitmap(error, nmc, bitmap, len);
	/* add bits to object/fs attr bitmaps */
	for (i=0; i < NFS_ATTR_BITMAP_LEN; i++) {
		nvap->nva_bitmap[i] |= bitmap[i] & nfs_object_attr_bitmap[i];
		nfsap->nfsa_bitmap[i] |= bitmap[i] & nfs_fs_attr_bitmap[i];
	}

	nfsm_chain_get_32(error, nmc, attrbytes);
	nfsmout_if(error);

	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SUPPORTED_ATTRS)) {
		len = NFS_ATTR_BITMAP_LEN;
		nfsm_chain_get_bitmap(error, nmc, nfsap->nfsa_supp_attr, len);
		attrbytes -= (len + 1) * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TYPE)) {
		nfsm_chain_get_32(error, nmc, val);
		nvap->nva_type = nfstov_type(val, NFS_VER4);
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FH_EXPIRE_TYPE)) {
		nfsm_chain_get_32(error, nmc, val);
		nfsmout_if(error);
		if (val != NFS_FH_PERSISTENT)
			printf("nfs: warning: non-persistent file handles!\n");
		if (val & ~0xff)
			printf("nfs: warning unknown fh type: 0x%x\n", val);
		nfsap->nfsa_flags &= ~NFS_FSFLAG_FHTYPE_MASK;
		nfsap->nfsa_flags |= val << 24;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_CHANGE)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_change);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SIZE)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_size);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_LINK_SUPPORT)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_LINK;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_LINK;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SYMLINK_SUPPORT)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_SYMLINK;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_SYMLINK;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_NAMED_ATTR)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nvap->nva_flags |= NFS_FFLAG_NAMED_ATTR;
		else
			nvap->nva_flags &= ~NFS_FFLAG_NAMED_ATTR;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FSID)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_fsid.major);
		nfsm_chain_get_64(error, nmc, nvap->nva_fsid.minor);
		attrbytes -= 4 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_UNIQUE_HANDLES)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_UNIQUE_FH;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_UNIQUE_FH;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_LEASE_TIME)) {
		nfsm_chain_get_32(error, nmc, nfsap->nfsa_lease);
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_RDATTR_ERROR)) {
		nfsm_chain_get_32(error, nmc, error);
		attrbytes -= NFSX_UNSIGNED;
		nfsmout_if(error);
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_ACL)) { /* skip for now */
		nfsm_chain_get_32(error, nmc, val); /* ACE count */
		for (i=0; !error && (i < val); i++) {
			nfsm_chain_adv(error, nmc, 3 * NFSX_UNSIGNED);
			nfsm_chain_get_32(error, nmc, val2); /* string length */
			nfsm_chain_adv(error, nmc, nfsm_rndup(val2));
			attrbytes -= 4*NFSX_UNSIGNED + nfsm_rndup(val2);
			nfsm_assert(error, (attrbytes >= 0), EBADRPC);
		}
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_ACLSUPPORT)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_ACL;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_ACL;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_ARCHIVE)) { /* SF_ARCHIVED */
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nvap->nva_flags |= NFS_FFLAG_ARCHIVED;
		else
			nvap->nva_flags &= ~NFS_FFLAG_ARCHIVED;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_CANSETTIME)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_SET_TIME;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_SET_TIME;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_CASE_INSENSITIVE)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_CASE_INSENSITIVE;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_CASE_INSENSITIVE;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_CASE_PRESERVING)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_CASE_PRESERVING;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_CASE_PRESERVING;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_CHOWN_RESTRICTED)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_CHOWN_RESTRICTED;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_CHOWN_RESTRICTED;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FILEHANDLE)) {
		nfsm_chain_get_32(error, nmc, val);
		if (fhp) {
			fhp->fh_len = val;
			nfsm_chain_get_opaque(error, nmc, nfsm_rndup(val), fhp->fh_data);
		} else {
			nfsm_chain_adv(error, nmc, nfsm_rndup(val));
		}
		attrbytes -= NFSX_UNSIGNED + nfsm_rndup(val);
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FILEID)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_fileid);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FILES_AVAIL)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_files_avail);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FILES_FREE)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_files_free);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FILES_TOTAL)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_files_total);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_FS_LOCATIONS)) { /* skip for now */
		nfsm_chain_get_32(error, nmc, val); /* root path length */
		nfsm_chain_adv(error, nmc, nfsm_rndup(val)); /* root path */
		attrbytes -= (2 * NFSX_UNSIGNED) + nfsm_rndup(val);
		nfsm_chain_get_32(error, nmc, val); /* location count */
		for (i=0; !error && (i < val); i++) {
			nfsm_chain_get_32(error, nmc, val2); /* server string length */
			nfsm_chain_adv(error, nmc, nfsm_rndup(val2)); /* server string */
			attrbytes -= (2 * NFSX_UNSIGNED) + nfsm_rndup(val2);
			nfsm_chain_get_32(error, nmc, val2); /* pathname component count */
			for (j=0; !error && (j < val2); j++) {
				nfsm_chain_get_32(error, nmc, val3); /* component length */
				nfsm_chain_adv(error, nmc, nfsm_rndup(val3)); /* component */
				attrbytes -= NFSX_UNSIGNED + nfsm_rndup(val3);
				nfsm_assert(error, (attrbytes >= 0), EBADRPC);
			}
			nfsm_assert(error, (attrbytes >= 0), EBADRPC);
		}
		nfsm_assert(error, (attrbytes >= 0), EBADRPC);
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_HIDDEN)) { /* UF_HIDDEN */
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nvap->nva_flags |= NFS_FFLAG_HIDDEN;
		else
			nvap->nva_flags &= ~NFS_FFLAG_HIDDEN;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_HOMOGENEOUS)) {
		/* XXX If NOT homogeneous, we may need to clear flags on the mount */
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_HOMOGENEOUS;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_HOMOGENEOUS;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MAXFILESIZE)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_maxfilesize);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MAXLINK)) {
		nfsm_chain_get_32(error, nmc, nvap->nva_maxlink);
		if (!error && (nfsap->nfsa_maxlink > INT32_MAX))
			nfsap->nfsa_maxlink = INT32_MAX;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MAXNAME)) {
		nfsm_chain_get_32(error, nmc, nfsap->nfsa_maxname);
		if (!error && (nfsap->nfsa_maxname > INT32_MAX))
			nfsap->nfsa_maxname = INT32_MAX;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MAXREAD)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_maxread);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MAXWRITE)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_maxwrite);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MIMETYPE)) {
		nfsm_chain_get_32(error, nmc, val);
		nfsm_chain_adv(error, nmc, nfsm_rndup(val));
		attrbytes -= NFSX_UNSIGNED + nfsm_rndup(val);
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MODE)) {
		nfsm_chain_get_32(error, nmc, nvap->nva_mode);
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_NO_TRUNC)) {
		nfsm_chain_get_32(error, nmc, val);
		if (val)
			nfsap->nfsa_flags |= NFS_FSFLAG_NO_TRUNC;
		else
			nfsap->nfsa_flags &= ~NFS_FSFLAG_NO_TRUNC;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_NUMLINKS)) {
		nfsm_chain_get_32(error, nmc, val);
		nvap->nva_nlink = val;
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER)) { /* XXX ugly hack for now */
		nfsm_chain_get_32(error, nmc, len);
		nfsm_chain_get_opaque_pointer(error, nmc, len, s);
		attrbytes -= NFSX_UNSIGNED + nfsm_rndup(len);
		nfsmout_if(error);
		if ((*s >= '0') && (*s <= '9'))
			nvap->nva_uid = strtol(s, NULL, 10);
		else if (!strncmp(s, "nobody@", 7))
			nvap->nva_uid = -2;
		else if (!strncmp(s, "root@", 5))
			nvap->nva_uid = 0;
		else
			nvap->nva_uid = 99; /* unknown */
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER_GROUP)) { /* XXX ugly hack for now */
		nfsm_chain_get_32(error, nmc, len);
		nfsm_chain_get_opaque_pointer(error, nmc, len, s);
		attrbytes -= NFSX_UNSIGNED + nfsm_rndup(len);
		nfsmout_if(error);
		if ((*s >= '0') && (*s <= '9'))
			nvap->nva_gid = strtol(s, NULL, 10);
		else if (!strncmp(s, "nobody@", 7))
			nvap->nva_gid = -2;
		else if (!strncmp(s, "root@", 5))
			nvap->nva_uid = 0;
		else
			nvap->nva_gid = 99; /* unknown */
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_QUOTA_AVAIL_HARD)) {
		nfsm_chain_get_64(error, nmc, dqbp->dqb_bhardlimit);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_QUOTA_AVAIL_SOFT)) {
		nfsm_chain_get_64(error, nmc, dqbp->dqb_bsoftlimit);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_QUOTA_USED)) {
		nfsm_chain_get_64(error, nmc, dqbp->dqb_curbytes);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_RAWDEV)) {
		nfsm_chain_get_32(error, nmc, nvap->nva_rawdev.specdata1);
		nfsm_chain_get_32(error, nmc, nvap->nva_rawdev.specdata2);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SPACE_AVAIL)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_space_avail);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SPACE_FREE)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_space_free);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SPACE_TOTAL)) {
		nfsm_chain_get_64(error, nmc, nfsap->nfsa_space_total);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SPACE_USED)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_bytes);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SYSTEM)) {
		/* we'd support this if we had a flag to map it to... */
		nfsm_chain_adv(error, nmc, NFSX_UNSIGNED);
		attrbytes -= NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_ACCESS)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_timesec[NFSTIME_ACCESS]);
		nfsm_chain_get_32(error, nmc, nvap->nva_timensec[NFSTIME_ACCESS]);
		attrbytes -= 3 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_ACCESS_SET)) {
		nfsm_chain_adv(error, nmc, 4*NFSX_UNSIGNED); /* just skip it */
		attrbytes -= 4 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_BACKUP)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_timesec[NFSTIME_BACKUP]);
		nfsm_chain_get_32(error, nmc, nvap->nva_timensec[NFSTIME_BACKUP]);
		attrbytes -= 3 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_CREATE)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_timesec[NFSTIME_CREATE]);
		nfsm_chain_get_32(error, nmc, nvap->nva_timensec[NFSTIME_CREATE]);
		attrbytes -= 3 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_DELTA)) { /* skip for now */
		nfsm_chain_adv(error, nmc, 3*NFSX_UNSIGNED);
		attrbytes -= 3 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_METADATA)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_timesec[NFSTIME_CHANGE]);
		nfsm_chain_get_32(error, nmc, nvap->nva_timensec[NFSTIME_CHANGE]);
		attrbytes -= 3 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_MODIFY)) {
		nfsm_chain_get_64(error, nmc, nvap->nva_timesec[NFSTIME_MODIFY]);
		nfsm_chain_get_32(error, nmc, nvap->nva_timensec[NFSTIME_MODIFY]);
		attrbytes -= 3 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_MODIFY_SET)) {
		nfsm_chain_adv(error, nmc, 4*NFSX_UNSIGNED); /* just skip it */
		attrbytes -= 4 * NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MOUNTED_ON_FILEID)) { /* skip for now */
		nfsm_chain_adv(error, nmc, 2*NFSX_UNSIGNED);
		attrbytes -= 2 * NFSX_UNSIGNED;
	}
	/* advance over any leftover attrbytes */
	nfsm_assert(error, (attrbytes >= 0), EBADRPC);
	nfsm_chain_adv(error, nmc, nfsm_rndup(attrbytes));
nfsmout:
	return (error);
}

/*
 * Add an NFSv4 "sattr" structure to an mbuf chain
 */
int
nfsm_chain_add_fattr4_f(struct nfsm_chain *nmc, struct vnode_attr *vap, struct nfsmount *nmp)
{
	int error = 0, attrbytes, slen, i;
	uint32_t *pattrbytes;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN];
	char s[32];

	/*
	 * Do this in two passes.
	 * First calculate the bitmap, then pack
	 * everything together and set the size.
	 */

	NFS_CLEAR_ATTRIBUTES(bitmap);
	if (VATTR_IS_ACTIVE(vap, va_data_size))
		NFS_BITMAP_SET(bitmap, NFS_FATTR_SIZE);
	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		// NFS_BITMAP_SET(bitmap, NFS_FATTR_ACL)
	}
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		NFS_BITMAP_SET(bitmap, NFS_FATTR_ARCHIVE);
		NFS_BITMAP_SET(bitmap, NFS_FATTR_HIDDEN);
	}
	// NFS_BITMAP_SET(bitmap, NFS_FATTR_MIMETYPE)
	if (VATTR_IS_ACTIVE(vap, va_mode))
		NFS_BITMAP_SET(bitmap, NFS_FATTR_MODE);
	if (VATTR_IS_ACTIVE(vap, va_uid))
		NFS_BITMAP_SET(bitmap, NFS_FATTR_OWNER);
	if (VATTR_IS_ACTIVE(vap, va_gid))
		NFS_BITMAP_SET(bitmap, NFS_FATTR_OWNER_GROUP);
	// NFS_BITMAP_SET(bitmap, NFS_FATTR_SYSTEM)
	if (vap->va_vaflags & VA_UTIMES_NULL) {
		NFS_BITMAP_SET(bitmap, NFS_FATTR_TIME_ACCESS_SET);
		NFS_BITMAP_SET(bitmap, NFS_FATTR_TIME_MODIFY_SET);
	} else {
		if (VATTR_IS_ACTIVE(vap, va_access_time))
			NFS_BITMAP_SET(bitmap, NFS_FATTR_TIME_ACCESS_SET);
		if (VATTR_IS_ACTIVE(vap, va_modify_time))
			NFS_BITMAP_SET(bitmap, NFS_FATTR_TIME_MODIFY_SET);
	}
	if (VATTR_IS_ACTIVE(vap, va_backup_time))
		NFS_BITMAP_SET(bitmap, NFS_FATTR_TIME_BACKUP);
	if (VATTR_IS_ACTIVE(vap, va_create_time))
		NFS_BITMAP_SET(bitmap, NFS_FATTR_TIME_CREATE);
	/* and limit to what is supported by server */
	for (i=0; i < NFS_ATTR_BITMAP_LEN; i++)
		bitmap[i] &= nmp->nm_fsattr.nfsa_supp_attr[i];

	/*
	 * Now pack it all together:
	 *     BITMAP, #BYTES, ATTRS
	 * Keep a pointer to the length so we can set it later.
	 */
	nfsm_chain_add_bitmap(error, nmc, bitmap, NFS_ATTR_BITMAP_LEN);
	attrbytes = 0;
	nfsm_chain_add_32(error, nmc, attrbytes);
	pattrbytes = (uint32_t*)(nmc->nmc_ptr - NFSX_UNSIGNED);

	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_SIZE)) {
		nfsm_chain_add_64(error, nmc, vap->va_data_size);
		attrbytes += 2*NFSX_UNSIGNED;
	}
	// NFS_BITMAP_ISSET(bitmap, NFS_FATTR_ACL)
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_ARCHIVE)) {
		nfsm_chain_add_32(error, nmc, (vap->va_flags & SF_ARCHIVED) ? 1 : 0);
		attrbytes += NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_HIDDEN)) {
		nfsm_chain_add_32(error, nmc, (vap->va_flags & UF_HIDDEN) ? 1 : 0);
		attrbytes += NFSX_UNSIGNED;
	}
	// NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MIMETYPE)
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_MODE)) {
		nfsm_chain_add_32(error, nmc, vap->va_mode);
		attrbytes += NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER)) {
		slen = snprintf(s, sizeof(s), "%d", vap->va_uid);
		nfsm_chain_add_string(error, nmc, s, slen);
		attrbytes += NFSX_UNSIGNED + nfsm_rndup(slen);
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER_GROUP)) {
		slen = snprintf(s, sizeof(s), "%d", vap->va_gid);
		nfsm_chain_add_string(error, nmc, s, slen);
		attrbytes += NFSX_UNSIGNED + nfsm_rndup(slen);
	}
	// NFS_BITMAP_SET(bitmap, NFS_FATTR_SYSTEM)
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_ACCESS_SET)) {
		if (vap->va_vaflags & VA_UTIMES_NULL) {
			nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_SERVER);
			attrbytes += NFSX_UNSIGNED;
		} else {
			nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_CLIENT);
			nfsm_chain_add_64(error, nmc, vap->va_access_time.tv_sec);
			nfsm_chain_add_32(error, nmc, vap->va_access_time.tv_nsec);
			attrbytes += 4*NFSX_UNSIGNED;
		}
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_BACKUP)) {
		nfsm_chain_add_64(error, nmc, vap->va_backup_time.tv_sec);
		nfsm_chain_add_32(error, nmc, vap->va_backup_time.tv_nsec);
		attrbytes += 3*NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_CREATE)) {
		nfsm_chain_add_64(error, nmc, vap->va_create_time.tv_sec);
		nfsm_chain_add_32(error, nmc, vap->va_create_time.tv_nsec);
		attrbytes += 3*NFSX_UNSIGNED;
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_MODIFY_SET)) {
		if (vap->va_vaflags & VA_UTIMES_NULL) {
			nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_SERVER);
			attrbytes += NFSX_UNSIGNED;
		} else {
			nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_CLIENT);
			nfsm_chain_add_64(error, nmc, vap->va_modify_time.tv_sec);
			nfsm_chain_add_32(error, nmc, vap->va_modify_time.tv_nsec);
			attrbytes += 4*NFSX_UNSIGNED;
		}
	}
	nfsmout_if(error);
	/* Now, set the attribute data length */
	*pattrbytes = txdr_unsigned(attrbytes);
nfsmout:
	return (error);
}

