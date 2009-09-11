/*
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
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
 * Create the unique client ID to use for this mount.
 *
 * Format: unique ID + en0_address + server_address + mntfromname + mntonname
 *
 * We could possibly use one client ID for all mounts of the same server;
 * however, that would complicate some aspects of state management.
 *
 * Each mount socket connection sends a SETCLIENTID.  If the ID is the same but
 * the verifier (mounttime) changes, then all previous (mounts') state gets dropped.
 *
 * State is typically managed per-mount and in order to keep it that way
 * each mount needs to use a separate client ID.  However, we also need to
 * make sure that each mount uses the same client ID each time.
 *
 * In an attempt to differentiate mounts we include the mntfromname and mntonname
 * strings to the client ID (as long as they fit).  We also make sure that the
 * value does not conflict with any existing values in use.
 */
int
nfs4_init_clientid(struct nfsmount *nmp)
{
	struct nfs_client_id *ncip, *ncip2;
	struct sockaddr *saddr;
	int error, len, len2, cmp;
	struct vfsstatfs *vsfs;

	static uint8_t en0addr[6];
	static uint8_t en0addr_set = 0;

	lck_mtx_lock(nfs_global_mutex);
	if (!en0addr_set) {
		ifnet_t interface = NULL;
		error = ifnet_find_by_name("en0", &interface);
		if (!error)
			error = ifnet_lladdr_copy_bytes(interface, en0addr, sizeof(en0addr));
		if (error)
			printf("nfs4_init_clientid: error getting en0 address, %d\n", error);
		if (!error)
			en0addr_set = 1;
		if (interface)
			ifnet_release(interface);
	}
	lck_mtx_unlock(nfs_global_mutex);

	MALLOC(ncip, struct nfs_client_id *, sizeof(struct nfs_client_id), M_TEMP, M_WAITOK);
	if (!ncip)
		return (ENOMEM);

	vsfs = vfs_statfs(nmp->nm_mountp);
	saddr = mbuf_data(nmp->nm_nam);
	ncip->nci_idlen = sizeof(uint32_t) + sizeof(en0addr) + saddr->sa_len +
		strlen(vsfs->f_mntfromname) + 1 + strlen(vsfs->f_mntonname) + 1;
	if (ncip->nci_idlen > NFS4_OPAQUE_LIMIT)
		ncip->nci_idlen = NFS4_OPAQUE_LIMIT;
	MALLOC(ncip->nci_id, char *, ncip->nci_idlen, M_TEMP, M_WAITOK);
	if (!ncip->nci_id) {
		FREE(ncip, M_TEMP);
		return (ENOMEM);
	}

	*(uint32_t*)ncip->nci_id = 0;
	len = sizeof(uint32_t);
	len2 = min(sizeof(en0addr), ncip->nci_idlen-len);
	bcopy(en0addr, &ncip->nci_id[len], len2);
	len += sizeof(en0addr);
	len2 = min(saddr->sa_len, ncip->nci_idlen-len);
	bcopy(saddr, &ncip->nci_id[len], len2);
	len += len2;
	if (len < ncip->nci_idlen) {
		len2 = strlcpy(&ncip->nci_id[len], vsfs->f_mntfromname, ncip->nci_idlen-len);
		if (len2 < (ncip->nci_idlen - len))
			len += len2 + 1;
		else
			len = ncip->nci_idlen;
	}
	if (len < ncip->nci_idlen) {
		len2 = strlcpy(&ncip->nci_id[len], vsfs->f_mntonname, ncip->nci_idlen-len);
		if (len2 < (ncip->nci_idlen - len))
			len += len2 + 1;
		else
			len = ncip->nci_idlen;
	}

	/* make sure the ID is unique, and add it to the sorted list */
	lck_mtx_lock(nfs_global_mutex);
	TAILQ_FOREACH(ncip2, &nfsclientids, nci_link) {
		if (ncip->nci_idlen > ncip2->nci_idlen)
			continue;
		if (ncip->nci_idlen < ncip2->nci_idlen)
			break;
		cmp = bcmp(ncip->nci_id + sizeof(uint32_t),
			ncip2->nci_id + sizeof(uint32_t),
			ncip->nci_idlen - sizeof(uint32_t));
		if (cmp > 0)
			continue;
		if (cmp < 0)
			break;
		if (*(uint32_t*)ncip->nci_id > *(uint32_t*)ncip2->nci_id)
			continue;
		if (*(uint32_t*)ncip->nci_id < *(uint32_t*)ncip2->nci_id)
			break;
		*(uint32_t*)ncip->nci_id += 1;
	}
	if (*(uint32_t*)ncip->nci_id)
		printf("nfs client ID collision (%d) for %s on %s\n", *(uint32_t*)ncip->nci_id,
			vsfs->f_mntfromname, vsfs->f_mntonname);
	if (ncip2)
		TAILQ_INSERT_BEFORE(ncip2, ncip, nci_link);
	else
		TAILQ_INSERT_TAIL(&nfsclientids, ncip, nci_link);
	nmp->nm_longid = ncip;
	lck_mtx_unlock(nfs_global_mutex);

	return (0);
}

/*
 * NFSv4 SETCLIENTID
 */
int
nfs4_setclientid(struct nfsmount *nmp)
{
	uint64_t verifier, xid;
	int error = 0, status, numops;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN];
	thread_t thd;
	kauth_cred_t cred;
	struct nfsm_chain nmreq, nmrep;
	struct sockaddr_in sin;
	uint8_t *addr;
	char raddr[32];
	int ralen = 0;

	thd = current_thread();
	cred = IS_VALID_CRED(nmp->nm_mcred) ? nmp->nm_mcred : vfs_context_ucred(vfs_context_kernel());
	kauth_cred_ref(cred);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	if (!nmp->nm_longid)
		error = nfs4_init_clientid(nmp);

	// SETCLIENTID
	numops = 1;
	nfsm_chain_build_alloc_init(error, &nmreq, 14 * NFSX_UNSIGNED + nmp->nm_longid->nci_idlen);
	nfsm_chain_add_compound_header(error, &nmreq, "setclid", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SETCLIENTID);
	/* nfs_client_id4  client; */
	nfsm_chain_add_64(error, &nmreq, nmp->nm_mounttime);
	nfsm_chain_add_32(error, &nmreq, nmp->nm_longid->nci_idlen);
	nfsm_chain_add_opaque(error, &nmreq, nmp->nm_longid->nci_id, nmp->nm_longid->nci_idlen);
	/* cb_client4      callback; */
	if (nmp->nm_cbid && nfs4_cb_port &&
	    !(error = sock_getsockname(nmp->nm_so, (struct sockaddr*)&sin, sizeof(sin)))) {
		/* assemble r_addr = h1.h2.h3.h4.p1.p2 */
		/* h = source address of nmp->nm_so */
		/* p = nfs4_cb_port */
		addr = (uint8_t*)&sin.sin_addr.s_addr;
		ralen = snprintf(raddr, sizeof(raddr), "%d.%d.%d.%d.%d.%d", 
				addr[0], addr[1], addr[2], addr[3],
				((nfs4_cb_port >> 8) & 0xff),
				(nfs4_cb_port & 0xff));
		/* make sure it fit, give up if it didn't */
		if (ralen >= (int)sizeof(raddr))
			ralen = 0;
	}
	if (ralen > 0) {
		/* add callback info */
		nfsm_chain_add_32(error, &nmreq, NFS4_CALLBACK_PROG); /* callback program */
		nfsm_chain_add_string(error, &nmreq, "tcp", 3); /* callback r_netid */
		nfsm_chain_add_string(error, &nmreq, raddr, ralen); /* callback r_addr */
		nfsm_chain_add_32(error, &nmreq, nmp->nm_cbid); /* callback_ident */
	} else {
		/* don't provide valid callback info */
		nfsm_chain_add_32(error, &nmreq, 0); /* callback program */
		nfsm_chain_add_string(error, &nmreq, "", 0); /* callback r_netid */
		nfsm_chain_add_string(error, &nmreq, "", 0); /* callback r_addr */
		nfsm_chain_add_32(error, &nmreq, 0); /* callback_ident */
	}
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

	// SETCLIENTID_CONFIRM, PUTFH, GETATTR(FS)
	numops = nmp->nm_dnp ? 3 : 1;
	nfsm_chain_build_alloc_init(error, &nmreq, 28 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "setclid_conf", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SETCLIENTID_CONFIRM);
	nfsm_chain_add_64(error, &nmreq, nmp->nm_clientid);
	nfsm_chain_add_64(error, &nmreq, verifier);
	if (nmp->nm_dnp) {
		/* refresh fs attributes too */
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
		nfsm_chain_add_fh(error, &nmreq, nmp->nm_vers, nmp->nm_dnp->n_fhp, nmp->nm_dnp->n_fhsize);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
		NFS_CLEAR_ATTRIBUTES(bitmap);
		NFS4_PER_FS_ATTRIBUTES(bitmap);
		nfsm_chain_add_bitmap(error, &nmreq, bitmap, NFS_ATTR_BITMAP_LEN);
	}
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND, thd, cred, R_SETUP, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SETCLIENTID_CONFIRM);
	if (error)
		printf("nfs4_setclientid: confirm error %d\n", error);
	if (nmp->nm_dnp) {
		nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
		nfsmout_if(error);
		lck_mtx_lock(&nmp->nm_lock);
		error = nfs4_parsefattr(&nmrep, &nmp->nm_fsattr, NULL, NULL, NULL);
		lck_mtx_unlock(&nmp->nm_lock);
	}

nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	kauth_cred_unref(&cred);
	if (error)
		printf("nfs4_setclientid failed, %d\n", error);
	return (error);
}

/*
 * renew/check lease state on server
 */
int
nfs4_renew(struct nfsmount *nmp, int rpcflag)
{
	int error = 0, status, numops;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	kauth_cred_t cred;

	cred = IS_VALID_CRED(nmp->nm_mcred) ? nmp->nm_mcred : vfs_context_ucred(vfs_context_kernel());
	kauth_cred_ref(cred);

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
	error = nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND,
			current_thread(), cred, rpcflag, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RENEW);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	kauth_cred_unref(&cred);
	return (error);
}


/*
 * periodic timer to renew lease state on server
 */
void
nfs4_renew_timer(void *param0, __unused void *param1)
{
	struct nfsmount *nmp = param0;
	u_int64_t clientid;
	int error = 0, interval;

	lck_mtx_lock(&nmp->nm_lock);
	clientid = nmp->nm_clientid;
	if ((nmp->nm_state & NFSSTA_RECOVER) || !(nmp->nm_sockflags & NMSOCK_READY)) {
		lck_mtx_unlock(&nmp->nm_lock);
		goto out;
	}
	lck_mtx_unlock(&nmp->nm_lock);

	error = nfs4_renew(nmp, R_RECOVER);
out:
	if (error == ETIMEDOUT)
		nfs_need_reconnect(nmp);
	else if (error)
		printf("nfs4_renew_timer: error %d\n", error);
	lck_mtx_lock(&nmp->nm_lock);
	if (error && (error != ETIMEDOUT) &&
	    (nmp->nm_clientid == clientid) && !(nmp->nm_state & NFSSTA_RECOVER)) {
		printf("nfs4_renew_timer: error %d, initiating recovery\n", error);
		nmp->nm_state |= NFSSTA_RECOVER;
		nfs_mount_sock_thread_wake(nmp);
	}

	interval = nmp->nm_fsattr.nfsa_lease / (error ? 4 : 2);
	if ((interval < 1) || (nmp->nm_state & NFSSTA_RECOVER))
		interval = 1;
	lck_mtx_unlock(&nmp->nm_lock);
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
		nfsap->nfsa_flags |= val << NFS_FSFLAG_FHTYPE_SHIFT;
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
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER)) {
		/* XXX Need ID mapping infrastructure - use ugly hack for now */
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
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER_GROUP)) {
		/* XXX Need ID mapping infrastructure - use ugly hack for now */
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
		/* XXX Need ID mapping infrastructure - use ugly hack for now */
		if (vap->va_uid == 0)
			slen = snprintf(s, sizeof(s), "root@localdomain");
		else if (vap->va_uid == (uid_t)-2)
			slen = snprintf(s, sizeof(s), "nobody@localdomain");
		else
			slen = snprintf(s, sizeof(s), "%d", vap->va_uid);
		nfsm_chain_add_string(error, nmc, s, slen);
		attrbytes += NFSX_UNSIGNED + nfsm_rndup(slen);
	}
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_OWNER_GROUP)) {
		/* XXX Need ID mapping infrastructure - use ugly hack for now */
		if (vap->va_gid == 0)
			slen = snprintf(s, sizeof(s), "root@localdomain");
		else if (vap->va_gid == (gid_t)-2)
			slen = snprintf(s, sizeof(s), "nobody@localdomain");
		else
			slen = snprintf(s, sizeof(s), "%d", vap->va_gid);
		nfsm_chain_add_string(error, nmc, s, slen);
		attrbytes += NFSX_UNSIGNED + nfsm_rndup(slen);
	}
	// NFS_BITMAP_SET(bitmap, NFS_FATTR_SYSTEM)
	if (NFS_BITMAP_ISSET(bitmap, NFS_FATTR_TIME_ACCESS_SET)) {
		if (vap->va_vaflags & VA_UTIMES_NULL) {
			nfsm_chain_add_32(error, nmc, NFS4_TIME_SET_TO_SERVER);
			attrbytes += NFSX_UNSIGNED;
		} else {
			nfsm_chain_add_32(error, nmc, NFS4_TIME_SET_TO_CLIENT);
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
			nfsm_chain_add_32(error, nmc, NFS4_TIME_SET_TO_SERVER);
			attrbytes += NFSX_UNSIGNED;
		} else {
			nfsm_chain_add_32(error, nmc, NFS4_TIME_SET_TO_CLIENT);
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

/*
 * Recover state for an NFS mount.
 *
 * Iterates over all open files, reclaiming opens and lock state.
 */
void
nfs4_recover(struct nfsmount *nmp)
{
	struct timespec ts = { 1, 0 };
	int error, lost, reopen;
	struct nfs_open_owner *noop;
	struct nfs_open_file *nofp;
	struct nfs_file_lock *nflp, *nextnflp;
	struct nfs_lock_owner *nlop;
	thread_t thd = current_thread();

restart:
	error = 0;
	lck_mtx_lock(&nmp->nm_lock);
	/*
	 * First, wait for the state inuse count to go to zero so
	 * we know there are no state operations in progress.
	 */
	do {
		if ((error = nfs_sigintr(nmp, NULL, NULL, 1)))
			break;
		if (!(nmp->nm_sockflags & NMSOCK_READY))
			error = EPIPE;
		if (nmp->nm_state & NFSSTA_FORCE)
			error = ENXIO;
		if (nmp->nm_sockflags & NMSOCK_UNMOUNT)
			error = ENXIO;
		if (error)
			break;
		if (nmp->nm_stateinuse)
			msleep(&nmp->nm_stateinuse, &nmp->nm_lock, (PZERO-1), "nfsrecoverstartwait", &ts);
	} while (nmp->nm_stateinuse);
	if (error) {
		if (error == EPIPE)
			printf("nfs recovery reconnecting\n");
		else
			printf("nfs recovery aborted\n");
		lck_mtx_unlock(&nmp->nm_lock);
		return;
	}

	printf("nfs recovery started\n");
	if (++nmp->nm_stategenid == 0)
		++nmp->nm_stategenid;
	lck_mtx_unlock(&nmp->nm_lock);

	/* for each open owner... */
	TAILQ_FOREACH(noop, &nmp->nm_open_owners, noo_link) {
		/* for each of its opens... */
		TAILQ_FOREACH(nofp, &noop->noo_opens, nof_oolink) {
			if (!nofp->nof_access || (nofp->nof_flags & NFS_OPEN_FILE_LOST))
				continue;
			lost = reopen = 0;
			if (nofp->nof_rw_drw)
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_BOTH, NFS_OPEN_SHARE_DENY_BOTH);
			if (!error && nofp->nof_w_drw)
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_WRITE, NFS_OPEN_SHARE_DENY_BOTH);
			if (!error && nofp->nof_r_drw)
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_READ, NFS_OPEN_SHARE_DENY_BOTH);
			if (!error && nofp->nof_rw_dw)
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_BOTH, NFS_OPEN_SHARE_DENY_WRITE);
			if (!error && nofp->nof_w_dw)
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_WRITE, NFS_OPEN_SHARE_DENY_WRITE);
			if (!error && nofp->nof_r_dw)
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_READ, NFS_OPEN_SHARE_DENY_WRITE);
			/*
			 * deny-none opens with no locks can just be reopened (later) if reclaim fails.
			 */
			if (!error && nofp->nof_rw) {
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_BOTH, NFS_OPEN_SHARE_DENY_NONE);
				if ((error == NFSERR_ADMIN_REVOKED) || (error == NFSERR_EXPIRED) || (error == NFSERR_NO_GRACE))
					reopen = 1;
			}
			if (!error && nofp->nof_w) {
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_WRITE, NFS_OPEN_SHARE_DENY_NONE);
				if ((error == NFSERR_ADMIN_REVOKED) || (error == NFSERR_EXPIRED) || (error == NFSERR_NO_GRACE))
					reopen = 1;
			}
			if (!error && nofp->nof_r) {
				error = nfs4_open_reclaim_rpc(nofp, NFS_OPEN_SHARE_ACCESS_READ, NFS_OPEN_SHARE_DENY_NONE);
				if ((error == NFSERR_ADMIN_REVOKED) || (error == NFSERR_EXPIRED) || (error == NFSERR_NO_GRACE))
					reopen = 1;
			}

			if (error) {
				/* restart recovery? */
				if ((error == ETIMEDOUT) || nfs_mount_state_error_should_restart(error)) {
					if (error == ETIMEDOUT)
						nfs_need_reconnect(nmp);
					tsleep(&lbolt, (PZERO-1), "nfsrecoverrestart", 0);
					printf("nfs recovery restarting %d\n", error);
					goto restart;
				}
				if (reopen && (nfs4_check_for_locks(noop, nofp) == 0)) {
					/* just reopen the file on next access */
					const char *vname = vnode_getname(NFSTOV(nofp->nof_np));
					printf("nfs4_recover: %d, need reopen for %s\n", error, vname ? vname : "???");
					vnode_putname(vname);
					lck_mtx_lock(&nofp->nof_lock);
					nofp->nof_flags |= NFS_OPEN_FILE_REOPEN;
					lck_mtx_unlock(&nofp->nof_lock);
					error = 0;
				} else {
					/* open file state lost */
					lost = 1;
					error = 0;
					lck_mtx_lock(&nofp->nof_lock);
					nofp->nof_flags &= ~NFS_OPEN_FILE_REOPEN;
					lck_mtx_unlock(&nofp->nof_lock);
				}
			} else {
				/* no error, so make sure the reopen flag isn't set */
				lck_mtx_lock(&nofp->nof_lock);
				nofp->nof_flags &= ~NFS_OPEN_FILE_REOPEN;
				lck_mtx_unlock(&nofp->nof_lock);
			}
			/*
			 * Scan this node's lock owner list for entries with this open owner,
			 * then walk the lock owner's held lock list recovering each lock.
			 */
rescanlocks:
			TAILQ_FOREACH(nlop, &nofp->nof_np->n_lock_owners, nlo_link) {
				if (nlop->nlo_open_owner != noop)
					continue;
				TAILQ_FOREACH_SAFE(nflp, &nlop->nlo_locks, nfl_lolink, nextnflp) {
					if (nflp->nfl_flags & (NFS_FILE_LOCK_DEAD|NFS_FILE_LOCK_BLOCKED))
						continue;
					if (!lost) {
						error = nfs4_lock_rpc(nofp->nof_np, nofp, nflp, 1, thd, noop->noo_cred);
						if (!error)
							continue;
						/* restart recovery? */
						if ((error == ETIMEDOUT) || nfs_mount_state_error_should_restart(error)) {
							if (error == ETIMEDOUT)
								nfs_need_reconnect(nmp);
							tsleep(&lbolt, (PZERO-1), "nfsrecoverrestart", 0);
							printf("nfs recovery restarting %d\n", error);
							goto restart;
						}
						/* lock state lost - attempt to close file */ 
						lost = 1;
						error = nfs4_close_rpc(nofp->nof_np, nofp, NULL, noop->noo_cred, R_RECOVER);
						if ((error == ETIMEDOUT) || nfs_mount_state_error_should_restart(error)) {
							if (error == ETIMEDOUT)
								nfs_need_reconnect(nmp);
							tsleep(&lbolt, (PZERO-1), "nfsrecoverrestart", 0);
							printf("nfs recovery restarting %d\n", error);
							goto restart;
						}
						error = 0;
						/* rescan locks so we can drop them all */
						goto rescanlocks;
					}
					if (lost) {
						/* kill/remove the lock */
						lck_mtx_lock(&nofp->nof_np->n_openlock);
						nflp->nfl_flags |= NFS_FILE_LOCK_DEAD;
						lck_mtx_lock(&nlop->nlo_lock);
						nextnflp = TAILQ_NEXT(nflp, nfl_lolink);
						TAILQ_REMOVE(&nlop->nlo_locks, nflp, nfl_lolink);
						lck_mtx_unlock(&nlop->nlo_lock);
						if (nflp->nfl_blockcnt) {
							/* wake up anyone blocked on this lock */
							wakeup(nflp);
						} else {
							/* remove nflp from lock list and destroy */
							TAILQ_REMOVE(&nofp->nof_np->n_locks, nflp, nfl_link);
							nfs_file_lock_destroy(nflp);
						}
						lck_mtx_unlock(&nofp->nof_np->n_openlock);
					}
				}
			}
			if (lost) {
				/* revoke open file state */
				lck_mtx_lock(&nofp->nof_lock);
				nofp->nof_flags |= NFS_OPEN_FILE_LOST;
				lck_mtx_unlock(&nofp->nof_lock);
				const char *vname = vnode_getname(NFSTOV(nofp->nof_np));
				printf("nfs4_recover: state lost for %s\n", vname ? vname : "???");
				vnode_putname(vname);
			}
		}
	}

	if (!error) {
		lck_mtx_lock(&nmp->nm_lock);
		nmp->nm_state &= ~NFSSTA_RECOVER;
		wakeup(&nmp->nm_state);
		printf("nfs recovery completed\n");
		lck_mtx_unlock(&nmp->nm_lock);
	} else {
		printf("nfs recovery failed %d\n", error);
	}
}

