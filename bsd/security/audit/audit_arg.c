/*-
 * Copyright (c) 1999-2009 Apple Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/malloc.h>
#include <sys/un.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/vfs_context.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>

#include <security/audit/audit.h>
#include <security/audit/audit_bsd.h>
#include <security/audit/audit_private.h>

#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/audit_triggers_server.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/lock.h>
#include <kern/wait_queue.h>
#include <kern/sched_prim.h>

#if CONFIG_MACF
#include <bsm/audit_record.h>
#include <security/mac.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>
extern zone_t audit_mac_label_zone;
#endif

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#if CONFIG_AUDIT
/*
 * Calls to manipulate elements of the audit record structure from system
 * call code.  Macro wrappers will prevent this functions from being entered
 * if auditing is disabled, avoiding the function call cost.  We check the
 * thread audit record pointer anyway, as the audit condition could change,
 * and pre-selection may not have allocated an audit record for this event.
 *
 * XXXAUDIT: Should we assert, in each case, that this field of the record
 * hasn't already been filled in?
 */
void
audit_arg_addr(struct kaudit_record *ar, user_addr_t addr)
{
	struct proc *p = current_proc();

	ar->k_ar.ar_arg_addr = addr;

	/*
	 * If the process is 64-bit then flag the address as such.
	 */
	if (proc_is64bit(p))
		ARG_SET_VALID(ar, ARG_ADDR64);
	else
		ARG_SET_VALID(ar, ARG_ADDR32);
}

void
audit_arg_exit(struct kaudit_record *ar, int status, int retval)
{

	ar->k_ar.ar_arg_exitstatus = status;
	ar->k_ar.ar_arg_exitretval = retval;
	ARG_SET_VALID(ar, ARG_EXIT);
}

void
audit_arg_len(struct kaudit_record *ar, user_size_t len)
{

	ar->k_ar.ar_arg_len = len;
	ARG_SET_VALID(ar, ARG_LEN);
}

void
audit_arg_fd(struct kaudit_record *ar, int fd)
{

	ar->k_ar.ar_arg_fd = fd;
	ARG_SET_VALID(ar, ARG_FD);
}

void
audit_arg_fflags(struct kaudit_record *ar, int fflags)
{

	ar->k_ar.ar_arg_fflags = fflags;
	ARG_SET_VALID(ar, ARG_FFLAGS);
}

void
audit_arg_gid(struct kaudit_record *ar, gid_t gid)
{

	ar->k_ar.ar_arg_gid = gid;
	ARG_SET_VALID(ar, ARG_GID);
}

void
audit_arg_uid(struct kaudit_record *ar, uid_t uid)
{

	ar->k_ar.ar_arg_uid = uid;
	ARG_SET_VALID(ar, ARG_UID);
}

void
audit_arg_egid(struct kaudit_record *ar, gid_t egid)
{

	ar->k_ar.ar_arg_egid = egid;
	ARG_SET_VALID(ar, ARG_EGID);
}

void
audit_arg_euid(struct kaudit_record *ar, uid_t euid)
{

	ar->k_ar.ar_arg_euid = euid;
	ARG_SET_VALID(ar, ARG_EUID);
}

void
audit_arg_rgid(struct kaudit_record *ar, gid_t rgid)
{

	ar->k_ar.ar_arg_rgid = rgid;
	ARG_SET_VALID(ar, ARG_RGID);
}

void
audit_arg_ruid(struct kaudit_record *ar, uid_t ruid)
{

	ar->k_ar.ar_arg_ruid = ruid;
	ARG_SET_VALID(ar, ARG_RUID);
}

void
audit_arg_sgid(struct kaudit_record *ar, gid_t sgid)
{

	ar->k_ar.ar_arg_sgid = sgid;
	ARG_SET_VALID(ar, ARG_SGID);
}

void
audit_arg_suid(struct kaudit_record *ar, uid_t suid)
{

	ar->k_ar.ar_arg_suid = suid;
	ARG_SET_VALID(ar, ARG_SUID);
}

void
audit_arg_groupset(struct kaudit_record *ar, gid_t *gidset, u_int gidset_size)
{
	u_int i;

	for (i = 0; i < gidset_size; i++)
		ar->k_ar.ar_arg_groups.gidset[i] = gidset[i];
	ar->k_ar.ar_arg_groups.gidset_size = gidset_size;
	ARG_SET_VALID(ar, ARG_GROUPSET);
}

void
audit_arg_login(struct kaudit_record *ar, char *login)
{

	strlcpy(ar->k_ar.ar_arg_login, login, MAXLOGNAME);
	ARG_SET_VALID(ar, ARG_LOGIN);
}

void
audit_arg_ctlname(struct kaudit_record *ar, int *name, int namelen)
{

	bcopy(name, &ar->k_ar.ar_arg_ctlname, namelen * sizeof(int));
	ar->k_ar.ar_arg_len = namelen;
	ARG_SET_VALID(ar, ARG_CTLNAME | ARG_LEN);
}

void
audit_arg_mask(struct kaudit_record *ar, int mask)
{

	ar->k_ar.ar_arg_mask = mask;
	ARG_SET_VALID(ar, ARG_MASK);
}

void
audit_arg_mode(struct kaudit_record *ar, mode_t mode)
{

	ar->k_ar.ar_arg_mode = mode;
	ARG_SET_VALID(ar, ARG_MODE);
}

void
audit_arg_value32(struct kaudit_record *ar, uint32_t value32)
{

	ar->k_ar.ar_arg_value32 = value32;
	ARG_SET_VALID(ar, ARG_VALUE32);
}

void
audit_arg_value64(struct kaudit_record *ar, uint64_t value64)
{

	ar->k_ar.ar_arg_value64 = value64;
	ARG_SET_VALID(ar, ARG_VALUE64);
}

void
audit_arg_owner(struct kaudit_record *ar, uid_t uid, gid_t gid)
{

	ar->k_ar.ar_arg_uid = uid;
	ar->k_ar.ar_arg_gid = gid;
	ARG_SET_VALID(ar, ARG_UID | ARG_GID);
}

void
audit_arg_pid(struct kaudit_record *ar, pid_t pid)
{

	ar->k_ar.ar_arg_pid = pid;
	ARG_SET_VALID(ar, ARG_PID);
}

void
audit_arg_process(struct kaudit_record *ar, proc_t p)
{
	kauth_cred_t my_cred;

	KASSERT(p != NULL, ("audit_arg_process: p == NULL"));

	if ( p == NULL)
		return;

	my_cred = kauth_cred_proc_ref(p);
	ar->k_ar.ar_arg_auid = my_cred->cr_audit.as_aia_p->ai_auid;
	ar->k_ar.ar_arg_asid = my_cred->cr_audit.as_aia_p->ai_asid;
	bcopy(&my_cred->cr_audit.as_aia_p->ai_termid,
	    &ar->k_ar.ar_arg_termid_addr, sizeof(au_tid_addr_t));
	ar->k_ar.ar_arg_euid = my_cred->cr_uid;
	ar->k_ar.ar_arg_egid = my_cred->cr_groups[0];
	ar->k_ar.ar_arg_ruid = my_cred->cr_ruid;
	ar->k_ar.ar_arg_rgid = my_cred->cr_rgid;
	kauth_cred_unref(&my_cred);
	ar->k_ar.ar_arg_pid = p->p_pid;
	ARG_SET_VALID(ar, ARG_AUID | ARG_EUID | ARG_EGID | ARG_RUID |
	    ARG_RGID | ARG_ASID | ARG_TERMID_ADDR | ARG_PID | ARG_PROCESS);
}

void
audit_arg_signum(struct kaudit_record *ar, u_int signum)
{

	ar->k_ar.ar_arg_signum = signum;
	ARG_SET_VALID(ar, ARG_SIGNUM);
}

void
audit_arg_socket(struct kaudit_record *ar, int sodomain, int sotype,
    int soprotocol)
{

	ar->k_ar.ar_arg_sockinfo.sai_domain = sodomain;
	ar->k_ar.ar_arg_sockinfo.sai_type = sotype;
	ar->k_ar.ar_arg_sockinfo.sai_protocol = soprotocol;
	ARG_SET_VALID(ar, ARG_SOCKINFO);
}

/*
 * Note that the current working directory vp must be supplied at the audit
 * call site to permit per thread current working directories, and that it
 * must take a upath starting with '/' into account for chroot if the path
 * is absolute.  This results in the real (non-chroot) path being recorded
 * in the audit record.
 */
void
audit_arg_sockaddr(struct kaudit_record *ar, struct vnode *cwd_vp,
    struct sockaddr *sa)
{
	int slen;
	struct sockaddr_un *sun;
	char path[SOCK_MAXADDRLEN - offsetof(struct sockaddr_un, sun_path) + 1];

	KASSERT(sa != NULL, ("audit_arg_sockaddr: sa == NULL"));

	if (cwd_vp == NULL || sa == NULL)
		return;

	bcopy(sa, &ar->k_ar.ar_arg_sockaddr, sa->sa_len);
	switch (sa->sa_family) {
	case AF_INET:
		ARG_SET_VALID(ar, ARG_SADDRINET);
		break;

	case AF_INET6:
		ARG_SET_VALID(ar, ARG_SADDRINET6);
		break;

	case AF_UNIX:
		sun = (struct sockaddr_un *)sa;
		slen = sun->sun_len - offsetof(struct sockaddr_un, sun_path);

		if (slen >= 0) {
			/*
			 * Make sure the path is NULL-terminated
			 */
			if (sun->sun_path[slen] != 0) {
				bcopy(sun->sun_path, path, slen);
				path[slen] = 0;
				audit_arg_upath(ar, cwd_vp, path, ARG_UPATH1);
			} else {
				audit_arg_upath(ar, cwd_vp, sun->sun_path, 
					ARG_UPATH1);
			}
		}
		ARG_SET_VALID(ar, ARG_SADDRUNIX);
		break;
	/* XXXAUDIT: default:? */
	}
}

void
audit_arg_auid(struct kaudit_record *ar, uid_t auid)
{

	ar->k_ar.ar_arg_auid = auid;
	ARG_SET_VALID(ar, ARG_AUID);
}

void
audit_arg_auditinfo(struct kaudit_record *ar, struct auditinfo *au_info)
{

	ar->k_ar.ar_arg_auid = au_info->ai_auid;
	ar->k_ar.ar_arg_asid = au_info->ai_asid;
	ar->k_ar.ar_arg_amask.am_success = au_info->ai_mask.am_success;
	ar->k_ar.ar_arg_amask.am_failure = au_info->ai_mask.am_failure;
	ar->k_ar.ar_arg_termid.port = au_info->ai_termid.port;
	ar->k_ar.ar_arg_termid.machine = au_info->ai_termid.machine;
	ARG_SET_VALID(ar, ARG_AUID | ARG_ASID | ARG_AMASK | ARG_TERMID);
}

void
audit_arg_auditinfo_addr(struct kaudit_record *ar,
    struct auditinfo_addr *au_info)
{

	ar->k_ar.ar_arg_auid = au_info->ai_auid;
	ar->k_ar.ar_arg_asid = au_info->ai_asid;
	ar->k_ar.ar_arg_amask.am_success = au_info->ai_mask.am_success;
	ar->k_ar.ar_arg_amask.am_failure = au_info->ai_mask.am_failure;
	ar->k_ar.ar_arg_termid_addr.at_type = au_info->ai_termid.at_type;
	ar->k_ar.ar_arg_termid_addr.at_port = au_info->ai_termid.at_port;
	ar->k_ar.ar_arg_termid_addr.at_addr[0] = au_info->ai_termid.at_addr[0];
	ar->k_ar.ar_arg_termid_addr.at_addr[1] = au_info->ai_termid.at_addr[1];
	ar->k_ar.ar_arg_termid_addr.at_addr[2] = au_info->ai_termid.at_addr[2];
	ar->k_ar.ar_arg_termid_addr.at_addr[3] = au_info->ai_termid.at_addr[3];
	ARG_SET_VALID(ar, ARG_AUID | ARG_ASID | ARG_AMASK | ARG_TERMID_ADDR);
}

void
audit_arg_text(struct kaudit_record *ar, char *text)
{

	KASSERT(text != NULL, ("audit_arg_text: text == NULL"));

	/* Invalidate the text string */
	ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_TEXT);
	if (text == NULL)
		return;

	if (ar->k_ar.ar_arg_text == NULL) 
		ar->k_ar.ar_arg_text = malloc(MAXPATHLEN, M_AUDITTEXT, 
		    M_WAITOK);

	strncpy(ar->k_ar.ar_arg_text, text, MAXPATHLEN);
	ARG_SET_VALID(ar, ARG_TEXT);
}

void
audit_arg_opaque(struct kaudit_record *ar, void *data, size_t size)
{

	KASSERT(data != NULL, ("audit_arg_opaque: data == NULL"));
	KASSERT(size <= UINT16_MAX, ("audit_arg_opaque: size > UINT16_MAX"));

	if (data == NULL || size > UINT16_MAX)
		return;

	if (ar->k_ar.ar_arg_opaque == NULL)
		ar->k_ar.ar_arg_opaque = malloc(size, M_AUDITDATA, M_WAITOK);
	else
		return;

	memcpy(ar->k_ar.ar_arg_opaque, data, size);
	ar->k_ar.ar_arg_opq_size = (u_int16_t) size;
	ARG_SET_VALID(ar, ARG_OPAQUE);
}

void
audit_arg_data(struct kaudit_record *ar, void *data, size_t size, size_t number)
{
	size_t sz;

	KASSERT(data != NULL, ("audit_arg_data: data == NULL"));
	KASSERT(size >= AUR_BYTE_SIZE && size <= AUR_INT64_SIZE,
	    ("audit_arg_data: size < AUR_BYTE_SIZE or size > AUR_INT64_SIZE"));
	KASSERT(number <= UINT8_MAX,
	    ("audit_arg_data: number > UINT8_MAX"));

	if (data == NULL || size < AUR_BYTE_SIZE || size > AUR_INT64_SIZE ||
	    number > UINT8_MAX)
		return;

	sz = size * number;

	if (ar->k_ar.ar_arg_data == NULL)
		ar->k_ar.ar_arg_data = malloc(sz, M_AUDITDATA, M_WAITOK);
	else
		return;

	memcpy(ar->k_ar.ar_arg_data, data, sz);

	switch(size) {
	case AUR_BYTE_SIZE:
		ar->k_ar.ar_arg_data_type = AUR_BYTE;
		break;

	case AUR_SHORT_SIZE:
		ar->k_ar.ar_arg_data_type = AUR_SHORT;
		break;

	case AUR_INT32_SIZE:
		ar->k_ar.ar_arg_data_type = AUR_INT32;
		break;

	case AUR_INT64_SIZE:
		ar->k_ar.ar_arg_data_type = AUR_INT64;
		break;

	default:
		free(ar->k_ar.ar_arg_data, M_AUDITDATA);
		ar->k_ar.ar_arg_data = NULL;
		return;
	}

	ar->k_ar.ar_arg_data_count = (u_char)number;

	ARG_SET_VALID(ar, ARG_DATA);
}

void
audit_arg_cmd(struct kaudit_record *ar, int cmd)
{

	ar->k_ar.ar_arg_cmd = cmd;
	ARG_SET_VALID(ar, ARG_CMD);
}

void
audit_arg_svipc_cmd(struct kaudit_record *ar, int cmd)
{

	ar->k_ar.ar_arg_svipc_cmd = cmd;
	ARG_SET_VALID(ar, ARG_SVIPC_CMD);
}

void
audit_arg_svipc_perm(struct kaudit_record *ar, struct ipc_perm *perm)
{

	bcopy(perm, &ar->k_ar.ar_arg_svipc_perm,
	    sizeof(ar->k_ar.ar_arg_svipc_perm));
	ARG_SET_VALID(ar, ARG_SVIPC_PERM);
}

void
audit_arg_svipc_id(struct kaudit_record *ar, int id)
{

	ar->k_ar.ar_arg_svipc_id = id;
	ARG_SET_VALID(ar, ARG_SVIPC_ID);
}

void
audit_arg_svipc_addr(struct kaudit_record *ar, user_addr_t addr)
{

	ar->k_ar.ar_arg_svipc_addr = addr;
	ARG_SET_VALID(ar, ARG_SVIPC_ADDR);
}

void
audit_arg_posix_ipc_perm(struct kaudit_record *ar, uid_t uid, gid_t gid,
    mode_t mode)
{

	ar->k_ar.ar_arg_pipc_perm.pipc_uid = uid;
	ar->k_ar.ar_arg_pipc_perm.pipc_gid = gid;
	ar->k_ar.ar_arg_pipc_perm.pipc_mode = mode;
	ARG_SET_VALID(ar, ARG_POSIX_IPC_PERM);
}

void
audit_arg_auditon(struct kaudit_record *ar, union auditon_udata *udata)
{

	bcopy((void *)udata, &ar->k_ar.ar_arg_auditon,
	    sizeof(ar->k_ar.ar_arg_auditon));
	ARG_SET_VALID(ar, ARG_AUDITON);
}

/*
 * Audit information about a file, either the file's vnode info, or its
 * socket address info.
 */
void
audit_arg_file(struct kaudit_record *ar, __unused proc_t p,
    struct fileproc *fp)
{
	struct socket *so;
	struct inpcb *pcb;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (fp->f_fglob->fg_type) {
	case DTYPE_VNODE:
	/* case DTYPE_FIFO: */
		audit_arg_vnpath_withref(ar,
		    (struct vnode *)fp->f_fglob->fg_data, ARG_VNODE1);
		break;

	case DTYPE_SOCKET:
		so = (struct socket *)fp->f_fglob->fg_data;
		if (INP_CHECK_SOCKAF(so, PF_INET)) {
			if (so->so_pcb == NULL)
				break;
			ar->k_ar.ar_arg_sockinfo.sai_type =
			    so->so_type;
			ar->k_ar.ar_arg_sockinfo.sai_domain =
			    INP_SOCKAF(so);
			ar->k_ar.ar_arg_sockinfo.sai_protocol =
			    so->so_proto->pr_protocol;
			pcb = (struct inpcb *)so->so_pcb;
			sin = (struct sockaddr_in *)
			    &ar->k_ar.ar_arg_sockinfo.sai_faddr;
			sin->sin_addr.s_addr = pcb->inp_faddr.s_addr;
			sin->sin_port = pcb->inp_fport;
			sin = (struct sockaddr_in *)
			    &ar->k_ar.ar_arg_sockinfo.sai_laddr;
			sin->sin_addr.s_addr = pcb->inp_laddr.s_addr;
			sin->sin_port = pcb->inp_lport;
			ARG_SET_VALID(ar, ARG_SOCKINFO);
		}
		if (INP_CHECK_SOCKAF(so, PF_INET6)) {
			if (so->so_pcb == NULL)
				break;
			ar->k_ar.ar_arg_sockinfo.sai_type =
			    so->so_type;
			ar->k_ar.ar_arg_sockinfo.sai_domain =
			    INP_SOCKAF(so);
			ar->k_ar.ar_arg_sockinfo.sai_protocol =
			    so->so_proto->pr_protocol;
			pcb = (struct inpcb *)so->so_pcb;
			sin6 = (struct sockaddr_in6 *)
			    &ar->k_ar.ar_arg_sockinfo.sai_faddr;
			sin6->sin6_addr = pcb->in6p_faddr;
			sin6->sin6_port = pcb->in6p_fport;
			sin6 = (struct sockaddr_in6 *)
			    &ar->k_ar.ar_arg_sockinfo.sai_laddr;
			sin6->sin6_addr = pcb->in6p_laddr;
			sin6->sin6_port = pcb->in6p_lport;
			ARG_SET_VALID(ar, ARG_SOCKINFO);
		}
		break;

	default:
		/* XXXAUDIT: else? */
		break;
	}
}

/*
 * Store a path as given by the user process for auditing into the audit
 * record stored on the user thread.  This function will allocate the memory
 * to store the path info if not already available.  This memory will be
 * freed when the audit record is freed.
 * 
 * Note that the current working directory vp must be supplied at the audit call
 * site to permit per thread current working directories, and that it must take
 * a upath starting with '/' into account for chroot if the path is absolute.
 * This results in the real (non-chroot) path being recorded in the audit
 * record.
 *
 * XXXAUDIT: Possibly assert that the memory isn't already allocated?
 */
void
audit_arg_upath(struct kaudit_record *ar, struct vnode *cwd_vp, char *upath, u_int64_t flag)
{
	char **pathp;

	KASSERT(upath != NULL, ("audit_arg_upath: upath == NULL"));
	KASSERT((flag == ARG_UPATH1) || (flag == ARG_UPATH2),
	    ("audit_arg_upath: flag %llu", (unsigned long long)flag));
	KASSERT((flag != ARG_UPATH1) || (flag != ARG_UPATH2),
	    ("audit_arg_upath: flag %llu", (unsigned long long)flag));

	if (flag == ARG_UPATH1)
		pathp = &ar->k_ar.ar_arg_upath1;
	else
		pathp = &ar->k_ar.ar_arg_upath2;

	if (*pathp == NULL)
		*pathp = malloc(MAXPATHLEN, M_AUDITPATH, M_WAITOK);
	else
		return;

	if (audit_canon_path(cwd_vp, upath, *pathp) == 0)
		ARG_SET_VALID(ar, flag);
	else {
		free(*pathp, M_AUDITPATH);
		*pathp = NULL;
	}
}

/*
 * Function to save the path and vnode attr information into the audit
 * record.
 *
 * It is assumed that the caller will hold any vnode locks necessary to
 * perform a VNOP_GETATTR() on the passed vnode.
 *
 * XXX: The attr code is very similar to vfs_vnops.c:vn_stat(), but always
 * provides access to the generation number as we need that to construct the
 * BSM file ID.
 *
 * XXX: We should accept the process argument from the caller, since it's
 * very likely they already have a reference.
 *
 * XXX: Error handling in this function is poor.
 *
 * XXXAUDIT: Possibly KASSERT the path pointer is NULL?
 */
void
audit_arg_vnpath(struct kaudit_record *ar, struct vnode *vp, u_int64_t flags)
{
	struct vnode_attr va;
	int error;
	int len;
	char **pathp;
	struct vnode_au_info *vnp;
	proc_t p;
#if CONFIG_MACF
	char **vnode_mac_labelp;
	struct mac mac;
#endif

	KASSERT(vp != NULL, ("audit_arg_vnpath: vp == NULL"));
	KASSERT((flags == ARG_VNODE1) || (flags == ARG_VNODE2),
	    ("audit_arg_vnpath: flags != ARG_VNODE[1,2]"));

	p = current_proc();

	/* 
	 * XXXAUDIT: The below clears, and then resets the flags for valid
	 * arguments.  Ideally, either the new vnode is used, or the old one
	 * would be.
	 */
	if (flags & ARG_VNODE1) {
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_KPATH1);
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_VNODE1);
		pathp = &ar->k_ar.ar_arg_kpath1;
		vnp = &ar->k_ar.ar_arg_vnode1;
#if CONFIG_MACF
		vnode_mac_labelp = &ar->k_ar.ar_vnode1_mac_labels;
#endif
	} else {
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_KPATH2);
		ar->k_ar.ar_valid_arg &= (ARG_ALL ^ ARG_VNODE2);
		pathp = &ar->k_ar.ar_arg_kpath2;
		vnp = &ar->k_ar.ar_arg_vnode2;
#if CONFIG_MACF
		vnode_mac_labelp = &ar->k_ar.ar_vnode2_mac_labels;
#endif
	}

	if (*pathp == NULL)
		*pathp = malloc(MAXPATHLEN, M_AUDITPATH, M_WAITOK);
	else
		return;

	/*
	 * If vn_getpath() succeeds, place it in a string buffer
	 * attached to the audit record, and set a flag indicating
	 * it is present.
	 */
	len = MAXPATHLEN;
	if (vn_getpath(vp, *pathp, &len) == 0) {
		if (flags & ARG_VNODE1)
			ARG_SET_VALID(ar, ARG_KPATH1);
		else
			ARG_SET_VALID(ar, ARG_KPATH2);
	} else {
		free(*pathp, M_AUDITPATH);
		*pathp = NULL;
	}

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_rdev);
	VATTR_WANTED(&va, va_fsid);
	VATTR_WANTED(&va, va_fileid);
	VATTR_WANTED(&va, va_gen);
	error = vnode_getattr(vp, &va, vfs_context_current());
	if (error) {
		/* XXX: How to handle this case? */
		return;
	}

#if CONFIG_MACF
	if (*vnode_mac_labelp == NULL && (vp->v_lflag & VL_LABELED) == VL_LABELED) {
		*vnode_mac_labelp = (char *)zalloc(audit_mac_label_zone);
		if (*vnode_mac_labelp != NULL) {
			mac.m_buflen = MAC_AUDIT_LABEL_LEN;
			mac.m_string = *vnode_mac_labelp;
			mac_vnode_label_externalize_audit(vp, &mac);
		}
	}
#endif

	/*
	 * XXX do we want to fall back here when these aren't supported?
	 */
	vnp->vn_mode = va.va_mode;
	vnp->vn_uid = va.va_uid;
	vnp->vn_gid = va.va_gid;
	vnp->vn_dev = va.va_rdev;
	vnp->vn_fsid = va.va_fsid;
	vnp->vn_fileid = (u_int32_t)va.va_fileid;
	vnp->vn_gen = va.va_gen;
	if (flags & ARG_VNODE1)
		ARG_SET_VALID(ar, ARG_VNODE1);
	else
		ARG_SET_VALID(ar, ARG_VNODE2);
}

void
audit_arg_vnpath_withref(struct kaudit_record *ar, struct vnode *vp, u_int64_t flags)
{
	if (vp == NULL || vnode_getwithref(vp))
		return;
	audit_arg_vnpath(ar, vp, flags);
	(void)vnode_put(vp);
}

void
audit_arg_mach_port1(struct kaudit_record *ar, mach_port_name_t port)
{

	ar->k_ar.ar_arg_mach_port1 = port;
	ARG_SET_VALID(ar, ARG_MACHPORT1);
}

void
audit_arg_mach_port2(struct kaudit_record *ar, mach_port_name_t port)
{

	ar->k_ar.ar_arg_mach_port2 = port;
	ARG_SET_VALID(ar, ARG_MACHPORT2);
}


/*
 * Audit the argument strings passed to exec.
 */
void
audit_arg_argv(struct kaudit_record *ar, char *argv, int argc, int length)
{

	if (audit_argv == 0 || argc == 0)
		return;

	if (ar->k_ar.ar_arg_argv == NULL)
		ar->k_ar.ar_arg_argv = malloc(length, M_AUDITTEXT, M_WAITOK);
	bcopy(argv, ar->k_ar.ar_arg_argv, length);
	ar->k_ar.ar_arg_argc = argc;
	ARG_SET_VALID(ar, ARG_ARGV);
}

/*
 * Audit the environment strings passed to exec.
 */
void
audit_arg_envv(struct kaudit_record *ar, char *envv, int envc, int length)
{

	if (audit_arge == 0 || envc == 0)
		return;

	if (ar->k_ar.ar_arg_envv == NULL)
		ar->k_ar.ar_arg_envv = malloc(length, M_AUDITTEXT, M_WAITOK);
	bcopy(envv, ar->k_ar.ar_arg_envv, length);
	ar->k_ar.ar_arg_envc = envc;
	ARG_SET_VALID(ar, ARG_ENVV);
}

/*
 * The close() system call uses it's own audit call to capture the path/vnode
 * information because those pieces are not easily obtained within the system
 * call itself.
 */
void
audit_sysclose(struct kaudit_record *ar, proc_t p, int fd)
{
	struct fileproc *fp;
	struct vnode *vp;

	KASSERT(p != NULL, ("audit_sysclose: p == NULL"));

	audit_arg_fd(ar, fd);

	if (fp_getfvp(p, fd, &fp, &vp) != 0)
		return;

	audit_arg_vnpath_withref(ar, (struct vnode *)fp->f_fglob->fg_data,
	    ARG_VNODE1);
	fp_drop(p, fd, fp, 0);
}

#endif /* CONFIG_AUDIT */
