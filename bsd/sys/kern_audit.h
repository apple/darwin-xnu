/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#ifndef _SYS_KERN_AUDIT_H
#define	_SYS_KERN_AUDIT_H

#ifdef KERNEL

/*
 * Audit subsystem condition flags.  The audit_enabled flag is set and
 * removed automatically as a result of configuring log files, and
 * can be observed but should not be directly manipulated.  The audit
 * suspension flag permits audit to be temporarily disabled without
 * reconfiguring the audit target.
 */
extern int	audit_enabled;
extern int	audit_suspended;

#define BSM_SUCCESS		0
#define BSM_FAILURE		1
#define BSM_NOAUDIT		2

/*
 * Define the masks for the audited arguments.
 */
#define ARG_EUID	0x0000000000000001ULL
#define ARG_RUID	0x0000000000000002ULL
#define ARG_SUID	0x0000000000000004ULL
#define ARG_EGID	0x0000000000000008ULL
#define ARG_RGID	0x0000000000000010ULL
#define ARG_SGID	0x0000000000000020ULL
#define ARG_PID		0x0000000000000040ULL
#define ARG_UID		0x0000000000000080ULL
#define ARG_AUID	0x0000000000000100ULL
#define ARG_GID		0x0000000000000200ULL
#define ARG_FD		0x0000000000000400ULL
#define UNUSED 		0x0000000000000800ULL
#define ARG_FFLAGS	0x0000000000001000ULL
#define ARG_MODE	0x0000000000002000ULL
#define ARG_DEV		0x0000000000004000ULL
#define ARG_ACCMODE	0x0000000000008000ULL
#define ARG_CMODE	0x0000000000010000ULL
#define ARG_MASK	0x0000000000020000ULL
#define ARG_SIGNUM	0x0000000000040000ULL
#define ARG_LOGIN	0x0000000000080000ULL
#define ARG_SADDRINET	0x0000000000100000ULL
#define ARG_SADDRINET6	0x0000000000200000ULL
#define ARG_SADDRUNIX	0x0000000000400000ULL
#define ARG_KPATH1	0x0000000000800000ULL
#define ARG_KPATH2	0x0000000001000000ULL
#define ARG_UPATH1	0x0000000002000000ULL
#define ARG_UPATH2	0x0000000004000000ULL
#define ARG_TEXT	0x0000000008000000ULL
#define ARG_VNODE1	0x0000000010000000ULL
#define ARG_VNODE2	0x0000000020000000ULL
#define ARG_SVIPC_CMD	0x0000000040000000ULL
#define ARG_SVIPC_PERM	0x0000000080000000ULL
#define ARG_SVIPC_ID	0x0000000100000000ULL
#define ARG_SVIPC_ADDR	0x0000000200000000ULL
#define ARG_GROUPSET	0x0000000400000000ULL
#define ARG_CMD		0x0000000800000000ULL
#define ARG_SOCKINFO	0x0000001000000000ULL
#define ARG_NONE	0x0000000000000000ULL
#define ARG_ALL		0xFFFFFFFFFFFFFFFFULL

struct vnode_au_info {
	mode_t		vn_mode;
	uid_t		vn_uid;
	gid_t		vn_gid;
	dev_t		vn_dev;
	long		vn_fsid;
	long		vn_fileid;
	long		vn_gen;
};

struct groupset {
	gid_t	gidset[NGROUPS];
	u_int	gidset_size;
};

struct socket_info {
	int 	sodomain;
	int	sotype;
	int	soprotocol;
};

struct audit_record {
	/* Audit record header. */
	u_int32_t		ar_magic;
	int			ar_event;
	int			ar_retval; /* value returned to the process */
	int			ar_errno;  /* return status of system call */
	struct timespec		ar_starttime;
	struct timespec		ar_endtime;
	u_int64_t		ar_valid_arg;  /* Bitmask of valid arguments */

	/* Audit subject information. */
	struct xucred			ar_subj_cred;
	uid_t				ar_subj_ruid;
	gid_t				ar_subj_rgid;
	gid_t				ar_subj_egid;
	uid_t				ar_subj_auid; /* Audit user ID */
	pid_t				ar_subj_asid; /* Audit session ID */
	pid_t				ar_subj_pid;
	struct au_tid			ar_subj_term;	
	char				ar_subj_comm[MAXCOMLEN + 1];
	struct au_mask			ar_subj_amask;

	/* Operation arguments. */
	uid_t				ar_arg_euid;
	uid_t				ar_arg_ruid;
	uid_t				ar_arg_suid;
	gid_t				ar_arg_egid;
	gid_t				ar_arg_rgid;
	gid_t				ar_arg_sgid;
	pid_t				ar_arg_pid;
	uid_t				ar_arg_uid;
	uid_t				ar_arg_auid;
	gid_t				ar_arg_gid;
	struct groupset			ar_arg_groups;
	int				ar_arg_fd;
	int				ar_arg_fflags;
	mode_t				ar_arg_mode;
	int				ar_arg_dev;
	int				ar_arg_accmode;
	int				ar_arg_cmode;
	int				ar_arg_mask;
	u_int				ar_arg_signum;
	char				ar_arg_login[MAXLOGNAME];
	struct sockaddr			ar_arg_sockaddr;
	struct socket_info		ar_arg_sockinfo;
	char				*ar_arg_upath1;
	char				*ar_arg_upath2;
	char				*ar_arg_kpath1;
	char				*ar_arg_kpath2;
	char				*ar_arg_text;
	struct au_mask			ar_arg_amask;
	struct vnode_au_info		ar_arg_vnode1;
	struct vnode_au_info		ar_arg_vnode2;
	int				ar_arg_cmd;
	int				ar_arg_svipc_cmd;
	struct ipc_perm			ar_arg_svipc_perm;
	int				ar_arg_svipc_id;
	void *				ar_arg_svipc_addr;
};

/*
 * In-kernel version of audit record; the basic record plus queue meta-data.
 * This record can also have a pointer set to some opaque data that will
 * be passed through to the audit writing mechanism.
 */
struct kaudit_record {
	struct audit_record		k_ar;
	caddr_t				k_udata;    /* user data */	
	u_int				k_ulen;     /* user data length */	
	struct uthread			*k_uthread; /* thread we are auditing */
	TAILQ_ENTRY(kaudit_record)	k_q;
};

struct proc;
struct vnode;
struct componentname;

void			 audit_abort(struct kaudit_record *ar);
void			 audit_commit(struct kaudit_record *ar, int error, 
					int retval);
void			 audit_init(void);
void			 audit_shutdown(void);

struct kaudit_record	*audit_new(int event, struct proc *p,
			    struct uthread *uthread);

void			 audit_syscall_enter(unsigned short code, 					    struct proc *proc, struct uthread *uthread);
void			 audit_syscall_exit(int error, struct proc *proc,
			    struct uthread *uthread);

int			kaudit_to_bsm(struct kaudit_record *kar,
					struct au_record **pau);

int			bsm_rec_verify(caddr_t rec);

/*
 * Kernel versions of the BSM audit record functions.
 */
struct au_record 	*kau_open(void);
int			kau_write(struct au_record *rec, token_t *m);
int			kau_close(struct au_record *rec, 
				 struct timespec *endtime, short event);
void			kau_free(struct au_record *rec);
void			kau_init(void);
token_t			*kau_to_file(char *file, struct timeval *tv);
token_t			*kau_to_header(struct timespec *ctime, int rec_size, 
					au_event_t e_type, au_emod_t e_mod);
token_t			*kau_to_header32(struct timespec *ctime, int rec_size, 
					au_event_t e_type, au_emod_t e_mod);
token_t			*kau_to_header64(struct timespec *ctime, int rec_size,
					 au_event_t e_type, au_emod_t e_mod);
/*
 * The remaining kernel functions are conditionally compiled in as they
 * are wrapped by a macro, and the macro should be the only place in 
 * the source tree where these functions are referenced.
 */
#ifdef AUDIT
void			 audit_arg_accmode(int mode);
void			 audit_arg_cmode(int cmode);
void			 audit_arg_fd(int fd);
void			 audit_arg_fflags(int fflags);
void			 audit_arg_gid(gid_t gid, gid_t egid, gid_t rgid, 
					gid_t sgid);
void			 audit_arg_uid(uid_t uid, uid_t euid, uid_t ruid, 
					uid_t suid);
void			 audit_arg_groupset(gid_t *gidset, u_int gidset_size);
void			 audit_arg_login(char[MAXLOGNAME]);
void			 audit_arg_mask(int mask);
void			 audit_arg_mode(mode_t mode);
void			 audit_arg_dev(int dev);
void			 audit_arg_owner(uid_t uid, gid_t gid);
void			 audit_arg_pid(pid_t pid);
void			 audit_arg_signum(u_int signum);
void			 audit_arg_socket(int sodomain, int sotype, 
						int soprotocol);
void			 audit_arg_sockaddr(struct proc *p, 
						struct sockaddr *so);
void			 audit_arg_auid(uid_t auid);
void			 audit_arg_upath(struct proc *p, char *upath, 
					 u_int64_t flags);
void			 audit_arg_vnpath(struct vnode *vp, u_int64_t flags);
void			 audit_arg_text(char *text);
void			 audit_arg_cmd(int cmd);
void			 audit_arg_svipc_cmd(int cmd);
void			 audit_arg_svipc_perm(struct ipc_perm *perm);
void			 audit_arg_svipc_id(int id);
void			 audit_arg_svipc_addr(void *addr);

void			 audit_proc_init(struct proc *p);
void			 audit_proc_fork(struct proc *parent, 
					 struct proc *child);
void			 audit_proc_free(struct proc *p);

/*
 * Define a macro to wrap the audit_arg_* calls by checking the global
 * audit_enabled flag before performing the actual call.
 */
#define	AUDIT_ARG(op, args...)	do {					\
	if (audit_enabled)						\
		audit_arg_ ## op (args);				\
	} while (0)

#define AUDIT_CMD(audit_cmd)	do {					\
	if (audit_enabled) {						\
		audit_cmd;						\
	}								\
	} while (0)

#else /* !AUDIT */
#define	AUDIT_ARG(op, args...)	do {					\
	} while (0)

#define	AUDIT_CMD(audit_cmd)	do {					\
	} while (0)

#endif /* AUDIT */

#endif /* KERNEL */

#endif /* !_SYS_KERN_AUDIT_H */
