/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/socketvar.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/fcntl.h>
#include <sys/audit.h>
#include <sys/kern_audit.h>
#include <sys/bsm_token.h>
#include <sys/bsm_kevents.h>
#include <sys/bsm_klib.h>
#include <sys/user.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <kern/lock.h>

/* The number of BSM records allocated. */
static int bsm_rec_count = 0; 

/* 
 * Records that can be recycled are maintained in the list given below
 * The maximum number of elements that can be present in this list is
 * bounded by MAX_AUDIT_RECORDS. Memory allocated for these records are never
 * freed 
 */ 
LIST_HEAD(, au_record) bsm_free_q;

/*
 * Lock for serializing access to the list of audit records.
 */
static mutex_t	*bsm_audit_mutex;

/*
 * Initialize the BSM auditing subsystem.
 */
void
kau_init(void)
{
	printf("BSM auditing present\n");
	LIST_INIT(&bsm_free_q);
	bsm_audit_mutex = mutex_alloc(ETAP_NO_TRACE);
}

/*
 * This call reserves memory for the audit record. 
 * Memory must be guaranteed before any auditable event can be
 * generated. 
 * The au_record structure maintains a reference to the
 * memory allocated above and also the list of tokens associated 
 * with this record
 */  
struct au_record * 
kau_open(void)
{	
	struct au_record *rec = NULL;
	
	/* 
	 * Find an unused record, remove it from the free list, mark as used
	 */  
	mutex_lock(bsm_audit_mutex);
	if (!LIST_EMPTY(&bsm_free_q)) {
		rec = LIST_FIRST(&bsm_free_q);
		LIST_REMOVE(rec, au_rec_q);
	}
	mutex_unlock(bsm_audit_mutex);

	if (rec == NULL) {
		mutex_lock(bsm_audit_mutex);
		if (bsm_rec_count >= MAX_AUDIT_RECORDS) {
			/* XXX We need to increase size of MAX_AUDIT_RECORDS */
			mutex_unlock(bsm_audit_mutex);
			return NULL;
		}
		mutex_unlock(bsm_audit_mutex);
			
		/*
		 * Create a new BSM kernel record.
		 */
		kmem_alloc(kernel_map, &rec, sizeof(*rec));
		if(rec == NULL) {
			return NULL;
		}
		kmem_alloc(kernel_map, &rec->data, 
			   MAX_AUDIT_RECORD_SIZE * sizeof(u_char));
		if((rec->data) == NULL) {
			kmem_free(kernel_map, rec, sizeof(*rec));
			return NULL;
		}
		mutex_lock(bsm_audit_mutex);
		bsm_rec_count++;
		mutex_unlock(bsm_audit_mutex);
	}
	memset(rec->data, 0, MAX_AUDIT_RECORD_SIZE);

	TAILQ_INIT(&rec->token_q);
	rec->len = 0;
	rec->used = 1;

	return rec;
}

/*
 * Store the token with the record descriptor
 *
 */ 
int kau_write(struct au_record *rec, struct au_token *tok)
{
	if(tok == NULL) {
		return -1; /* Invalid Token */
	}		

	/* Add the token to the tail */
	/* 
	 * XXX Not locking here -- we should not be writing to
	 * XXX the same audit record from different threads
	 */ 
	TAILQ_INSERT_TAIL(&rec->token_q, tok, tokens);

	rec->len += tok->len; /* grow record length by token size bytes */
	
	return 0; 
}

/*
 * Close out the audit record by adding the header token, identifying 
 * any missing tokens.  Write out the tokens to the record memory.
 */
int kau_close(struct au_record *rec, struct timespec *ctime, short event)
{
	u_char *dptr;
	size_t tot_rec_size;
	token_t *cur, *hdr, *trail;
	int retval = 0;
		
	tot_rec_size = rec->len + HEADER_SIZE + TRAILER_SIZE;
	if(tot_rec_size <= MAX_AUDIT_RECORD_SIZE) {
		/* Create the header token */
		hdr = kau_to_header32(ctime, tot_rec_size, event, 0);
			
		if(hdr != NULL) {
			/* Add to head of list */
			TAILQ_INSERT_HEAD(&rec->token_q, hdr, tokens);

			trail = au_to_trailer(tot_rec_size);
			if(trail != NULL) {
				TAILQ_INSERT_TAIL(&rec->token_q, trail, tokens);
			}
		}
		/* Serialize token data to the record */

		rec->len = tot_rec_size;
		dptr = rec->data;
		TAILQ_FOREACH(cur, &rec->token_q, tokens) {
			memcpy(dptr, cur->t_data, cur->len);		
			dptr += cur->len;
		}
	}
}

/*
 * Free a BSM audit record by releasing all the tokens and clearing the
 * audit record information.
 */
void kau_free(struct au_record *rec)
{
	struct au_token *tok;

	/* Free the token list */
	while ((tok = TAILQ_FIRST(&rec->token_q))) {
		TAILQ_REMOVE(&rec->token_q, tok, tokens);
		kmem_free(kernel_map, tok->t_data, tok->len);
		kmem_free(kernel_map, tok, sizeof(struct au_token));
	}	

	rec->used = 0;
	rec->len = 0;	

	mutex_lock(bsm_audit_mutex);

	/* Add the record to the freelist */
	LIST_INSERT_HEAD(&bsm_free_q, rec, au_rec_q);
	
	mutex_unlock(bsm_audit_mutex);

}

/*
 * XXX May want turn some (or all) of these macros into functions in order
 * to reduce the generated code sized.
 */
#define UPATH1_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_UPATH1) {  		\
			tok = au_to_path(ar->ar_arg_upath1);	\
			kau_write(rec, tok);			\
		}						\
	} while (0)

#define UPATH2_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_UPATH2) {  		\
			tok = au_to_path(ar->ar_arg_upath2);	\
			kau_write(rec, tok);			\
		}						\
	} while (0)

#define KPATH1_VNODE1_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_KPATH1) {  		\
			tok = au_to_path(ar->ar_arg_kpath1);	\
			kau_write(rec, tok);			\
		}						\
		if (ar->ar_valid_arg & ARG_VNODE1) {  		\
			fill_vattr(&vattr, &ar->ar_arg_vnode1);	\
			tok = au_to_attr32(&vattr);		\
			kau_write(rec, tok);			\
		}						\
	} while (0)

#define KPATH1_VNODE1_OR_UPATH1_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_KPATH1) {  		\
			tok = au_to_path(ar->ar_arg_kpath1);	\
			kau_write(rec, tok);			\
		} else {					\
			UPATH1_TOKENS;				\
		}						\
		if (ar->ar_valid_arg & ARG_VNODE1) {  		\
			fill_vattr(&vattr, &ar->ar_arg_vnode1);	\
			tok = au_to_attr32(&vattr);		\
			kau_write(rec, tok);			\
		}						\
	} while (0)

#define KPATH2_VNODE2_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_KPATH2) {  		\
			tok = au_to_path(ar->ar_arg_kpath2);	\
			kau_write(rec, tok);			\
		}						\
		if (ar->ar_valid_arg & ARG_VNODE2) {  		\
			fill_vattr(&vattr, &ar->ar_arg_vnode2);	\
			tok = au_to_attr32(&vattr);		\
			kau_write(rec, tok);			\
		}						\
	} while (0)

#define FD_KPATH1_VNODE1_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_KPATH1) {		\
			tok = au_to_path(ar->ar_arg_kpath1);	\
			kau_write(rec, tok);			\
			if (ar->ar_valid_arg & ARG_VNODE1) {  	\
				fill_vattr(&vattr, &ar->ar_arg_vnode1);	\
				tok = au_to_attr32(&vattr);		\
				kau_write(rec, tok);		\
			}					\
		} else {					\
			tok = au_to_arg32(1, "no path: fd", ar->ar_arg_fd); \
			kau_write(rec, tok);			\
		}						\
	} while (0)

/*
 * Convert an internal kernel audit record to a BSM record and return 
 * a success/failure indicator. The BSM record is passed as an out
 * parameter to this function. 
 * Return conditions:
 *   BSM_SUCCESS: The BSM record is valid
 *   BSM_FAILURE: Failure; the BSM record is NULL.
 *   BSM_NOAUDIT: The event is not auditable for BSM; the BSM record is NULL. 
 */
int
kaudit_to_bsm(struct kaudit_record *kar, struct au_record **pau)
{
	struct au_token *tok, *subj_tok;
	struct au_record *rec;
	au_tid_t tid;
	struct audit_record *ar;
	struct vattr vattr;
	int sorf;
	int ctr;

	*pau = NULL;
	if (kar == NULL)
		return (BSM_FAILURE);

	ar = &kar->k_ar;

	/*
	 * Decide whether to create the BSM audit record by checking the
	 * error value from the system call and using the appropriate
	 * user audit mask. 
	 */
	if (ar->ar_errno) 
		sorf = AU_PRS_FAILURE;
	else
		sorf = AU_PRS_SUCCESS;

	if (au_preselect(ar->ar_event, &ar->ar_subj_amask, sorf) == 0)
		return (BSM_NOAUDIT);

	rec = kau_open();
	if (rec == NULL)
		return (BSM_FAILURE);

	/* Create the subject token */
	tid.port = ar->ar_subj_term.port;
	tid.machine = ar->ar_subj_term.machine;
	subj_tok = au_to_subject32(ar->ar_subj_auid,  /* audit ID */
		ar->ar_subj_cred.cr_uid, /* eff uid */
		ar->ar_subj_egid,	/* eff group id */
		ar->ar_subj_ruid, 	/* real uid */
		ar->ar_subj_rgid, 	/* real group id */
		ar->ar_subj_pid,	/* process id */
		ar->ar_subj_asid,	/* session ID */
		&tid);

	/* The logic inside each case fills in the tokens required for the
	 * event, except for the header, trailer, and return tokens. The 
	 * header and trailer tokens are added by the kau_close() function.
	 * The return token is added outside of the switch statement.
	 */ 
	switch(ar->ar_event) {

	/* 
	 * Socket-related events. 
	 */
	case AUE_ACCEPT:
	case AUE_BIND:
	case AUE_CONNECT:
	case AUE_RECVFROM:
	case AUE_RECVMSG:   
	case AUE_SENDMSG:
	case AUE_SENDTO:
		tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_SADDRINET) {
			tok = au_to_sock_inet(
				(struct sockaddr_in *)&ar->ar_arg_sockaddr);
			kau_write(rec, tok);
		}
		if (ar->ar_valid_arg & ARG_SADDRUNIX) {
			tok = au_to_sock_unix(
				(struct sockaddr_un *)&ar->ar_arg_sockaddr);
			kau_write(rec, tok);
			UPATH1_TOKENS;
		}
		/* XXX Need to handle ARG_SADDRINET6 */
		break;

	case AUE_SOCKET:
	case AUE_SOCKETPAIR:
		tok = au_to_arg32(1,"domain", ar->ar_arg_sockinfo.sodomain);
		kau_write(rec, tok);
		tok = au_to_arg32(2,"type", ar->ar_arg_sockinfo.sotype);
		kau_write(rec, tok);
		tok = au_to_arg32(3,"protocol", ar->ar_arg_sockinfo.soprotocol);
		kau_write(rec, tok);
		break;

	case AUE_SETSOCKOPT:
	case AUE_SHUTDOWN:
		tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
		kau_write(rec, tok);
		break;

	case AUE_SETAUID:
		tok = au_to_arg32(2, "setauid", ar->ar_arg_auid);
		kau_write(rec, tok);
		/* fall through */
	case AUE_ADJTIME:
	case AUE_AUDIT:
	case AUE_EXIT:
	case AUE_GETAUID:
	case AUE_GETFSSTAT:
	case AUE_PIPE:
	case AUE_SETPGRP:
	case AUE_SETRLIMIT:
		/* Header, subject, and return tokens added at end */
		break;

	case AUE_ACCESS:
	case AUE_CHDIR:
	case AUE_CHROOT:
	case AUE_EXECVE:
	case AUE_GETATTRLIST:
	case AUE_GETFH:
	case AUE_LSTAT:
	case AUE_MKFIFO:
	case AUE_PATHCONF:
	case AUE_READLINK:
	case AUE_REVOKE:
	case AUE_RMDIR:
	case AUE_SEARCHFS:
	case AUE_SETATTRLIST:
	case AUE_STAT:
	case AUE_STATFS:
	case AUE_TRUNCATE:
	case AUE_UNDELETE:
	case AUE_UNLINK:
	case AUE_UTIMES:
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;

	case AUE_CHFLAGS:
		tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;
	
	case AUE_CHMOD:
		tok = au_to_arg32(2, "new file mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;
	
	case AUE_CHOWN:
		tok = au_to_arg32(2, "new file uid", ar->ar_arg_uid);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "new file gid", ar->ar_arg_gid);
		kau_write(rec, tok);
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;
	
	case AUE_EXCHANGEDATA:
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		KPATH2_VNODE2_TOKENS;
		break;

/*
 * XXXAUDIT: Close is not audited in the kernel yet. 
	case AUE_CLOSE:
		tok = au_to_arg32(2, "fd", ar->ar_arg_fd);
		kau_write(rec, tok);
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;
*/
	case AUE_FCHMOD:
		tok = au_to_arg32(2, "new file mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		FD_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_FCHDIR:
	case AUE_FPATHCONF:
	case AUE_FSTAT:		/* XXX Need to handle sockets and shm */
	case AUE_FSTATFS:
	case AUE_FTRUNCATE:
	case AUE_FUTIMES:
	case AUE_GETDIRENTRIES:
	case AUE_GETDIRENTRIESATTR:
		FD_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_FCHOWN:
		tok = au_to_arg32(2, "new file uid", ar->ar_arg_uid);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "new file gid", ar->ar_arg_gid);
		kau_write(rec, tok);
		FD_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_FCNTL:
		if (ar->ar_arg_cmd == F_GETLK || ar->ar_arg_cmd == F_SETLK ||
			ar->ar_arg_cmd == F_SETLKW) {
			tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
			kau_write(rec, tok);
			FD_KPATH1_VNODE1_TOKENS;
		}
		break;
	
	case AUE_FCHFLAGS:
		tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		FD_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_FLOCK:
		tok = au_to_arg32(2, "operation", ar->ar_arg_cmd);
		kau_write(rec, tok);
		FD_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_LINK:
	case AUE_RENAME:
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		UPATH2_TOKENS;
		break;

	case AUE_MKDIR:
		tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;

	case AUE_MKNOD:
		tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "dev", ar->ar_arg_dev);
		kau_write(rec, tok);
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;

	case AUE_MOUNT:
		/* XXX Need to handle NFS mounts */
		tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		if (ar->ar_arg_text != NULL) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		/* fall through */
	case AUE_UMOUNT:
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;

	case AUE_MSGCTL:
		ar->ar_event = msgctl_to_event(ar->ar_arg_svipc_cmd);
		/* Fall through */
	case AUE_MSGRCV:
	case AUE_MSGSND:
		tok = au_to_arg32(1, "msg ID", ar->ar_arg_svipc_id);
		kau_write(rec, tok);
		if (ar->ar_errno != EINVAL) {
			tok = au_to_ipc(AT_IPC_MSG, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		break;

	case AUE_MSGGET:
		if (ar->ar_errno == 0) {
			tok = au_to_ipc(AT_IPC_MSG, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		break;

	case AUE_OPEN_R:
	case AUE_OPEN_RC:
	case AUE_OPEN_RTC:
	case AUE_OPEN_RT:
	case AUE_OPEN_RW:
	case AUE_OPEN_RWC:
	case AUE_OPEN_RWTC:
	case AUE_OPEN_RWT:
	case AUE_OPEN_W:
	case AUE_OPEN_WC:
	case AUE_OPEN_WTC:
	case AUE_OPEN_WT:
		/* The open syscall always writes a OPEN_R event; convert the
		 * file flags to the proper type of event.
		 */
		ar->ar_event = flags_to_openevent(ar->ar_arg_fflags);
		UPATH1_TOKENS;		/* Save the user space path */
		KPATH1_VNODE1_TOKENS;	/* Audit the kernel path as well */
		break;

	case AUE_QUOTACTL:
		tok = au_to_arg32(2, "command", ar->ar_arg_cmd);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "uid", ar->ar_arg_uid);
		kau_write(rec, tok);
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;

	case AUE_SEMCTL:
		ar->ar_event = semctl_to_event(ar->ar_arg_svipc_cmd);
		/* Fall through */
	case AUE_SEMOP:
		tok = au_to_arg32(1, "sem ID", ar->ar_arg_svipc_id);
		kau_write(rec, tok);
		if (ar->ar_errno != EINVAL) {
			tok = au_to_ipc(AT_IPC_SEM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		break;
	case AUE_SEMGET:
		if (ar->ar_errno == 0) {
			tok = au_to_ipc(AT_IPC_SEM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		break;
	case AUE_SETEGID:
		tok = au_to_arg32(1, "gid", ar->ar_arg_egid);
		kau_write(rec, tok);
		break;
	case AUE_SETEUID:
		tok = au_to_arg32(1, "uid", ar->ar_arg_euid);
		kau_write(rec, tok);
		break;
	case AUE_SETGID:
		tok = au_to_arg32(1, "gid", ar->ar_arg_gid);
		kau_write(rec, tok);
		break;
	case AUE_SETUID:
		tok = au_to_arg32(1, "uid", ar->ar_arg_uid);
		kau_write(rec, tok);
		break;
	case AUE_SETGROUPS:
		if (ar->ar_valid_arg & ARG_GROUPSET) {
			for(ctr = 0; ctr < ar->ar_arg_groups.gidset_size; ctr++)
			{
				tok = au_to_arg32(1, "setgroups", 							ar->ar_arg_groups.gidset[ctr]);
				kau_write(rec, tok);
			}
		}
		break;
	case AUE_SHMAT:
		tok = au_to_arg32(1, "shmid", ar->ar_arg_svipc_id);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "shmaddr", (int)ar->ar_arg_svipc_addr);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_SVIPC_PERM) {
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SHMCTL:
		tok = au_to_arg32(1, "shmid", ar->ar_arg_svipc_id);
		kau_write(rec, tok);
		switch (ar->ar_arg_svipc_cmd) {
		case IPC_STAT:
			ar->ar_event = AUE_SHMCTL_STAT;
			if (ar->ar_valid_arg & ARG_SVIPC_PERM) {
				tok = au_to_ipc(AT_IPC_SHM, 
						ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
			break;
		case IPC_RMID:
			ar->ar_event = AUE_SHMCTL_RMID;
			if (ar->ar_valid_arg & ARG_SVIPC_PERM) {
				tok = au_to_ipc(AT_IPC_SHM, 
						ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
			break;
		case IPC_SET:
			ar->ar_event = AUE_SHMCTL_SET;
			if (ar->ar_valid_arg & ARG_SVIPC_PERM) {
				tok = au_to_ipc(AT_IPC_SHM, 
						ar->ar_arg_svipc_id);
				kau_write(rec, tok);
				tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
				kau_write(rec, tok);
		}
			break;
		default:
			break;	/* We will audit a bad command */
		}
		break;

	case AUE_SHMDT:
		tok = au_to_arg32(1, "shmaddr", (int)ar->ar_arg_svipc_addr);
		kau_write(rec, tok);
		break;

	case AUE_SHMGET:
		/* This is unusual; the return value is in an argument token */
		tok = au_to_arg32(0, "shmid", ar->ar_arg_svipc_id);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_SVIPC_PERM) {
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SYMLINK:
		if (ar->ar_valid_arg & ARG_TEXT) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		KPATH1_VNODE1_OR_UPATH1_TOKENS;
		break;

	case AUE_UMASK:
		tok = au_to_arg32(1, "new mask", ar->ar_arg_mask);
		kau_write(rec, tok);
		tok = au_to_arg32(0, "prev mask", ar->ar_retval);
		kau_write(rec, tok);
		break;

	default: /* We shouldn't fall through to here. */
		printf("BSM conversion requested for unknown event %d\n",
			ar->ar_event);
		kau_free(rec);
		return BSM_NOAUDIT;
	}

	kau_write(rec, subj_tok); 
	tok = au_to_return32((char)ar->ar_errno, ar->ar_retval);
	kau_write(rec, tok);  /* Every record gets a return token */

	kau_close(rec, &ar->ar_endtime, ar->ar_event);

	*pau = rec;
	return BSM_SUCCESS;
}

/*
 * Verify that a record is a valid BSM record. This verification is
 * simple now, but may be expanded on sometime in the future.
 * Return 1 if the record is good, 0 otherwise.
 *
 */
int
bsm_rec_verify(caddr_t rec)
{
	/* 
	 * Check the token ID of the first token; it has to be a header
	 * token.
	 */
	/* XXXAUDIT There needs to be a token structure to map a token. 
	 * XXXAUDIT 'Shouldn't be simply looking at the first char.
	 */
	if ( ((char)*rec != AU_HEADER_32_TOKEN) && 
		((char)*rec != AU_HEADER_EX_32_TOKEN) && 
		((char)*rec != AU_HEADER_64_TOKEN) && 
		((char)*rec != AU_HEADER_EX_64_TOKEN) ) {
		return (0);
	}
	return (1);
}
