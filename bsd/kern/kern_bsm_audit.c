/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
#include <sys/types.h>
#include <sys/vnode_internal.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/socketvar.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/fcntl.h>
#include <sys/user.h>

#include <sys/ipc.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>
#include <bsm/audit_klib.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <kern/lock.h>
#include <kern/kalloc.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

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
static lck_grp_t	*bsm_audit_grp;
static lck_attr_t	*bsm_audit_attr;
static lck_grp_attr_t	*bsm_audit_grp_attr;
static lck_mtx_t	*bsm_audit_mutex;

static void audit_sys_auditon(struct audit_record *ar, struct au_record *rec);

/*
 * Initialize the BSM auditing subsystem.
 */
void
kau_init(void)
{
	printf("BSM auditing present\n");
	LIST_INIT(&bsm_free_q);
	bsm_audit_grp_attr = lck_grp_attr_alloc_init();
	bsm_audit_grp = lck_grp_alloc_init("BSM Audit", bsm_audit_grp_attr);
	bsm_audit_attr = lck_attr_alloc_init();
	bsm_audit_mutex = lck_mtx_alloc_init(bsm_audit_grp, bsm_audit_attr);
	au_evclassmap_init();
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
	lck_mtx_lock(bsm_audit_mutex);
	if (!LIST_EMPTY(&bsm_free_q)) {
		rec = LIST_FIRST(&bsm_free_q);
		LIST_REMOVE(rec, au_rec_q);
	}
	lck_mtx_unlock(bsm_audit_mutex);

	if (rec == NULL) {
		lck_mtx_lock(bsm_audit_mutex);
		if (bsm_rec_count >= MAX_AUDIT_RECORDS) {
			/* XXX We need to increase size of MAX_AUDIT_RECORDS */
			lck_mtx_unlock(bsm_audit_mutex);
			return NULL;
		}
		lck_mtx_unlock(bsm_audit_mutex);
			
		/*
		 * Create a new BSM kernel record.
		 */
		rec = (struct au_record *)kalloc(sizeof(*rec));
		if(rec == NULL) {
			return NULL;
		}
		rec->data = (u_char *)kalloc(MAX_AUDIT_RECORD_SIZE * sizeof(u_char));
		if((rec->data) == NULL) {
			kfree(rec, sizeof(*rec));
			return NULL;
		}
		lck_mtx_lock(bsm_audit_mutex);
		bsm_rec_count++;
		lck_mtx_unlock(bsm_audit_mutex);
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
int
kau_close(struct au_record *rec, struct timespec *ctime, short event)
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

	return(retval);
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
		kfree(tok, sizeof(*tok) + tok->len);
	}	

	rec->used = 0;
	rec->len = 0;	

	lck_mtx_lock(bsm_audit_mutex);

	/* Add the record to the freelist */
	LIST_INSERT_HEAD(&bsm_free_q, rec, au_rec_q);
	
	lck_mtx_unlock(bsm_audit_mutex);

}

/*
 * XXX May want turn some (or all) of these macros into functions in order
 * to reduce the generated code size.
 */
#if CONFIG_MACF
#define MAC_VNODE1_LABEL_TOKEN						\
	do {								\
		if (ar->ar_vnode1_mac_labels != NULL) {			\
			tok = au_to_text(ar->ar_vnode1_mac_labels);	\
			kau_write(rec, tok);				\
		}							\
	} while (0)

#define MAC_VNODE2_LABEL_TOKEN						\
	do {								\
		if (ar->ar_vnode2_mac_labels != NULL) {			\
			tok = au_to_text(ar->ar_vnode2_mac_labels);	\
			kau_write(rec, tok);				\
		}							\
	} while (0)
#else
#define MAC_VNODE1_LABEL_TOKEN
#define MAC_VNODE2_LABEL_TOKEN
#endif
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

#define UPATH1_KPATH1_VNODE1_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_UPATH1) {  		\
			tok = au_to_path(ar->ar_arg_upath1);	\
			kau_write(rec, tok);			\
		}						\
		if (ar->ar_valid_arg & ARG_KPATH1) {  		\
			tok = au_to_path(ar->ar_arg_kpath1);	\
			kau_write(rec, tok);			\
		}						\
		if (ar->ar_valid_arg & ARG_VNODE1) {  		\
			tok = kau_to_attr32(&ar->ar_arg_vnode1);\
			kau_write(rec, tok);			\
			MAC_VNODE1_LABEL_TOKEN;			\
		}						\
	} while (0)

#define KPATH1_VNODE1_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_KPATH1) {  		\
			tok = au_to_path(ar->ar_arg_kpath1);	\
			kau_write(rec, tok);			\
		}						\
		if (ar->ar_valid_arg & ARG_VNODE1) {  		\
			tok = kau_to_attr32(&ar->ar_arg_vnode1);\
			kau_write(rec, tok);			\
			MAC_VNODE1_LABEL_TOKEN;			\
		}						\
	} while (0)

#define KPATH2_VNODE2_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_KPATH2) {  		\
			tok = au_to_path(ar->ar_arg_kpath2);	\
			kau_write(rec, tok);			\
		}						\
		if (ar->ar_valid_arg & ARG_VNODE2) {  		\
			tok = kau_to_attr32(&ar->ar_arg_vnode2);\
			kau_write(rec, tok);			\
			MAC_VNODE2_LABEL_TOKEN;			\
		}						\
	} while (0)

#define FD_KPATH1_VNODE1_TOKENS	\
	do { \
		if (ar->ar_valid_arg & ARG_KPATH1) {		\
			tok = au_to_path(ar->ar_arg_kpath1);	\
			kau_write(rec, tok);			\
			if (ar->ar_valid_arg & ARG_VNODE1) {  	\
				tok = kau_to_attr32(&ar->ar_arg_vnode1);\
				kau_write(rec, tok);		\
				MAC_VNODE1_LABEL_TOKEN;		\
			}					\
		} else {					\
			tok = au_to_arg32(1, "no path: fd", ar->ar_arg_fd); \
			kau_write(rec, tok);			\
		}						\
	} while (0)

#define PROCESS_PID_TOKENS(argn)	\
	do { \
		if ((ar->ar_arg_pid > 0) /* Kill a single process */	\
		    && (ar->ar_valid_arg & ARG_PROCESS)) {		\
			tok = au_to_process(ar->ar_arg_auid, ar->ar_arg_euid, \
				ar->ar_arg_egid, ar->ar_arg_ruid,	\
				ar->ar_arg_rgid, ar->ar_arg_pid,	\
				ar->ar_arg_asid, &ar->ar_arg_termid);	\
			kau_write(rec, tok);				\
		} else {						\
			tok = au_to_arg32(argn, "process", ar->ar_arg_pid);\
			kau_write(rec, tok);				\
		}							\
	} while (0)							\

#define PROCESS_MAC_TOKENS						\
	do {								\
		if (ar->ar_valid_arg & ARG_MAC_STRING) {		\
			tok = au_to_text(ar->ar_arg_mac_string);	\
			kau_write(rec, tok);				\
		}							\
	} while (0)							\

/*
 * Implement auditing for the auditon() system call. The audit tokens
 * that are generated depend on the command that was sent into the 
 * auditon() system call.
 *
 */
static void
audit_sys_auditon(struct audit_record *ar, struct au_record *rec)
{
	struct au_token *tok;

	switch (ar->ar_arg_cmd) {
	case A_SETPOLICY:
		if (sizeof(ar->ar_arg_auditon.au_flags) > 4)
			tok = au_to_arg64(1, "policy", 
				ar->ar_arg_auditon.au_flags);
		else
			tok = au_to_arg32(1, "policy", 
				ar->ar_arg_auditon.au_flags);
		kau_write(rec, tok);
		break;
	case A_SETKMASK:
		tok = au_to_arg32(2, "setkmask:as_success", 
			ar->ar_arg_auditon.au_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setkmask:as_failure", 
			ar->ar_arg_auditon.au_mask.am_failure);
		kau_write(rec, tok);
		break;
	case A_SETQCTRL:
		tok = au_to_arg32(3, "setqctrl:aq_hiwater", 
			ar->ar_arg_auditon.au_qctrl.aq_hiwater);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_lowater", 
			ar->ar_arg_auditon.au_qctrl.aq_lowater);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_bufsz", 
			ar->ar_arg_auditon.au_qctrl.aq_bufsz);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_delay", 
			ar->ar_arg_auditon.au_qctrl.aq_delay);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setqctrl:aq_minfree", 
			ar->ar_arg_auditon.au_qctrl.aq_minfree);
		kau_write(rec, tok);
		break;
	case A_SETUMASK:
		tok = au_to_arg32(3, "setumask:as_success", 
			ar->ar_arg_auditon.au_auinfo.ai_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setumask:as_failure", 
			ar->ar_arg_auditon.au_auinfo.ai_mask.am_failure);
		kau_write(rec, tok);
		break;
	case A_SETSMASK:
		tok = au_to_arg32(3, "setsmask:as_success", 
			ar->ar_arg_auditon.au_auinfo.ai_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setsmask:as_failure", 
			ar->ar_arg_auditon.au_auinfo.ai_mask.am_failure);
		kau_write(rec, tok);
		break;
	case A_SETCOND:
		if (sizeof(ar->ar_arg_auditon.au_cond) > 4)
			tok = au_to_arg64(3, "setcond", 
				ar->ar_arg_auditon.au_cond);
		else
			tok = au_to_arg32(3, "setcond", 
				ar->ar_arg_auditon.au_cond);
		kau_write(rec, tok);
		break;
	case A_SETCLASS:
		tok = au_to_arg32(2, "setclass:ec_event",
			ar->ar_arg_auditon.au_evclass.ec_number);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setclass:ec_class",
			ar->ar_arg_auditon.au_evclass.ec_class);
		kau_write(rec, tok);
		break;
	case A_SETPMASK:
		tok = au_to_arg32(2, "setpmask:as_success", 
			ar->ar_arg_auditon.au_aupinfo.ap_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setpmask:as_failure", 
			ar->ar_arg_auditon.au_aupinfo.ap_mask.am_failure);
		kau_write(rec, tok);
		break;
	case A_SETFSIZE:
		tok = au_to_arg32(2, "setfsize:filesize", 
			ar->ar_arg_auditon.au_fstat.af_filesz);
		kau_write(rec, tok);
		break;
	default:
		break;
	}
}

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
	struct au_token *tok = NULL, *subj_tok;
	struct au_record *rec;
	au_tid_t tid;
	struct audit_record *ar;

	*pau = NULL;
	if (kar == NULL)
		return (BSM_FAILURE);

	ar = &kar->k_ar;

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
		tok = au_to_arg32(1,"domain", ar->ar_arg_sockinfo.so_domain);
		kau_write(rec, tok);
		tok = au_to_arg32(2,"type", ar->ar_arg_sockinfo.so_type);
		kau_write(rec, tok);
		tok = au_to_arg32(3,"protocol",ar->ar_arg_sockinfo.so_protocol);
		kau_write(rec, tok);
		break;

	case AUE_SETSOCKOPT:
	case AUE_SHUTDOWN:
		tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
		kau_write(rec, tok);
		break;

	case AUE_ACCT:
		if (ar->ar_valid_arg & (ARG_KPATH1 | ARG_UPATH1)) {
			UPATH1_KPATH1_VNODE1_TOKENS;
		} else {
			tok = au_to_arg32(1, "accounting off", 0);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUID:
		tok = au_to_arg32(2, "setauid", ar->ar_arg_auid);
		kau_write(rec, tok);
		break;

	case AUE_SETAUDIT:
		if (ar->ar_valid_arg & ARG_AUID) {
			tok = au_to_arg32(1, "setaudit:auid", ar->ar_arg_auid);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:port", 
					ar->ar_arg_termid.port);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:machine", 
					ar->ar_arg_termid.machine);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:as_success", 
					ar->ar_arg_amask.am_success);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:as_failure", 
					ar->ar_arg_amask.am_failure);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit:asid", ar->ar_arg_asid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUDIT_ADDR:
		break;		/* XXX need to add arguments */

	case AUE_AUDITON:
		/* For AUDITON commands without own event, audit the cmd */
		tok = au_to_arg32(1, "cmd", ar->ar_arg_cmd);
		kau_write(rec, tok);
		/* fall thru */

	case AUE_AUDITON_GETCAR:
	case AUE_AUDITON_GETCLASS:
	case AUE_AUDITON_GETCOND:
	case AUE_AUDITON_GETCWD:
	case AUE_AUDITON_GETKMASK:
	case AUE_AUDITON_GETSTAT:
	case AUE_AUDITON_GPOLICY:
	case AUE_AUDITON_GQCTRL:
	case AUE_AUDITON_SETCLASS:
	case AUE_AUDITON_SETCOND:
	case AUE_AUDITON_SETKMASK:
	case AUE_AUDITON_SETSMASK:
	case AUE_AUDITON_SETSTAT:
	case AUE_AUDITON_SETUMASK:
	case AUE_AUDITON_SPOLICY:
	case AUE_AUDITON_SQCTRL:
		if (ar->ar_valid_arg & ARG_AUDITON) {
			audit_sys_auditon(ar, rec);
		}
		break;
	
	case AUE_AUDITCTL:
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_ADJTIME:
	case AUE_AUDIT:
	case AUE_EXIT:
	case AUE_GETAUDIT:
	case AUE_GETAUDIT_ADDR:
	case AUE_GETAUID:
	case AUE_GETFSSTAT:
	case AUE_MAC_GETFSSTAT:
	case AUE_PIPE:
	case AUE_SETPGRP:
	case AUE_SETRLIMIT:
	case AUE_SETSID:
	case AUE_SETTIMEOFDAY:
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
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_CHFLAGS:
		tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_CHMOD:
		tok = au_to_arg32(2, "new file mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_CHOWN:
	case AUE_LCHOWN:
		tok = au_to_arg32(2, "new file uid", ar->ar_arg_uid);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "new file gid", ar->ar_arg_gid);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_EXCHANGEDATA:
		UPATH1_KPATH1_VNODE1_TOKENS;
		KPATH2_VNODE2_TOKENS;
		break;

	case AUE_CLOSE:
		tok = au_to_arg32(2, "fd", ar->ar_arg_fd);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_FCHMOD:
		tok = au_to_arg32(2, "new file mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		FD_KPATH1_VNODE1_TOKENS;
		break;
	
	case AUE_NFSSVC:
		tok = au_to_arg32(1, "request", ar->ar_arg_cmd);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & (ARG_KPATH1 | ARG_UPATH1)) {
			UPATH1_KPATH1_VNODE1_TOKENS;
		}
		break;

	case AUE_FCHDIR:
	case AUE_FPATHCONF:
	case AUE_FSTAT:		/* XXX Need to handle sockets and shm */
	case AUE_FSTATFS:
	case AUE_FTRUNCATE:
	case AUE_FUTIMES:
	case AUE_GETDIRENTRIES:
	case AUE_GETDIRENTRIESATTR:
	case AUE_EXTATTR_GET_FD:
	case AUE_EXTATTR_LIST_FD:
	case AUE_EXTATTR_SET_FD:
	case AUE_EXTATTR_DELETE_FD:
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
		tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_VNODE1) {
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
	
	case AUE_FORK:
	case AUE_VFORK:
		tok = au_to_arg32(0, "child PID", ar->ar_arg_pid);
		kau_write(rec, tok);
		break;
	
	case AUE_GETLCID:
		tok = au_to_arg32(1, "pid", (u_int32_t)ar->ar_arg_pid);
		kau_write(rec, tok);
		break;

	case AUE_SETLCID:
		tok = au_to_arg32(1, "pid", (u_int32_t)ar->ar_arg_pid);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "lcid", (u_int32_t)ar->ar_arg_value);
		kau_write(rec, tok);
		break;

	case AUE_IOCTL:
		tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
		kau_write(rec, tok);
		tok = au_to_arg32(1, "arg", (u_int32_t)ar->ar_arg_addr);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_VNODE1) {
			FD_KPATH1_VNODE1_TOKENS;
		} else {
			if (ar->ar_valid_arg & ARG_SOCKINFO) {
			    tok = kau_to_socket(&ar->ar_arg_sockinfo); 
			    kau_write(rec, tok);
			} else {
			    tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
			    kau_write(rec, tok);
			}
		}
		break;

	case AUE_KILL:
		tok = au_to_arg32(2, "signal", ar->ar_arg_signum);
		kau_write(rec, tok);
		PROCESS_PID_TOKENS(1);
		break;

	case AUE_LINK:
	case AUE_RENAME:
		UPATH1_KPATH1_VNODE1_TOKENS;
		UPATH2_TOKENS;
		break;

	case AUE_MKDIR:
		tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_MKNOD:
		tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "dev", ar->ar_arg_dev);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_MMAP:
	case AUE_MUNMAP:
	case AUE_MPROTECT:
	case AUE_MLOCK:
	case AUE_MUNLOCK:
	case AUE_MINHERIT:
		tok = au_to_arg32(1, "addr", (u_int32_t)ar->ar_arg_addr); /* LP64todo */
		kau_write(rec, tok);
		tok = au_to_arg32(2, "len", ar->ar_arg_len); /* LP64todo */
		kau_write(rec, tok);
		if (ar->ar_event == AUE_MMAP)
			FD_KPATH1_VNODE1_TOKENS;
		if (ar->ar_event == AUE_MPROTECT) {
			tok = au_to_arg32(3, "protection", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		if (ar->ar_event == AUE_MINHERIT) {
			tok = au_to_arg32(3, "inherit", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		break;

#if CONFIG_MACF
	case AUE_MAC_MOUNT:
		PROCESS_MAC_TOKENS;
		/* fall through */
#endif
	case AUE_MOUNT:
		/* XXX Need to handle NFS mounts */
		tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_TEXT) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		/* fall through */
	case AUE_UNMOUNT:
		UPATH1_KPATH1_VNODE1_TOKENS;
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

	case AUE_OPEN_RC:
	case AUE_OPEN_RTC:
	case AUE_OPEN_RWC:
	case AUE_OPEN_RWTC:
	case AUE_OPEN_WC:
	case AUE_OPEN_WTC:
		tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		/* fall thru */

	case AUE_OPEN:
	case AUE_OPEN_R:
	case AUE_OPEN_RT:
	case AUE_OPEN_RW:
	case AUE_OPEN_RWT:
	case AUE_OPEN_W:
	case AUE_OPEN_WT:
		tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_PTRACE:
		tok = au_to_arg32(1, "request", ar->ar_arg_cmd);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "addr", (u_int32_t)ar->ar_arg_addr); /* LP64todo */
		kau_write(rec, tok);
		tok = au_to_arg32(4, "data", ar->ar_arg_value);
		kau_write(rec, tok);
		PROCESS_PID_TOKENS(2);
		break;

	case AUE_QUOTACTL:
		tok = au_to_arg32(2, "command", ar->ar_arg_cmd);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "uid", ar->ar_arg_uid);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_REBOOT:
		tok = au_to_arg32(1, "howto", ar->ar_arg_cmd);
		kau_write(rec, tok);
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
			u_int ctr;

			for(ctr = 0; ctr < ar->ar_arg_groups.gidset_size; ctr++)
			{
				tok = au_to_arg32(1, "setgroups", ar->ar_arg_groups.gidset[ctr]);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_SETLOGIN:
		if (ar->ar_valid_arg & ARG_TEXT) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETPRIORITY:
		tok = au_to_arg32(1, "which", ar->ar_arg_cmd);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "who", ar->ar_arg_uid);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "priority", ar->ar_arg_value);
		kau_write(rec, tok);
		break;

	case AUE_SETPRIVEXEC:
		tok = au_to_arg32(1, "flag", ar->ar_arg_value);
		kau_write(rec, tok);
		break;

	/* AUE_SHMAT, AUE_SHMCTL, AUE_SHMDT and AUE_SHMGET are SysV IPC */
	case AUE_SHMAT:
		tok = au_to_arg32(1, "shmid", ar->ar_arg_svipc_id);
		kau_write(rec, tok);
		tok = au_to_arg64(2, "shmaddr", ar->ar_arg_svipc_addr);
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
		tok = au_to_arg64(1, "shmaddr", ar->ar_arg_svipc_addr);
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

	/* AUE_SHMOPEN, AUE_SHMUNLINK, AUE_SEMOPEN, AUE_SEMCLOSE 
	 * and AUE_SEMUNLINK are Posix IPC */
	case AUE_SHMOPEN:
		tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
		kau_write(rec, tok);
	case AUE_SHMUNLINK:
		if (ar->ar_valid_arg & ARG_TEXT) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		if (ar->ar_valid_arg & ARG_POSIX_IPC_PERM) {
		/* Create an ipc_perm token */
			struct ipc_perm perm;
			perm.uid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.gid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.cuid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.cgid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.mode = ar->ar_arg_pipc_perm.pipc_mode;
			perm._seq = 0;
			perm._key = 0;
			tok = au_to_ipc_perm(&perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SEMOPEN:
		tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
		kau_write(rec, tok);
		tok = au_to_arg32(4, "value", ar->ar_arg_value);
		kau_write(rec, tok);
		/* fall through */
	case AUE_SEMUNLINK:
		if (ar->ar_valid_arg & ARG_TEXT) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		if (ar->ar_valid_arg & ARG_POSIX_IPC_PERM) {
		/* Create an ipc_perm token */
			struct ipc_perm perm;
			perm.uid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.gid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.cuid = ar->ar_arg_pipc_perm.pipc_uid;
			perm.cgid = ar->ar_arg_pipc_perm.pipc_gid;
			perm.mode = ar->ar_arg_pipc_perm.pipc_mode;
			perm._seq = 0;
			perm._key = 0;
			tok = au_to_ipc_perm(&perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SEMCLOSE:
		tok = au_to_arg32(1, "sem", ar->ar_arg_fd);
		kau_write(rec, tok);
		break;

	case AUE_SYMLINK:
		if (ar->ar_valid_arg & ARG_TEXT) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_SYSCTL:
	case AUE_SYSCTL_NONADMIN:
		if (ar->ar_valid_arg & (ARG_CTLNAME | ARG_LEN)) {
			int ctr;

			for (ctr = 0; ctr < ar->ar_arg_len; ctr++) {
			  tok = au_to_arg32(1, "name", ar->ar_arg_ctlname[ctr]);
			  kau_write(rec, tok);
			}
		}
		if (ar->ar_valid_arg & ARG_VALUE) {
			tok = au_to_arg32(5, "newval", ar->ar_arg_value);
			kau_write(rec, tok);
		}
		if (ar->ar_valid_arg & ARG_TEXT) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_UMASK:
		tok = au_to_arg32(1, "new mask", ar->ar_arg_mask);
		kau_write(rec, tok);
		tok = au_to_arg32(0, "prev mask", ar->ar_retval);
		kau_write(rec, tok);
		break;

	/************************
	 * Mach system calls    *
	 ************************/
	case AUE_INITPROCESS:
		break;

	case AUE_PIDFORTASK:
		tok = au_to_arg32(1, "port", (u_int32_t)ar->ar_arg_mach_port1);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_PID) {
			tok = au_to_arg32(2, "pid", (u_int32_t)ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		break;

	case AUE_TASKFORPID:
		tok = au_to_arg32(1, "target port", 
			(u_int32_t)ar->ar_arg_mach_port1);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & ARG_MACHPORT2) {
			tok = au_to_arg32(3, "task port", 
				(u_int32_t)ar->ar_arg_mach_port2);
			kau_write(rec, tok);
		}
		PROCESS_PID_TOKENS(2);
		break;

	case AUE_SWAPON:
		tok = au_to_arg32(4, "priority", 
			(u_int32_t)ar->ar_arg_value);
		kau_write(rec, tok);
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_SWAPOFF:
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_MAPFD:
		tok = au_to_arg32(3, "va", (u_int32_t)ar->ar_arg_addr);
		kau_write(rec, tok);
		FD_KPATH1_VNODE1_TOKENS;
		break;

	case AUE_EXTATTR_GET_FILE:
	case AUE_EXTATTR_SET_FILE:
	case AUE_EXTATTR_LIST_FILE:
	case AUE_EXTATTR_DELETE_FILE:
	case AUE_EXTATTR_GET_LINK:
	case AUE_EXTATTR_SET_LINK:
	case AUE_EXTATTR_LIST_LINK:
	case AUE_EXTATTR_DELETE_LINK:
		UPATH1_KPATH1_VNODE1_TOKENS;
		break;

#if CONFIG_MACF
	case AUE_MAC_GET_FILE:
	case AUE_MAC_SET_FILE:
	case AUE_MAC_GET_LINK:
	case AUE_MAC_SET_LINK:
	case AUE_MAC_GET_MOUNT:
		UPATH1_KPATH1_VNODE1_TOKENS;
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_FD:
	case AUE_MAC_SET_FD:
		FD_KPATH1_VNODE1_TOKENS;
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_SYSCALL:
		PROCESS_MAC_TOKENS;
		tok = au_to_arg32(3, "call", ar->ar_arg_value);
		kau_write(rec, tok);
		break;

	case AUE_MAC_EXECVE:
		UPATH1_KPATH1_VNODE1_TOKENS;
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_PID:
		tok = au_to_arg32(1, "pid", (u_int32_t)ar->ar_arg_pid);
		kau_write(rec, tok);
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_LCID:
		tok = au_to_arg32(1, "lcid", (u_int32_t)ar->ar_arg_value);
		kau_write(rec, tok);
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_PROC:
	case AUE_MAC_SET_PROC:
	case AUE_MAC_GET_LCTX:
	case AUE_MAC_SET_LCTX:
		PROCESS_MAC_TOKENS;
		break;
#endif

	default: /* We shouldn't fall through to here. */
		printf("BSM conversion requested for unknown event %d\n",
			ar->ar_event);
		kau_free(rec);
		return BSM_NOAUDIT;
	}

#if CONFIG_MACF
	do {
		/* Convert the audit data from the MAC policies */
		struct mac_audit_record *mar;
		
		LIST_FOREACH(mar, ar->ar_mac_records, records) {
			switch (mar->type) {
				case MAC_AUDIT_DATA_TYPE:
					tok = au_to_data(AUP_BINARY, AUR_BYTE,
					    mar->length, mar->data);
					break;
				case MAC_AUDIT_TEXT_TYPE:
					tok = au_to_text((char*) mar->data);
					break;
				default:
					/*
					 * XXX: we can either continue,
					 * skipping this particular entry,
					 * or we can pre-verify the list and
					 * abort before writing any records
					 */
					printf("kaudit_to_bsm(): BSM conversion requested for unknown mac_audit data type %d\n",
					    mar->type);
			}

			kau_write(rec, tok);
		}
	} while (0);
#endif

	kau_write(rec, subj_tok); 

#if CONFIG_MACF
	if (ar->ar_cred_mac_labels != NULL) {
		tok = au_to_text(ar->ar_cred_mac_labels);
		kau_write(rec, tok);
	}
#endif

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
bsm_rec_verify(void* rec)
{
	char c = *(char *)rec;
	/* 
	 * Check the token ID of the first token; it has to be a header
	 * token.
	 */
	/* XXXAUDIT There needs to be a token structure to map a token. 
	 * XXXAUDIT 'Shouldn't be simply looking at the first char.
	 */
	if ( (c != AU_HEADER_32_TOKEN) && 
		(c != AU_HEADER_EX_32_TOKEN) && 
		(c != AU_HEADER_64_TOKEN) && 
		(c != AU_HEADER_EX_64_TOKEN) ) {
		return (0);
	}
	return (1);
}
