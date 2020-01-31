/*
 * Copyright (c) 1999-2016 Apple Inc.
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
#include <bsm/audit_internal.h>
#include <bsm/audit_record.h>
#include <bsm/audit_kevents.h>

#include <security/audit/audit.h>
#include <security/audit/audit_bsd.h>
#include <security/audit/audit_private.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#if CONFIG_AUDIT
MALLOC_DEFINE(M_AUDITBSM, "audit_bsm", "Audit BSM data");

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

static void     audit_sys_auditon(struct audit_record *ar,
    struct au_record *rec);
static void     audit_sys_fcntl(struct kaudit_record *kar,
    struct au_record *rec);

/*
 * Initialize the BSM auditing subsystem.
 */
void
kau_init(void)
{
	au_evclassmap_init();
}

/*
 * This call reserves memory for the audit record.  Memory must be guaranteed
 * before any auditable event can be generated.  The au_record structure
 * maintains a reference to the memory allocated above and also the list of
 * tokens associated with this record.
 */
static struct au_record *
kau_open(void)
{
	struct au_record *rec;

	rec = malloc(sizeof(*rec), M_AUDITBSM, M_WAITOK);
	rec->data = NULL;
	TAILQ_INIT(&rec->token_q);
	rec->len = 0;
	rec->used = 1;

	return rec;
}

/*
 * Store the token with the record descriptor.
 */
static void
kau_write(struct au_record *rec, struct au_token *tok)
{
	KASSERT(tok != NULL, ("kau_write: tok == NULL"));

	TAILQ_INSERT_TAIL(&rec->token_q, tok, tokens);
	rec->len += tok->len;
}

/*
 * Close out the audit record by adding the header token, identifying any
 * missing tokens.  Write out the tokens to the record memory.
 */
static void
kau_close(struct au_record *rec, struct timespec *ctime, short event)
{
	u_char *dptr;
	size_t tot_rec_size;
	token_t *cur, *hdr, *trail;
	struct timeval tm;
	size_t hdrsize;
	struct auditinfo_addr ak;
	struct in6_addr *ap;

	audit_get_kinfo(&ak);
	hdrsize = 0;
	switch (ak.ai_termid.at_type) {
	case AU_IPv4:
		hdrsize = (ak.ai_termid.at_addr[0] == INADDR_ANY) ?
		    AUDIT_HEADER_SIZE : AUDIT_HEADER_EX_SIZE(&ak);
		break;
	case AU_IPv6:
		ap = (struct in6_addr *)&ak.ai_termid.at_addr[0];
		hdrsize = (IN6_IS_ADDR_UNSPECIFIED(ap)) ? AUDIT_HEADER_SIZE :
		    AUDIT_HEADER_EX_SIZE(&ak);
		break;
	default:
		panic("kau_close: invalid address family");
	}
	tot_rec_size = rec->len + AUDIT_HEADER_SIZE + AUDIT_TRAILER_SIZE;
	rec->data = malloc(tot_rec_size, M_AUDITBSM, M_WAITOK | M_ZERO);

	tm.tv_usec = ctime->tv_nsec / 1000;
	tm.tv_sec = ctime->tv_sec;
	if (hdrsize != AUDIT_HEADER_SIZE) {
		hdr = au_to_header32_ex_tm(tot_rec_size, event, 0, tm, &ak);
	} else {
		hdr = au_to_header32_tm(tot_rec_size, event, 0, tm);
	}
	TAILQ_INSERT_HEAD(&rec->token_q, hdr, tokens);

	trail = au_to_trailer(tot_rec_size);
	TAILQ_INSERT_TAIL(&rec->token_q, trail, tokens);

	rec->len = tot_rec_size;
	dptr = rec->data;
	TAILQ_FOREACH(cur, &rec->token_q, tokens) {
		memcpy(dptr, cur->t_data, cur->len);
		dptr += cur->len;
	}
}

/*
 * Free a BSM audit record by releasing all the tokens and clearing the audit
 * record information.
 */
void
kau_free(struct au_record *rec)
{
	struct au_token *tok;

	/* Free the token list. */
	while ((tok = TAILQ_FIRST(&rec->token_q))) {
		TAILQ_REMOVE(&rec->token_q, tok, tokens);
		free(tok->t_data, M_AUDITBSM);
		free(tok, M_AUDITBSM);
	}

	rec->used = 0;
	rec->len = 0;
	free(rec->data, M_AUDITBSM);
	free(rec, M_AUDITBSM);
}

/*
 * XXX: May want turn some (or all) of these macros into functions in order
 * to reduce the generated code size.
 *
 * XXXAUDIT: These macros assume that 'kar', 'ar', 'rec', and 'tok' in the
 * caller are OK with this.
 */
#if CONFIG_MACF
#define MAC_VNODE1_LABEL_TOKEN   do {                                     \
	if (ar->ar_vnode1_mac_labels != NULL &&                           \
	    strlen(ar->ar_vnode1_mac_labels) != 0) {                      \
	        tok = au_to_text(ar->ar_vnode1_mac_labels);               \
	        kau_write(rec, tok);                                      \
	}                                                                 \
} while (0)

#define MAC_VNODE2_LABEL_TOKEN  do {                                      \
	if (ar->ar_vnode2_mac_labels != NULL &&                           \
	    strlen(ar->ar_vnode2_mac_labels) != 0) {                      \
	        tok = au_to_text(ar->ar_vnode2_mac_labels);               \
	        kau_write(rec, tok);                                      \
	}                                                                 \
} while (0)
#else
#define MAC_VNODE1_LABEL_TOKEN
#define MAC_VNODE2_LABEL_TOKEN
#endif
#define UPATH1_TOKENS do {                                              \
	if (ARG_IS_VALID(kar, ARG_UPATH1)) {                            \
	        tok = au_to_path(ar->ar_arg_upath1);                    \
	        kau_write(rec, tok);                                    \
	}                                                               \
} while (0)

#define UPATH2_TOKENS do {                                              \
	if (ARG_IS_VALID(kar, ARG_UPATH2)) {                            \
	        tok = au_to_path(ar->ar_arg_upath2);                    \
	        kau_write(rec, tok);                                    \
	}                                                               \
} while (0)

#define KPATH2_TOKENS do {                                              \
	if (ARG_IS_VALID(kar, ARG_KPATH2)) {                            \
	        tok = au_to_path(ar->ar_arg_kpath2);                    \
	        kau_write(rec, tok);                                    \
	}                                                               \
} while (0)

#define VNODE1_TOKENS do {                                              \
	if (ARG_IS_VALID(kar, ARG_KPATH1)) {                            \
	        tok = au_to_path(ar->ar_arg_kpath1);                    \
	        kau_write(rec, tok);                                    \
	}                                                               \
	if (ARG_IS_VALID(kar, ARG_VNODE1)) {                            \
	        tok = au_to_attr32(&ar->ar_arg_vnode1);                 \
	        kau_write(rec, tok);                                    \
	        MAC_VNODE1_LABEL_TOKEN;                                 \
	}                                                               \
} while (0)

#define UPATH1_VNODE1_TOKENS do {                                       \
	if (ARG_IS_VALID(kar, ARG_UPATH1)) {                            \
	        tok = au_to_path(ar->ar_arg_upath1);                    \
	        kau_write(rec, tok);                                    \
	}                                                               \
	if (ARG_IS_VALID(kar, ARG_KPATH1)) {                            \
	        tok = au_to_path(ar->ar_arg_kpath1);                    \
	        kau_write(rec, tok);                                    \
	}                                                               \
	if (ARG_IS_VALID(kar, ARG_VNODE1)) {                            \
	        tok = au_to_attr32(&ar->ar_arg_vnode1);                 \
	        kau_write(rec, tok);                                    \
	        MAC_VNODE1_LABEL_TOKEN;                                 \
	}                                                               \
} while (0)

#define VNODE2_TOKENS do {                                              \
	if (ARG_IS_VALID(kar, ARG_VNODE2)) {                            \
	        tok = au_to_attr32(&ar->ar_arg_vnode2);                 \
	        kau_write(rec, tok);                                    \
	        MAC_VNODE2_LABEL_TOKEN;                                 \
	}                                                               \
} while (0)

#define VNODE2_PATH_TOKENS do {                                 \
	if (ARG_IS_VALID(kar, ARG_KPATH2)) {                            \
	        tok = au_to_path(ar->ar_arg_kpath2);                    \
	        kau_write(rec, tok);                                    \
	}                                                               \
	if (ARG_IS_VALID(kar, ARG_VNODE2)) {                            \
	        tok = au_to_attr32(&ar->ar_arg_vnode2);                 \
	        kau_write(rec, tok);                                    \
	        MAC_VNODE2_LABEL_TOKEN;                                 \
	}                                                               \
} while (0)

#define FD_VNODE1_TOKENS do {                                           \
	if (ARG_IS_VALID(kar, ARG_VNODE1)) {                            \
	        if (ARG_IS_VALID(kar, ARG_KPATH1)) {                    \
	                tok = au_to_path(ar->ar_arg_kpath1);            \
	                kau_write(rec, tok);                            \
	        }                                                       \
	        if (ARG_IS_VALID(kar, ARG_FD)) {                        \
	                tok = au_to_arg32(1, "fd", ar->ar_arg_fd);      \
	                kau_write(rec, tok);                            \
	                MAC_VNODE1_LABEL_TOKEN;                         \
	        }                                                       \
	        tok = au_to_attr32(&ar->ar_arg_vnode1);                 \
	        kau_write(rec, tok);                                    \
	} else {                                                        \
	        if (ARG_IS_VALID(kar, ARG_FD)) {                        \
	                tok = au_to_arg32(1, "fd",                      \
	                    ar->ar_arg_fd);                             \
	                kau_write(rec, tok);                            \
	                MAC_VNODE1_LABEL_TOKEN;                         \
	        }                                                       \
	}                                                               \
} while (0)

#define PROCESS_PID_TOKENS(argn) do {                                   \
	if ((ar->ar_arg_pid > 0) /* Reference a single process */       \
	    && (ARG_IS_VALID(kar, ARG_PROCESS))) {                      \
	        tok = au_to_process32_ex(ar->ar_arg_auid,               \
	            ar->ar_arg_euid, ar->ar_arg_egid,                   \
	            ar->ar_arg_ruid, ar->ar_arg_rgid,                   \
	            ar->ar_arg_pid, ar->ar_arg_asid,                    \
	            &ar->ar_arg_termid_addr);                           \
	        kau_write(rec, tok);                                    \
	} else if (ARG_IS_VALID(kar, ARG_PID)) {                        \
	        tok = au_to_arg32(argn, "process", ar->ar_arg_pid);     \
	        kau_write(rec, tok);                                    \
	}                                                               \
} while (0)

#define EXTATTR_TOKENS do {                                             \
	if (ARG_IS_VALID(kar, ARG_VALUE32)) {                           \
	        switch (ar->ar_arg_value32) {                           \
	        case EXTATTR_NAMESPACE_USER:                            \
	                tok = au_to_text(EXTATTR_NAMESPACE_USER_STRING);\
	                break;                                          \
	        case EXTATTR_NAMESPACE_SYSTEM:                          \
	                tok = au_to_text(EXTATTR_NAMESPACE_SYSTEM_STRING);\
	                break;                                          \
	        default:                                                \
	                tok = au_to_arg32(3, "attrnamespace",           \
	                    ar->ar_arg_value32);                        \
	                break;                                          \
	        }                                                       \
	        kau_write(rec, tok);                                    \
	}                                                               \
	/* attrname is in the text field */                             \
	if (ARG_IS_VALID(kar, ARG_TEXT)) {                              \
	        tok = au_to_text(ar->ar_arg_text);                      \
	        kau_write(rec, tok);                                    \
	}                                                               \
} while (0)

#define EXTENDED_TOKENS(n) do {                                         \
	/* ACL data */                                          \
	        if (ARG_IS_VALID(kar, ARG_OPAQUE)) {                    \
	                tok = au_to_opaque(ar->ar_arg_opaque,           \
	                    ar->ar_arg_opq_size);                       \
	                kau_write(rec, tok);                            \
	        }                                                       \
	        if (ARG_IS_VALID(kar, ARG_MODE)) {                      \
	                tok = au_to_arg32(n+2, "mode", ar->ar_arg_mode);\
	                kau_write(rec, tok);                            \
	        }                                                       \
	        if (ARG_IS_VALID(kar, ARG_GID)) {                       \
	                tok = au_to_arg32(n+1, "gid", ar->ar_arg_gid);  \
	                kau_write(rec, tok);                            \
	        }                                                       \
	        if (ARG_IS_VALID(kar, ARG_UID)) {                       \
	                tok = au_to_arg32(n, "uid", ar->ar_arg_uid);    \
	                kau_write(rec, tok);                            \
	        }                                                       \
} while (0)

#define PROCESS_MAC_TOKENS do {                                         \
	if (ar->ar_valid_arg & ARG_MAC_STRING) {                        \
	        tok = au_to_text(ar->ar_arg_mac_string);                \
	        kau_write(rec, tok);                                    \
	}                                                               \
} while (0)

/*
 * Implement auditing for the auditon() system call. The audit tokens that
 * are generated depend on the command that was sent into the auditon()
 * system call.
 */
static void
audit_sys_auditon(struct audit_record *ar, struct au_record *rec)
{
	struct au_token *tok;

	switch (ar->ar_arg_cmd) {
	case A_OLDSETPOLICY:
		if (ar->ar_arg_len > sizeof(int)) {
			tok = au_to_arg32(3, "length", ar->ar_arg_len);
			kau_write(rec, tok);
			tok = au_to_arg64(2, "policy",
			    ar->ar_arg_auditon.au_policy64);
			kau_write(rec, tok);
			break;
		}
	/* FALLTHROUGH */
	case A_SETPOLICY:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "policy", ar->ar_arg_auditon.au_policy);
		kau_write(rec, tok);
		break;

	case A_SETKMASK:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setkmask:as_success",
		    ar->ar_arg_auditon.au_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setkmask:as_failure",
		    ar->ar_arg_auditon.au_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_OLDSETQCTRL:
		if (ar->ar_arg_len > sizeof(au_qctrl_t)) {
			tok = au_to_arg32(3, "length", ar->ar_arg_len);
			kau_write(rec, tok);
			tok = au_to_arg64(2, "setqctrl:aq_hiwater",
			    ar->ar_arg_auditon.au_qctrl64.aq64_hiwater);
			kau_write(rec, tok);
			tok = au_to_arg64(2, "setqctrl:aq_lowater",
			    ar->ar_arg_auditon.au_qctrl64.aq64_lowater);
			kau_write(rec, tok);
			tok = au_to_arg64(2, "setqctrl:aq_bufsz",
			    ar->ar_arg_auditon.au_qctrl64.aq64_bufsz);
			kau_write(rec, tok);
			tok = au_to_arg64(2, "setqctrl:aq_delay",
			    ar->ar_arg_auditon.au_qctrl64.aq64_delay);
			kau_write(rec, tok);
			tok = au_to_arg32(2, "setqctrl:aq_minfree",
			    ar->ar_arg_auditon.au_qctrl64.aq64_minfree);
			kau_write(rec, tok);
			break;
		}
	/* FALLTHROUGH */
	case A_SETQCTRL:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setqctrl:aq_hiwater",
		    ar->ar_arg_auditon.au_qctrl.aq_hiwater);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setqctrl:aq_lowater",
		    ar->ar_arg_auditon.au_qctrl.aq_lowater);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setqctrl:aq_bufsz",
		    ar->ar_arg_auditon.au_qctrl.aq_bufsz);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setqctrl:aq_delay",
		    ar->ar_arg_auditon.au_qctrl.aq_delay);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setqctrl:aq_minfree",
		    ar->ar_arg_auditon.au_qctrl.aq_minfree);
		kau_write(rec, tok);
		break;

	case A_SETUMASK:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setumask:as_success",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setumask:as_failure",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_SETSMASK:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setsmask:as_success",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setsmask:as_failure",
		    ar->ar_arg_auditon.au_auinfo.ai_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_OLDSETCOND:
		if (ar->ar_arg_len > sizeof(int)) {
			tok = au_to_arg32(3, "length", ar->ar_arg_len);
			kau_write(rec, tok);
			tok = au_to_arg64(2, "setcond",
			    ar->ar_arg_auditon.au_cond64);
			kau_write(rec, tok);
			break;
		}
	/* FALLTHROUGH */
	case A_SETCOND:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setcond", ar->ar_arg_auditon.au_cond);
		kau_write(rec, tok);
		break;

	case A_SETCLASS:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setclass:ec_event",
		    ar->ar_arg_auditon.au_evclass.ec_number);
		kau_write(rec, tok);
		tok = au_to_arg32(3, "setclass:ec_class",
		    ar->ar_arg_auditon.au_evclass.ec_class);
		kau_write(rec, tok);
		break;

	case A_SETPMASK:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setpmask:as_success",
		    ar->ar_arg_auditon.au_aupinfo.ap_mask.am_success);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setpmask:as_failure",
		    ar->ar_arg_auditon.au_aupinfo.ap_mask.am_failure);
		kau_write(rec, tok);
		break;

	case A_SETFSIZE:
		tok = au_to_arg32(3, "length", ar->ar_arg_len);
		kau_write(rec, tok);
		tok = au_to_arg32(2, "setfsize:filesize",
		    ar->ar_arg_auditon.au_fstat.af_filesz);
		kau_write(rec, tok);
		break;

	default:
		break;
	}
	tok = au_to_arg32(1, "cmd", ar->ar_arg_cmd);
	kau_write(rec, tok);
}

/*
 * Implement auditing for the fcntl() system call. The audit tokens that
 * are generated depend on the command that was sent into the fcntl()
 * system call.
 */
static void
audit_sys_fcntl(struct kaudit_record *kar, struct au_record *rec)
{
	struct au_token *tok;
	struct audit_record *ar = &kar->k_ar;

	switch (ar->ar_arg_cmd) {
	case F_DUPFD:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(3, "min fd", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case F_SETFD:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(3, "close-on-exec flag",
			    ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case F_SETFL:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(3, "fd flags", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case F_SETOWN:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(3, "pid", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

#ifdef  F_SETSIZE
	case F_SETSIZE:
		if (ARG_IS_VALID(kar, ARG_VALUE64)) {
			tok = au_to_arg64(3, "offset", ar->ar_arg_value64);
			kau_write(rec, tok);
		}
		break;
#endif /* F_SETSIZE */

#ifdef  F_PATHPKG_CHECK
	case F_PATHPKG_CHECK:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;
#endif

	default:
		break;
	}
	tok = au_to_arg32(2, "cmd", au_fcntl_cmd_to_bsm(ar->ar_arg_cmd));
	kau_write(rec, tok);
}

/*
 * Convert an internal kernel audit record to a BSM record and return a
 * success/failure indicator. The BSM record is passed as an out parameter to
 * this function.
 *
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
	int ctr;
	u_int uctr;

	KASSERT(kar != NULL, ("kaudit_to_bsm: kar == NULL"));

	*pau = NULL;
	ar = &kar->k_ar;
	rec = kau_open();

	/*
	 * Create the subject token.
	 */
	switch (ar->ar_subj_term_addr.at_type) {
	case AU_IPv4:
		tid.port = ar->ar_subj_term_addr.at_port;
		tid.machine = ar->ar_subj_term_addr.at_addr[0];
		subj_tok = au_to_subject32(ar->ar_subj_auid,  /* audit ID */
		    ar->ar_subj_cred.cr_uid, /* eff uid */
		    ar->ar_subj_egid,   /* eff group id */
		    ar->ar_subj_ruid,   /* real uid */
		    ar->ar_subj_rgid,   /* real group id */
		    ar->ar_subj_pid,    /* process id */
		    ar->ar_subj_asid,   /* session ID */
		    &tid);
		break;
	case AU_IPv6:
		subj_tok = au_to_subject32_ex(ar->ar_subj_auid,
		    ar->ar_subj_cred.cr_uid,
		    ar->ar_subj_egid,
		    ar->ar_subj_ruid,
		    ar->ar_subj_rgid,
		    ar->ar_subj_pid,
		    ar->ar_subj_asid,
		    &ar->ar_subj_term_addr);
		break;
	default:
		bzero(&tid, sizeof(tid));
		subj_tok = au_to_subject32(ar->ar_subj_auid,
		    ar->ar_subj_cred.cr_uid,
		    ar->ar_subj_egid,
		    ar->ar_subj_ruid,
		    ar->ar_subj_rgid,
		    ar->ar_subj_pid,
		    ar->ar_subj_asid,
		    &tid);
	}

	/*
	 * The logic inside each case fills in the tokens required for the
	 * event, except for the header, trailer, and return tokens.  The
	 * header and trailer tokens are added by the kau_close() function.
	 * The return token is added outside of the switch statement.
	 */
	switch (ar->ar_event) {
	case AUE_SENDFILE:
		/* For sendfile the file and socket descriptor are both saved */
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(2, "sd", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
	/* FALLTHROUGH */
	case AUE_ACCEPT:
	case AUE_BIND:
	case AUE_LISTEN:
	case AUE_CONNECT:
	case AUE_RECVFROM:
	case AUE_RECVMSG:
	case AUE_SENDMSG:
	case AUE_SENDTO:
		/*
		 * Socket-related events.
		 */
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SADDRINET)) {
			tok = au_to_sock_inet((struct sockaddr_in *)
			    &ar->ar_arg_sockaddr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SADDRUNIX)) {
			tok = au_to_sock_unix((struct sockaddr_un *)
			    &ar->ar_arg_sockaddr);
			kau_write(rec, tok);
			UPATH1_TOKENS;
		}
		if (ARG_IS_VALID(kar, ARG_SADDRINET6)) {
			tok = au_to_sock_inet128((struct sockaddr_in6 *)
			    &ar->ar_arg_sockaddr);
			kau_write(rec, tok);
		}
		break;

	case AUE_SOCKET:
	case AUE_SOCKETPAIR:
		if (ARG_IS_VALID(kar, ARG_SOCKINFO)) {
			tok = au_to_arg32(1, "domain",
			    au_domain_to_bsm(ar->ar_arg_sockinfo.sai_domain));
			kau_write(rec, tok);
			tok = au_to_arg32(2, "type",
			    au_socket_type_to_bsm(ar->ar_arg_sockinfo.sai_type));
			kau_write(rec, tok);
			tok = au_to_arg32(3, "protocol",
			    ar->ar_arg_sockinfo.sai_protocol);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETSOCKOPT:
	case AUE_SHUTDOWN:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		break;

	case AUE_ACCT:
		if (ARG_IS_VALID(kar, (ARG_KPATH1 | ARG_UPATH1))) {
			UPATH1_VNODE1_TOKENS;
		} else {
			tok = au_to_arg32(1, "accounting off", 0);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUID:
		if (ARG_IS_VALID(kar, ARG_AUID)) {
			tok = au_to_arg32(2, "setauid", ar->ar_arg_auid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUDIT:
		if (ARG_IS_VALID(kar, ARG_AUID) &&
		    ARG_IS_VALID(kar, ARG_ASID) &&
		    ARG_IS_VALID(kar, ARG_AMASK) &&
		    ARG_IS_VALID(kar, ARG_TERMID)) {
			tok = au_to_arg32(1, "setaudit:auid",
			    ar->ar_arg_auid);
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
			tok = au_to_arg32(1, "setaudit:asid",
			    ar->ar_arg_asid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETAUDIT_ADDR:
		if (ARG_IS_VALID(kar, ARG_AUID) &&
		    ARG_IS_VALID(kar, ARG_ASID) &&
		    ARG_IS_VALID(kar, ARG_AMASK) &&
		    ARG_IS_VALID(kar, ARG_TERMID_ADDR)) {
			tok = au_to_arg32(1, "setaudit_addr:auid",
			    ar->ar_arg_auid);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit_addr:as_success",
			    ar->ar_arg_amask.am_success);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit_addr:as_failure",
			    ar->ar_arg_amask.am_failure);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit_addr:asid",
			    ar->ar_arg_asid);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit_addr:type",
			    ar->ar_arg_termid_addr.at_type);
			kau_write(rec, tok);
			tok = au_to_arg32(1, "setaudit_addr:port",
			    ar->ar_arg_termid_addr.at_port);
			kau_write(rec, tok);
			if (ar->ar_arg_termid_addr.at_type == AU_IPv6) {
				tok = au_to_in_addr_ex((struct in6_addr *)
				    &ar->ar_arg_termid_addr.at_addr[0]);
			}
			if (ar->ar_arg_termid_addr.at_type == AU_IPv4) {
				tok = au_to_in_addr((struct in_addr *)
				    &ar->ar_arg_termid_addr.at_addr[0]);
			}
			kau_write(rec, tok);
		}
		break;

	case AUE_AUDITON:
		/*
		 * For AUDITON commands without own event, audit the cmd.
		 */
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "cmd", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
	/* FALLTHROUGH */

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
		if (ARG_IS_VALID(kar, ARG_AUDITON)) {
			audit_sys_auditon(ar, rec);
		}
		break;

	case AUE_AUDITCTL:
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_EXIT:
		if (ARG_IS_VALID(kar, ARG_EXIT)) {
			tok = au_to_exit(ar->ar_arg_exitretval,
			    ar->ar_arg_exitstatus);
			kau_write(rec, tok);
		}
		break;

	case AUE_ADJTIME:
	case AUE_AUDIT:
	case AUE_DUP2:
	case AUE_GETAUDIT:
	case AUE_GETAUDIT_ADDR:
	case AUE_GETAUID:
	case AUE_GETFSSTAT:
	case AUE_KQUEUE:
	case AUE_LSEEK:
#if 0
/*  XXXss replace with kext  */
	case AUE_MODLOAD:
	case AUE_MODUNLOAD:
#endif
	case AUE_MAC_GETFSSTAT:
	case AUE_PIPE:
	case AUE_PROFILE:
	case AUE_SEMSYS:
	case AUE_SHMSYS:
	case AUE_SETPGRP:
	case AUE_SETRLIMIT:
	case AUE_SETSID:
	case AUE_SETTIMEOFDAY:
	case AUE_KDEBUGTRACE:
	case AUE_PTHREADSIGMASK:
		/*
		 * Header, subject, and return tokens added at end.
		 */
		break;

	case AUE_MKFIFO:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_ACCESS_EXTENDED:
		/*
		 * The access_extended() argument vector is stored in an
		 * opaque token.
		 */
		if (ARG_IS_VALID(kar, ARG_OPAQUE)) {
			tok = au_to_opaque(ar->ar_arg_opaque,
			    ar->ar_arg_opq_size);
			kau_write(rec, tok);
		}
		/*
		 * The access_extended() result vector is stored in an arbitrary
		 * data token.
		 */
		if (ARG_IS_VALID(kar, ARG_DATA)) {
			tok = au_to_data(AUP_DECIMAL, ar->ar_arg_data_type,
			    ar->ar_arg_data_count, ar->ar_arg_data);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_LSTAT_EXTENDED:
	case AUE_STAT_EXTENDED:
	case AUE_ACCESS:
	case AUE_CHDIR:
	case AUE_CHROOT:
	case AUE_GETATTRLIST:
	case AUE_NFS_GETFH:
	case AUE_LSTAT:
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
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_FHOPEN:
		break;

	case AUE_CHFLAGS:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_CHMOD:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "new file mode",
			    ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_CHOWN:
	case AUE_LCHOWN:
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(2, "new file uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_GID)) {
			tok = au_to_arg32(3, "new file gid", ar->ar_arg_gid);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_EXCHANGEDATA:
		UPATH1_VNODE1_TOKENS;
		UPATH2_TOKENS;
		break;

	case AUE_CLOSE:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(2, "fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_CORE:
		if (ARG_IS_VALID(kar, ARG_SIGNUM)) {
			tok = au_to_arg32(0, "signal", ar->ar_arg_signum);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_POSIX_SPAWN:
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(0, "child PID", ar->ar_arg_pid);
			kau_write(rec, tok);
		}
	/* FALLTHROUGH */

	case AUE_EXECVE:
		if (ARG_IS_VALID(kar, ARG_ARGV)) {
			tok = au_to_exec_args(ar->ar_arg_argv,
			    ar->ar_arg_argc);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_ENVV)) {
			tok = au_to_exec_env(ar->ar_arg_envv,
			    ar->ar_arg_envc);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		VNODE2_PATH_TOKENS;
		if (ARG_IS_VALID(kar, ARG_DATA)) {
			tok = au_to_data(AUP_HEX, ar->ar_arg_data_type,
			    ar->ar_arg_data_count, ar->ar_arg_data);
			kau_write(rec, tok);
		}
		break;

	case AUE_FCHMOD_EXTENDED:
		EXTENDED_TOKENS(2);
		FD_VNODE1_TOKENS;
		break;

	case AUE_FCHMOD:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "new file mode",
			    ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_NFS_SVC:
		tok = au_to_arg32(1, "request", ar->ar_arg_cmd);
		kau_write(rec, tok);
		if (ar->ar_valid_arg & (ARG_KPATH1 | ARG_UPATH1)) {
			UPATH1_VNODE1_TOKENS;
		}
		break;

	/*
	 * XXXRW: Some of these need to handle non-vnode cases as well.
	 */
	case AUE_FSTAT_EXTENDED:
	case AUE_FCHDIR:
	case AUE_FPATHCONF:
	case AUE_FSTAT:         /* XXX Need to handle sockets and shm */
	case AUE_FSTATFS:
	case AUE_FSYNC:
	case AUE_FTRUNCATE:
	case AUE_FUTIMES:
	case AUE_GETDIRENTRIES:
	case AUE_GETDIRENTRIESATTR:
	case AUE_GETATTRLISTBULK:
#if 0  /* XXXss new */
	case AUE_POLL:
#endif
	case AUE_READ:
	case AUE_READV:
	case AUE_PREAD:
	case AUE_WRITE:
	case AUE_WRITEV:
	case AUE_PWRITE:
		FD_VNODE1_TOKENS;
		break;

	case AUE_FCHOWN:
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(2, "new file uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_GID)) {
			tok = au_to_arg32(3, "new file gid", ar->ar_arg_gid);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_FCNTL:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			audit_sys_fcntl(kar, rec);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_FSCTL:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(4, "options", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_FFSCTL:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(4, "options", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;


	case AUE_FCHFLAGS:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_FLOCK:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "operation", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

	case AUE_FORK:
	case AUE_VFORK:
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(0, "child PID", ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		break;

	case AUE_GETLCID:
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(1, "pid", (u_int32_t)ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETLCID:
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(1, "pid", (u_int32_t)ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(2, "lcid",
			    (u_int32_t)ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case AUE_IOCTL:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "cmd", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE64)) {
			tok = au_to_arg64(2, "cmd", ar->ar_arg_value64);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_ADDR64)) {
			tok = au_to_arg64(3, "arg", ar->ar_arg_addr);
			kau_write(rec, tok);
		} else if (ARG_IS_VALID(kar, ARG_ADDR32)) {
			tok = au_to_arg32(3, "arg",
			    (u_int32_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VNODE1)) {
			FD_VNODE1_TOKENS;
		} else {
			if (ARG_IS_VALID(kar, ARG_SOCKINFO)) {
				tok = au_to_socket_ex(
					ar->ar_arg_sockinfo.sai_domain,
					ar->ar_arg_sockinfo.sai_type,
					(struct sockaddr *)
					&ar->ar_arg_sockinfo.sai_laddr,
					(struct sockaddr *)
					&ar->ar_arg_sockinfo.sai_faddr);
				kau_write(rec, tok);
			} else {
				if (ARG_IS_VALID(kar, ARG_FD)) {
					tok = au_to_arg32(1, "fd",
					    ar->ar_arg_fd);
					kau_write(rec, tok);
				}
			}
		}
		break;

	case AUE_KILL:
		if (ARG_IS_VALID(kar, ARG_SIGNUM)) {
			tok = au_to_arg32(2, "signal", ar->ar_arg_signum);
			kau_write(rec, tok);
		}
		PROCESS_PID_TOKENS(1);
		break;

	case AUE_LINK:
	case AUE_RENAME:
		UPATH1_VNODE1_TOKENS;
		UPATH2_TOKENS;
		KPATH2_TOKENS;
		break;

	case AUE_MKDIR_EXTENDED:
	case AUE_CHMOD_EXTENDED:
	case AUE_MKFIFO_EXTENDED:
		EXTENDED_TOKENS(2);
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MKDIR:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MKNOD:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(2, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(3, "dev", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MMAP:
	case AUE_MUNMAP:
	case AUE_MPROTECT:
	case AUE_MLOCK:
	case AUE_MUNLOCK:
	case AUE_MINHERIT:
		if (ARG_IS_VALID(kar, ARG_ADDR64)) {
			tok = au_to_arg64(1, "addr", ar->ar_arg_addr);
			kau_write(rec, tok);
		} else if (ARG_IS_VALID(kar, ARG_ADDR32)) {
			tok = au_to_arg32(1, "addr",
			    (u_int32_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_LEN)) {
			tok = au_to_arg64(2, "len", ar->ar_arg_len);
			kau_write(rec, tok);
		}
		if (ar->ar_event == AUE_MMAP) {
			FD_VNODE1_TOKENS;
		}
		if (ar->ar_event == AUE_MPROTECT) {
			if (ARG_IS_VALID(kar, ARG_VALUE32)) {
				tok = au_to_arg32(3, "protection",
				    ar->ar_arg_value32);
				kau_write(rec, tok);
			}
		}
		if (ar->ar_event == AUE_MINHERIT) {
			if (ARG_IS_VALID(kar, ARG_VALUE32)) {
				tok = au_to_arg32(3, "inherit",
				    ar->ar_arg_value32);
				kau_write(rec, tok);
			}
		}
		break;

#if CONFIG_MACF
	case AUE_MAC_MOUNT:
		PROCESS_MAC_TOKENS;
		/* FALLTHROUGH */
#endif
	case AUE_MOUNT:
		/* XXX Need to handle NFS mounts */
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
	/* FALLTHROUGH */

	case AUE_UMOUNT:
	case AUE_UNMOUNT:
		UPATH1_VNODE1_TOKENS;
		break;
	case AUE_FMOUNT:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(2, "dir fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_MSGCTL:
		ar->ar_event = audit_msgctl_to_event(ar->ar_arg_svipc_cmd);
	/* FALLTHROUGH */

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
			if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
				tok = au_to_ipc(AT_IPC_MSG,
				    ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_OPEN:
	case AUE_OPEN_R:
	case AUE_OPEN_RT:
	case AUE_OPEN_RW:
	case AUE_OPEN_RWT:
	case AUE_OPEN_W:
	case AUE_OPEN_WT:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_OPEN_RC:
	case AUE_OPEN_RTC:
	case AUE_OPEN_RWC:
	case AUE_OPEN_RWTC:
	case AUE_OPEN_WC:
	case AUE_OPEN_WTC:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_OPEN_EXTENDED:
	case AUE_OPEN_EXTENDED_R:
	case AUE_OPEN_EXTENDED_RT:
	case AUE_OPEN_EXTENDED_RW:
	case AUE_OPEN_EXTENDED_RWT:
	case AUE_OPEN_EXTENDED_W:
	case AUE_OPEN_EXTENDED_WT:
		EXTENDED_TOKENS(3);
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_OPEN_EXTENDED_RC:
	case AUE_OPEN_EXTENDED_RTC:
	case AUE_OPEN_EXTENDED_RWC:
	case AUE_OPEN_EXTENDED_RWTC:
	case AUE_OPEN_EXTENDED_WC:
	case AUE_OPEN_EXTENDED_WTC:
		EXTENDED_TOKENS(3);
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_OPENAT:
	case AUE_OPENAT_R:
	case AUE_OPENAT_RT:
	case AUE_OPENAT_RW:
	case AUE_OPENAT_RWT:
	case AUE_OPENAT_W:
	case AUE_OPENAT_WT:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "dir fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_OPENAT_RC:
	case AUE_OPENAT_RTC:
	case AUE_OPENAT_RWC:
	case AUE_OPENAT_RWTC:
	case AUE_OPENAT_WC:
	case AUE_OPENAT_WTC:
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(4, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "dir fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_OPENBYID:
	case AUE_OPENBYID_R:
	case AUE_OPENBYID_RT:
	case AUE_OPENBYID_RW:
	case AUE_OPENBYID_RWT:
	case AUE_OPENBYID_W:
	case AUE_OPENBYID_WT:
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(3, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(1, "volfsid", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE64)) {
			tok = au_to_arg64(2, "objid", ar->ar_arg_value64);
			kau_write(rec, tok);
		}
		break;

	case AUE_RENAMEAT:
	case AUE_FACCESSAT:
	case AUE_FCHMODAT:
	case AUE_FCHOWNAT:
	case AUE_FSTATAT:
	case AUE_LINKAT:
	case AUE_UNLINKAT:
	case AUE_READLINKAT:
	case AUE_SYMLINKAT:
	case AUE_MKDIRAT:
	case AUE_GETATTRLISTAT:
	case AUE_SETATTRLISTAT:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "dir fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_CLONEFILEAT:
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "src dir fd", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		if (ARG_IS_VALID(kar, ARG_FD2)) {
			tok = au_to_arg32(1, "dst dir fd", ar->ar_arg_fd2);
			kau_write(rec, tok);
		}
		UPATH2_TOKENS;
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(1, "flags", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case AUE_FCLONEFILEAT:
		FD_VNODE1_TOKENS;
		if (ARG_IS_VALID(kar, ARG_FD2)) {
			tok = au_to_arg32(1, "dst dir fd", ar->ar_arg_fd2);
			kau_write(rec, tok);
		}
		UPATH2_TOKENS;
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(1, "flags", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case AUE_PTRACE:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "request", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_ADDR64)) {
			tok = au_to_arg64(3, "addr", ar->ar_arg_addr);
			kau_write(rec, tok);
		} else if (ARG_IS_VALID(kar, ARG_ADDR32)) {
			tok = au_to_arg32(3, "addr",
			    (u_int32_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(4, "data", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		PROCESS_PID_TOKENS(2);
		break;

	case AUE_QUOTACTL:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(2, "command", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(3, "uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_REBOOT:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "howto", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		break;

	case AUE_SEMCTL:
		ar->ar_event = audit_semctl_to_event(ar->ar_arg_svipc_cmd);
	/* FALLTHROUGH */

	case AUE_SEMOP:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(1, "sem ID", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			if (ar->ar_errno != EINVAL) {
				tok = au_to_ipc(AT_IPC_SEM,
				    ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_SEMGET:
		if (ar->ar_errno == 0) {
			if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
				tok = au_to_ipc(AT_IPC_SEM,
				    ar->ar_arg_svipc_id);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_SETEGID:
		if (ARG_IS_VALID(kar, ARG_EGID)) {
			tok = au_to_arg32(1, "gid", ar->ar_arg_egid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETEUID:
		if (ARG_IS_VALID(kar, ARG_EUID)) {
			tok = au_to_arg32(1, "uid", ar->ar_arg_euid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETREGID:
		if (ARG_IS_VALID(kar, ARG_RGID)) {
			tok = au_to_arg32(1, "rgid", ar->ar_arg_rgid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_EGID)) {
			tok = au_to_arg32(2, "egid", ar->ar_arg_egid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETREUID:
		if (ARG_IS_VALID(kar, ARG_RUID)) {
			tok = au_to_arg32(1, "ruid", ar->ar_arg_ruid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_EUID)) {
			tok = au_to_arg32(2, "euid", ar->ar_arg_euid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETGID:
		if (ARG_IS_VALID(kar, ARG_GID)) {
			tok = au_to_arg32(1, "gid", ar->ar_arg_gid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETUID:
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(1, "uid", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETGROUPS:
		if (ARG_IS_VALID(kar, ARG_GROUPSET)) {
			for (uctr = 0; uctr < ar->ar_arg_groups.gidset_size;
			    uctr++) {
				tok = au_to_arg32(1, "setgroups",
				    ar->ar_arg_groups.gidset[uctr]);
				kau_write(rec, tok);
			}
		}
		break;

	case AUE_SETLOGIN:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETPRIORITY:
		if (ARG_IS_VALID(kar, ARG_CMD)) {
			tok = au_to_arg32(1, "which", ar->ar_arg_cmd);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_UID)) {
			tok = au_to_arg32(2, "who", ar->ar_arg_uid);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(2, "priority", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case AUE_SETPRIVEXEC:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(1, "flag", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	/* AUE_SHMAT, AUE_SHMCTL, AUE_SHMDT and AUE_SHMGET are SysV IPC */
	case AUE_SHMAT:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(1, "shmid", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			/* XXXAUDIT: Does having the ipc token make sense? */
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SVIPC_ADDR)) {
			tok = au_to_arg64(2, "shmaddr", ar->ar_arg_svipc_addr);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SVIPC_PERM)) {
			tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
			kau_write(rec, tok);
		}
		break;

	case AUE_SHMCTL:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(1, "shmid", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			/* XXXAUDIT: Does having the ipc token make sense? */
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		switch (ar->ar_arg_svipc_cmd) {
		case IPC_STAT:
			ar->ar_event = AUE_SHMCTL_STAT;
			break;
		case IPC_RMID:
			ar->ar_event = AUE_SHMCTL_RMID;
			break;
		case IPC_SET:
			ar->ar_event = AUE_SHMCTL_SET;
			if (ARG_IS_VALID(kar, ARG_SVIPC_PERM)) {
				tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
				kau_write(rec, tok);
			}
			break;
		default:
			break;  /* We will audit a bad command */
		}
		break;

	case AUE_SHMDT:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ADDR)) {
			tok = au_to_arg64(1, "shmaddr",
			    (int)(uintptr_t)ar->ar_arg_svipc_addr);
			kau_write(rec, tok);
		}
		break;

	case AUE_SHMGET:
		/* This is unusual; the return value is in an argument token */
		if (ARG_IS_VALID(kar, ARG_SVIPC_ID)) {
			tok = au_to_arg32(0, "shmid", ar->ar_arg_svipc_id);
			kau_write(rec, tok);
			tok = au_to_ipc(AT_IPC_SHM, ar->ar_arg_svipc_id);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_SVIPC_PERM)) {
			tok = au_to_ipc_perm(&ar->ar_arg_svipc_perm);
			kau_write(rec, tok);
		}
		break;

	/* AUE_SHMOPEN, AUE_SHMUNLINK, AUE_SEMOPEN, AUE_SEMCLOSE
	 * and AUE_SEMUNLINK are Posix IPC */
	case AUE_SHMOPEN:
		if (ARG_IS_VALID(kar, ARG_SVIPC_ADDR)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
	/* FALLTHROUGH */

	case AUE_SHMUNLINK:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_POSIX_IPC_PERM)) {
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
		if (ARG_IS_VALID(kar, ARG_FFLAGS)) {
			tok = au_to_arg32(2, "flags", ar->ar_arg_fflags);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_MODE)) {
			tok = au_to_arg32(3, "mode", ar->ar_arg_mode);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(4, "value", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
	/* FALLTHROUGH */

	case AUE_SEMUNLINK:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_POSIX_IPC_PERM)) {
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
		if (ARG_IS_VALID(kar, ARG_FD)) {
			tok = au_to_arg32(1, "sem", ar->ar_arg_fd);
			kau_write(rec, tok);
		}
		break;

	case AUE_SYMLINK:
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_SYSCTL:
	case AUE_SYSCTL_NONADMIN:
		if (ARG_IS_VALID(kar, ARG_CTLNAME | ARG_LEN)) {
			for (ctr = 0; ctr < (int)ar->ar_arg_len; ctr++) {
				tok = au_to_arg32(1, "name",
				    ar->ar_arg_ctlname[ctr]);
				kau_write(rec, tok);
			}
		}
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(5, "newval", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_UMASK_EXTENDED:
		/* ACL data */
		if (ARG_IS_VALID(kar, ARG_OPAQUE)) {
			tok = au_to_opaque(ar->ar_arg_opaque,
			    ar->ar_arg_opq_size);
			kau_write(rec, tok);
		}
	/* FALLTHROUGH */

	case AUE_UMASK:
		if (ARG_IS_VALID(kar, ARG_MASK)) {
			tok = au_to_arg32(1, "new mask", ar->ar_arg_mask);
			kau_write(rec, tok);
		}
		tok = au_to_arg32(0, "prev mask", ar->ar_retval);
		kau_write(rec, tok);
		break;

	case AUE_WAIT4:
#if 0 /* XXXss - new  */
	case AUE_WAITID:
#endif
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(0, "pid", ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		break;

	case AUE_FSGETPATH:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(3, "volfsid", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_VALUE64)) {
			tok = au_to_arg64(4, "objid", ar->ar_arg_value64);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_TEXT)) {
			tok = au_to_text(ar->ar_arg_text);
			kau_write(rec, tok);
		}
		break;

	case AUE_SESSION_START:
	case AUE_SESSION_UPDATE:
	case AUE_SESSION_END:
	case AUE_SESSION_CLOSE:
		if (ARG_IS_VALID(kar, ARG_VALUE64)) {
			tok = au_to_arg64(1, "sflags", ar->ar_arg_value64);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_AMASK)) {
			tok = au_to_arg32(2, "am_success",
			    ar->ar_arg_amask.am_success);
			kau_write(rec, tok);
			tok = au_to_arg32(3, "am_failure",
			    ar->ar_arg_amask.am_failure);
			kau_write(rec, tok);
		}
		break;

	/************************
	* Mach system calls    *
	************************/
	case AUE_INITPROCESS:
		break;

	case AUE_PIDFORTASK:
		if (ARG_IS_VALID(kar, ARG_MACHPORT1)) {
			tok = au_to_arg32(1, "port",
			    (u_int32_t)ar->ar_arg_mach_port1);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(2, "pid", (u_int32_t)ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		break;

	case AUE_TASKFORPID:
	case AUE_TASKNAMEFORPID:
		if (ARG_IS_VALID(kar, ARG_MACHPORT1)) {
			tok = au_to_arg32(1, "target port",
			    (u_int32_t)ar->ar_arg_mach_port1);
			kau_write(rec, tok);
		}
		if (ARG_IS_VALID(kar, ARG_MACHPORT2)) {
			tok = au_to_arg32(3, "task port",
			    (u_int32_t)ar->ar_arg_mach_port2);
			kau_write(rec, tok);
		}
		PROCESS_PID_TOKENS(2);
		break;

	case AUE_SWAPON:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(4, "priority",
			    (u_int32_t)ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_SWAPOFF:
		UPATH1_VNODE1_TOKENS;
		break;

	case AUE_MAPFD:
		if (ARG_IS_VALID(kar, ARG_ADDR64)) {
			tok = au_to_arg64(3, "va", ar->ar_arg_addr);
			kau_write(rec, tok);
		} else if (ARG_IS_VALID(kar, ARG_ADDR32)) {
			tok = au_to_arg32(3, "va",
			    (u_int32_t)ar->ar_arg_addr);
			kau_write(rec, tok);
		}
		FD_VNODE1_TOKENS;
		break;

#if CONFIG_MACF
	case AUE_MAC_GET_FILE:
	case AUE_MAC_SET_FILE:
	case AUE_MAC_GET_LINK:
	case AUE_MAC_SET_LINK:
	case AUE_MAC_GET_MOUNT:
		UPATH1_VNODE1_TOKENS;
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_FD:
	case AUE_MAC_SET_FD:
		FD_VNODE1_TOKENS;
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_SYSCALL:
		PROCESS_MAC_TOKENS;
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(3, "call", ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		break;

	case AUE_MAC_EXECVE:
		UPATH1_VNODE1_TOKENS;
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_PID:
		if (ARG_IS_VALID(kar, ARG_PID)) {
			tok = au_to_arg32(1, "pid", (u_int32_t)ar->ar_arg_pid);
			kau_write(rec, tok);
		}
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_LCID:
		if (ARG_IS_VALID(kar, ARG_VALUE32)) {
			tok = au_to_arg32(1, "lcid",
			    (u_int32_t)ar->ar_arg_value32);
			kau_write(rec, tok);
		}
		PROCESS_MAC_TOKENS;
		break;

	case AUE_MAC_GET_PROC:
	case AUE_MAC_SET_PROC:
		PROCESS_MAC_TOKENS;
		break;
#endif
	case AUE_NULL:
	default:
#if DIAGNOSTIC
		printf("BSM conversion requested for unknown event %d\n",
		    ar->ar_event);
#endif

		/*
		 * Write the subject token so it is properly freed here.
		 */
		kau_write(rec, subj_tok);
		kau_free(rec);
		return BSM_NOAUDIT;
	}

#if CONFIG_MACF
	if (NULL != ar->ar_mac_records) {
		/* Convert the audit data from the MAC policies */
		struct mac_audit_record *mar;

		LIST_FOREACH(mar, ar->ar_mac_records, records) {
			switch (mar->type) {
			case MAC_AUDIT_DATA_TYPE:
				tok = au_to_data(AUP_BINARY, AUR_BYTE,
				    mar->length,
				    (const char *)mar->data);
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
				printf("kaudit_to_bsm(): "
				    "BSM conversion requested for"
				    "unknown mac_audit data type %d\n",
				    mar->type);
			}

			kau_write(rec, tok);
		}
	}
#endif

	kau_write(rec, subj_tok);

#if CONFIG_MACF
	if (ar->ar_cred_mac_labels != NULL &&
	    strlen(ar->ar_cred_mac_labels) != 0) {
		tok = au_to_text(ar->ar_cred_mac_labels);
		kau_write(rec, tok);
	}
#endif

	tok = au_to_return32(au_errno_to_bsm(ar->ar_errno), ar->ar_retval);
	kau_write(rec, tok);  /* Every record gets a return token */

	if (ARG_IS_VALID(kar, ARG_IDENTITY)) {
		struct au_identity_info *id = &ar->ar_arg_identity;
		tok = au_to_identity(id->signer_type, id->signing_id,
		    id->signing_id_trunc, id->team_id, id->team_id_trunc,
		    id->cdhash, id->cdhash_len);
		kau_write(rec, tok);
	}

	kau_close(rec, &ar->ar_endtime, ar->ar_event);

	*pau = rec;
	return BSM_SUCCESS;
}

/*
 * Verify that a record is a valid BSM record. Return 1 if the
 * record is good, 0 otherwise.
 */
int
bsm_rec_verify(void *rec, int length)
{
	/* Used to partially deserialize the buffer */
	struct hdr_tok_partial *hdr;
	struct trl_tok_partial *trl;

	/* A record requires a complete header and trailer token */
	if (length < (AUDIT_HEADER_SIZE + AUDIT_TRAILER_SIZE)) {
		return 0;
	}

	hdr = (struct hdr_tok_partial*)rec;

	/* Ensure the provided length matches what the record shows */
	if ((uint32_t)length != ntohl(hdr->len)) {
		return 0;
	}

	trl = (struct trl_tok_partial*)(rec + (length - AUDIT_TRAILER_SIZE));

	/* Ensure the buffer contains what look like header and trailer tokens */
	if (((hdr->type != AUT_HEADER32) && (hdr->type != AUT_HEADER32_EX) &&
	    (hdr->type != AUT_HEADER64) && (hdr->type != AUT_HEADER64_EX)) ||
	    (trl->type != AUT_TRAILER)) {
		return 0;
	}

	/* Ensure the header and trailer agree on the length */
	if (hdr->len != trl->len) {
		return 0;
	}

	/* Ensure the trailer token has a proper magic value */
	if (ntohs(trl->magic) != AUT_TRAILER_MAGIC) {
		return 0;
	}

	return 1;
}
#endif /* CONFIG_AUDIT */
