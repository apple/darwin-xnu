/*-
 * Copyright (c) 1999-2010, Apple Inc.
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
#include <kern/sched_prim.h>

#if CONFIG_MACF
#include <bsm/audit_record.h>
#include <security/mac.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>
#endif

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include <IOKit/IOBSD.h>

#if CONFIG_AUDIT

#define	IS_NOT_VALID_PID(p)	((p) < 1 || (p) > PID_MAX)

#ifdef AUDIT_API_WARNINGS
/*
 * Macro to warn about auditinfo_addr_t/auditpinfo_addr_t changing sizes
 * to encourage the userland code to be recompiled and updated.
 */
#define	WARN_IF_AINFO_ADDR_CHANGED(sz1, sz2, scall, tp) do {		\
	if ((size_t)(sz1) != (size_t)(sz2)) {				\
		char pn[MAXCOMLEN + 1];					\
									\
		proc_selfname(pn, MAXCOMLEN + 1);			\
		printf("Size of %s used by %s in %s is different from " \
		    "kernel's.  Please recompile %s.\n", (tp),	 	\
		    (scall), pn, pn);					\
	}								\
} while (0)

/*
 * Macro to warn about using ASID's outside the range [1 to PID_MAX] to 
 * encourage userland code changes.
 */
#define	WARN_IF_BAD_ASID(asid, scall) do {				\
	if (((asid) < 1 || (asid) > PID_MAX) &&				\
	     (asid) != AU_ASSIGN_ASID) {				\
		char pn[MAXCOMLEN + 1];					\
									\
		proc_selfname(pn, MAXCOMLEN + 1);			\
		printf("%s in %s is using an ASID (%u) outside the "	\
		    "range [1 to %d].  Please change %s to use an ASID "\
		    "within this range or use AU_ASSIGN_ASID.\n",	\
		    (scall), pn, (uint32_t)(asid), PID_MAX, pn);	\
	}								\
} while (0)

#else /* ! AUDIT_API_WARNINGS */

#define	WARN_IF_AINFO_ADDR_CHANGED(sz1, sz2, scall, tp) do {		\
} while (0)

#define	WARN_IF_BAD_ASID(asid, scall) do {				\
} while (0)

#endif /* AUDIT_API_WARNINGS */

/*
 * System call to allow a user space application to submit a BSM audit record
 * to the kernel for inclusion in the audit log.  This function does little
 * verification on the audit record that is submitted.
 *
 * XXXAUDIT: Audit preselection for user records does not currently work,
 * since we pre-select only based on the AUE_audit event type, not the event
 * type submitted as part of the user audit data.
 */
/* ARGSUSED */
int
audit(proc_t p, struct audit_args *uap, __unused int32_t *retval)
{
	int error = 0;
	void * rec = NULL;
	void * full_rec = NULL;
	struct kaudit_record *ar = NULL;
	struct uthread *uthr = NULL;
	int add_identity_token = 1;
	int max_record_length = MAX_AUDIT_RECORD_SIZE;
	void *udata = NULL;
	u_int ulen = 0;
	struct au_identity_info id_info = {0, NULL, 0, NULL, 0, NULL, 0};
	token_t *id_tok = NULL;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error) {
		goto free_out;
	}

	mtx_lock(&audit_mtx);
	max_record_length = MIN(audit_qctrl.aq_bufsz, MAX_AUDIT_RECORD_SIZE);
	mtx_unlock(&audit_mtx);

	if (IOTaskHasEntitlement(current_task(),
		AU_CLASS_RESERVED_ENTITLEMENT)) {
		/* Entitled tasks are trusted to add appropriate identity info */
		add_identity_token = 0;
	} else {
		/*
		 * If the caller is unentitled, an identity token will be added and
		 * the space must be accounted for
		 */
		max_record_length -= MAX_AUDIT_IDENTITY_SIZE;
	}

	if ((uap->length <= 0) || (uap->length > max_record_length)) {
		error = EINVAL;
		goto free_out;
	}

	ar = currecord();

	/*
	 * If there's no current audit record (audit() itself not audited)
	 * commit the user audit record.
	 */
	if (ar == NULL) {
		uthr = curthread();
		if (uthr == NULL) {
			/* can this happen? */
			error = ENOTSUP;
			goto free_out;
		}

		/*
		 * This is not very efficient; we're required to allocate a
		 * complete kernel audit record just so the user record can
		 * tag along.
		 */
		uthr->uu_ar = audit_new(AUE_NULL, p, uthr);
		if (uthr->uu_ar == NULL) {
			error = ENOTSUP;
			goto free_out;
		}
		ar = uthr->uu_ar;
	}

	rec = malloc(uap->length, M_AUDITDATA, M_WAITOK);
	if (!rec) {
		error = ENOMEM;
		goto free_out;
	}

	error = copyin(uap->record, rec, uap->length);
	if (error) {
		goto free_out;
	}

#if CONFIG_MACF
	error = mac_system_check_audit(kauth_cred_get(), rec, uap->length);
	if (error) {
		goto free_out;
	}
#endif

	/* Verify the record. */
	if (bsm_rec_verify(rec, uap->length) == 0) {
		error = EINVAL;
		goto free_out;
	}

	if (add_identity_token) {
		struct hdr_tok_partial *hdr;
		struct trl_tok_partial *trl;
		int bytes_copied = 0;

		/* Create a new identity token for this buffer */
		audit_identity_info_construct(&id_info);
		id_tok = au_to_identity(id_info.signer_type, id_info.signing_id,
			id_info.signing_id_trunc, id_info.team_id, id_info.team_id_trunc,
			id_info.cdhash, id_info.cdhash_len);
		if (!id_tok) {
			error = ENOMEM;
			goto free_out;
		}

		/* Splice the record together using a new buffer */
		full_rec = malloc(uap->length + id_tok->len, M_AUDITDATA, M_WAITOK);
		if (!full_rec) {
			error = ENOMEM;
			goto free_out;
		}

		/* Copy the original buffer up to but not including the trailer */
		memcpy(full_rec, rec, uap->length - AUDIT_TRAILER_SIZE);
		bytes_copied = uap->length - AUDIT_TRAILER_SIZE;

		/* Copy the identity token */
		memcpy(full_rec + bytes_copied, id_tok->t_data, id_tok->len);
		bytes_copied += id_tok->len;

		/* Copy the old trailer */
		memcpy(full_rec + bytes_copied,
			rec + (uap->length - AUDIT_TRAILER_SIZE), AUDIT_TRAILER_SIZE);
		bytes_copied += AUDIT_TRAILER_SIZE;

		/* Fix the record size stored in the header token */
		hdr = (struct hdr_tok_partial*)full_rec;
		hdr->len = htonl(bytes_copied);

		/* Fix the record size stored in the trailer token */
		trl = (struct trl_tok_partial*)
			(full_rec + bytes_copied - AUDIT_TRAILER_SIZE);
		trl->len = htonl(bytes_copied);

		udata = full_rec;
		ulen = bytes_copied;
	} else {
		udata = rec;
		ulen = uap->length;
	}

	/*
	 * Attach the user audit record to the kernel audit record.  Because
	 * this system call is an auditable event, we will write the user
	 * record along with the record for this audit event.
	 *
	 * XXXAUDIT: KASSERT appropriate starting values of k_udata, k_ulen,
	 * k_ar_commit & AR_COMMIT_USER?
	 */
	ar->k_udata = udata;
	ar->k_ulen  = ulen;
	ar->k_ar_commit |= AR_COMMIT_USER;

	/*
	 * Currently we assume that all preselection has been performed in
	 * userspace.  We unconditionally set these masks so that the records
	 * get committed both to the trail and pipe.  In the future we will
	 * want to setup kernel based preselection.
	 */
	ar->k_ar_commit |= (AR_PRESELECT_USER_TRAIL | AR_PRESELECT_USER_PIPE);

free_out:
	/*
	 * If rec was allocated, it must be freed if an identity token was added
	 * (since full_rec will be used) OR there was an error (since nothing
	 * will be attached to the kernel structure).
	 */
	if (rec && (add_identity_token || error)) {
		free(rec, M_AUDITDATA);
	}

	/* Only free full_rec if an error occurred */
	if (full_rec && error) {
		free(full_rec, M_AUDITDATA);
	}

	audit_identity_info_destruct(&id_info);
	if (id_tok) {
		if (id_tok->t_data) {
			free(id_tok->t_data, M_AUDITBSM);
		}
		free(id_tok, M_AUDITBSM);
	}

	return (error);
}

/*
 *  System call to manipulate auditing.
 */
/* ARGSUSED */
int
auditon(proc_t p, struct auditon_args *uap, __unused int32_t *retval)
{
	kauth_cred_t scred;
	int error = 0;
	union auditon_udata udata;
	proc_t tp = PROC_NULL;
	struct auditinfo_addr aia;

	AUDIT_ARG(cmd, uap->cmd);

#if CONFIG_MACF
	error = mac_system_check_auditon(kauth_cred_get(), uap->cmd);
	if (error)
		return (error);
#endif

	if ((uap->length <= 0) || (uap->length >
	    (int)sizeof(union auditon_udata)))
		return (EINVAL);

	memset((void *)&udata, 0, sizeof(udata));

	/*
	 * Some of the GET commands use the arguments too.
	 */
	switch (uap->cmd) {
	case A_SETPOLICY:
	case A_OLDSETPOLICY:
	case A_SETKMASK:
	case A_SETQCTRL:
	case A_OLDSETQCTRL:
	case A_SETSTAT:
	case A_SETUMASK:
	case A_SETSMASK:
	case A_SETCOND:
	case A_OLDSETCOND:
	case A_SETCLASS:
	case A_SETPMASK:
	case A_SETFSIZE:
	case A_SETKAUDIT:
	case A_GETCLASS:
	case A_GETPINFO:
	case A_GETPINFO_ADDR:
	case A_SENDTRIGGER:
	case A_GETSINFO_ADDR:
	case A_GETSFLAGS:
	case A_SETSFLAGS:
	case A_SETCTLMODE:
	case A_SETEXPAFTER:
		error = copyin(uap->data, (void *)&udata, uap->length);
		if (error)
			return (error);
		AUDIT_ARG(auditon, &udata);
		AUDIT_ARG(len, uap->length);
		break;
	}

	/* Check appropriate privilege. */
	switch (uap->cmd) {
	/*
	 * A_GETSINFO doesn't require priviledge but only superuser  
	 * gets to see the audit masks. 
	 */
	case A_GETSINFO_ADDR:
		if ((sizeof(udata.au_kau_info) != uap->length) ||
	   		(audit_session_lookup(udata.au_kau_info.ai_asid,
					      &udata.au_kau_info) != 0))
			error = EINVAL;
		else if (!kauth_cred_issuser(kauth_cred_get())) {
			udata.au_kau_info.ai_mask.am_success = ~0;
			udata.au_kau_info.ai_mask.am_failure = ~0;
		}
		break;
	case A_GETSFLAGS:
	case A_SETSFLAGS:
		/* Getting one's own audit session flags requires no
		 * privilege.  Setting the flags is subject to access
		 * control implemented in audit_session_setaia().
		 */
		break;
	case A_SETCTLMODE:
	case A_SETEXPAFTER:
		if (!IOTaskHasEntitlement(current_task(),
			AU_CLASS_RESERVED_ENTITLEMENT)) {
			error = EPERM;
		}
		break;
	default:
		error = suser(kauth_cred_get(), &p->p_acflag);
		break;
	}
	if (error)
		return (error);

	/*
	 * If the audit subsytem is in external control mode, additional
	 * privilege checks are required for a subset of auditon commands
	 */
	if (audit_ctl_mode == AUDIT_CTLMODE_EXTERNAL) {
		switch (uap->cmd) {
		case A_SETCOND:
		case A_SETFSIZE:
		case A_SETPOLICY:
		case A_SETQCTRL:
			if (!IOTaskHasEntitlement(current_task(),
				AU_CLASS_RESERVED_ENTITLEMENT)) {
				error = EPERM;
			}
			break;
		}
		if (error)
			return (error);
	}

	/*
	 * XXX Need to implement these commands by accessing the global
	 * values associated with the commands.
	 */
	switch (uap->cmd) {
	case A_OLDGETPOLICY:
	case A_GETPOLICY:
		if (sizeof(udata.au_policy64) == uap->length) {
			mtx_lock(&audit_mtx);
			if (!audit_fail_stop)
				udata.au_policy64 |= AUDIT_CNT;
			if (audit_panic_on_write_fail)
				udata.au_policy64 |= AUDIT_AHLT;
			if (audit_argv)
				udata.au_policy64 |= AUDIT_ARGV;
			if (audit_arge)
				udata.au_policy64 |= AUDIT_ARGE;
			mtx_unlock(&audit_mtx);
			break;
		}
		if (sizeof(udata.au_policy) != uap->length)
			return (EINVAL);
		mtx_lock(&audit_mtx);
		if (!audit_fail_stop)
			udata.au_policy |= AUDIT_CNT;
		if (audit_panic_on_write_fail)
			udata.au_policy |= AUDIT_AHLT;
		if (audit_argv)
			udata.au_policy |= AUDIT_ARGV;
		if (audit_arge)
			udata.au_policy |= AUDIT_ARGE;
		mtx_unlock(&audit_mtx);
		break;

	case A_OLDSETPOLICY:
	case A_SETPOLICY:
		if (sizeof(udata.au_policy64) == uap->length) {
			if (udata.au_policy64 & ~(AUDIT_CNT|AUDIT_AHLT|
				AUDIT_ARGV|AUDIT_ARGE))
				return (EINVAL);
			mtx_lock(&audit_mtx);
			audit_fail_stop = ((udata.au_policy64 & AUDIT_CNT) ==
			    0);
			audit_panic_on_write_fail = (udata.au_policy64 &
			    AUDIT_AHLT);
			audit_argv = (udata.au_policy64 & AUDIT_ARGV);
			audit_arge = (udata.au_policy64 & AUDIT_ARGE);
			mtx_unlock(&audit_mtx);
			break;
		}	
		if ((sizeof(udata.au_policy) != uap->length) ||
		    (udata.au_policy & ~(AUDIT_CNT|AUDIT_AHLT|AUDIT_ARGV|
					 AUDIT_ARGE)))
			return (EINVAL);
		/*
		 * XXX - Need to wake up waiters if the policy relaxes?
		 */
		mtx_lock(&audit_mtx);
		audit_fail_stop = ((udata.au_policy & AUDIT_CNT) == 0);
		audit_panic_on_write_fail = (udata.au_policy & AUDIT_AHLT);
		audit_argv = (udata.au_policy & AUDIT_ARGV);
		audit_arge = (udata.au_policy & AUDIT_ARGE);
		mtx_unlock(&audit_mtx);
		break;

	case A_GETKMASK:
		if (sizeof(udata.au_mask) != uap->length)
			return (EINVAL);
		mtx_lock(&audit_mtx);
		udata.au_mask = audit_nae_mask;
		mtx_unlock(&audit_mtx);
		break;

	case A_SETKMASK:
		if (sizeof(udata.au_mask) != uap->length)
			return (EINVAL);
		mtx_lock(&audit_mtx);
		audit_nae_mask = udata.au_mask;
		AUDIT_CHECK_IF_KEVENTS_MASK(audit_nae_mask);
		mtx_unlock(&audit_mtx);
		break;

	case A_OLDGETQCTRL:
	case A_GETQCTRL:
		if (sizeof(udata.au_qctrl64) == uap->length) {
			mtx_lock(&audit_mtx);
			udata.au_qctrl64.aq64_hiwater =
			    (u_int64_t)audit_qctrl.aq_hiwater;
			udata.au_qctrl64.aq64_lowater =
			    (u_int64_t)audit_qctrl.aq_lowater;
			udata.au_qctrl64.aq64_bufsz =
			    (u_int64_t)audit_qctrl.aq_bufsz;
			udata.au_qctrl64.aq64_delay =
			    (u_int64_t)audit_qctrl.aq_delay;
			udata.au_qctrl64.aq64_minfree = 
			    (int64_t)audit_qctrl.aq_minfree;
			mtx_unlock(&audit_mtx);
			break;
		} 
		if (sizeof(udata.au_qctrl) != uap->length)
			return (EINVAL);
		mtx_lock(&audit_mtx);
		udata.au_qctrl = audit_qctrl;
		mtx_unlock(&audit_mtx);
		break;

	case A_OLDSETQCTRL:
	case A_SETQCTRL:
		if (sizeof(udata.au_qctrl64) == uap->length) {
			 if ((udata.au_qctrl64.aq64_hiwater > AQ_MAXHIGH) ||
			     (udata.au_qctrl64.aq64_lowater >= 
			      udata.au_qctrl64.aq64_hiwater) ||
			     (udata.au_qctrl64.aq64_bufsz > AQ_MAXBUFSZ) ||
			     (udata.au_qctrl64.aq64_minfree < 0) ||
			     (udata.au_qctrl64.aq64_minfree > 100))
				return (EINVAL);
			mtx_lock(&audit_mtx);
			audit_qctrl.aq_hiwater =
			     (int)udata.au_qctrl64.aq64_hiwater;
			audit_qctrl.aq_lowater =
			     (int)udata.au_qctrl64.aq64_lowater;
			audit_qctrl.aq_bufsz =
			     (int)udata.au_qctrl64.aq64_bufsz;
			audit_qctrl.aq_minfree = 
			    (int)udata.au_qctrl64.aq64_minfree;
			audit_qctrl.aq_delay = -1;  /* Not used. */
			mtx_unlock(&audit_mtx);
			break;
		}
		if ((sizeof(udata.au_qctrl) != uap->length) ||
		    (udata.au_qctrl.aq_hiwater > AQ_MAXHIGH) ||
		    (udata.au_qctrl.aq_lowater >= udata.au_qctrl.aq_hiwater) ||
		    (udata.au_qctrl.aq_bufsz > AQ_MAXBUFSZ) ||
		    (udata.au_qctrl.aq_minfree < 0) ||
		    (udata.au_qctrl.aq_minfree > 100))
			return (EINVAL);

		mtx_lock(&audit_mtx);
		audit_qctrl = udata.au_qctrl;
		/* XXX The queue delay value isn't used with the kernel. */
		audit_qctrl.aq_delay = -1;
		mtx_unlock(&audit_mtx);
		break;

	case A_GETCWD:
		return (ENOSYS);

	case A_GETCAR:
		return (ENOSYS);

	case A_GETSTAT:
		return (ENOSYS);

	case A_SETSTAT:
		return (ENOSYS);

	case A_SETUMASK:
		return (ENOSYS);

	case A_SETSMASK:
		return (ENOSYS);

	case A_OLDGETCOND:
	case A_GETCOND:
		if (sizeof(udata.au_cond64) == uap->length) {
			mtx_lock(&audit_mtx);
			if (audit_enabled && !audit_suspended)
				udata.au_cond64 = AUC_AUDITING;
			else
				udata.au_cond64 = AUC_NOAUDIT;
			mtx_unlock(&audit_mtx);
			break;
		}
		if (sizeof(udata.au_cond) != uap->length)
			return (EINVAL);
		mtx_lock(&audit_mtx);
		if (audit_enabled && !audit_suspended)
			udata.au_cond = AUC_AUDITING;
		else
			udata.au_cond = AUC_NOAUDIT;
		mtx_unlock(&audit_mtx);
		break;

	case A_OLDSETCOND:
	case A_SETCOND:
		if (sizeof(udata.au_cond64) == uap->length) {
			mtx_lock(&audit_mtx);
			if (udata.au_cond64 == AUC_NOAUDIT)
				audit_suspended = 1;
			if (udata.au_cond64 == AUC_AUDITING)
				audit_suspended = 0;
			if (udata.au_cond64 == AUC_DISABLED) {
				audit_suspended = 1;
				mtx_unlock(&audit_mtx);
				audit_shutdown();
				break;
			}
			mtx_unlock(&audit_mtx);
			break;
		}
		if (sizeof(udata.au_cond) != uap->length) {
			return (EINVAL);
		}
		mtx_lock(&audit_mtx);
		if (udata.au_cond == AUC_NOAUDIT)
			audit_suspended = 1;
		if (udata.au_cond == AUC_AUDITING)
			audit_suspended = 0;
		if (udata.au_cond == AUC_DISABLED) {
			audit_suspended = 1;
			mtx_unlock(&audit_mtx);
			audit_shutdown();
			break;
		}
		mtx_unlock(&audit_mtx);
		break;

	case A_GETCLASS:
		if (sizeof(udata.au_evclass) != uap->length)
			return (EINVAL);
		udata.au_evclass.ec_class = au_event_class(
		    udata.au_evclass.ec_number);
		break;

	case A_SETCLASS:
		if (sizeof(udata.au_evclass) != uap->length)
			return (EINVAL);
		au_evclassmap_insert(udata.au_evclass.ec_number,
		    udata.au_evclass.ec_class);
		break;

	case A_GETPINFO:
		if ((sizeof(udata.au_aupinfo) != uap->length) ||
		    IS_NOT_VALID_PID(udata.au_aupinfo.ap_pid))
			return (EINVAL);
		if ((tp = proc_find(udata.au_aupinfo.ap_pid)) == NULL)
			return (ESRCH);

		scred = kauth_cred_proc_ref(tp);
		if (scred->cr_audit.as_aia_p->ai_termid.at_type == AU_IPv6) {
			kauth_cred_unref(&scred);
			proc_rele(tp);
			return (EINVAL);
		}
		
		udata.au_aupinfo.ap_auid =
		    scred->cr_audit.as_aia_p->ai_auid;
		udata.au_aupinfo.ap_mask.am_success =
		    scred->cr_audit.as_mask.am_success;
		udata.au_aupinfo.ap_mask.am_failure =
		    scred->cr_audit.as_mask.am_failure;
		udata.au_aupinfo.ap_termid.machine =
		    scred->cr_audit.as_aia_p->ai_termid.at_addr[0];
		udata.au_aupinfo.ap_termid.port =
		    scred->cr_audit.as_aia_p->ai_termid.at_port;
		udata.au_aupinfo.ap_asid =
		    scred->cr_audit.as_aia_p->ai_asid;
		kauth_cred_unref(&scred);
		proc_rele(tp);
		tp = PROC_NULL;
		break;

	case A_SETPMASK:
		if ((sizeof(udata.au_aupinfo) != uap->length) ||
		    IS_NOT_VALID_PID(udata.au_aupinfo.ap_pid))
			return (EINVAL);
		if ((tp = proc_find(udata.au_aupinfo.ap_pid)) == NULL)
			return (ESRCH);
		scred = kauth_cred_proc_ref(tp);
		bcopy(scred->cr_audit.as_aia_p, &aia, sizeof(aia));
		kauth_cred_unref(&scred);
		aia.ai_mask.am_success =
		    udata.au_aupinfo.ap_mask.am_success;
		aia.ai_mask.am_failure =
		    udata.au_aupinfo.ap_mask.am_failure;
		AUDIT_CHECK_IF_KEVENTS_MASK(aia.ai_mask);
		error = audit_session_setaia(tp, &aia);
		proc_rele(tp);
		tp = PROC_NULL;
		if (error)
			return (error);
		break;

	case A_SETFSIZE:
		if ((sizeof(udata.au_fstat) != uap->length) ||
		    ((udata.au_fstat.af_filesz != 0) &&
		     (udata.au_fstat.af_filesz < MIN_AUDIT_FILE_SIZE)))
			return (EINVAL);
		mtx_lock(&audit_mtx);
		audit_fstat.af_filesz = udata.au_fstat.af_filesz;
		mtx_unlock(&audit_mtx);
		break;

	case A_GETFSIZE:
		if (sizeof(udata.au_fstat) != uap->length)
			return (EINVAL);
		mtx_lock(&audit_mtx);
		udata.au_fstat.af_filesz = audit_fstat.af_filesz;
		udata.au_fstat.af_currsz = audit_fstat.af_currsz;
		mtx_unlock(&audit_mtx);
		break;

	case A_GETPINFO_ADDR:
		if ((sizeof(udata.au_aupinfo_addr) != uap->length) ||
		    IS_NOT_VALID_PID(udata.au_aupinfo_addr.ap_pid))
			return (EINVAL);
		if ((tp = proc_find(udata.au_aupinfo.ap_pid)) == NULL)
			return (ESRCH);
		WARN_IF_AINFO_ADDR_CHANGED(uap->length,
		    sizeof(auditpinfo_addr_t), "auditon(A_GETPINFO_ADDR,...)",
		    "auditpinfo_addr_t");
		scred = kauth_cred_proc_ref(tp);
		udata.au_aupinfo_addr.ap_auid =
		    scred->cr_audit.as_aia_p->ai_auid;
		udata.au_aupinfo_addr.ap_asid =
		    scred->cr_audit.as_aia_p->ai_asid;
		udata.au_aupinfo_addr.ap_mask.am_success =
		    scred->cr_audit.as_mask.am_success;
		udata.au_aupinfo_addr.ap_mask.am_failure =
		    scred->cr_audit.as_mask.am_failure;
		bcopy(&scred->cr_audit.as_aia_p->ai_termid, 
		    &udata.au_aupinfo_addr.ap_termid,
		    sizeof(au_tid_addr_t));
		udata.au_aupinfo_addr.ap_flags =
		    scred->cr_audit.as_aia_p->ai_flags;
		kauth_cred_unref(&scred);
		proc_rele(tp);
		tp = PROC_NULL;
		break;

	case A_GETKAUDIT:
		if (sizeof(udata.au_kau_info) != uap->length) 
			return (EINVAL);
		audit_get_kinfo(&udata.au_kau_info);
		break;

	case A_SETKAUDIT:
		if ((sizeof(udata.au_kau_info) != uap->length) ||
		    (udata.au_kau_info.ai_termid.at_type != AU_IPv4 &&
		    udata.au_kau_info.ai_termid.at_type != AU_IPv6))
			return (EINVAL);
		audit_set_kinfo(&udata.au_kau_info);
		break;

	case A_SENDTRIGGER:
		if ((sizeof(udata.au_trigger) != uap->length) || 
		    (udata.au_trigger < AUDIT_TRIGGER_MIN) ||
		    (udata.au_trigger > AUDIT_TRIGGER_MAX))
			return (EINVAL);
		return (audit_send_trigger(udata.au_trigger));

	case A_GETSINFO_ADDR:
		/* Handled above before switch(). */
		break;

	case A_GETSFLAGS:
		if (sizeof(udata.au_flags) != uap->length)
			return (EINVAL);
		bcopy(&(kauth_cred_get()->cr_audit.as_aia_p->ai_flags),
		    &udata.au_flags, sizeof(udata.au_flags));
		break;

	case A_SETSFLAGS:
		if (sizeof(udata.au_flags) != uap->length)
			return (EINVAL);
		bcopy(kauth_cred_get()->cr_audit.as_aia_p, &aia, sizeof(aia));
		aia.ai_flags = udata.au_flags;
		error = audit_session_setaia(p, &aia);
		if (error)
			return (error);
		break;

	case A_GETCTLMODE:
		if (sizeof(udata.au_ctl_mode) != uap->length) {
			return (EINVAL);
		}
		mtx_lock(&audit_mtx);
		udata.au_ctl_mode = audit_ctl_mode;
		mtx_unlock(&audit_mtx);
		break;

	case A_SETCTLMODE:
		if (sizeof(udata.au_ctl_mode) != uap->length) {
			return (EINVAL);
		}

		mtx_lock(&audit_mtx);

		if (udata.au_ctl_mode == AUDIT_CTLMODE_NORMAL) {
			audit_ctl_mode = AUDIT_CTLMODE_NORMAL;
		} else if (udata.au_ctl_mode == AUDIT_CTLMODE_EXTERNAL) {
			audit_ctl_mode = AUDIT_CTLMODE_EXTERNAL;
		} else {
			mtx_unlock(&audit_mtx);
			return (EINVAL);
		}

		mtx_unlock(&audit_mtx);
		break;

	case A_GETEXPAFTER:
		if (sizeof(udata.au_expire_after) != uap->length) {
			return (EINVAL);
		}
		mtx_lock(&audit_mtx);
		udata.au_expire_after.age = audit_expire_after.age;
		udata.au_expire_after.size = audit_expire_after.size;
		udata.au_expire_after.op_type = audit_expire_after.op_type;
		mtx_unlock(&audit_mtx);
		break;

	case A_SETEXPAFTER:
		if (sizeof(udata.au_expire_after) != uap->length) {
			return (EINVAL);
		}
		mtx_lock(&audit_mtx);
		audit_expire_after.age = udata.au_expire_after.age;
		audit_expire_after.size = udata.au_expire_after.size;
		audit_expire_after.op_type = udata.au_expire_after.op_type;
		mtx_unlock(&audit_mtx);
		break;

	default:
		return (EINVAL);
	}

	/*
	 * Copy data back to userspace for the GET comands.
	 */
	switch (uap->cmd) {
	case A_GETPOLICY:
	case A_OLDGETPOLICY:
	case A_GETKMASK:
	case A_GETQCTRL:
	case A_OLDGETQCTRL:
	case A_GETCWD:
	case A_GETCAR:
	case A_GETSTAT:
	case A_GETCOND:
	case A_OLDGETCOND:
	case A_GETCLASS:
	case A_GETPINFO:
	case A_GETFSIZE:
	case A_GETPINFO_ADDR:
	case A_GETKAUDIT:
	case A_GETSINFO_ADDR:
	case A_GETSFLAGS:
	case A_GETCTLMODE:
	case A_GETEXPAFTER:
		error = copyout((void *)&udata, uap->data, uap->length);
		if (error)
			return (ENOSYS);
		break;
	}

	return (0);
}

/*
 * System calls to manage the user audit information.
 */
/* ARGSUSED */
int
getauid(proc_t p, struct getauid_args *uap, __unused int32_t *retval)
{
	au_id_t id;
	int error;
	kauth_cred_t scred;

#if CONFIG_MACF
	error = mac_proc_check_getauid(p);
	if (error)
		return (error);
#endif
	scred = kauth_cred_proc_ref(p);
	id = scred->cr_audit.as_aia_p->ai_auid;
	kauth_cred_unref(&scred);

	error = copyout((void *)&id, uap->auid, sizeof(id));
	if (error)
		return (error);

	return (0);
}

/* ARGSUSED */
int
setauid(proc_t p, struct setauid_args *uap, __unused int32_t *retval)
{
	int error;
	au_id_t	id;
	kauth_cred_t scred;
	struct auditinfo_addr aia;

	error = copyin(uap->auid, &id, sizeof(id));
	if (error)
		return (error);
	AUDIT_ARG(auid, id);

#if CONFIG_MACF
	error = mac_proc_check_setauid(p, id);
	if (error)
		return (error);
#endif

	scred = kauth_cred_proc_ref(p);
	error = suser(scred, &p->p_acflag);
	if (error) {
		kauth_cred_unref(&scred);
		return (error);
	}

	bcopy(scred->cr_audit.as_aia_p, &aia, sizeof(aia));
	if (aia.ai_asid == AU_DEFAUDITSID) {
		aia.ai_asid = AU_ASSIGN_ASID;
	}
	bcopy(&scred->cr_audit.as_mask, &aia.ai_mask, sizeof(au_mask_t));
	kauth_cred_unref(&scred);
	aia.ai_auid = id;
	error = audit_session_setaia(p, &aia);

	return (error);
}

static int
getaudit_addr_internal(proc_t p, user_addr_t user_addr, size_t length)
{
	kauth_cred_t scred;
	auditinfo_addr_t aia;

	scred = kauth_cred_proc_ref(p);
	bcopy(scred->cr_audit.as_aia_p, &aia, sizeof (auditinfo_addr_t));
	/*
	 * Only superuser gets to see the real mask.
	 */
	if (suser(scred, &p->p_acflag)) {
		aia.ai_mask.am_success = ~0;
		aia.ai_mask.am_failure = ~0;
	}
	kauth_cred_unref(&scred);

	return (copyout(&aia, user_addr, min(sizeof(aia), length)));
}

/* ARGSUSED */
int
getaudit_addr(proc_t p, struct getaudit_addr_args *uap,
    __unused int32_t *retval)
{
#if CONFIG_MACF
	int error = mac_proc_check_getaudit(p);

	if (error)
		return (error);
#endif /* CONFIG_MACF */
	WARN_IF_AINFO_ADDR_CHANGED(uap->length, sizeof(auditinfo_addr_t),
	    "getaudit_addr(2)", "auditinfo_addr_t");
	
	return (getaudit_addr_internal(p, uap->auditinfo_addr, uap->length));
}

/* ARGSUSED */
int
setaudit_addr(proc_t p, struct setaudit_addr_args *uap,
    __unused int32_t *retval)
{
	struct auditinfo_addr aia;
	kauth_cred_t scred;
	int error;

	bzero(&aia, sizeof(auditinfo_addr_t));
	error = copyin(uap->auditinfo_addr, &aia, 
	    min(sizeof(aia), uap->length));
	if (error)
		return (error);
	AUDIT_ARG(auditinfo_addr, &aia);
	if (aia.ai_termid.at_type != AU_IPv6 &&
	    aia.ai_termid.at_type != AU_IPv4)
		return (EINVAL);
	if (aia.ai_asid != AU_ASSIGN_ASID && 
	    (uint32_t)aia.ai_asid > ASSIGNED_ASID_MAX)
		return (EINVAL);

#if CONFIG_MACF
	error = mac_proc_check_setaudit(p, &aia);
	if (error)
		return (error);
#endif

	scred = kauth_cred_proc_ref(p);
	error = suser(scred, &p->p_acflag);
	if (error) {
		kauth_cred_unref(&scred);
		return (error);
	}

	WARN_IF_AINFO_ADDR_CHANGED(uap->length, sizeof(auditinfo_addr_t),
	    "setaudit_addr(2)", "auditinfo_addr_t");
	WARN_IF_BAD_ASID(aia.ai_asid, "setaudit_addr(2)");
	kauth_cred_unref(&scred);

	AUDIT_CHECK_IF_KEVENTS_MASK(aia.ai_mask);
	if (aia.ai_asid == AU_DEFAUDITSID)
		aia.ai_asid = AU_ASSIGN_ASID;

	error = audit_session_setaia(p, &aia);
	if (error)
		return (error);

	/*
	 * If asked to assign an ASID then let the user know what the ASID is
	 * by copying the auditinfo_addr struct back out.
	 */
	if (aia.ai_asid == AU_ASSIGN_ASID)
		error = getaudit_addr_internal(p, uap->auditinfo_addr,
		    uap->length);

	return (error);
}

/*
 * Syscall to manage audit files.
 *
 */
/* ARGSUSED */
int
auditctl(proc_t p, struct auditctl_args *uap, __unused int32_t *retval)
{
	struct nameidata nd;
	kauth_cred_t cred;
	struct vnode *vp;
	int error = 0;
	au_ctlmode_t ctlmode;

	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);

	ctlmode = audit_ctl_mode;

	/*
	 * Do not allow setting of a path when auditing is in reserved mode
	 */
	if (ctlmode == AUDIT_CTLMODE_EXTERNAL &&
		!IOTaskHasEntitlement(current_task(), AU_AUDITCTL_RESERVED_ENTITLEMENT)) {
		return (EPERM);
	}

	vp = NULL;
	cred = NULL;

	/*
	 * If a path is specified, open the replacement vnode, perform
	 * validity checks, and grab another reference to the current
	 * credential.
	 *
	 * XXX Changes API slightly.  NULL path no longer disables audit but
	 * returns EINVAL.
	 */
	if (uap->path == USER_ADDR_NULL)
		return (EINVAL);

	NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | LOCKLEAF | AUDITVNPATH1,
	    (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 :
	    UIO_USERSPACE32), uap->path, vfs_context_current());
	error = vn_open(&nd, AUDIT_OPEN_FLAGS, 0);
	if (error)
		return (error);
	vp = nd.ni_vp;
#if CONFIG_MACF
	/*
	 * Accessibility of the vnode was determined in vn_open; the
	 * mac_system_check_auditctl should only determine whether that vnode
	 * is appropriate for storing audit data, or that the caller was
	 * permitted to control the auditing system at all.  For example, a
	 * confidentiality policy may want to ensure that audit files are
	 * always high sensitivity.
	 */
	error = mac_system_check_auditctl(kauth_cred_get(), vp);
	if (error) {
		vn_close(vp, AUDIT_CLOSE_FLAGS, vfs_context_current());
		vnode_put(vp);
		return (error);
	}
#endif
	if (vp->v_type != VREG) {
		vn_close(vp, AUDIT_CLOSE_FLAGS, vfs_context_current());
		vnode_put(vp);
		return (EINVAL);
	}
	mtx_lock(&audit_mtx);
	/*
	 * XXXAUDIT: Should audit_suspended actually be cleared by
	 * audit_worker?
	 */
	audit_suspended = 0;
	mtx_unlock(&audit_mtx);

	/*
	 * The following gets unreferenced in audit_rotate_vnode()
	 * after the rotation and it is no longer needed.
	 */
	cred = kauth_cred_get_with_ref();
	audit_rotate_vnode(cred, vp);
	vnode_put(vp);

	return (error);
}

#else /* !CONFIG_AUDIT */

int
audit(proc_t p, struct audit_args *uap, int32_t *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

int
auditon(proc_t p, struct auditon_args *uap, int32_t *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

int
getauid(proc_t p, struct getauid_args *uap, int32_t *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

int
setauid(proc_t p, struct setauid_args *uap, int32_t *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

int
getaudit_addr(proc_t p, struct getaudit_addr_args *uap, int32_t *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

int
setaudit_addr(proc_t p, struct setaudit_addr_args *uap, int32_t *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

int
auditctl(proc_t p, struct auditctl_args *uap, int32_t *retval)
{
#pragma unused(p, uap, retval)

	return (ENOSYS);
}

#endif /* CONFIG_AUDIT */
