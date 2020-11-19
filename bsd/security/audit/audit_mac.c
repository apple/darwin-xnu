/*-
 * Copyright (c) 1999-2020 Apple Inc.
 * All rights reserved.
 *
 * @APPLE_BSD_LICENSE_HEADER_START@
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
 * @APPLE_BSD_LICENSE_HEADER_END@
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/queue.h>
#include <sys/systm.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>

#include <security/audit/audit.h>
#include <security/audit/audit_private.h>

#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/audit_triggers_server.h>

#include <kern/host.h>
#include <kern/zalloc.h>
#include <kern/sched_prim.h>

#if CONFIG_AUDIT

#if CONFIG_MACF
#include <bsm/audit_record.h>
#include <security/mac.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>
#define MAC_ARG_PREFIX "arg: "
#define MAC_ARG_PREFIX_LEN 5

ZONE_DECLARE(audit_mac_label_zone, "audit_mac_label_zone",
    MAC_AUDIT_LABEL_LEN, ZC_NONE);

int
audit_mac_new(proc_t p, struct kaudit_record *ar)
{
	struct mac mac;

	/*
	 * Retrieve the MAC labels for the process.
	 */
	ar->k_ar.ar_cred_mac_labels = (char *)zalloc(audit_mac_label_zone);
	if (ar->k_ar.ar_cred_mac_labels == NULL) {
		return 1;
	}
	mac.m_buflen = MAC_AUDIT_LABEL_LEN;
	mac.m_string = ar->k_ar.ar_cred_mac_labels;
	mac_cred_label_externalize_audit(p, &mac);

	/*
	 * grab space for the reconds.
	 */
	ar->k_ar.ar_mac_records = (struct mac_audit_record_list_t *)
	    kheap_alloc(KHEAP_AUDIT, sizeof(*ar->k_ar.ar_mac_records), Z_WAITOK);
	if (ar->k_ar.ar_mac_records == NULL) {
		zfree(audit_mac_label_zone, ar->k_ar.ar_cred_mac_labels);
		return 1;
	}
	LIST_INIT(ar->k_ar.ar_mac_records);
	ar->k_ar.ar_forced_by_mac = 0;

	return 0;
}

void
audit_mac_free(struct kaudit_record *ar)
{
	struct mac_audit_record *head, *next;

	if (ar->k_ar.ar_vnode1_mac_labels != NULL) {
		zfree(audit_mac_label_zone, ar->k_ar.ar_vnode1_mac_labels);
	}
	if (ar->k_ar.ar_vnode2_mac_labels != NULL) {
		zfree(audit_mac_label_zone, ar->k_ar.ar_vnode2_mac_labels);
	}
	if (ar->k_ar.ar_cred_mac_labels != NULL) {
		zfree(audit_mac_label_zone, ar->k_ar.ar_cred_mac_labels);
	}
	if (ar->k_ar.ar_arg_mac_string != NULL) {
		kheap_free(KHEAP_AUDIT, ar->k_ar.ar_arg_mac_string,
		    MAC_MAX_LABEL_BUF_LEN + MAC_ARG_PREFIX_LEN);
	}

	/*
	 * Free the audit data from the MAC policies.
	 */
	head = LIST_FIRST(ar->k_ar.ar_mac_records);
	while (head != NULL) {
		next = LIST_NEXT(head, records);
		zfree(mac_audit_data_zone, head->data);
		kheap_free(KHEAP_AUDIT, head, sizeof(*head));
		head = next;
	}
	kheap_free(KHEAP_AUDIT, ar->k_ar.ar_mac_records,
	    sizeof(*ar->k_ar.ar_mac_records));
}

int
audit_mac_syscall_enter(unsigned short code, proc_t p, struct uthread *uthread,
    kauth_cred_t my_cred, au_event_t event)
{
	int error;

	error = mac_audit_check_preselect(my_cred, code,
	    (void *)uthread->uu_arg);
	if (error == MAC_AUDIT_YES) {
		uthread->uu_ar = audit_new(event, p, uthread);
		if (uthread->uu_ar) {
			uthread->uu_ar->k_ar.ar_forced_by_mac = 1;
		}
		return 1;
	} else if (error == MAC_AUDIT_NO) {
		return 0;
	} else if (error == MAC_AUDIT_DEFAULT) {
		return 1;
	}

	return 0;
}

int
audit_mac_syscall_exit(unsigned short code, struct uthread *uthread, int error,
    int retval)
{
	int mac_error;

	if (uthread->uu_ar == NULL) { /* syscall wasn't audited */
		return 1;
	}

	/*
	 * Note, no other postselect mechanism exists.  If
	 * mac_audit_check_postselect returns MAC_AUDIT_NO, the record will be
	 * suppressed.  Other values at this point result in the audit record
	 * being committed.  This suppression behavior will probably go away in
	 * the port to 10.3.4.
	 */
	mac_error = mac_audit_check_postselect(kauth_cred_get(), code,
	    (void *) uthread->uu_arg, error, retval,
	    uthread->uu_ar->k_ar.ar_forced_by_mac);

	if (mac_error == MAC_AUDIT_YES) {
		uthread->uu_ar->k_ar_commit |= AR_COMMIT_KERNEL;
	} else if (mac_error == MAC_AUDIT_NO) {
		audit_free(uthread->uu_ar);
		return 1;
	}
	return 0;
}

/*
 * This function is called by the MAC Framework to add audit data
 * from a policy to the current audit record.
 */
int
audit_mac_data(int type, int len, u_char *data)
{
	struct kaudit_record *cur;
	struct mac_audit_record *record;

	if (audit_enabled == 0) {
		zfree(mac_audit_data_zone, data);
		return ENOTSUP;
	}

	cur = currecord();
	if (cur == NULL) {
		zfree(mac_audit_data_zone, data);
		return ENOTSUP;
	}

	/*
	 * XXX: Note that we silently drop the audit data if this
	 * allocation fails - this is consistent with the rest of the
	 * audit implementation.
	 */
	record = kheap_alloc(KHEAP_AUDIT, sizeof(*record), Z_WAITOK);
	if (record == NULL) {
		zfree(mac_audit_data_zone, data);
		return 0;
	}

	record->type = type;
	record->length = len;
	record->data = data;
	LIST_INSERT_HEAD(cur->k_ar.ar_mac_records, record, records);

	return 0;
}

void
audit_arg_mac_string(struct kaudit_record *ar, char *string)
{
	if (ar->k_ar.ar_arg_mac_string == NULL) {
		ar->k_ar.ar_arg_mac_string = kheap_alloc(KHEAP_AUDIT,
		    MAC_MAX_LABEL_BUF_LEN + MAC_ARG_PREFIX_LEN, Z_WAITOK);
	}

	/*
	 * XXX This should be a rare event. If kheap_alloc() returns NULL,
	 * the system is low on kernel virtual memory. To be
	 * consistent with the rest of audit, just return
	 * (may need to panic if required to for audit).
	 */
	if (ar->k_ar.ar_arg_mac_string == NULL) {
		if (ar->k_ar.ar_arg_mac_string == NULL) {
			return;
		}
	}

	strlcpy(ar->k_ar.ar_arg_mac_string, MAC_ARG_PREFIX,
	    MAC_ARG_PREFIX_LEN);
	strlcpy(ar->k_ar.ar_arg_mac_string + MAC_ARG_PREFIX_LEN, string,
	    MAC_MAX_LABEL_BUF_LEN);
	ARG_SET_VALID(ar, ARG_MAC_STRING);
}
#endif  /* MAC */

#endif /* CONFIG_AUDIT */
