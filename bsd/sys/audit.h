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

#ifndef _SYS_AUDIT_H
#define	_SYS_AUDIT_H

#include <sys/queue.h>
#include <sys/ucred.h>
#include <sys/param.h>
#include <sys/ipc.h>
#include <sys/socket.h>

#define	AUDIT_RECORD_MAGIC	0x828a0f1b
#define MAX_AUDIT_RECORDS	20
#define MAX_AUDIT_RECORD_SIZE	4096	

/*
 * Define the masks for the classes of audit events.
 */
#define	AU_NULL		0x00000000
#define	AU_FREAD	0x00000001
#define	AU_FWRITE	0x00000002
#define	AU_FACCESS	0x00000004
#define	AU_FMODIFY	0x00000008
#define	AU_FCREATE	0x00000010
#define	AU_FDELETE	0x00000020
#define	AU_CLOSE	0x00000040
#define	AU_PROCESS	0x00000080
#define	AU_NET		0x00000100
#define	AU_IPC		0x00000200
#define	AU_NONAT	0x00000400
#define	AU_ADMIN	0x00000800
#define	AU_LOGIN	0x00001000
#define	AU_TFM		0x00002000
#define	AU_APPL		0x00004000
#define	AU_SETL		0x00008000
#define	AU_IFLOAT	0x00010000
#define	AU_PRIV		0x00020000
#define	AU_MAC_RW	0x00040000
#define	AU_XCONN	0x00080000
#define	AU_XCREATE	0x00100000
#define	AU_XDELETE	0x00200000
#define	AU_XIFLOAT	0x00400000
#define	AU_XPRIVS	0x00800000
#define	AU_XPRIVF	0x01000000
#define	AU_XMOVE	0x02000000
#define	AU_XDACF	0x04000000
#define	AU_XMACF	0x08000000
#define	AU_XSECATTR	0x10000000
#define	AU_IOCTL	0x20000000
#define	AU_EXEC		0x40000000
#define	AU_OTHER	0x80000000
#define	AU_ALL		0xffffffff

/*
 * IPC types
 */
#define AT_IPC_MSG	((u_char)1) /* message IPC id */
#define AT_IPC_SEM	((u_char)2) /* semaphore IPC id */
#define AT_IPC_SHM	((u_char)3) /* shared mem IPC id */

/*
 * Audit conditions.
 */
#define AUC_UNSET		0
#define AUC_AUDITING		1
#define AUC_NOAUDIT		2
#define AUC_DISABLED		-1

/*
 * auditon(2) commands.
 */
#define A_GETPOLICY	2
#define A_SETPOLICY	3
#define A_GETKMASK	4
#define A_SETKMASK	5
#define	A_GETQCTRL	6
#define A_SETQCTRL	7
#define A_GETCWD	8
#define A_GETCAR	9
#define A_GETSTAT	12
#define A_SETSTAT	13
#define	A_SETUMASK	14
#define A_SETSMASK	15
#define A_GETCOND	20
#define A_SETCOND	21
#define A_GETCLASS	22
#define A_SETCLASS	23
#define A_GETPINFO	24
#define A_SETPMASK	25
#define A_SETFSIZE	26
#define A_GETFSIZE	27
#define A_GETPINFO_ADDR	28
#define A_GETKAUDIT	29
#define A_SETKAUDIT	30

/*
 * Audit policy controls.
 */
#define AUDIT_CNT	0x0001
#define AUDIT_AHLT	0x0002
#define AUDIT_ARGV	0x0004
#define AUDIT_ARGE	0x0008
#define AUDIT_PASSWD	0x0010
#define AUDIT_SEQ	0x0020
#define AUDIT_WINDATA	0x0040
#define AUDIT_USER	0x0080
#define AUDIT_GROUP	0x0100
#define AUDIT_TRAIL	0x0200
#define AUDIT_PATH	0x0400

typedef uid_t au_id_t;
typedef pid_t au_asid_t;
typedef u_int16_t au_event_t;
typedef u_int16_t au_emod_t; 
typedef u_int32_t au_class_t;

struct au_tid {
	dev_t port;
	u_int32_t machine;
};
typedef struct au_tid au_tid_t;

struct au_tid_addr {
	dev_t  at_port;
	u_int32_t at_type;
	u_int32_t at_addr[4];
};
typedef struct au_tid_addr au_tid_addr_t;

struct au_mask {
	unsigned int    am_success;     /* success bits */
	unsigned int    am_failure;     /* failure bits */
};
typedef struct au_mask au_mask_t;

struct auditinfo {
	au_id_t			ai_auid;	/* Audit user ID */
	au_mask_t		ai_mask;	/* Audit masks */
	au_tid_t		ai_termid;	/* Terminal ID */
	au_asid_t		ai_asid;	/* Audit session ID */
};
typedef struct auditinfo auditinfo_t;

struct auditinfo_addr {
	au_id_t			ai_auid;	/* Audit user ID */
	au_mask_t		ai_mask;	/* Audit masks */
	au_tid_addr_t		ai_termid;	/* Terminal ID */
	au_asid_t		ai_asid;	/* Audit session ID */
};
typedef struct auditinfo_addr auditinfo_addr_t;

/* Token and record structures */

struct au_token {
	u_char *t_data;
	size_t len;
	TAILQ_ENTRY(au_token) tokens;
};
typedef struct au_token token_t;

struct au_record {
	char used; /* Is this record currently being used */
	int desc; /* The descriptor associated with this record */
	TAILQ_HEAD(, au_token) token_q; /* queue of BSM tokens */
	u_char *data;
	size_t len;
	LIST_ENTRY(au_record) au_rec_q;
}; 
typedef struct au_record au_record_t;

#ifndef KERNEL
#include <sys/cdefs.h>

__BEGIN_DECLS
int audit (const void *, int);
int auditon (int, void *, int);
int auditsvc (int, int);
int auditctl (const char *);
int getauid (au_id_t *);
int setauid (const au_id_t *);
int getaudit (struct auditinfo *);
int setaudit (const struct auditinfo *);
int getaudit_addr (struct auditinfo_addr *, int);
int setaudit_addr (const struct auditinfo_addr *, int);
__END_DECLS
#endif /* !KERNEL */

#endif /* !_SYS_AUDIT_H */
