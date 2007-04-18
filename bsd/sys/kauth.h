/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#ifndef _SYS_KAUTH_H
#define _SYS_KAUTH_H

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>

#ifdef __APPLE_API_EVOLVING

/*
 * Identities.
 */

#define KAUTH_UID_NONE	(~(uid_t)0 - 100)	/* not a valid UID */
#define KAUTH_GID_NONE	(~(gid_t)0 - 100)	/* not a valid GID */

#ifndef _KAUTH_GUID
#define _KAUTH_GUID
/* Apple-style globally unique identifier */
typedef struct {
#define KAUTH_GUID_SIZE	16	/* 128-bit identifier */
	unsigned char g_guid[KAUTH_GUID_SIZE];
} guid_t;
#define _GUID_T
#endif /* _KAUTH_GUID */

/* NT Security Identifier, structure as defined by Microsoft */
#pragma pack(1)    /* push packing of 1 byte */
typedef struct {
	u_int8_t		sid_kind;
	u_int8_t		sid_authcount;
	u_int8_t		sid_authority[6];
#define KAUTH_NTSID_MAX_AUTHORITIES 16
	u_int32_t	sid_authorities[KAUTH_NTSID_MAX_AUTHORITIES];
} ntsid_t;
#pragma pack()    /* pop packing to previous packing level */
#define _NTSID_T

/* valid byte count inside a SID structure */
#define KAUTH_NTSID_HDRSIZE	(8)
#define KAUTH_NTSID_SIZE(_s)	(KAUTH_NTSID_HDRSIZE + ((_s)->sid_authcount * sizeof(u_int32_t)))

/*
 * External lookup message payload
 */
struct kauth_identity_extlookup {
	u_int32_t	el_seqno;	/* request sequence number */
	u_int32_t	el_result;	/* lookup result */
#define KAUTH_EXTLOOKUP_SUCCESS		0	/* results here are good */
#define KAUTH_EXTLOOKUP_BADRQ		1	/* request badly formatted */
#define KAUTH_EXTLOOKUP_FAILURE		2	/* transient failure during lookup */
#define KAUTH_EXTLOOKUP_FATAL		3	/* permanent failure during lookup */
#define KAUTH_EXTLOOKUP_INPROG		100	/* request in progress */
	u_int32_t	el_flags;
#define KAUTH_EXTLOOKUP_VALID_UID	(1<<0)
#define KAUTH_EXTLOOKUP_VALID_UGUID	(1<<1)
#define KAUTH_EXTLOOKUP_VALID_USID	(1<<2)
#define KAUTH_EXTLOOKUP_VALID_GID	(1<<3)
#define KAUTH_EXTLOOKUP_VALID_GGUID	(1<<4)
#define KAUTH_EXTLOOKUP_VALID_GSID	(1<<5)
#define KAUTH_EXTLOOKUP_WANT_UID	(1<<6)
#define KAUTH_EXTLOOKUP_WANT_UGUID	(1<<7)
#define KAUTH_EXTLOOKUP_WANT_USID	(1<<8)
#define KAUTH_EXTLOOKUP_WANT_GID	(1<<9)
#define KAUTH_EXTLOOKUP_WANT_GGUID	(1<<10)
#define KAUTH_EXTLOOKUP_WANT_GSID	(1<<11)
#define KAUTH_EXTLOOKUP_WANT_MEMBERSHIP	(1<<12)
#define KAUTH_EXTLOOKUP_VALID_MEMBERSHIP (1<<13)
#define KAUTH_EXTLOOKUP_ISMEMBER	(1<<14)
	uid_t		el_uid;		/* user ID */
	guid_t		el_uguid;	/* user GUID */
	u_int32_t	el_uguid_valid;	/* TTL on translation result (seconds) */
	ntsid_t		el_usid;	/* user NT SID */
	u_int32_t	el_usid_valid;	/* TTL on translation result (seconds) */
	gid_t		el_gid;		/* group ID */
	guid_t		el_gguid;	/* group GUID */
	u_int32_t	el_gguid_valid;	/* TTL on translation result (seconds) */
	ntsid_t		el_gsid;	/* group SID */
	u_int32_t	el_gsid_valid;	/* TTL on translation result (seconds) */
	u_int32_t	el_member_valid; /* TTL on group lookup result */
};

#define KAUTH_EXTLOOKUP_REGISTER	(0)
#define KAUTH_EXTLOOKUP_RESULT		(1<<0)
#define KAUTH_EXTLOOKUP_WORKER		(1<<1)


#ifdef KERNEL
/*
 * Credentials.
 */

#if 0
/*
 * Supplemental credential data.
 *
 * This interface allows us to associate arbitrary data with a credential.
 * As with the credential, the data is considered immutable.
 */
struct kauth_cred_supplement {
	TAILQ_ENTRY(kauth_cred_supplement) kcs_link;

	int	kcs_ref;		/* reference count */
	int	kcs_id;			/* vended identifier */
	size_t	kcs_size;		/* size of data field */
	char	kcs_data[0];
};

typedef struct kauth_cred_supplement *kauth_cred_supplement_t;

struct kauth_cred {
	TAILQ_ENTRY(kauth_cred)	kc_link;
	
	int	kc_ref;			/* reference count */
	uid_t	kc_uid;			/* effective user id */
	uid_t	kc_ruid;		/* real user id */
	uid_t	kc_svuid;		/* saved user id */
	gid_t	kc_gid;			/* effective group id */
	gid_t	kc_rgid;		/* real group id */
	gid_t	kc_svgid;		/* saved group id */

	int	kc_flags;
#define KAUTH_CRED_GRPOVERRIDE		(1<<0)	/* private group list is authoritative */

	int	kc_npvtgroups;		/* private group list, advisory or authoritative */
	gid_t	kc_pvtgroups[NGROUPS];	/* based on KAUTH_CRED_GRPOVERRIDE flag */

	int	kc_nsuppgroups;		/* supplementary group list */
	gid_t	*kc_suppgroups;

	int	kc_nwhtgroups;		/* whiteout group list */
	gid_t	*kc_whtgroups;
	
	struct auditinfo cr_au;		/* user auditing data */

	int	kc_nsupplement;		/* entry count in supplemental data pointer array */
	kauth_cred_supplement_t *kc_supplement;
};
#else

/* XXX just for now */
#include <sys/ucred.h>
// typedef struct ucred *kauth_cred_t;
#endif

/* Kernel SPI for now */
__BEGIN_DECLS
extern uid_t	kauth_getuid(void);
extern uid_t	kauth_getruid(void);
extern gid_t	kauth_getgid(void);
extern gid_t	kauth_getrgid(void);
extern kauth_cred_t kauth_cred_get(void);
extern kauth_cred_t kauth_cred_get_with_ref(void);
extern kauth_cred_t kauth_cred_proc_ref(proc_t procp);
extern kauth_cred_t kauth_cred_alloc(void);
extern kauth_cred_t kauth_cred_create(kauth_cred_t cred);
extern void	kauth_cred_ref(kauth_cred_t _cred);
extern void	kauth_cred_rele(kauth_cred_t _cred);
extern kauth_cred_t kauth_cred_dup(kauth_cred_t cred);
extern kauth_cred_t kauth_cred_copy_real(kauth_cred_t cred);
extern void	kauth_cred_unref(kauth_cred_t *_cred);
extern kauth_cred_t	kauth_cred_setuid(kauth_cred_t cred, uid_t uid);
extern kauth_cred_t	kauth_cred_seteuid(kauth_cred_t cred, uid_t euid);
extern kauth_cred_t	kauth_cred_setgid(kauth_cred_t cred, gid_t gid);
extern kauth_cred_t	kauth_cred_setegid(kauth_cred_t cred, gid_t egid);
extern kauth_cred_t kauth_cred_setuidgid(kauth_cred_t cred, uid_t uid, gid_t gid);
extern kauth_cred_t kauth_cred_setsvuidgid(kauth_cred_t cred, uid_t uid, gid_t gid);
extern kauth_cred_t	kauth_cred_setgroups(kauth_cred_t cred, gid_t *groups, int groupcount, uid_t gmuid);
extern kauth_cred_t kauth_cred_find(kauth_cred_t cred);
extern int	kauth_cred_getgroups(gid_t *_groups, int *_groupcount);
extern int	kauth_cred_assume(uid_t _uid);
extern uid_t	kauth_cred_getuid(kauth_cred_t _cred);
extern gid_t	kauth_cred_getgid(kauth_cred_t _cred);
extern int      kauth_cred_guid2uid(guid_t *_guid, uid_t *_uidp);
extern int      kauth_cred_guid2gid(guid_t *_guid, gid_t *_gidp);
extern int      kauth_cred_ntsid2uid(ntsid_t *_sid, uid_t *_uidp);
extern int      kauth_cred_ntsid2gid(ntsid_t *_sid, gid_t *_gidp);
extern int      kauth_cred_ntsid2guid(ntsid_t *_sid, guid_t *_guidp);
extern int      kauth_cred_uid2guid(uid_t _uid, guid_t *_guidp);
extern int	kauth_cred_getguid(kauth_cred_t _cred, guid_t *_guidp);
extern int      kauth_cred_gid2guid(gid_t _gid, guid_t *_guidp);
extern int      kauth_cred_uid2ntsid(uid_t _uid, ntsid_t *_sidp);
extern int	kauth_cred_getntsid(kauth_cred_t _cred, ntsid_t *_sidp);
extern int      kauth_cred_gid2ntsid(gid_t _gid, ntsid_t *_sidp);
extern int      kauth_cred_guid2ntsid(guid_t *_guid, ntsid_t *_sidp);
extern int	kauth_cred_ismember_gid(kauth_cred_t _cred, gid_t _gid, int *_resultp);
extern int	kauth_cred_ismember_guid(kauth_cred_t _cred, guid_t *_guidp, int *_resultp);

extern int	kauth_cred_supplementary_register(const char *name, int *ident);
extern int	kauth_cred_supplementary_add(kauth_cred_t cred, int ident, const void *data, size_t datasize);
extern int	kauth_cred_supplementary_remove(kauth_cred_t cred, int ident);

/* NOT KPI - fast path for in-kernel code only */
extern int	kauth_cred_issuser(kauth_cred_t _cred);


/* GUID, NTSID helpers */
extern guid_t	kauth_null_guid;
extern int	kauth_guid_equal(guid_t *_guid1, guid_t *_guid2);
extern int	kauth_ntsid_equal(ntsid_t *_sid1, ntsid_t *_sid2);

extern int	kauth_wellknown_guid(guid_t *_guid);
#define KAUTH_WKG_NOT		0	/* not a well-known GUID */
#define KAUTH_WKG_OWNER		1
#define KAUTH_WKG_GROUP		2
#define KAUTH_WKG_NOBODY	3
#define KAUTH_WKG_EVERYBODY	4

extern int	cantrace(proc_t cur_procp, kauth_cred_t creds, proc_t traced_procp, int *errp);

__END_DECLS

#endif /* KERNEL */

/*
 * Generic Access Control Lists.
 */
#if defined(KERNEL) || defined (_SYS_ACL_H)

typedef u_int32_t kauth_ace_rights_t;

/* Access Control List Entry (ACE) */
struct kauth_ace {
	guid_t		ace_applicable;
	u_int32_t	ace_flags;
#define KAUTH_ACE_KINDMASK		0xf
#define KAUTH_ACE_PERMIT		1
#define KAUTH_ACE_DENY			2
#define KAUTH_ACE_AUDIT			3	/* not implemented */
#define KAUTH_ACE_ALARM			4	/* not implemented */
#define	KAUTH_ACE_INHERITED		(1<<4)
#define KAUTH_ACE_FILE_INHERIT		(1<<5)
#define KAUTH_ACE_DIRECTORY_INHERIT	(1<<6)
#define KAUTH_ACE_LIMIT_INHERIT		(1<<7)
#define KAUTH_ACE_ONLY_INHERIT		(1<<8)
#define KAUTH_ACE_SUCCESS		(1<<9)	/* not implemented (AUDIT/ALARM) */
#define KAUTH_ACE_FAILURE		(1<<10)	/* not implemented (AUDIT/ALARM) */
	kauth_ace_rights_t ace_rights;		/* scope specific */
	/* These rights are never tested, but may be present in an ACL */
#define KAUTH_ACE_GENERIC_ALL		(1<<21) 
#define KAUTH_ACE_GENERIC_EXECUTE	(1<<22)
#define KAUTH_ACE_GENERIC_WRITE		(1<<23)
#define KAUTH_ACE_GENERIC_READ		(1<<24)

};

#ifndef _KAUTH_ACE
#define _KAUTH_ACE
typedef struct kauth_ace *kauth_ace_t;
#endif


/* Access Control List */
struct kauth_acl {
	u_int32_t	acl_entrycount;
	u_int32_t	acl_flags;
	
	struct kauth_ace acl_ace[];
};

/*
 * XXX this value needs to be raised - 3893388
 */
#define KAUTH_ACL_MAX_ENTRIES		128

/*
 * The low 16 bits of the flags field are reserved for filesystem
 * internal use and must be preserved by all APIs.  This includes
 * round-tripping flags through user-space interfaces.
 */
#define KAUTH_ACL_FLAGS_PRIVATE	(0xffff)

/*
 * The high 16 bits of the flags are used to store attributes and
 * to request specific handling of the ACL.
 */

/* inheritance will be deferred until the first rename operation */
#define KAUTH_ACL_DEFER_INHERIT	(1<<16)
/* this ACL must not be overwritten as part of an inheritance operation */
#define KAUTH_ACL_NO_INHERIT	(1<<17)

/* acl_entrycount that tells us the ACL is not valid */
#define KAUTH_FILESEC_NOACL ((u_int32_t)(-1))

/*
 * If the acl_entrycount field is KAUTH_FILESEC_NOACL, then the size is the
 * same as a kauth_acl structure; the intent is to put an actual entrycount of
 * KAUTH_FILESEC_NOACL on disk to distinguish a kauth_filesec_t with an empty
 * entry (Windows treats this as "deny all") from one that merely indicates a
 * file group and/or owner guid values.
 */
#define KAUTH_ACL_SIZE(c)	(sizeof(struct kauth_acl) + ((u_int32_t)(c) != KAUTH_FILESEC_NOACL ? ((c) * sizeof(struct kauth_ace)) : 0))
#define KAUTH_ACL_COPYSIZE(p)	KAUTH_ACL_SIZE((p)->acl_entrycount)


#ifndef _KAUTH_ACL
#define _KAUTH_ACL
typedef struct kauth_acl *kauth_acl_t;
#endif

#ifdef KERNEL
__BEGIN_DECLS
kauth_acl_t	kauth_acl_alloc(int size);
void		kauth_acl_free(kauth_acl_t fsp);
__END_DECLS
#endif


/*
 * Extended File Security.
 */

/* File Security information */
struct kauth_filesec {
	u_int32_t	fsec_magic;
#define KAUTH_FILESEC_MAGIC	0x012cc16d
	guid_t		fsec_owner;
	guid_t		fsec_group;

	struct kauth_acl fsec_acl;
};

/* backwards compatibility */
#define fsec_entrycount fsec_acl.acl_entrycount
#define fsec_flags 	fsec_acl.acl_flags
#define fsec_ace	fsec_acl.acl_ace
#define KAUTH_FILESEC_FLAGS_PRIVATE	KAUTH_ACL_FLAGS_PRIVATE
#define KAUTH_FILESEC_DEFER_INHERIT	KAUTH_ACL_DEFER_INHERIT
#define KAUTH_FILESEC_NO_INHERIT	KAUTH_ACL_NO_INHERIT
#define KAUTH_FILESEC_NONE	((kauth_filesec_t)0)
#define KAUTH_FILESEC_WANTED	((kauth_filesec_t)1)
	
#ifndef _KAUTH_FILESEC
#define _KAUTH_FILESEC
typedef struct kauth_filesec *kauth_filesec_t;
#endif

#define KAUTH_FILESEC_SIZE(c)		(sizeof(struct kauth_filesec) + (c) * sizeof(struct kauth_ace))
#define KAUTH_FILESEC_COPYSIZE(p)	KAUTH_FILESEC_SIZE(((p)->fsec_entrycount == KAUTH_FILESEC_NOACL) ? 0 : (p)->fsec_entrycount)
#define KAUTH_FILESEC_COUNT(s)		((s  - sizeof(struct kauth_filesec)) / sizeof(struct kauth_ace))
#define KAUTH_FILESEC_VALID(s)		((s) >= sizeof(struct kauth_filesec) && (((s) - sizeof(struct kauth_filesec)) % sizeof(struct kauth_ace)) == 0)

#define KAUTH_FILESEC_XATTR	"com.apple.system.Security"

/* Allowable first arguments to kauth_filesec_acl_setendian() */
#define	KAUTH_ENDIAN_HOST	0x00000001	/* set host endianness */
#define	KAUTH_ENDIAN_DISK	0x00000002	/* set disk endianness */

__BEGIN_DECLS
kauth_filesec_t	kauth_filesec_alloc(int size);
void		kauth_filesec_free(kauth_filesec_t fsp);
int		kauth_copyinfilesec(user_addr_t xsecurity, kauth_filesec_t *xsecdestpp);
 void		kauth_filesec_acl_setendian(int, kauth_filesec_t, kauth_acl_t);
__END_DECLS	

#endif /* KERNEL || <sys/acl.h> */


#ifdef KERNEL
/*
 * Scope management.
 */
struct kauth_scope;
typedef struct kauth_scope *kauth_scope_t;
struct kauth_listener;
typedef struct kauth_listener *kauth_listener_t;
#ifndef _KAUTH_ACTION_T
typedef int kauth_action_t;
# define _KAUTH_ACTION_T
#endif

typedef int (* kauth_scope_callback_t)(kauth_cred_t _credential,
				void *_idata,
				kauth_action_t _action,
				uintptr_t _arg0,
				uintptr_t _arg1,
				uintptr_t _arg2,
				uintptr_t _arg3);

#define KAUTH_RESULT_ALLOW	(1)
#define KAUTH_RESULT_DENY	(2)
#define KAUTH_RESULT_DEFER	(3)

struct kauth_acl_eval {
	kauth_ace_t		ae_acl;
	int			ae_count;
	kauth_ace_rights_t	ae_requested;
	kauth_ace_rights_t	ae_residual;
	int			ae_result;
	int			ae_options;
#define KAUTH_AEVAL_IS_OWNER	(1<<0)		/* authorizing operation for owner */
#define KAUTH_AEVAL_IN_GROUP	(1<<1)		/* authorizing operation for groupmember */
	/* expansions for 'generic' rights bits */
	kauth_ace_rights_t	ae_exp_gall;
	kauth_ace_rights_t	ae_exp_gread;
	kauth_ace_rights_t	ae_exp_gwrite;
	kauth_ace_rights_t	ae_exp_gexec;
};

typedef struct kauth_acl_eval *kauth_acl_eval_t;
	
__BEGIN_DECLS
extern kauth_scope_t kauth_register_scope(const char *_identifier, kauth_scope_callback_t _callback, void *_idata);
extern void	kauth_deregister_scope(kauth_scope_t _scope);
extern kauth_listener_t kauth_listen_scope(const char *_identifier, kauth_scope_callback_t _callback, void *_idata);
extern void	kauth_unlisten_scope(kauth_listener_t _scope);
extern int	kauth_authorize_action(kauth_scope_t _scope, kauth_cred_t _credential, kauth_action_t _action,
			uintptr_t _arg0, uintptr_t _arg1, uintptr_t _arg2, uintptr_t _arg3);
extern int	kauth_acl_evaluate(kauth_cred_t _credential, kauth_acl_eval_t _eval);
extern int	kauth_acl_inherit(vnode_t _dvp, kauth_acl_t _initial, kauth_acl_t *_product, int _isdir, vfs_context_t _ctx);

/* default scope handlers */
extern int	kauth_authorize_allow(kauth_cred_t _credential, void *_idata, kauth_action_t _action,
    uintptr_t _arg0, uintptr_t _arg1, uintptr_t _arg2, uintptr_t _arg3);
__END_DECLS

/*
 * Generic scope.
 */
#define KAUTH_SCOPE_GENERIC	"com.apple.kauth.generic"

/* Actions */
#define KAUTH_GENERIC_ISSUSER			1

__BEGIN_DECLS
extern int	kauth_authorize_generic(kauth_cred_t credential, kauth_action_t action);
__END_DECLS

/*
 * Process/task scope.
 */
#define KAUTH_SCOPE_PROCESS	"com.apple.kauth.process"

/* Actions */
#define KAUTH_PROCESS_CANSIGNAL			1
#define KAUTH_PROCESS_CANTRACE			2

__BEGIN_DECLS
extern int	kauth_authorize_process(kauth_cred_t _credential, kauth_action_t _action,
    struct proc *_process, uintptr_t _arg1, uintptr_t _arg2, uintptr_t _arg3);
__END_DECLS

/*
 * Vnode operation scope.
 *
 * Prototype for vnode_authorize is in vnode.h
 */
#define KAUTH_SCOPE_VNODE	"com.apple.kauth.vnode"

/*
 * File system operation scope.
 *
 */
#define KAUTH_SCOPE_FILEOP	"com.apple.kauth.fileop"

/* Actions */
#define KAUTH_FILEOP_OPEN			1
#define KAUTH_FILEOP_CLOSE			2
#define KAUTH_FILEOP_RENAME			3
#define KAUTH_FILEOP_EXCHANGE		4
#define KAUTH_FILEOP_LINK			5
#define KAUTH_FILEOP_EXEC			6

/*
 * arguments passed to KAUTH_FILEOP_OPEN listeners
 *		arg0 is pointer to vnode (vnode *) for given user path.
 *		arg1 is pointer to path (char *) passed in to open.
 * arguments passed to KAUTH_FILEOP_CLOSE listeners
 *		arg0 is pointer to vnode (vnode *) for file to be closed.
 *		arg1 is pointer to path (char *) of file to be closed.
 *		arg2 is close flags.
 * arguments passed to KAUTH_FILEOP_RENAME listeners
 *		arg0 is pointer to "from" path (char *).
 *		arg1 is pointer to "to" path (char *).
 * arguments passed to KAUTH_FILEOP_EXCHANGE listeners
 *		arg0 is pointer to file 1 path (char *).
 *		arg1 is pointer to file 2 path (char *).
 * arguments passed to KAUTH_FILEOP_LINK listeners
 *		arg0 is pointer to path to file we are linking to (char *).
 *		arg1 is pointer to path to the new link file (char *).
 * arguments passed to KAUTH_FILEOP_EXEC listeners
 *		arg0 is pointer to vnode (vnode *) for executable.
 *		arg1 is pointer to path (char *) to executable.
 */
 
/* Flag values returned to close listeners. */
#define KAUTH_FILEOP_CLOSE_MODIFIED			(1<<1)

__BEGIN_DECLS
extern int	kauth_authorize_fileop_has_listeners(void);
extern int	kauth_authorize_fileop(kauth_cred_t _credential, kauth_action_t _action,
    uintptr_t _arg0, uintptr_t _arg1);
__END_DECLS

#endif /* KERNEL */

/* Actions, also rights bits in an ACE */

#if defined(KERNEL) || defined (_SYS_ACL_H)
#define KAUTH_VNODE_READ_DATA			(1<<1)
#define KAUTH_VNODE_LIST_DIRECTORY		KAUTH_VNODE_READ_DATA
#define KAUTH_VNODE_WRITE_DATA			(1<<2)
#define KAUTH_VNODE_ADD_FILE			KAUTH_VNODE_WRITE_DATA
#define KAUTH_VNODE_EXECUTE			(1<<3)
#define KAUTH_VNODE_SEARCH			KAUTH_VNODE_EXECUTE
#define KAUTH_VNODE_DELETE			(1<<4)
#define KAUTH_VNODE_APPEND_DATA			(1<<5)
#define KAUTH_VNODE_ADD_SUBDIRECTORY		KAUTH_VNODE_APPEND_DATA
#define KAUTH_VNODE_DELETE_CHILD		(1<<6)
#define KAUTH_VNODE_READ_ATTRIBUTES		(1<<7)
#define KAUTH_VNODE_WRITE_ATTRIBUTES		(1<<8)
#define KAUTH_VNODE_READ_EXTATTRIBUTES		(1<<9)
#define KAUTH_VNODE_WRITE_EXTATTRIBUTES		(1<<10)
#define KAUTH_VNODE_READ_SECURITY		(1<<11)
#define KAUTH_VNODE_WRITE_SECURITY		(1<<12)
#define KAUTH_VNODE_TAKE_OWNERSHIP		(1<<13)

/* backwards compatibility only */
#define KAUTH_VNODE_CHANGE_OWNER		KAUTH_VNODE_TAKE_OWNERSHIP

/* For Windows interoperability only */
#define KAUTH_VNODE_SYNCHRONIZE			(1<<20)

/* (1<<21) - (1<<24) are reserved for generic rights bits */

/* Actions not expressed as rights bits */
/*
 * Authorizes the vnode as the target of a hard link.
 */
#define KAUTH_VNODE_LINKTARGET			(1<<25)

/*
 * Indicates that other steps have been taken to authorise the action,
 * but authorisation should be denied for immutable objects.
 */
#define KAUTH_VNODE_CHECKIMMUTABLE		(1<<26)

/* Action modifiers */
/*
 * The KAUTH_VNODE_ACCESS bit is passed to the callback if the authorisation
 * request in progress is advisory, rather than authoritative.  Listeners
 * performing consequential work (i.e. not strictly checking authorisation)
 * may test this flag to avoid performing unnecessary work.
 *
 * This bit will never be present in an ACE.
 */
#define KAUTH_VNODE_ACCESS			(1<<31)

/*
 * The KAUTH_VNODE_NOIMMUTABLE bit is passed to the callback along with the
 * KAUTH_VNODE_WRITE_SECURITY bit (and no others) to indicate that the
 * caller wishes to change one or more of the immutable flags, and the
 * state of these flags should not be considered when authorizing the request.
 * The system immutable flags are only ignored when the system securelevel
 * is low enough to allow their removal.
 */
#define KAUTH_VNODE_NOIMMUTABLE			(1<<30)

/* The expansions of the GENERIC bits at evaluation time */
#define KAUTH_VNODE_GENERIC_READ_BITS	(KAUTH_VNODE_READ_DATA |		\
					KAUTH_VNODE_READ_ATTRIBUTES |		\
					KAUTH_VNODE_READ_EXTATTRIBUTES |	\
					KAUTH_VNODE_READ_SECURITY)
 
#define KAUTH_VNODE_GENERIC_WRITE_BITS	(KAUTH_VNODE_WRITE_DATA |		\
					KAUTH_VNODE_APPEND_DATA |		\
					KAUTH_VNODE_DELETE |			\
					KAUTH_VNODE_DELETE_CHILD |		\
					KAUTH_VNODE_WRITE_ATTRIBUTES |		\
					KAUTH_VNODE_WRITE_EXTATTRIBUTES |	\
					KAUTH_VNODE_WRITE_SECURITY)
 
#define KAUTH_VNODE_GENERIC_EXECUTE_BITS (KAUTH_VNODE_EXECUTE)
 
#define KAUTH_VNODE_GENERIC_ALL_BITS	(KAUTH_VNODE_GENERIC_READ_BITS |	\
					KAUTH_VNODE_GENERIC_WRITE_BITS |	\
					KAUTH_VNODE_GENERIC_EXECUTE_BITS)
 
/*
 * Some sets of bits, defined here for convenience.
 */
#define KAUTH_VNODE_WRITE_RIGHTS	(KAUTH_VNODE_ADD_FILE |				\
					KAUTH_VNODE_ADD_SUBDIRECTORY |			\
					KAUTH_VNODE_DELETE_CHILD |			\
					KAUTH_VNODE_WRITE_DATA |			\
					KAUTH_VNODE_APPEND_DATA |			\
					KAUTH_VNODE_DELETE |				\
					KAUTH_VNODE_WRITE_ATTRIBUTES |			\
					KAUTH_VNODE_WRITE_EXTATTRIBUTES |		\
					KAUTH_VNODE_WRITE_SECURITY |			\
	    				KAUTH_VNODE_TAKE_OWNERSHIP |			\
					KAUTH_VNODE_LINKTARGET |			\
					KAUTH_VNODE_CHECKIMMUTABLE)


#endif /* KERNEL || <sys/acl.h> */

#ifdef KERNEL
#include <sys/lock.h>	/* lck_grp_t */

/*
 * Debugging
 *
 * XXX this wouldn't be necessary if we had a *real* debug-logging system.
 */
#if 0
# ifndef _FN_KPRINTF
#  define	_FN_KPRINTF
void kprintf(const char *fmt, ...);
# endif
# define KAUTH_DEBUG_ENABLE
# define K_UUID_FMT "%08x:%08x:%08x:%08x"
# define K_UUID_ARG(_u) *(int *)&_u.g_guid[0],*(int *)&_u.g_guid[4],*(int *)&_u.g_guid[8],*(int *)&_u.g_guid[12]
# define KAUTH_DEBUG(fmt, args...)	do { kprintf("%s:%d: " fmt "\n", __PRETTY_FUNCTION__, __LINE__ , ##args); } while (0)
# define KAUTH_DEBUG_CTX(_c)		KAUTH_DEBUG("p = %p c = %p", _c->vc_proc, _c->vc_ucred)
# define VFS_DEBUG(_ctx, _vp, fmt, args...)						\
	do {										\
		kprintf("%p '%s' %s:%d " fmt "\n",					\
		    _ctx,								\
		    (_vp != NULL && _vp->v_name != NULL) ? _vp->v_name : "????",	\
		    __PRETTY_FUNCTION__, __LINE__ ,					\
		    ##args);								\
	} while(0)
#else
# define KAUTH_DEBUG(fmt, args...)		do { } while (0)
# define VFS_DEBUG(ctx, vp, fmt, args...)	do { } while(0)
#endif

/*
 * Initialisation.
 */
extern lck_grp_t *kauth_lck_grp;
__BEGIN_DECLS
extern void	kauth_init(void);
extern void	kauth_identity_init(void);
extern void	kauth_groups_init(void);
extern void	kauth_cred_init(void);
extern void	kauth_resolver_init(void);
__END_DECLS
#endif

#endif /* __APPLE_API_EVOLVING */
#endif /* _SYS_KAUTH_H */

