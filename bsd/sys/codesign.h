/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#ifndef _SYS_CODESIGN_H_
#define _SYS_CODESIGN_H_

/* code signing attributes of a process */
#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_ADHOC		0x0000002	/* ad hoc signed */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement */
#define CS_INSTALLER		0x0000008	/* has installer entitlement */

#define	CS_HARD			0x0000100	/* don't load invalid pages */
#define	CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION	0x0000400	/* force expiration checking */
#define CS_RESTRICT		0x0000800	/* tell dyld to treat restricted */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
#define CS_REQUIRE_LV		0x0002000	/* require library validation */

#define	CS_ALLOWED_MACHO	0x00ffffe

#define CS_EXEC_SET_HARD	0x0100000	/* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL	0x0200000	/* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT	0x0400000	/* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER	0x0800000	/* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED		0x1000000	/* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM	0x2000000	/* dyld used to load this is a platform binary */

#define CS_ENTITLEMENT_FLAGS	(CS_GET_TASK_ALLOW | CS_INSTALLER)

/* csops  operations */
#define	CS_OPS_STATUS		0	/* return status */
#define	CS_OPS_MARKINVALID	1	/* invalidate process */
#define	CS_OPS_MARKHARD		2	/* set HARD flag */
#define	CS_OPS_MARKKILL		3	/* set KILL flag (sticky) */
#ifdef KERNEL_PRIVATE
/* CS_OPS_PIDPATH		4	*/
#endif
#define	CS_OPS_CDHASH		5	/* get code directory hash */
#define CS_OPS_PIDOFFSET	6	/* get offset of active Mach-o slice */
#define CS_OPS_ENTITLEMENTS_BLOB 7	/* get entitlements blob */
#define CS_OPS_MARKRESTRICT	8	/* set RESTRICT flag (sticky) */
#define CS_OPS_SET_STATUS	9	/* set codesign flags */
#define CS_OPS_BLOB		10	/* get codesign blob */
#define CS_OPS_IDENTITY		11	/* get codesign identity */

/* SigPUP */
#define CS_OPS_SIGPUP_INSTALL	20
#define CS_OPS_SIGPUP_DROP	21
#define CS_OPS_SIGPUP_VALIDATE	22

struct sigpup_install_table {
	uint64_t data;
	uint64_t length;
	uint64_t path;
};


/*
 * Magic numbers used by Code Signing
 */
enum {
	CSMAGIC_REQUIREMENT = 0xfade0c00,		/* single Requirement blob */
	CSMAGIC_REQUIREMENTS = 0xfade0c01,		/* Requirements vector (internal requirements) */
	CSMAGIC_CODEDIRECTORY = 0xfade0c02,		/* CodeDirectory blob */
	CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
	CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02,	/* XXX */
	CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171,	/* embedded entitlements */
	CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
	CSMAGIC_BLOBWRAPPER = 0xfade0b01,	/* CMS Signature, among other things */
	
	CS_SUPPORTSSCATTER = 0x20100,
	CS_SUPPORTSTEAMID = 0x20200,

	CSSLOT_CODEDIRECTORY = 0,				/* slot index for CodeDirectory */
	CSSLOT_INFOSLOT = 1,
	CSSLOT_REQUIREMENTS = 2,
	CSSLOT_RESOURCEDIR = 3,
	CSSLOT_APPLICATION = 4,
	CSSLOT_ENTITLEMENTS = 5,

	CSSLOT_SIGNATURESLOT = 0x10000,			/* CMS Signature */

	CSTYPE_INDEX_REQUIREMENTS = 0x00000002,		/* compat with amfi */
	CSTYPE_INDEX_ENTITLEMENTS = 0x00000005,		/* compat with amfi */

	CS_HASHTYPE_SHA1 = 1
};


#define KERNEL_HAVE_CS_CODEDIRECTORY 1

/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
	uint32_t magic;					/* magic number (CSMAGIC_CODEDIRECTORY) */
	uint32_t length;				/* total length of CodeDirectory blob */
	uint32_t version;				/* compatibility version */
	uint32_t flags;					/* setup and mode flags */
	uint32_t hashOffset;			/* offset of hash slot element at index zero */
	uint32_t identOffset;			/* offset of identifier string */
	uint32_t nSpecialSlots;			/* number of special hash slots */
	uint32_t nCodeSlots;			/* number of ordinary (code) hash slots */
	uint32_t codeLimit;				/* limit to main image signature range */
	uint8_t hashSize;				/* size of each hash in bytes */
	uint8_t hashType;				/* type of hash (cdHashType* constants) */
	uint8_t spare1;					/* unused (must be zero) */
	uint8_t	pageSize;				/* log2(page size in bytes); 0 => infinite */
	uint32_t spare2;				/* unused (must be zero) */
	/* Version 0x20100 */
	uint32_t scatterOffset;				/* offset of optional scatter vector */
	/* Version 0x20200 */
	uint32_t teamOffset;				/* offset of optional team identifier */
	/* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

/*
 * Structure of an embedded-signature SuperBlob
 */

typedef struct __BlobIndex {
	uint32_t type;					/* type of entry */
	uint32_t offset;				/* offset of entry */
} CS_BlobIndex;

typedef struct __SC_SuperBlob {
	uint32_t magic;					/* magic number */
	uint32_t length;				/* total length of SuperBlob */
	uint32_t count;					/* number of index entries following */
	CS_BlobIndex index[];			/* (count) entries */
	/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

typedef struct __SC_GenericBlob {
	uint32_t magic;				/* magic number */
	uint32_t length;			/* total length of blob */
	char data[];
} CS_GenericBlob;

typedef struct __SC_Scatter {
	uint32_t count;			// number of pages; zero for sentinel (only)
	uint32_t base;			// first page number
	uint64_t targetOffset;		// offset in target
	uint64_t spare;			// reserved
} SC_Scatter;


#ifndef KERNEL

#include <sys/types.h>
#include <mach/message.h>

__BEGIN_DECLS
/* code sign operations */
int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
int csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
__END_DECLS

#else /* !KERNEL */

#include <sys/cdefs.h>
#include <sys/_types/_off_t.h>

struct vnode;
struct cs_blob;
struct fileglob;

struct cscsr_functions  {
	int		csr_version;
#define CSCSR_VERSION 1
	int		(*csr_validate_header)(const uint8_t *, size_t);
	const void*	(*csr_find_file_codedirectory)(struct vnode *, const uint8_t *, size_t, size_t *);
};

__BEGIN_DECLS
int	cs_enforcement(struct proc *);
int	cs_require_lv(struct proc *);
uint32_t cs_entitlement_flags(struct proc *p);
int	cs_entitlements_blob_get(struct proc *, void **, size_t *);
uint8_t * cs_get_cdhash(struct proc *);
void	cs_register_cscsr(struct cscsr_functions *);

const 	CS_GenericBlob *
	cs_find_blob(struct cs_blob *, uint32_t, uint32_t);

const 	char * csblob_get_teamid(struct cs_blob *);
const 	char * csproc_get_teamid(struct proc *);
const 	char * csvnode_get_teamid(struct vnode *, off_t);
int 	csproc_get_platform_binary(struct proc *);
const 	char * csfg_get_teamid(struct fileglob *);
int	csfg_get_path(struct fileglob *, char *, int *);
int 	csfg_get_platform_binary(struct fileglob *);

__END_DECLS

#ifdef XNU_KERNEL_PRIVATE

void	cs_init(void);
int	cs_allow_invalid(struct proc *);
int	cs_invalid_page(addr64_t);
int	sigpup_install(user_addr_t);
int	sigpup_drop(void);

extern int cs_debug;
extern int cs_validation;
#if !SECURE_KERNEL
extern int cs_enforcement_panic;
#endif

#endif /* XNU_KERNEL_PRIVATE */

#endif /* KERNEL */

#endif /* _SYS_CODESIGN_H_ */
