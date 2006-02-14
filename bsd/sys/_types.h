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

#ifndef _SYS__TYPES_H_
#define _SYS__TYPES_H_

#include <sys/cdefs.h>
#include <machine/_types.h>

/* Forward references */
#ifndef _POSIX_C_SOURCE
struct mcontext;
struct mcontext64;
#else /* _POSIX_C_SOURCE */
struct __darwin_mcontext;
#endif /* _POSIX_C_SOURCE */

/* pthread opaque structures */
#if defined(__LP64__)
#define __PTHREAD_SIZE__           1168
#define __PTHREAD_ATTR_SIZE__      56
#define __PTHREAD_MUTEXATTR_SIZE__ 8
#define __PTHREAD_MUTEX_SIZE__     56
#define __PTHREAD_CONDATTR_SIZE__  8
#define __PTHREAD_COND_SIZE__      40
#define __PTHREAD_ONCE_SIZE__      8
#define __PTHREAD_RWLOCK_SIZE__      192
#define __PTHREAD_RWLOCKATTR_SIZE__      16
#else /* __LP64__ */
#define __PTHREAD_SIZE__           596 
#define __PTHREAD_ATTR_SIZE__      36
#define __PTHREAD_MUTEXATTR_SIZE__ 8
#define __PTHREAD_MUTEX_SIZE__     40
#define __PTHREAD_CONDATTR_SIZE__  4
#define __PTHREAD_COND_SIZE__      24
#define __PTHREAD_ONCE_SIZE__      4
#define __PTHREAD_RWLOCK_SIZE__    124
#define __PTHREAD_RWLOCKATTR_SIZE__ 12
#endif /* __LP64__ */

struct __darwin_pthread_handler_rec
{
	void           (*__routine)(void *);	/* Routine to call */
	void           *__arg;			/* Argument to pass */
	struct __darwin_pthread_handler_rec *__next;
};
struct _opaque_pthread_attr_t { long __sig; char __opaque[__PTHREAD_ATTR_SIZE__]; };
struct _opaque_pthread_cond_t { long __sig; char __opaque[__PTHREAD_COND_SIZE__]; };
struct _opaque_pthread_condattr_t { long __sig; char __opaque[__PTHREAD_CONDATTR_SIZE__]; };
struct _opaque_pthread_mutex_t { long __sig; char __opaque[__PTHREAD_MUTEX_SIZE__]; };
struct _opaque_pthread_mutexattr_t { long __sig; char __opaque[__PTHREAD_MUTEXATTR_SIZE__]; };
struct _opaque_pthread_once_t { long __sig; char __opaque[__PTHREAD_ONCE_SIZE__]; };
struct _opaque_pthread_rwlock_t { long __sig; char __opaque[__PTHREAD_RWLOCK_SIZE__]; };
struct _opaque_pthread_rwlockattr_t { long __sig; char __opaque[__PTHREAD_RWLOCKATTR_SIZE__]; };
struct _opaque_pthread_t { long __sig; struct __darwin_pthread_handler_rec  *__cleanup_stack; char __opaque[__PTHREAD_SIZE__]; };

/*
 * Type definitions; takes common type definitions that must be used
 * in multiple header files due to [XSI], removes them from the system
 * space, and puts them in the implementation space.
 */

#ifdef __cplusplus
#ifdef __GNUG__
#define __DARWIN_NULL __null
#else /* ! __GNUG__ */
#ifdef __LP64__
#define __DARWIN_NULL (0L)
#else /* !__LP64__ */
#define __DARWIN_NULL 0
#endif /* __LP64__ */
#endif /* __GNUG__ */
#else /* ! __cplusplus */
#define __DARWIN_NULL ((void *)0)
#endif /* __cplusplus */

typedef	__int64_t	__darwin_blkcnt_t;	/* total blocks */
typedef	__int32_t	__darwin_blksize_t;	/* preferred block size */
typedef __int32_t	__darwin_dev_t;		/* dev_t */
typedef unsigned int	__darwin_fsblkcnt_t;	/* Used by statvfs and fstatvfs */
typedef unsigned int	__darwin_fsfilcnt_t;	/* Used by statvfs and fstatvfs */
typedef __uint32_t	__darwin_gid_t;		/* [???] process and group IDs */
typedef __uint32_t	__darwin_id_t;		/* [XSI] pid_t, uid_t, or gid_t*/
typedef __uint32_t	__darwin_ino_t;		/* [???] Used for inodes */
typedef __darwin_natural_t __darwin_mach_port_name_t; /* Used by mach */
typedef __darwin_mach_port_name_t __darwin_mach_port_t; /* Used by mach */
#ifndef _POSIX_C_SOURCE
typedef struct mcontext *__darwin_mcontext_t;	/* [???] machine context */
typedef struct mcontext64 *__darwin_mcontext64_t; /* [???] machine context */
#else /* _POSIX_C_SOURCE */
typedef struct __darwin_mcontext *__darwin_mcontext_t; /* [???] machine context */
#endif /* _POSIX_C_SOURCE */
typedef __uint16_t	__darwin_mode_t;	/* [???] Some file attributes */
typedef __int64_t	__darwin_off_t;		/* [???] Used for file sizes */
typedef __int32_t	__darwin_pid_t;		/* [???] process and group IDs */
typedef struct _opaque_pthread_attr_t
			__darwin_pthread_attr_t; /* [???] Used for pthreads */
typedef struct _opaque_pthread_cond_t
			__darwin_pthread_cond_t; /* [???] Used for pthreads */
typedef struct _opaque_pthread_condattr_t
			__darwin_pthread_condattr_t; /* [???] Used for pthreads */
typedef unsigned long	__darwin_pthread_key_t;	/* [???] Used for pthreads */
typedef struct _opaque_pthread_mutex_t
			__darwin_pthread_mutex_t; /* [???] Used for pthreads */
typedef struct _opaque_pthread_mutexattr_t
			__darwin_pthread_mutexattr_t; /* [???] Used for pthreads */
typedef struct _opaque_pthread_once_t
			__darwin_pthread_once_t; /* [???] Used for pthreads */
typedef struct _opaque_pthread_rwlock_t
			__darwin_pthread_rwlock_t; /* [???] Used for pthreads */
typedef struct _opaque_pthread_rwlockattr_t
			__darwin_pthread_rwlockattr_t; /* [???] Used for pthreads */
typedef struct _opaque_pthread_t
			*__darwin_pthread_t;	/* [???] Used for pthreads */
typedef __uint32_t	__darwin_sigset_t;	/* [???] signal set */
typedef __int32_t	__darwin_suseconds_t;	/* [???] microseconds */
typedef __uint32_t	__darwin_uid_t;		/* [???] user IDs */
typedef __uint32_t	__darwin_useconds_t;	/* [???] microseconds */
typedef	unsigned char	__darwin_uuid_t[16];

/* Structure used in sigaltstack call. */
#ifndef _POSIX_C_SOURCE
struct	sigaltstack
#else /* _POSIX_C_SOURCE */
struct	__darwin_sigaltstack
#endif /* _POSIX_C_SOURCE */
{
	void	*ss_sp;			/* signal stack base */
	__darwin_size_t ss_size;	/* signal stack length */
	int	ss_flags;		/* SA_DISABLE and/or SA_ONSTACK */
};
#ifndef _POSIX_C_SOURCE
typedef struct sigaltstack __darwin_stack_t;	/* [???] signal stack */
#else /* _POSIX_C_SOURCE */
typedef struct __darwin_sigaltstack __darwin_stack_t; /* [???] signal stack */
#endif /* _POSIX_C_SOURCE */

/* user context */
#ifndef _POSIX_C_SOURCE
struct ucontext
#else /* _POSIX_C_SOURCE */
struct __darwin_ucontext
#endif /* _POSIX_C_SOURCE */
{
	int		uc_onstack;
	__darwin_sigset_t	uc_sigmask;	/* signal mask used by this context */
	__darwin_stack_t 	uc_stack;	/* stack used by this context */
#ifndef _POSIX_C_SOURCE
	struct ucontext	*uc_link;		/* pointer to resuming context */
#else /* _POSIX_C_SOURCE */
	struct __darwin_ucontext *uc_link;	/* pointer to resuming context */
#endif /* _POSIX_C_SOURCE */
	__darwin_size_t	uc_mcsize;		/* size of the machine context passed in */
	__darwin_mcontext_t	uc_mcontext;	/* pointer to machine specific context */
};
#ifndef _POSIX_C_SOURCE
typedef struct ucontext __darwin_ucontext_t;	/* [???] user context */
#else /* _POSIX_C_SOURCE */
typedef struct __darwin_ucontext __darwin_ucontext_t; /* [???] user context */
#endif /* _POSIX_C_SOURCE */

#ifndef _POSIX_C_SOURCE
struct ucontext64 {
	int		uc_onstack;
	__darwin_sigset_t	uc_sigmask;	/* signal mask used by this context */
	__darwin_stack_t 	uc_stack;	/* stack used by this context */
	struct ucontext64 *uc_link;		/* pointer to resuming context */
	__darwin_size_t	uc_mcsize;		/* size of the machine context passed in */
	__darwin_mcontext64_t uc_mcontext64;	/* pointer to machine specific context */
};
typedef struct ucontext64 __darwin_ucontext64_t; /* [???] user context */
#endif /* _POSIX_C_SOURCE */

#ifdef KERNEL
#ifndef offsetof
#define offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif /* offsetof */
#endif /* KERNEL */
#endif	/* _SYS__TYPES_H_ */
