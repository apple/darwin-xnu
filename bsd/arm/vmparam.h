/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 */

#ifndef _BSD_ARM_VMPARAM_H_
#define _BSD_ARM_VMPARAM_H_ 1

#include <sys/resource.h>

#ifndef KERNEL
#include <TargetConditionals.h>
#endif

#define USRSTACK        (0x27E00000)    /* ASLR slides stack down by up to 1MB */
#define USRSTACK64      (0x000000016FE00000ULL)

/*
 * Virtual memory related constants, all in bytes
 */
#ifndef DFLDSIZ
#define DFLDSIZ         (RLIM_INFINITY)         /* initial data size limit */
#endif
#ifndef MAXDSIZ
#define MAXDSIZ         (RLIM_INFINITY)         /* max data size */
#endif
#ifndef DFLSSIZ
/* XXX stack size default is a platform property: use getrlimit(2) */
#if (defined(TARGET_OS_OSX) && (TARGET_OS_OSX != 0)) || \
        (defined(KERNEL) && !defined(CONFIG_EMBEDDED) || (CONFIG_EMBEDDED == 0))
#define DFLSSIZ         (8*1024*1024 - 16*1024)
#else
#define DFLSSIZ         (1024*1024 - 16*1024)   /* initial stack size limit */
#endif /* TARGET_OS_OSX .. || XNU_KERNEL_PRIVATE .. */
#endif /* DFLSSIZ */
#ifndef MAXSSIZ
/* XXX stack size limit is a platform property: use getrlimit(2) */
#if (defined(TARGET_OS_OSX) && (TARGET_OS_OSX != 0)) || \
        (defined(KERNEL) && !defined(CONFIG_EMBEDDED) || (CONFIG_EMBEDDED == 0))
#define MAXSSIZ         (64*1024*1024)          /* max stack size */
#else
#define MAXSSIZ         (1024*1024)             /* max stack size */
#endif /* TARGET_OS_OSX .. || XNU_KERNEL_PRIVATE .. */
#endif /* MAXSSIZ */
#ifndef DFLCSIZ
#define DFLCSIZ         (0)                     /* initial core size limit */
#endif
#ifndef MAXCSIZ
#define MAXCSIZ         (RLIM_INFINITY)         /* max core size */
#endif  /* MAXCSIZ */

#endif  /* _BSD_ARM_VMPARAM_H_ */
