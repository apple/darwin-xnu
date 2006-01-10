/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Define the internal interfaces between the profiling support that is
 * common between the kernel, mach servers, and user space library.
 */

#ifndef _PROFILE_INTERNAL_H
#define _PROFILE_INTERNAL_H

/*
 * Allow us not to require stdio.h in kernel/server space, but
 * use it in user space.
 */

#if !defined(MACH_KERNEL) && !defined(_KERNEL)
#include <stdio.h>
#endif

/*
 * Scaling factor for the profil system call.
 */

#define	SCALE_1_TO_1	0x10000L


/*
 * Forward reference to structures used.
 */

struct profile_vars;
struct profile_stats;
struct profile_md;
struct profile_dci;
struct profile_profil;
struct callback;
struct gprof_arc;
struct prof_ext;

/*
 * Profiling type
 */

typedef enum profile_type {
	PROFILE_NONE,
	PROFILE_GPROF,
	PROFILE_PROF
} profile_type_t;

/*
 * Whether to allocate memory in _profile_md_init.
 */

typedef enum profile_alloc_mem {
	PROFILE_ALLOC_MEM_NO,
	PROFILE_ALLOC_MEM_YES
} profile_alloc_mem_t;

/*
 * Allocation context block types.
 */

typedef enum acontext_type {
	ACONTEXT_PROF,			/* 0: prof records */
	ACONTEXT_GPROF,			/* 1: gprof arcs */
	ACONTEXT_GFUNC,			/* 2: gprof function headers */
	ACONTEXT_MISC,			/* 3: misc. allocations */
	ACONTEXT_PROFIL,		/* 4: profil based allocations */
	ACONTEXT_DCI,			/* 5: dci based allocations */
	ACONTEXT_BASIC_BLOCK,		/* 6: basic block allocations */
	ACONTEXT_CALLBACK,		/* 7: callback structures */
	ACONTEXT_MAX = 32		/* # allocation contexts */
} acontext_type_t;

#define ACONTEXT_FIRST ACONTEXT_PROF

#define	ACONTEXT_NAMES {						\
		 "prof",						\
		 "gprof",						\
		 "gfunc",						\
		 "misc",						\
		 "profil",						\
		 "dci",							\
		 "bb",							\
		 "callback",						\
		 "#8",							\
		 "#9",							\
		 "#10",							\
		 "#11",							\
		 "#12",							\
		 "#13",							\
		 "#14",							\
		 "#15",							\
		 "#16",							\
		 "#17",							\
		 "#18",							\
		 "#19",							\
		 "#20",							\
		 "#21",							\
		 "#22",							\
		 "#23",							\
		 "#24",							\
		 "#25",							\
		 "#26",							\
		 "#27",							\
		 "#28",							\
		 "#29",							\
		 "#30",							\
		 "#31",							\
	 }

/*
 * Kgmon control codes
 */

typedef enum kgmon_control {
	KGMON_UNUSED,			/* insure no 0 is ever used */
	KGMON_GET_STATUS,		/* return whether or not profiling is active */
	KGMON_GET_PROFILE_VARS,		/* return the _profile_vars structure */
	KGMON_GET_PROFILE_STATS,	/* return the _profile_stats structure */
	KGMON_GET_DEBUG,		/* return whether or not debugging is on */

	KGMON_SET_PROFILE_ON	= 50,	/* turn on profiling */
	KGMON_SET_PROFILE_OFF,		/* turn off profiling */
	KGMON_SET_PROFILE_RESET,	/* reset profiling tables */
	KGMON_SET_DEBUG_ON,		/* turn on debugging */
	KGMON_SET_DEBUG_OFF		/* turn off debugging */
} kgmon_control_t;

#define KGMON_GET_MIN	KGMON_GET_STATUS
#define	KGMON_GET_MAX	KGMON_GET_DEBUG
#define	KGMON_SET_MIN	KGMON_SET_PROFILE_ON
#define	KGMON_SET_MAX	KGMON_SET_DEBUG_OFF

#define ENCODE_KGMON(num, control, cpu_thread)				\
  ((num) = ((cpu_thread) << 8) | (control))

#define DECODE_KGMON(num, control, cpu_thread)				\
do {									\
	control = (num) & 0xff;						\
	cpu_thread = (num) >> 8;					\
} while (0)

#define	LEGAL_KGMON(num) (((unsigned long)(num)) <= 0xffff)

/*
 * Pull in all of the machine dependent types now after defining the enums.
 */

#include <profiling/machine/profile-md.h>

/*
 *  general rounding functions.
 */

#define ROUNDDOWN(x,y)  (((x)/(y))*(y))
#define ROUNDUP(x,y)    ((((x)+(y)-1)/(y))*(y))

/*
 * Linked list of pages allocated for a particular allocation context block.
 */

struct page_list {
	void *first;			/* pointer to first byte available */
	void *ptr;			/* pointer to next available byte */
	struct page_list *next;		/* next page allocated */
	size_t bytes_free;		/* # bytes available */
	size_t bytes_allocated;		/* # bytes allocates so far */
	size_t num_allocations;		/* # of allocations */
};

/*
 * Allocation context block.
 */

struct alloc_context {
	struct alloc_context *next;	/* next allocation context block */
	struct page_list *plist;	/* head of page list */
	prof_lock_t lock;		/* lock field available to asm */
};


/*
 * Callback structure that records information for one record in the
 * profiling output.
 */

#define STR_MAX 32

struct callback {
	void	*sec_ptr;		/* callback user data */
					/* callback function */
	size_t (*callback)(struct profile_vars *, struct callback *);
	long	 sec_val1;		/* section specific value */
	long	 sec_val2;		/* section specific value */
	size_t	 sec_recsize;		/* record size */
	size_t	 sec_length;		/* total length */
	char	 sec_name[STR_MAX];	/* section name */
};

/*
 * Basic profil information (except for the profil buffer).
 */

struct profile_profil {
	prof_uptrint_t lowpc;		/* lowest address */
	prof_uptrint_t highpc;		/* highest address */
	size_t text_len;		/* highpc-lowpc */
	size_t profil_len;		/* length of the profil buffer */
	size_t counter_size;		/* size of indivual counters (HISTCOUNTER) */
	unsigned long scale;		/* scaling factor (65536 / scale) */
	unsigned long profil_unused[8];	/* currently unused */
};

/*
 * Profiling internal variables.  This structure is intended to be machine independent.
 */

struct profile_vars {
	int major_version;		/* major version number */
	int minor_version;		/* minor version number */
	size_t vars_size;		/* size of profile_vars structure */
	size_t plist_size;		/* size of page_list structure */
	size_t acontext_size;		/* size of allocation context struct */
	size_t callback_size;		/* size of callback structure */
	profile_type_t type;		/* profile type */
	const char *error_msg;		/* error message for perror */
	const char *filename;		/* filename to write to */
	char *str_ptr;			/* string table */

#if !defined(MACH_KERNEL) && !defined(_KERNEL)
	FILE *stream;			/* stdio stream to write to */
	FILE *diag_stream;		/* stdio stream to write diagnostics to */
					/* function to write out some bytes */
	size_t (*fwrite_func)(const void *, size_t, size_t, FILE *);
#else
	void *stream;			/* pointer passed to fwrite_func */
	void *diag_stream;		/* stdio stream to write diagnostics to */
					/* function to write out some bytes */
	size_t (*fwrite_func)(const void *, size_t, size_t, void *);
#endif

	size_t page_size;		/* machine pagesize */
	size_t str_bytes;		/* # bytes in string table */
	size_t str_total;		/* # bytes allocated total for string table */
	long clock_ticks;		/* # clock ticks per second */

					/* profil related variables */
	struct profile_profil profil_info; /* profil information */
	HISTCOUNTER *profil_buf;	/* profil buffer */

					/* Profiling output selection */
	void (*output_init)(struct profile_vars *);	/* output init function */
	void (*output)(struct profile_vars *);		/* output function */
	void *output_ptr;				/* output specific info */

					/* allocation contexts */
	struct alloc_context *acontext[(int)ACONTEXT_MAX];

	void (*bogus_func)(void);	/* Function to use if address out of bounds */
	prof_uptrint_t vars_unused[63];	/* future growth */

					/* Various flags */
	prof_flag_t init;		/* != 0 if initialized */
	prof_flag_t active;		/* != 0 if profiling is active */
	prof_flag_t do_profile;		/* != 0 if profiling is being done */
	prof_flag_t use_dci;		/* != 0 if using DCI */

	prof_flag_t use_profil;		/* != 0 if using profil */
	prof_flag_t recursive_alloc;	/* != 0 if alloc taking place */
	prof_flag_t output_uarea;	/* != 0 if output the uarea */
	prof_flag_t output_stats;	/* != 0 if output the stats */

	prof_flag_t output_clock;	/* != 0 if output the clock ticks */
	prof_flag_t multiple_sections;	/* != 0 if output allows multiple sections */
	prof_flag_t have_bb;		/* != 0 if we have basic block data */
	prof_flag_t init_format;	/* != 0 if output format has been chosen */

	prof_flag_t debug;		/* != 0 if debugging */
	prof_flag_t check_funcs;	/* != 0 if check gprof arcs for being in range */
	prof_flag_t flag_unused[62];	/* space for more flags */

	struct profile_stats stats;	/* profiling statistics */
	struct profile_md md;		/* machine dependent info */
};

/*
 * Profiling static data.
 */

extern struct profile_vars  _profile_vars;

/*
 * Functions called by the machine dependent routines, and provided by
 * specific routines to the kernel, server, and user space library.
 */

#if (__GNUC__ < 2) || (__GNUC__ == 2 && __GNUC_MINOR__ < 5) || defined(lint)
#define __attribute__(arg)
#endif

#if defined(_KERNEL) || defined(MACH_KERNEL)
#define _profile_printf printf
#else
extern int _profile_printf(const char *, ...) __attribute__((format(printf,1,2)));
#endif

extern void *_profile_alloc_pages (size_t);
extern void _profile_free_pages (void *, size_t);
extern void _profile_error(struct profile_vars *);

/*
 * Functions provided by the machine dependent files.
 */

extern void _profile_md_init(struct profile_vars *, profile_type_t, profile_alloc_mem_t);
extern int _profile_md_start(void);
extern int _profile_md_stop(void);
extern void *_profile_alloc(struct profile_vars *, size_t, acontext_type_t);
extern size_t _gprof_write(struct profile_vars *, struct callback *);
extern size_t _prof_write(struct profile_vars *, struct callback *);
extern void _profile_update_stats(struct profile_vars *);
extern void _profile_reset(struct profile_vars *);

#if !defined(_KERNEL) && !defined(MACH_KERNEL)
extern void _profile_print_stats(FILE *, const struct profile_stats *, const struct profile_profil *);
extern void _profile_merge_stats(struct profile_stats *, const struct profile_stats *);
#else

/*
 * Functions defined in profile-kgmon.c
 */

extern long _profile_kgmon(int,
			   size_t,
			   long,
			   int,
			   void **,
			   void (*)(kgmon_control_t));
#ifdef _KERNEL
extern void kgmon_server_control(kgmon_control_t);

#endif /* _KERNEL */
#endif /* _KERNEL or MACH_KERNEL */

#endif /* _PROFILE_INTERNAL_H */
