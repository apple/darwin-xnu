/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:49  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:08  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.5.1  1995/01/06  19:53:45  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	new file for mk6
 * 	[1994/10/12  22:25:24  dwm]
 *
 * Revision 1.1.2.2  1994/05/16  19:19:22  meissner
 * 	Protect against hash_ptr being null in _profile_update_stats.
 * 	[1994/05/16  17:23:53  meissner]
 * 
 * 	Remove _profile_cnt_to_hex, _profile_strbuffer.
 * 	_profile_print_stats now takes const pointers.
 * 	Use the new 64-bit arithmetic support instead of converting to double.
 * 	Add _profile_merge_stats to merge statistics.
 * 	[1994/04/28  21:45:04  meissner]
 * 
 * 	If MACH_ASSERT is on in server or kernel, turn on profiling printfs.
 * 	Print out fractional digits for average # of hash searches in stats.
 * 	Update overflow_ticks for # times the lprofil counter overflows into high word.
 * 	Don't make sizes of C/asm structures a const array, since it has pointers in it.
 * 	Add support for converting 64 bit ints to a string.
 * 	Use PROF_CNT_TO_DECIMAL where possible instead of PROF_CNT_TO_LDOUBLE.
 * 	[1994/04/20  15:47:02  meissner]
 * 
 * Revision 1.1.2.1  1994/04/08  17:51:51  meissner
 * 	no change
 * 	[1994/04/08  02:11:40  meissner]
 * 
 * 	Make most stats 64 bits, except for things like memory allocation.
 * 	[1994/04/02  14:58:28  meissner]
 * 
 * 	Add some printfs under #idef DEBUG_PROFILE.
 * 	[1994/03/29  21:00:11  meissner]
 * 
 * 	Further changes for gprof/prof overflow support.
 * 	Add overflow support for {gprof,prof,old,dummy}_mcount counters.
 * 	[1994/03/17  20:13:31  meissner]
 * 
 * 	Add gprof/prof overflow support
 * 	[1994/03/17  14:56:51  meissner]
 * 
 * 	Use memset instead of bzero.
 * 	[1994/02/28  23:56:10  meissner]
 * 
 * 	Add size of histogram counters & unused fields to profile_profil struct
 * 	[1994/02/17  21:41:50  meissner]
 * 
 * 	Allocate slop space for server in addition to microkernel.
 * 	Add 3rd argument to _profile_print_stats for profil info.
 * 	Print # histogram ticks too low/too high for server/mk.
 * 	[1994/02/16  22:38:18  meissner]
 * 
 * 	Calculate percentages for # of hash buckets.
 * 	[1994/02/11  16:52:04  meissner]
 * 
 * 	Print stats as an unsigned number.
 * 	[1994/02/07  18:47:05  meissner]
 * 
 * 	For kernel and server, include <kern/assert.h> not <assert.h>.
 * 	Always do assert on comparing asm vs. C structure sizes.
 * 	Add _profile_reset to reset profiling information.
 * 	Add _profile_update_stats to update the statistics.
 * 	Move _gprof_write code that updates hash stats to _profile_update_stats.
 * 	Don't allocate space for basic block support just yet.
 * 	Add support for range checking the gprof arc {from,self}pc addresses.
 * 	_profile_debug now calls _profile_update_stats.
 * 	Print how many times the acontext was locked.
 * 	If DEBUG_PROFILE is defined, set pv->debug to 1.
 * 	Expand copyright.
 * 	[1994/02/07  12:41:03  meissner]
 * 
 * 	Keep track of the number of times the kernel overflows the HISTCOUNTER counter.
 * 	[1994/02/03  20:13:28  meissner]
 * 
 * 	Add stats for {user,kernel,idle} mode in the kernel.
 * 	[1994/02/03  15:17:31  meissner]
 * 
 * 	Print unused stats in hex as well as decimal.
 * 	[1994/02/03  14:52:20  meissner]
 * 
 * 	_profile_print_stats no longer takes profile_{vars,md} pointer arguments.
 * 	If stream is NULL, _profile_print_stats will use stdout.
 * 	Separate _profile_update_stats from _gprof_write.
 * 	[1994/02/03  00:58:55  meissner]
 * 
 * 	Combine _profile_{vars,stats,md}; Allow more than one _profile_vars.
 * 	[1994/02/01  12:04:01  meissner]
 * 
 * 	Add allocation flag to _profile_md_init.
 * 	Fix core dumps in _profile_print_stats if no profile_vars ptr passed.
 * 	Print numbers in 12 columns, not 8.
 * 	Print my_cpu/max_cpu if max_cpu != 0.
 * 	Make allocations print like other stats.
 * 	Use ACONTEXT_FIRST to start loop on, not ACONTEXT_PROF.
 * 	[1994/01/28  23:33:26  meissner]
 * 
 * 	Move callback pointers into separate allocation context.
 * 	Add size fields for other structures to profile-vars.
 * 	[1994/01/26  20:23:37  meissner]
 * 
 * 	Allocate initial memory at startup.
 * 	Print structure sizes and version number when printing stats.
 * 	Initialize size fields and version numbers.
 * 	Allocation context pointers moved to _profile_vars.
 * 	[1994/01/25  01:46:04  meissner]
 * 
 * 	Move init code here from assembly language.
 * 	[1994/01/22  01:13:21  meissner]
 * 
 * 	Include <profile/profile-internal.h> instead of "profile-md.h".
 * 	[1994/01/20  20:56:49  meissner]
 * 
 * 	Fixup copyright.
 * 	[1994/01/18  23:08:02  meissner]
 * 
 * 	Rename profile.h -> profile-md.h.
 * 	[1994/01/18  19:44:57  meissner]
 * 
 * 	Write out stats unused fields.
 * 	Make _prof_write write out the prof stats gprof collects.
 * 	[1994/01/15  18:40:37  meissner]
 * 
 * 	Remove debug code called from profile-asm.s.
 * 	Always print out the # of profil buckets.
 * 	[1994/01/15  00:59:06  meissner]
 * 
 * 	Fix typo.
 * 	[1994/01/04  16:34:46  meissner]
 * 
 * 	Move max hash bucket calculation into _gprof_write & put info in stats structure.
 * 	[1994/01/04  16:15:17  meissner]
 * 
 * 	Use _profile_printf to write diagnostics; add diag_stream to hold stream to write to.
 * 	[1994/01/04  15:37:46  meissner]
 * 
 * 	Correctly handle case where more than one allocation context was
 * 	allocated due to multiple threads.
 * 	Cast stats to long for output.
 * 	Print number of profil buckets field in _profile_stats.
 * 	Add support for GFUNC allocation context.
 * 	[1994/01/04  14:26:00  meissner]
 * 
 * 	CR 10198 - Initial version.
 * 	[1994/01/01  22:44:10  meissne
 * 
 * $EndLog$
 */

#include <profiling/profile-internal.h>
#include <stdlib.h>
#include <string.h>

#if defined(MACH_KERNEL) || defined(_KERNEL)

#include <mach_assert.h>
#if MACH_ASSERT && !defined(DEBUG_PROFILE)
#define DEBUG_PROFILE 1
#endif

extern int printf(const char *, ...);
extern void panic(const char *);
#else
#include <assert.h>
#define panic(str) exit(1)
#endif

#ifndef PROFILE_NUM_FUNCS
#define	PROFILE_NUM_FUNCS	2000
#endif

#ifndef PROFILE_NUM_ARCS
#define	PROFILE_NUM_ARCS	8000
#endif

/*
 * Information passed on from profile-asm.s
 */

extern int _profile_do_stats;
extern size_t _profile_size;
extern size_t _profile_stats_size;
extern size_t _profile_md_size;
extern size_t _profile_profil_size;
extern size_t _profile_hash_size;

/*
 * All profiling variables, and a dummy gprof record.
 */

struct profile_vars _profile_vars = { 0 };
struct hasharc _gprof_dummy = { 0 };

/*
 * Forward references.
 */

static void *_profile_md_acontext(struct profile_vars *pv,
				  void *ptr,
				  size_t len,
				  acontext_type_t type);

static void _profile_reset_alloc(struct profile_vars *,
				 acontext_type_t);

extern void _bogus_function(void);

/*
 * Function to set up the initial allocation for a context block.
 */

static void *
_profile_md_acontext(struct profile_vars *pv,
		     void *ptr,
		     size_t len,
		     acontext_type_t type)
{
	struct memory {
		struct alloc_context context;
		struct page_list plist;
		int data[1];
	};

	struct memory *mptr = (struct memory *)ptr;
	struct alloc_context *context = &mptr->context;
	struct page_list *plist = &mptr->plist;

#ifdef DEBUG_PROFILE
	_profile_printf("_profile_md_acontext: pv= 0x%lx, ptr= 0x%lx, len= %6ld, type= %d\n",
			(long)pv,
			(long)ptr,
			(long)len,
			(int)type);
#endif

	/* Fill in context block header */
	context->next = pv->acontext[type];
	context->plist = plist;
	context->lock = 0;

	/* Fill in first page list information */
	plist->ptr = plist->first = (void *)&mptr->data[0];
	plist->next = (struct page_list *)0;
	plist->bytes_free = len - ((char *)plist->ptr - (char *)ptr);
	plist->bytes_allocated = 0;
	plist->num_allocations = 0;

	/* Update statistics */
	pv->stats.num_context[type]++;
	pv->stats.wasted[type] += plist->bytes_free;
	pv->stats.overhead[type] += len - plist->bytes_free;

	/* And setup context block */
	pv->acontext[type] = context;

	return (void *)((char *)ptr+len);
}


/*
 * Machine dependent function to initialize things.
 */

void
_profile_md_init(struct profile_vars *pv,
		 profile_type_t type,
		 profile_alloc_mem_t alloc_mem)
{
	size_t page_size = pv->page_size;
	size_t arc_size;
	size_t func_size;
	size_t misc_size;
	size_t hash_size;
	size_t extra_arc_size;
	size_t extra_func_size;
	size_t callback_size = page_size;
	void *ptr;
	acontext_type_t ac;
	int i;
	static struct {
		size_t	    c_size;		/* size C thinks structure is */
		size_t	   *asm_size_ptr;	/* pointer to size asm thinks struct is */
		const char *name;		/* structure name */
	} sizes[] = {
		{ sizeof(struct profile_profil), &_profile_profil_size,	"profile_profil" },
		{ sizeof(struct profile_stats),	 &_profile_stats_size,	"profile_stats" },
		{ sizeof(struct profile_md),	 &_profile_md_size,	"profile_md" },
		{ sizeof(struct profile_vars),	 &_profile_size,	"profile_vars" }};

#ifdef DEBUG_PROFILE
	_profile_printf("_profile_md_init: pv = 0x%lx, type = %d, alloc = %d\n",
			(long) pv,
			(int)type,
			(int)alloc_mem);
#endif

	for (i = 0; i < sizeof (sizes) / sizeof(sizes[0]); i++) {
		if (sizes[i].c_size != *sizes[i].asm_size_ptr) {
			_profile_printf("C thinks struct %s is %ld bytes, asm thinks it is %ld bytes\n",
					sizes[i].name,
					(long)sizes[i].c_size,
					(long)*sizes[i].asm_size_ptr);

			panic(sizes[i].name);
		}
	}

	/* Figure out which function will handle compiler generated profiling */
	if (type == PROFILE_GPROF) {
		pv->md.save_mcount_ptr = _gprof_mcount;

	} else if (type == PROFILE_PROF) {
		pv->md.save_mcount_ptr = _prof_mcount;

	} else {
		pv->md.save_mcount_ptr = _dummy_mcount;
	}

	pv->vars_size         = sizeof(struct profile_vars);
	pv->plist_size        = sizeof(struct page_list);
	pv->acontext_size     = sizeof(struct alloc_context);
	pv->callback_size     = sizeof(struct callback);
	pv->major_version     = PROFILE_MAJOR_VERSION;
	pv->minor_version     = PROFILE_MINOR_VERSION;
	pv->type              = type;
	pv->do_profile        = 1;
	pv->use_dci	      = 1;
	pv->use_profil	      = 1;
	pv->output_uarea      = 1;
	pv->output_stats      = (prof_flag_t) _profile_do_stats;
	pv->output_clock      = 1;
	pv->multiple_sections = 1;
	pv->init_format	      = 0;
	pv->bogus_func	      = _bogus_function;

#ifdef DEBUG_PROFILE
	pv->debug	      = 1;
#endif

	if (!pv->error_msg) {
		pv->error_msg = "error in profiling";
	}

	if (!pv->page_size) {
		pv->page_size = 4096;
	}

	pv->stats.stats_size    = sizeof(struct profile_stats);
	pv->stats.major_version = PROFILE_MAJOR_VERSION;
	pv->stats.minor_version = PROFILE_MINOR_VERSION;

	pv->md.md_size	       = sizeof(struct profile_md);
	pv->md.major_version   = PROFILE_MAJOR_VERSION;
	pv->md.minor_version   = PROFILE_MINOR_VERSION;
	pv->md.hash_size       = _profile_hash_size;
	pv->md.num_cache       = MAX_CACHE;
	pv->md.mcount_ptr_ptr  = &_mcount_ptr;
	pv->md.dummy_ptr       = &_gprof_dummy;
	pv->md.alloc_pages     = _profile_alloc_pages;

	/* zero out all allocation context blocks */
	for (ac = ACONTEXT_FIRST; ac < ACONTEXT_MAX; ac++) {
		pv->acontext[ac] = (struct alloc_context *)0;
	}

	/* Don't allocate memory if not desired */
	if (!alloc_mem) {
		return;
	}

	/* Allocate some space for the initial allocations */
	switch (type) {
	default:
		misc_size = page_size;
		ptr = _profile_alloc_pages(misc_size + callback_size);
		ptr = _profile_md_acontext(pv, ptr, misc_size, ACONTEXT_MISC);
		ptr = _profile_md_acontext(pv, ptr, callback_size, ACONTEXT_CALLBACK);
		break;

	case PROFILE_GPROF:

#if defined(MACH_KERNEL) || defined(_KERNEL)
		/*
		 * For the MK & server allocate some slop space now for the
		 * secondary context blocks in case allocations are done at
		 * interrupt level when another allocation is being done.  This
		 * is done before the main allocation blocks and will be pushed
		 * so that it will only be used when the main allocation block
		 * is locked.
		 */
		extra_arc_size = 4*page_size;
		extra_func_size = 2*page_size;
#else
		extra_arc_size = extra_func_size = 0;
#endif

		/* Set up allocation areas */
		arc_size = ROUNDUP(PROFILE_NUM_ARCS * sizeof(struct hasharc), page_size);
		func_size = ROUNDUP(PROFILE_NUM_FUNCS * sizeof(struct gfuncs), page_size);
		hash_size = _profile_hash_size * sizeof (struct hasharc *);
		misc_size = ROUNDUP(hash_size + page_size, page_size);

		ptr = _profile_alloc_pages(arc_size
					   + func_size
					   + misc_size
					   + callback_size
					   + extra_arc_size
					   + extra_func_size);

#if defined(MACH_KERNEL) || defined(_KERNEL)
		ptr = _profile_md_acontext(pv, ptr, extra_arc_size, ACONTEXT_GPROF);
		ptr = _profile_md_acontext(pv, ptr, extra_func_size, ACONTEXT_GFUNC);
#endif
		ptr = _profile_md_acontext(pv, ptr, arc_size, ACONTEXT_GPROF);
		ptr = _profile_md_acontext(pv, ptr, func_size, ACONTEXT_GFUNC);
		ptr = _profile_md_acontext(pv, ptr, misc_size, ACONTEXT_MISC);
		ptr = _profile_md_acontext(pv, ptr, callback_size, ACONTEXT_CALLBACK);

		/* Allocate hash table */
		pv->md.hash_ptr = (struct hasharc **) _profile_alloc(pv, hash_size, ACONTEXT_MISC);
		break;

	case PROFILE_PROF:
		/* Set up allocation areas */
		func_size = ROUNDUP(PROFILE_NUM_FUNCS * sizeof(struct prof_ext), page_size);
		misc_size = page_size;

		ptr = _profile_alloc_pages(func_size
					   + misc_size
					   + callback_size);

		ptr = _profile_md_acontext(pv, ptr, func_size, ACONTEXT_PROF);
		ptr = _profile_md_acontext(pv, ptr, misc_size, ACONTEXT_MISC);
		ptr = _profile_md_acontext(pv, ptr, callback_size, ACONTEXT_CALLBACK);
		break;
	}
}


/*
 * Machine dependent functions to start and stop profiling.
 */

int
_profile_md_start(void)
{
	_mcount_ptr = _profile_vars.md.save_mcount_ptr;
	return 0;
}

int
_profile_md_stop(void)
{
	_mcount_ptr = _dummy_mcount;
	return 0;
}


/*
 * Free up all memory in a memory context block.
 */

static void
_profile_reset_alloc(struct profile_vars *pv, acontext_type_t ac)
{
	struct alloc_context *aptr;
	struct page_list *plist;

	for (aptr = pv->acontext[ac];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist;
		     plist != (struct page_list *)0;
		     plist = plist->next) {

			plist->ptr = plist->first;
			plist->bytes_free += plist->bytes_allocated;
			plist->bytes_allocated = 0;
			plist->num_allocations = 0;
			memset(plist->first, '\0', plist->bytes_allocated);
		}
	}
}


/*
 * Reset profiling.  Since the only user of this function is the kernel
 * and the server, we don't have to worry about other stuff than gprof.
 */

void
_profile_reset(struct profile_vars *pv)
{
	struct alloc_context *aptr;
	struct page_list *plist;
	struct gfuncs *gfunc;

	if (pv->active) {
		_profile_md_stop();
	}

	/* Reset all function unique pointers back to 0 */
	for (aptr = pv->acontext[ACONTEXT_GFUNC];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist;
		     plist != (struct page_list *)0;
		     plist = plist->next) {

			for (gfunc = (struct gfuncs *)plist->first;
			     gfunc < (struct gfuncs *)plist->ptr;
			     gfunc++) {

				*(gfunc->unique_ptr) = (struct hasharc *)0;
			}
		}
	}

	/* Release memory */
	_profile_reset_alloc(pv, ACONTEXT_GPROF);
	_profile_reset_alloc(pv, ACONTEXT_GFUNC);
	_profile_reset_alloc(pv, ACONTEXT_PROF);

	memset((void *)pv->profil_buf, '\0', pv->profil_info.profil_len);
	memset((void *)pv->md.hash_ptr, '\0', pv->md.hash_size * sizeof(struct hasharc *));
	memset((void *)&pv->stats, '\0', sizeof(pv->stats));

	pv->stats.stats_size    = sizeof(struct profile_stats);
	pv->stats.major_version = PROFILE_MAJOR_VERSION;
	pv->stats.minor_version = PROFILE_MINOR_VERSION;

	if (pv->active) {
		_profile_md_start();
	}
}


/*
 * Machine dependent function to write out gprof records.
 */

size_t
_gprof_write(struct profile_vars *pv, struct callback *callback_ptr)
{
	struct alloc_context *aptr;
	struct page_list *plist;
	size_t bytes = 0;
	struct hasharc *hptr;
	int i;

	for (aptr = pv->acontext[ACONTEXT_GPROF];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist; plist != (struct page_list *)0; plist = plist->next) {
			hptr = (struct hasharc *)plist->first;
			for (i = 0; i < plist->num_allocations; (i++, hptr++)) {

				struct gprof_arc arc = hptr->arc;
				int nrecs = 1 + (hptr->overflow * 2);
				int j;

				if (pv->check_funcs) {
					if (arc.frompc < pv->profil_info.lowpc ||
					    arc.frompc > pv->profil_info.highpc) {

						arc.frompc = (prof_uptrint_t)pv->bogus_func;
					}

					if (arc.selfpc < pv->profil_info.lowpc ||
					    arc.selfpc > pv->profil_info.highpc) {

						arc.selfpc = (prof_uptrint_t)pv->bogus_func;
					}
				}

				/* For each overflow, emit 2 extra records with the count
				   set to 0x80000000 */
				for (j = 0; j < nrecs; j++) {
					bytes += sizeof (arc);
					if ((*pv->fwrite_func)((void *)&arc,
							       sizeof(arc),
							       1,
							       pv->stream) != 1) {

						_profile_error(pv);
					}

					arc.count = 0x80000000;
				}
			}
		}
	}

	return bytes;
}


/*
 * Machine dependent function to write out prof records.
 */

size_t
_prof_write(struct profile_vars *pv, struct callback *callback_ptr)
{
	struct alloc_context *aptr;
	struct page_list *plist;
	size_t bytes = 0;
	struct prof_ext prof_st;
	struct prof_int *pptr;
	struct gfuncs *gptr;
	int nrecs;
	int i, j;

	/* Write out information prof_mcount collects */
	for (aptr = pv->acontext[ACONTEXT_PROF];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist; plist != (struct page_list *)0; plist = plist->next) {
			pptr = (struct prof_int *)plist->first;

			for (i = 0; i < plist->num_allocations; (i++, pptr++)) {

				/* Write out 2 records for each overflow, each with a
				   count of 0x80000000 + the normal record */
				prof_st = pptr->prof;
				nrecs = 1 + (pptr->overflow * 2);

				for (j = 0; j < nrecs; j++) {
					bytes += sizeof (struct prof_ext);
					if ((*pv->fwrite_func)((void *)&prof_st,
							       sizeof(prof_st),
							       1,
							       pv->stream) != 1) {

						_profile_error(pv);
					}

					prof_st.cncall = 0x80000000;
				}
			}
		}
	}

	/* Now write out the prof information that gprof collects */
	for (aptr = pv->acontext[ACONTEXT_GFUNC];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist; plist != (struct page_list *)0; plist = plist->next) {
			gptr = (struct gfuncs *)plist->first;

			for (i = 0; i < plist->num_allocations; (i++, gptr++)) {

				/* Write out 2 records for each overflow, each with a
				   count of 0x80000000 + the normal record */
				prof_st = gptr->prof.prof;
				nrecs = 1 + (gptr->prof.overflow * 2);

				for (j = 0; j < nrecs; j++) {
					bytes += sizeof (struct prof_ext);
					if ((*pv->fwrite_func)((void *)&prof_st,
							       sizeof(prof_st),
							       1,
							       pv->stream) != 1) {

						_profile_error(pv);
					}

					prof_st.cncall = 0x80000000;
				}
			}
		}
	}

	return bytes;
}


/*
 * Update any statistics.  For the 386, calculate the hash table loading factor.
 * Also figure out how many overflows occured.
 */

void
_profile_update_stats(struct profile_vars *pv)
{
	struct alloc_context *aptr;
	struct page_list *plist;
	struct hasharc *hptr;
	struct prof_int *pptr;
	struct gfuncs *fptr;
	LHISTCOUNTER *lptr;
	int i;

	for(i = 0; i < MAX_BUCKETS+1; i++) {
		pv->stats.buckets[i] = 0;
	}

	pv->stats.hash_buckets = 0;

	if (pv->md.hash_ptr) {
		for (i = 0; i < pv->md.hash_size; i++) {
			long nbuckets = 0;
			struct hasharc *hptr;

			for (hptr = pv->md.hash_ptr[i]; hptr; hptr = hptr->next) {
				nbuckets++;
			}

			pv->stats.buckets[ (nbuckets < MAX_BUCKETS) ? nbuckets : MAX_BUCKETS ]++;
			if (pv->stats.hash_buckets < nbuckets) {
				pv->stats.hash_buckets = nbuckets;
			}
		}
	}

	/* Count how many times functions are out of bounds */
	if (pv->check_funcs) {
		pv->stats.bogus_count = 0;

		for (aptr = pv->acontext[ACONTEXT_GPROF];
		     aptr != (struct alloc_context *)0;
		     aptr = aptr->next) {

			for (plist = aptr->plist;
			     plist != (struct page_list *)0;
			     plist = plist->next) {

				hptr = (struct hasharc *)plist->first;
				for (i = 0; i < plist->num_allocations; (i++, hptr++)) {

					if (hptr->arc.frompc < pv->profil_info.lowpc ||
					    hptr->arc.frompc > pv->profil_info.highpc) {
						pv->stats.bogus_count++;
					}

					if (hptr->arc.selfpc < pv->profil_info.lowpc ||
					    hptr->arc.selfpc > pv->profil_info.highpc) {
						pv->stats.bogus_count++;
					}
				}
			}
		}
	}

	/* Figure out how many overflows occurred */
	PROF_ULONG_TO_CNT(pv->stats.prof_overflow, 0);
	PROF_ULONG_TO_CNT(pv->stats.gprof_overflow, 0);

	for (aptr = pv->acontext[ACONTEXT_GPROF];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist;
		     plist != (struct page_list *)0;
		     plist = plist->next) {

			hptr = (struct hasharc *)plist->first;
			for (i = 0; i < plist->num_allocations; (i++, hptr++)) {
				PROF_CNT_ADD(pv->stats.gprof_overflow, hptr->overflow);
			}
		}
	}

	for (aptr = pv->acontext[ACONTEXT_PROF];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist;
		     plist != (struct page_list *)0;
		     plist = plist->next) {

			pptr = (struct prof_int *)plist->first;
			for (i = 0; i < plist->num_allocations; (i++, pptr++)) {
				PROF_CNT_ADD(pv->stats.prof_overflow, pptr->overflow);
			}
		}
	}

	for (aptr = pv->acontext[ACONTEXT_GFUNC];
	     aptr != (struct alloc_context *)0;
	     aptr = aptr->next) {

		for (plist = aptr->plist;
		     plist != (struct page_list *)0;
		     plist = plist->next) {

			fptr = (struct gfuncs *)plist->first;
			for (i = 0; i < plist->num_allocations; (i++, fptr++)) {
				PROF_CNT_ADD(pv->stats.prof_overflow, fptr->prof.overflow);
			}
		}
	}

	/* Now go through & count how many times the LHISTCOUNTER overflowed into a 2nd word */
	lptr = (LHISTCOUNTER *)pv->profil_buf;

	if (pv->use_profil &&
	    pv->profil_info.counter_size == sizeof(LHISTCOUNTER) &&
	    lptr != (LHISTCOUNTER *)0) {

		PROF_ULONG_TO_CNT(pv->stats.overflow_ticks, 0);
		for (i = 0; i < pv->stats.profil_buckets; i++) {
			PROF_CNT_ADD(pv->stats.overflow_ticks, lptr[i].high);
		}
	}
}

#if !defined(_KERNEL) && !defined(MACH_KERNEL)

/*
 * Routine callable from the debugger that prints the statistics.
 */

int _profile_debug(void)
{
	_profile_update_stats(&_profile_vars);
	_profile_print_stats(stderr, &_profile_vars.stats, &_profile_vars.profil_info);
	return 0;
}

/*
 * Print the statistics structure in a meaningful way.
 */

void _profile_print_stats(FILE *stream,
			  const struct profile_stats *stats,
			  const struct profile_profil *pinfo)
{
	int i;
	prof_cnt_t total_hits;
	acontext_type_t ac;
	int width_cname = 0;
	int width_alloc = 0;
	int width_wasted = 0;
	int width_overhead = 0;
	int width_context = 0;
	static const char *cname[ACONTEXT_MAX] = ACONTEXT_NAMES;
	char buf[20];

	if (!stats) {
		return;
	}

	if (!stream) {
		stream = stdout;
	}

	sprintf(buf, "%ld.%ld", (long)stats->major_version, (long)stats->minor_version);
	fprintf(stream, "%12s profiling version number\n", buf);
	fprintf(stream, "%12lu size of profile_vars\n", (long unsigned)sizeof(struct profile_vars));
	fprintf(stream, "%12lu size of profile_stats\n", (long unsigned)sizeof(struct profile_stats));
	fprintf(stream, "%12lu size of profile_md\n", (long unsigned)sizeof(struct profile_md));
	fprintf(stream, "%12s calls to _{,g}prof_mcount\n", PROF_CNT_TO_DECIMAL((char *)0, stats->cnt));
	fprintf(stream, "%12s calls to old mcount\n", PROF_CNT_TO_DECIMAL((char *)0, stats->old_mcount));
	fprintf(stream, "%12s calls to _dummy_mcount\n", PROF_CNT_TO_DECIMAL((char *)0, stats->dummy));
	fprintf(stream, "%12lu functions profiled\n", (long unsigned)stats->prof_records);
	fprintf(stream, "%12lu gprof arcs\n", (long unsigned)stats->gprof_records);

	if (pinfo) {
		fprintf(stream, "%12lu profil buckets\n", (long unsigned)stats->profil_buckets);
		fprintf(stream, "%12lu profil lowpc  [0x%lx]\n",
			(long unsigned)pinfo->lowpc,
			(long unsigned)pinfo->lowpc);

		fprintf(stream, "%12lu profil highpc [0x%lx]\n",
			(long unsigned)pinfo->highpc,
			(long unsigned)pinfo->highpc);

		fprintf(stream, "%12lu profil highpc-lowpc\n", (long unsigned)(pinfo->highpc - pinfo->lowpc));
		fprintf(stream, "%12lu profil buffer length\n", (long unsigned)pinfo->profil_len);
		fprintf(stream, "%12lu profil sizeof counters\n", (long unsigned)pinfo->counter_size);
		fprintf(stream, "%12lu profil scale (%g)\n",
			(long unsigned)pinfo->scale,
			((double)pinfo->scale) / ((double) 0x10000));


		for (i = 0; i < sizeof (pinfo->profil_unused) / sizeof (pinfo->profil_unused[0]); i++) {
			if (pinfo->profil_unused[i]) {
				fprintf(stream, "%12lu profil unused[%2d] {0x%.8lx}\n",
					(long unsigned)pinfo->profil_unused[i],
					i,
					(long unsigned)pinfo->profil_unused[i]);
			}
		}
	}

	if (stats->max_cpu) {
		fprintf(stream, "%12lu current cpu/thread\n", (long unsigned)stats->my_cpu);
		fprintf(stream, "%12lu max cpu/thread+1\n", (long unsigned)stats->max_cpu);
	}

	if (stats->bogus_count != 0) {
		fprintf(stream,
			"%12lu gprof functions found outside of range\n",
			(long unsigned)stats->bogus_count);
	}

	if (PROF_CNT_NE_0(stats->too_low)) {
		fprintf(stream,
			"%12s histogram ticks were too low\n",
			PROF_CNT_TO_DECIMAL((char *)0, stats->too_low));
	}

	if (PROF_CNT_NE_0(stats->too_high)) {
		fprintf(stream,
			"%12s histogram ticks were too high\n",
			PROF_CNT_TO_DECIMAL((char *)0, stats->too_high));
	}

	if (PROF_CNT_NE_0(stats->acontext_locked)) {
		fprintf(stream,
			"%12s times an allocation context was locked\n",
			PROF_CNT_TO_DECIMAL((char *)0, stats->acontext_locked));
	}

	if (PROF_CNT_NE_0(stats->kernel_ticks)
	    || PROF_CNT_NE_0(stats->user_ticks)
	    || PROF_CNT_NE_0(stats->idle_ticks)) {

		prof_cnt_t total_ticks;
		long double total_ticks_dbl;

		total_ticks = stats->kernel_ticks;
		PROF_CNT_LADD(total_ticks, stats->user_ticks);
		PROF_CNT_LADD(total_ticks, stats->idle_ticks);
		total_ticks_dbl = PROF_CNT_TO_LDOUBLE(total_ticks);

		fprintf(stream,
			"%12s total ticks\n",
			PROF_CNT_TO_DECIMAL((char *)0, total_ticks));

		fprintf(stream,
			"%12s ticks within the kernel (%5.2Lf%%)\n",
			PROF_CNT_TO_DECIMAL((char *)0, stats->kernel_ticks),
			100.0L * (PROF_CNT_TO_LDOUBLE(stats->kernel_ticks) / total_ticks_dbl));

		fprintf(stream,
			"%12s ticks within user space (%5.2Lf%%)\n",
			PROF_CNT_TO_DECIMAL((char *)0, stats->user_ticks),
			100.0L * (PROF_CNT_TO_LDOUBLE(stats->user_ticks) / total_ticks_dbl));

		fprintf(stream,
			"%12s ticks idle              (%5.2Lf%%)\n",
			PROF_CNT_TO_DECIMAL((char *)0, stats->idle_ticks),
			100.0L * (PROF_CNT_TO_LDOUBLE(stats->idle_ticks) / total_ticks_dbl));
	}

	if (PROF_CNT_NE_0(stats->overflow_ticks)) {
		fprintf(stream, "%12s times a HISTCOUNTER counter would have overflowed\n",
			PROF_CNT_TO_DECIMAL((char *)0, stats->overflow_ticks));
	}

	if (PROF_CNT_NE_0(stats->hash_num)) {
		long double total_buckets = 0.0L;

		for (i = 0; i <= MAX_BUCKETS; i++) {
			total_buckets += (long double)stats->buckets[i];
		}

		fprintf(stream, "%12lu max bucket(s) on hash chain.\n", (long unsigned)stats->hash_buckets);
		for (i = 0; i < MAX_BUCKETS; i++) {
			if (stats->buckets[i] != 0) {
				fprintf(stream, "%12lu bucket(s) had %d entries (%5.2Lf%%)\n",
					(long unsigned)stats->buckets[i], i,
					100.0L * ((long double)stats->buckets[i] / total_buckets));
			}
		}

		if (stats->buckets[MAX_BUCKETS] != 0) {
			fprintf(stream, "%12lu bucket(s) had more than %d entries (%5.2Lf%%)\n",
				(long unsigned)stats->buckets[MAX_BUCKETS], MAX_BUCKETS,
				100.0L * ((long double)stats->buckets[MAX_BUCKETS] / total_buckets));
		}
	}

	PROF_ULONG_TO_CNT(total_hits, 0);
	for (i = 0; i < MAX_CACHE; i++) {
		PROF_CNT_LADD(total_hits, stats->cache_hits[i]);
	}

	if (PROF_CNT_NE_0(total_hits)) {
		long double total		= PROF_CNT_TO_LDOUBLE(stats->cnt);
		long double total_hits_dbl	= PROF_CNT_TO_LDOUBLE(total_hits);

		fprintf(stream,
			"%12s cache hits (%.2Lf%%)\n",
			PROF_CNT_TO_DECIMAL((char *)0, total_hits),
			100.0L * (total_hits_dbl / total));

		for (i = 0; i < MAX_CACHE; i++) {
			if (PROF_CNT_NE_0(stats->cache_hits[i])) {
				fprintf(stream,
					"%12s times cache#%d matched (%5.2Lf%% of cache hits, %5.2Lf%% total)\n",
					PROF_CNT_TO_DECIMAL((char *)0, stats->cache_hits[i]),
					i+1,
					100.0L * (PROF_CNT_TO_LDOUBLE(stats->cache_hits[i]) / total_hits_dbl),
					100.0L * (PROF_CNT_TO_LDOUBLE(stats->cache_hits[i]) / total));
			}
		}

		if (PROF_CNT_NE_0(stats->hash_num)) {
			fprintf(stream, "%12s times hash table searched\n", PROF_CNT_TO_DECIMAL((char *)0, stats->hash_num));
			fprintf(stream, "%12s hash buckets searched\n", PROF_CNT_TO_DECIMAL((char *)0, stats->hash_search));
			fprintf(stream, "%12.4Lf average buckets searched\n",
				PROF_CNT_TO_LDOUBLE(stats->hash_search) / PROF_CNT_TO_LDOUBLE(stats->hash_num));
		}
	}

	for (i = 0; i < sizeof (stats->stats_unused) / sizeof (stats->stats_unused[0]); i++) {
		if (PROF_CNT_NE_0(stats->stats_unused[i])) {
			fprintf(stream, "%12s unused[%2d] {0x%.8lx 0x%.8lx}\n",
				PROF_CNT_TO_DECIMAL((char *)0, stats->stats_unused[i]),
				i,
				(unsigned long)stats->stats_unused[i].high,
				(unsigned long)stats->stats_unused[i].low);
		}
	}

	/* Get the width for the allocation contexts */
	for (ac = ACONTEXT_FIRST; ac < ACONTEXT_MAX; ac++) {
		int len;

		if (stats->num_context[ac] == 0) {
			continue;
		}

		len = strlen (cname[ac]);
		if (len > width_cname)
			width_cname = len;

		len = sprintf (buf, "%lu", (long unsigned)stats->num_alloc[ac]);
		if (len > width_alloc)
			width_alloc = len;

		len = sprintf (buf, "%lu", (long unsigned)stats->wasted[ac]);
		if (len > width_wasted)
			width_wasted = len;

		len = sprintf (buf, "%lu", (long unsigned)stats->overhead[ac]);
		if (len > width_overhead)
			width_overhead = len;

		len = sprintf (buf, "%lu", (long unsigned)stats->num_context[ac]);
		if (len > width_context)
			width_context = len;
	}

	/* Print info about allocation contexts */
	for (ac = ACONTEXT_FIRST; ac < ACONTEXT_MAX; ac++) {
		if (stats->num_context[ac] == 0) {
			continue;
		}

		fprintf (stream,
			 "%12lu bytes in %-*s %*lu alloc, %*lu unused, %*lu over, %*lu context\n",
			 (long unsigned)stats->bytes_alloc[ac],
			 width_cname,    cname[ac],
			 width_alloc,    (long unsigned)stats->num_alloc[ac],
			 width_wasted,   (long unsigned)stats->wasted[ac],
			 width_overhead, (long unsigned)stats->overhead[ac],
			 width_context,  (long unsigned)stats->num_context[ac]);
	}
}


/*
 * Merge a new statistics field into an old one.
 */

void _profile_merge_stats(struct profile_stats  *old_stats, const struct profile_stats  *new_stats)
{
	int i;

	/* If nothing passed, just return */
	if (!old_stats || !new_stats)
		return;

	/* If the old_stats has not been initialized, just copy in the new stats */
	if (old_stats->major_version == 0) {
	    *old_stats = *new_stats;

	/* Otherwise, update stats, field by field */
	} else {
		if (old_stats->prof_records < new_stats->prof_records)
			old_stats->prof_records = new_stats->prof_records;

		if (old_stats->gprof_records < new_stats->gprof_records)
			old_stats->gprof_records = new_stats->gprof_records;

		if (old_stats->hash_buckets < new_stats->hash_buckets)
			old_stats->hash_buckets = new_stats->hash_buckets;

		if (old_stats->bogus_count < new_stats->bogus_count)
			old_stats->bogus_count = new_stats->bogus_count;

		PROF_CNT_LADD(old_stats->cnt,		  new_stats->cnt);
		PROF_CNT_LADD(old_stats->dummy,		  new_stats->dummy);
		PROF_CNT_LADD(old_stats->old_mcount,	  new_stats->old_mcount);
		PROF_CNT_LADD(old_stats->hash_search,	  new_stats->hash_search);
		PROF_CNT_LADD(old_stats->hash_num,	  new_stats->hash_num);
		PROF_CNT_LADD(old_stats->user_ticks,	  new_stats->user_ticks);
		PROF_CNT_LADD(old_stats->kernel_ticks,	  new_stats->kernel_ticks);
		PROF_CNT_LADD(old_stats->idle_ticks,	  new_stats->idle_ticks);
		PROF_CNT_LADD(old_stats->overflow_ticks,  new_stats->overflow_ticks);
		PROF_CNT_LADD(old_stats->acontext_locked, new_stats->acontext_locked);
		PROF_CNT_LADD(old_stats->too_low,	  new_stats->too_low);
		PROF_CNT_LADD(old_stats->too_high,	  new_stats->too_high);
		PROF_CNT_LADD(old_stats->prof_overflow,	  new_stats->prof_overflow);
		PROF_CNT_LADD(old_stats->gprof_overflow,  new_stats->gprof_overflow);

		for (i = 0; i < (int)ACONTEXT_MAX; i++) {
			if (old_stats->num_alloc[i] < new_stats->num_alloc[i])
				old_stats->num_alloc[i] = new_stats->num_alloc[i];

			if (old_stats->bytes_alloc[i] < new_stats->bytes_alloc[i])
				old_stats->bytes_alloc[i] = new_stats->bytes_alloc[i];

			if (old_stats->num_context[i] < new_stats->num_context[i])
				old_stats->num_context[i] = new_stats->num_context[i];

			if (old_stats->wasted[i] < new_stats->wasted[i])
				old_stats->wasted[i] = new_stats->wasted[i];

			if (old_stats->overhead[i] < new_stats->overhead[i])
				old_stats->overhead[i] = new_stats->overhead[i];

		}

		for (i = 0; i < MAX_BUCKETS+1; i++) {
			if (old_stats->buckets[i] < new_stats->buckets[i])
				old_stats->buckets[i] = new_stats->buckets[i];
		}

		for (i = 0; i < MAX_CACHE; i++) {
			PROF_CNT_LADD(old_stats->cache_hits[i], new_stats->cache_hits[i]);
		}

		for (i = 0; i < sizeof(old_stats->stats_unused) / sizeof(old_stats->stats_unused[0]); i++) {
			PROF_CNT_LADD(old_stats->stats_unused[i], new_stats->stats_unused[i]);
		}
	}
}

#endif


/*
 * Invalid function address used when checking of function addresses is
 * desired for gprof arcs, and we discover an address out of bounds.
 * There should be no callers of this function.
 */

void
_bogus_function(void)
{
}
