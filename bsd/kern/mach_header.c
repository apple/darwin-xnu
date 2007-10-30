/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/*
 *	File: kern/mach_header.c
 *
 *	Functions for accessing mach-o headers.
 *
 * NOTE:	This file supports only 32 bit mach headers at the present
 *		time; it's primary use is by kld, and all externally
 *		referenced routines at the present time operate against
 *		the 32 bit mach header _mh_execute_header, which is the
 *		header for the currently executing kernel.  Adding support
 *		for 64 bit kernels is possible, but is not necessary at the
 *		present time.
 *
 * HISTORY
 * 27-MAR-97  Umesh Vaishampayan (umeshv@NeXT.com)
 *	Added getsegdatafromheader();
 *
 * 29-Jan-92  Mike DeMoney (mike@next.com)
 *	Made into machine independent form from machdep/m68k/mach_header.c.
 *	Ifdef'ed out most of this since I couldn't find any references.
 */

#if !defined(KERNEL_PRELOAD)
#include <kern/mach_header.h>
#include <string.h>		// from libsa
#if DEBUG
#include <libkern/libkern.h>
#endif

extern struct mach_header _mh_execute_header;

/*
 * return the last address (first avail)
 *
 * This routine operates against the currently executing kernel only
 */
vm_offset_t
getlastaddr(void)
{
	struct segment_command	*sgp;
	vm_offset_t		last_addr = 0;
	struct mach_header *header = &_mh_execute_header;
	unsigned long i;

	sgp = (struct segment_command *)
		((char *)header + sizeof(struct mach_header));
	for (i = 0; i < header->ncmds; i++){
		if (   sgp->cmd == LC_SEGMENT) {
			if (sgp->vmaddr + sgp->vmsize > last_addr)
				last_addr = sgp->vmaddr + sgp->vmsize;
		}
		sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	}
	return last_addr;
}

#if FIXME  /* [ */
/*
 * This routine operates against the currently executing kernel only
 */
struct mach_header **
getmachheaders(void)
{
	struct mach_header **tl;
	tl = (struct mach_header **)malloc(2*sizeof(struct mach_header *));
	tl[0] = &_mh_execute_header;
	tl[1] = (struct mach_header *)0;
	return tl;
}
#endif  /* FIXME ] */

/*
 * This routine returns the a pointer to the data for the named section in the
 * named segment if it exist in the mach header passed to it.  Also it returns
 * the size of the section data indirectly through the pointer size.  Otherwise
 *  it returns zero for the pointer and the size.
 *
 * This routine can operate against any 32 bit mach header.
 */
void *
getsectdatafromheader(
    struct mach_header *mhp,
    const char *segname,
    const char *sectname,
    int *size)
{		
	const struct section *sp;
	void *result;

	sp = getsectbynamefromheader(mhp, segname, sectname);
	if(sp == (struct section *)0){
	    *size = 0;
	    return((char *)0);
	}
	*size = sp->size;
	result = (void *)sp->addr;
	return result;
}

/*
 * This routine returns the a pointer to the data for the named segment
 * if it exist in the mach header passed to it.  Also it returns
 * the size of the segment data indirectly through the pointer size.
 * Otherwise it returns zero for the pointer and the size.
 *
 * This routine can operate against any 32 bit mach header.
 */
void *
getsegdatafromheader(
	struct mach_header *mhp,
	const char *segname,
	int *size)
{
	const struct segment_command *sc;
	void *result;

	sc = getsegbynamefromheader(mhp, segname);
	if(sc == (struct segment_command *)0){
	    *size = 0;
	    return((char *)0);
	}
	*size = sc->vmsize;
	result = (void *)sc->vmaddr;
	return result;
}

/*
 * This routine returns the section structure for the named section in the
 * named segment for the mach_header pointer passed to it if it exist.
 * Otherwise it returns zero.
 *
 * This routine can operate against any 32 bit mach header.
 */
struct section *
getsectbynamefromheader(
    struct mach_header *mhp,
    const char *segname,
    const char *sectname)
{
	struct segment_command *sgp;
	struct section *sp;
	unsigned long i, j;

	sgp = (struct segment_command *)
	      ((char *)mhp + sizeof(struct mach_header));
	for(i = 0; i < mhp->ncmds; i++){
	    if(sgp->cmd == LC_SEGMENT)
		if(strncmp(sgp->segname, segname, sizeof(sgp->segname)) == 0 ||
		   mhp->filetype == MH_OBJECT){
		    sp = (struct section *)((char *)sgp +
			 sizeof(struct segment_command));
		    for(j = 0; j < sgp->nsects; j++){
			if(strncmp(sp->sectname, sectname,
			   sizeof(sp->sectname)) == 0 &&
			   strncmp(sp->segname, segname,
			   sizeof(sp->segname)) == 0)
			    return(sp);
			sp = (struct section *)((char *)sp +
			     sizeof(struct section));
		    }
		}
	    sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	}
	return((struct section *)0);
}

/*
 * This routine can operate against any 32 bit mach header.
 */
struct segment_command *
getsegbynamefromheader(
	struct mach_header	*header,
	const char		*seg_name)
{
	struct segment_command *sgp;
	unsigned long i;

	sgp = (struct segment_command *)
		((char *)header + sizeof(struct mach_header));
	for (i = 0; i < header->ncmds; i++){
		if (   sgp->cmd == LC_SEGMENT
		    && !strncmp(sgp->segname, seg_name, sizeof(sgp->segname)))
			return sgp;
		sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	}
	return (struct segment_command *)0;
}


/*
 * For now at least, all the rest of this seems unused.
 * NOTE: The constant in here for segment alignment is machine-dependent,
 * so if you include this, define a machine dependent constant for it's
 * value.
 */
static struct {
	struct segment_command	seg;
	struct section		sect;
} fvm_data = {
	{
		LC_SEGMENT, 		// cmd
		sizeof(fvm_data),	// cmdsize
		"__USER",		// segname
		0,			// vmaddr
		0,			// vmsize
		0,			// fileoff
		0,			// filesize
		VM_PROT_READ,		// maxprot
		VM_PROT_READ,		// initprot,
		1,			// nsects
		0			// flags
	},
	{
		"",			// sectname
		"__USER",		// segname
		0,			// addr
		0,			// size
		0,			// offset
		4,			// align
		0,			// reloff
		0,			// nreloc
		0,			// flags
		0,			// reserved1
		0			// reserved2
	}
};

struct segment_command *fvm_seg;

static struct fvmfile_command *fvmfilefromheader(struct mach_header *header);
static vm_offset_t getsizeofmacho(struct mach_header *header);

/*
 * Return the first segment_command in the header.
 *
 * This routine operates against the currently executing kernel only
 */
struct segment_command *
firstseg(void)
{
	return firstsegfromheader(&_mh_execute_header);
}

/*
 * This routine can operate against any 32 bit mach header, and returns a
 * pointer to a 32 bit segment_command structure from the file prefixed by
 * the header it is passed as its argument.
 */
struct segment_command *
firstsegfromheader(struct mach_header *header)
{
	struct segment_command *sgp;
	unsigned long i;

	sgp = (struct segment_command *)
		((char *)header + sizeof(struct mach_header));
	for (i = 0; i < header->ncmds; i++){
		if (sgp->cmd == LC_SEGMENT)
			return sgp;
		sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	}
	return (struct segment_command *)0;
}

/*
 * This routine operates against a 32 bit mach segment_command structure
 * pointer from the currently executing kernel only, to obtain the
 * sequentially next segment_command structure in the currently executing
 * kernel
 */
struct segment_command *
nextseg(struct segment_command *sgp)
{
	struct segment_command *this;

	this = nextsegfromheader(&_mh_execute_header, sgp);

	/*
	 * For the kernel's header add on the faked segment for the
	 * USER boot code identified by a FVMFILE_COMMAND in the mach header.
	 */
	if (!this && sgp != fvm_seg)
		this = fvm_seg;

	return this;
}

/*
 * This routine operates against any 32 bit mach segment_command structure
 * pointer and the provided 32 bit header, to obtain the sequentially next
 * segment_command structure in that header.
 */
struct segment_command *
nextsegfromheader(
	struct mach_header	*header,
	struct segment_command	*seg)
{
	struct segment_command *sgp;
	unsigned long i;

	sgp = (struct segment_command *)
		((char *)header + sizeof(struct mach_header));
	for (i = 0; i < header->ncmds; i++) {
		if (sgp == seg)
			break;
		sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	}

	if (i == header->ncmds)
		return (struct segment_command *)0;

	sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	for (; i < header->ncmds; i++) {
		if (sgp->cmd == LC_SEGMENT)
			return sgp;
		sgp = (struct segment_command *)((char *)sgp + sgp->cmdsize);
	}

	return (struct segment_command *)0;
}


/*
 * Return the address of the named Mach-O segment from the currently
 * executing 32 bit kernel, or NULL.
 */
struct segment_command *
getsegbyname(const char *seg_name)
{
	struct segment_command *this;

	this = getsegbynamefromheader(&_mh_execute_header, seg_name);

	/*
	 * For the kernel's header add on the faked segment for the
	 * USER boot code identified by a FVMFILE_COMMAND in the mach header.
	 */
	if (!this && strncmp(seg_name, fvm_seg->segname,
				sizeof(fvm_seg->segname)) == 0)
		this = fvm_seg;

	return this;
}

/*
 * This routine returns the a pointer the section structure of the named
 * section in the named segment if it exists in the currently executing
 * kernel, which it is presumed to be linked into.  Otherwise it returns NULL.
 */
struct section *
getsectbyname(
    const char *segname,
    const char *sectname)
{
	return(getsectbynamefromheader(
		(struct mach_header *)&_mh_execute_header, segname, sectname));
}

/*
 * This routine can operate against any 32 bit segment_command structure to
 * return the first 32 bit section immediately following that structure.  If
 * there are no sections associated with the segment_command structure, it
 * returns NULL.
 */
struct section *
firstsect(struct segment_command *sgp)
{
	if (!sgp || sgp->nsects == 0)
		return (struct section *)0;

	return (struct section *)(sgp+1);
}

/*
 * This routine can operate against any 32 bit segment_command structure and
 * 32 bit section to return the next consecutive  32 bit section immediately
 * following the 32 bit section provided.  If there are no sections following
 * the provided section, it returns NULL.
 */
struct section *
nextsect(struct segment_command *sgp, struct section *sp)
{
	struct section *fsp = firstsect(sgp);

	if (((unsigned long)(sp - fsp) + 1) >= sgp->nsects)
		return (struct section *)0;

	return sp+1;
}

/*
 * This routine can operate against any 32 bit mach header to return the
 * first occurring 32 bit fvmfile_command section.  If one is not present,
 * it returns NULL.
 */
static struct fvmfile_command *
fvmfilefromheader(struct mach_header *header)
{
	struct fvmfile_command *fvp;
	unsigned long i;

	fvp = (struct fvmfile_command *)
		((char *)header + sizeof(struct mach_header));
	for (i = 0; i < header->ncmds; i++){
		if (fvp->cmd == LC_FVMFILE)
			return fvp;
		fvp = (struct fvmfile_command *)((char *)fvp + fvp->cmdsize);
	}
	return (struct fvmfile_command *)0;
}

/*
 * Create a fake USER seg if a fvmfile_command is present.
 *
 * This routine operates against the currently executing kernel only
 */
struct segment_command *
getfakefvmseg(void)
{
	struct segment_command *sgp = getsegbyname("__USER");
	struct fvmfile_command *fvp = fvmfilefromheader(&_mh_execute_header);
	struct section *sp;

	if (sgp)
		return sgp;

	if (!fvp)
		return (struct segment_command *)0;

	fvm_seg = &fvm_data.seg;
	sgp = fvm_seg;
	sp = &fvm_data.sect;

	sgp->vmaddr = fvp->header_addr;
	sgp->vmsize = getsizeofmacho((struct mach_header *)(sgp->vmaddr));

	strlcpy(sp->sectname, fvp->name.ptr, sizeof(sp->sectname));
	sp->addr = sgp->vmaddr;
	sp->size = sgp->vmsize;

#if	DEBUG
	printf("fake fvm seg __USER/\"%s\" at 0x%x, size 0x%x\n",
		sp->sectname, sp->addr, sp->size);
#endif	/* DEBUG */

	return sgp;
}

/*
 * Figure out the size the size of the data associated with a
 * loaded mach_header.
 *
 * This routine can operate against any 32 bit mach header.
 */
static vm_offset_t
getsizeofmacho(struct mach_header *header)
{
	struct segment_command	*sgp;
	vm_offset_t		last_addr;

	last_addr = 0;
	for (  sgp = firstsegfromheader(header)
	    ; sgp
	    ; sgp = nextsegfromheader(header, sgp))
	{
		if (sgp->fileoff + sgp->filesize > last_addr)
			last_addr = sgp->fileoff + sgp->filesize;
	}

	return last_addr;
}
#endif  /* !defined(KERNEL_PRELOAD) */
