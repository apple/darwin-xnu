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
/* Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.
 *
 *	File:	bsd/kern/kern_symfile.c
 *
 *	This file contains creates a dummy symbol file for mach_kernel based on
 *      the symbol table information passed by the SecondaryLoader/PlatformExpert.
 *      This allows us to correctly link other executables (drivers, etc) against the 
 *      the kernel in cases where the kernel image on the root device does not match
 *      the live kernel. This can occur during net-booting where the actual kernel
 *      image is obtained from the network via tftp rather than the root
 *      device.
 *
 *      If a symbol table is available, then the file /mach.sym will be created
 *      containing a Mach Header and a LC_SYMTAB load command followed by the
 *      the symbol table data for mach_kernel.
 *
 * HISTORY
 * 
 *	.
 */

#include <mach/vm_param.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/buf.h>
#include <sys/acct.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/stat.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <vm/vm_kern.h>

extern unsigned char 	rootdevice[];
extern struct mach_header _mh_execute_header;

static int kernel_symfile_opened = 0;
static int error_code = 0;

extern int  IODTGetLoaderInfo(char *key, void **infoAddr, int *infoSize);
extern void IODTFreeLoaderInfo(char *key, void *infoAddr, int infoSize);

/*
 * 
 */
static int output_kernel_symbols(struct proc *p)
{
    struct vnode		*vp;
    struct pcred 		*pcred = p->p_cred;
    struct ucred 		*cred = pcred->pc_ucred;
    struct nameidata 		nd;
    struct vattr		vattr;
    struct load_command		*cmd;
    struct mach_header		*orig_mh, *mh;
    struct segment_command	*orig_ds, *orig_ts, *orig_le, *sg;
    struct section		*se, *const_text;
    struct symtab_command	*st, *orig_st;
    struct nlist		*sym;
    vm_size_t			orig_mhsize, orig_st_size;
    vm_offset_t			header;
    vm_size_t			header_size;
    int				error, error1;
    int				i, j;
    caddr_t			addr;
    vm_offset_t			offset;
    int				rc_mh, rc_sc;

    error = EFAULT;

    vp		= NULL;
    header	= NULL;
    orig_mh	= NULL;
    orig_st	= NULL;
    
    // Dispose of unnecessary gumf, the booter doesn't need to load these
    rc_mh = IODTGetLoaderInfo("Kernel-__HEADER",
				(void **)&orig_mh, &orig_mhsize);
    if (rc_mh == 0 && orig_mh)
	IODTFreeLoaderInfo("Kernel-__HEADER",
			    (void *)orig_mh, round_page_32(orig_mhsize));

    rc_sc = IODTGetLoaderInfo("Kernel-__SYMTAB",
				(void **) &orig_st, &orig_st_size);
    if (rc_sc == 0 && orig_st)
	IODTFreeLoaderInfo("Kernel-__SYMTAB",
			    (void *)orig_st, round_page_32(orig_st_size));

    if (pcred->p_svuid != pcred->p_ruid || pcred->p_svgid != pcred->p_rgid)
	goto out;

    // Check to see if the root is 'e' or 'n', is this a test for network?
    if (rootdevice[0] == 'e' && rootdevice[1] == 'n')
	goto out;

    NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, "mach.sym", p);
    if((error = vn_open(&nd, O_CREAT | FWRITE, S_IRUSR | S_IRGRP | S_IROTH))) goto out;

    vp = nd.ni_vp;
    
    /* Don't dump to non-regular files or files with links. */
    error = EFAULT;
    if (vp->v_type != VREG || VOP_GETATTR(vp, &vattr, cred, p)
    ||  vattr.va_nlink != 1)
	goto out;

    VATTR_NULL(&vattr);
    vattr.va_size = 0;
    VOP_LEASE(vp, p, cred, LEASE_WRITE);
    VOP_SETATTR(vp, &vattr, cred, p);
    p->p_acflag |= ACORE;

    // If the file type is MH_EXECUTE then this must be a kernel
    // as all Kernel extensions must be of type MH_OBJECT
    orig_ds = orig_ts = orig_le = NULL;
    orig_st = NULL;
    orig_mh = &_mh_execute_header;
    cmd = (struct load_command *) &orig_mh[1];
    for (i = 0; i < orig_mh->ncmds; i++) {
	if (cmd->cmd == LC_SEGMENT) {
	    struct segment_command *sg = (struct segment_command *) cmd;
    
	    if (!strcmp(SEG_TEXT, sg->segname))
		orig_ts = sg;
	    else if (!strcmp(SEG_DATA, sg->segname))
		orig_ds = sg;
	    else if (!strcmp(SEG_LINKEDIT, sg->segname))
		orig_le = sg;
	}
	else if (cmd->cmd == LC_SYMTAB)
	    orig_st = (struct symtab_command *) cmd;
    
	cmd = (struct load_command *) ((caddr_t) cmd + cmd->cmdsize);
    }

    if (!orig_ts || !orig_ds || !orig_le || !orig_st) 
	goto out;

    const_text = NULL;
    se = (struct section *) &orig_ts[1];
    for (i = 0; i < orig_ts->nsects; i++, se++) {
	if (!strcmp("__const", se->sectname)) {
	    const_text = se;
	    break;
	}
    }
    if (!const_text)
	goto out;

    header_size =   sizeof(struct mach_header) 
		    + orig_ts->cmdsize
		    + orig_ds->cmdsize
		    + sizeof(struct symtab_command);

    (void) kmem_alloc_wired(kernel_map,
			    (vm_offset_t *) &header,
			    (vm_size_t) header_size);
    if (header)
	bzero((void *) header, header_size);
    else
	goto out;

    /*
     *	Set up Mach-O header.
     */
    mh = (struct mach_header *) header;
    mh->magic      = orig_mh->magic;
    mh->cputype    = orig_mh->cputype;
    mh->cpusubtype = orig_mh->cpusubtype;
    mh->filetype   = orig_mh->filetype;
    mh->ncmds      = 3;
    mh->sizeofcmds = header_size - sizeof(struct mach_header);
    mh->flags      = orig_mh->flags;

    // Initialise the current file offset and addr
    offset = round_page_32(header_size);
    addr = (caddr_t) const_text->addr;	// Load address of __TEXT,__const

    /*
     * Construct a TEXT segment load command
     * the only part of the TEXT segment we keep is the __TEXT,__const
     * which contains the kernel vtables. 
     */
    sg = (struct segment_command *) &mh[1];
    bcopy(orig_ts, sg, orig_ts->cmdsize);
    sg->vmaddr   = (unsigned long) addr;
    sg->vmsize   = const_text->size;
    sg->fileoff  = 0;
    sg->filesize = const_text->size + round_page_32(header_size);
    sg->maxprot  = 0;
    sg->initprot = 0;
    sg->flags    = 0;
    se = (struct section *)(sg+1);
    for ( j = 0; j < sg->nsects; j++, se++ ) {
	se->addr  = (unsigned long) addr;
	se->size  = 0;
	se->offset = offset;
	se->nreloc = 0;
	if (!strcmp("__const", se->sectname)) {
	    se->size = const_text->size;
	    addr    += const_text->size;
	    offset  += const_text->size;
	    const_text = se;
	}
    }
    offset = round_page_32((vm_address_t) offset);

    // Now copy of the __DATA segment load command, the image need
    // not be stored to disk nobody needs it, yet!
    sg = (struct segment_command *)((int)sg + sg->cmdsize);
    bcopy(orig_ds, sg, orig_ds->cmdsize);

    sg->vmaddr   = (unsigned long) addr;
    sg->vmsize   = 0x1000;	// One page for some reason?
    sg->fileoff  = offset;
    sg->filesize = 0;
    sg->maxprot  = 0;
    sg->initprot = 0;
    sg->flags    = 0;
    se = (struct section *)(sg+1);
    for ( j = 0; j < sg->nsects; j++, se++ ) {
	se->addr  = (unsigned long) addr;
	se->size  = 0;
	se->offset = offset;
	se->nreloc = 0;
    }
    offset = round_page_32(offset);


    /*
     *	Set up LC_SYMTAB command
     */
    st          = (struct symtab_command *)((int)sg + sg->cmdsize);
    st->cmd     = LC_SYMTAB;
    st->cmdsize = sizeof(struct symtab_command);
    st->symoff  = offset;
    st->nsyms   = orig_st->nsyms;
    st->strsize = orig_st->strsize;
    st->stroff =  offset + st->nsyms * sizeof(struct nlist);    

    /*
     * Convert the symbol table in place from section references
     * to absolute references.
     */
    sym = (struct nlist *) orig_le->vmaddr;
    for (i = 0; i < st->nsyms; i++, sym++ ) {
	if ( (sym->n_type & N_TYPE) == N_SECT) {
	    sym->n_sect = NO_SECT;
	    sym->n_type = (sym->n_type & ~N_TYPE) | N_ABS;
	}
    }

    /*
     *	Write out the load commands at the beginning of the file.
     */
    error = vn_rdwr(UIO_WRITE, vp, (caddr_t) mh, header_size, (off_t) 0,
		    UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, cred, (int *) 0, p);
    if (error)
	goto out;

    /*
     *	Write out the __TEXT,__const data segment.
     */
    error = vn_rdwr(UIO_WRITE, vp, (caddr_t) const_text->addr,
		    const_text->size, const_text->offset,
		    UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, cred, (int *) 0, p);
    if (error)
	goto out;

    /*
     * 	Write out kernel symbols
     */
    offset = st->nsyms * sizeof(struct nlist) + st->strsize;	// symtab size
    error = vn_rdwr(UIO_WRITE, vp,
		   (caddr_t) orig_le->vmaddr, offset, st->symoff,
		    UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, cred, (int *) 0, p);
    if (error)
	goto out;

out:
    if (header)
	kmem_free(kernel_map, header, header_size);

    if (vp) {
	VOP_UNLOCK(vp, 0, p);
	error1 = vn_close(vp, FWRITE, cred, p);
	if (!error) error = error1;
    }

    return(error);
}
/*
 * 
 */
int get_kernel_symfile(struct proc *p, char **symfile)
{
    if (!kernel_symfile_opened) {
        kernel_symfile_opened = 1;
        error_code = output_kernel_symbols(p);
    }
    if (!error_code)
	*symfile = "\\mach.sym";

    return error_code;
}
