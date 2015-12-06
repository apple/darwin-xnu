/*
 * Copyright (c) 2015 Apple Computer, Inc. All rights reserved.
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

#ifdef CONFIG_KDP_INTERACTIVE_DEBUGGING

#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <libsa/types.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/zlib.h>
#include <kdp/kdp_internal.h>
#include <kdp/kdp_core.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IOBSD.h>
#include <sys/errno.h>
#include <sys/msgbuf.h>

#if defined(__i386__) || defined(__x86_64__)
#include <i386/pmap_internal.h>
#include <kdp/ml/i386/kdp_x86_common.h>
#endif /* defined(__i386__) || defined(__x86_64__) */



typedef int (*pmap_traverse_callback)(vm_map_offset_t start,
				      vm_map_offset_t end,
				      void *context);

extern int pmap_traverse_present_mappings(pmap_t pmap,
					  vm_map_offset_t start,
					  vm_map_offset_t end,
					  pmap_traverse_callback callback,
					  void *context);


static int
kern_dump_pmap_traverse_preflight_callback(vm_map_offset_t start,
					       vm_map_offset_t end,
					       void *context);
static int
kern_dump_pmap_traverse_send_seg_callback(vm_map_offset_t start,
					      vm_map_offset_t end,
					      void *context);
static int
kern_dump_pmap_traverse_send_segdata_callback(vm_map_offset_t start,
						  vm_map_offset_t end,
						  void *context);

struct kdp_core_out_vars;
typedef int (*kern_dump_output_proc)(unsigned int request, char *corename, 
    			             uint64_t length, void *panic_data);

struct kdp_core_out_vars
{
     kern_dump_output_proc outproc;
     z_output_func	   zoutput;
     size_t                zipped;
     uint64_t              totalbytes;
     uint64_t              lastpercent;
     IOReturn              error;
     unsigned              outremain;
     unsigned              outlen;
     unsigned              writes;
     Bytef *               outbuf;
};

struct kern_dump_preflight_context
{
    uint32_t region_count;
    uint64_t dumpable_bytes;
};

struct kern_dump_send_context
{
    struct kdp_core_out_vars * outvars;
    uint64_t hoffset;
    uint64_t foffset;
    uint64_t header_size;
    uint64_t dumpable_bytes;
    uint32_t region_count;
};

extern uint32_t kdp_crashdump_pkt_size;

static vm_offset_t kdp_core_zmem;
static size_t      kdp_core_zsize;
static size_t      kdp_core_zoffset;
static z_stream	   kdp_core_zs;


#define DEBG	kdb_printf

boolean_t kdp_has_polled_corefile(void)
{
    return (NULL != gIOPolledCoreFileVars);
}

static IOReturn 
kern_dump_disk_proc(unsigned int request, __unused char *corename, 
		    uint64_t length, void * data)
{
    uint64_t        noffset;
    uint32_t        err = kIOReturnSuccess;

    switch (request) 
    {
        case KDP_WRQ:
	    err = IOPolledFileSeek(gIOPolledCoreFileVars, 0);
	    if (kIOReturnSuccess != err) break;
	    err = IOPolledFilePollersOpen(gIOPolledCoreFileVars, kIOPolledBeforeSleepState, false);
	    break;

        case KDP_SEEK:
	    noffset = *((uint64_t *) data);
	    err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
	    if (kIOReturnSuccess != err) break;
	    err = IOPolledFileSeek(gIOPolledCoreFileVars, noffset);
	    break;

        case KDP_DATA:
	    err = IOPolledFileWrite(gIOPolledCoreFileVars, data, length, NULL);
	    if (kIOReturnSuccess != err) break;
	    break;

        case KDP_EOF:
	    err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
	    if (kIOReturnSuccess != err) break;
	    err = IOPolledFilePollersClose(gIOPolledCoreFileVars, kIOPolledBeforeSleepState);
	    if (kIOReturnSuccess != err) break;
	    break;
    }

    return (err);
}

static int
kdp_core_zoutput(z_streamp strm, Bytef *buf, unsigned len)
{
    struct kdp_core_out_vars * vars = (typeof(vars)) strm->opaque;
    IOReturn                   ret;

    vars->zipped += len;

    if (vars->error >= 0)
    {
	if ((ret = (*vars->outproc)(KDP_DATA, NULL, len, buf)) != kIOReturnSuccess)
	{ 
	    DEBG("KDP_DATA(0x%x)\n", ret);
	    vars->error = ret;
	}
	if (!buf && !len) DEBG("100..");
    }
    return (len);
}

static int
kdp_core_zoutputbuf(z_streamp strm, Bytef *inbuf, unsigned inlen)
{
    struct kdp_core_out_vars * vars = (typeof(vars)) strm->opaque;
    unsigned remain;
    IOReturn ret;
    unsigned chunk;
    boolean_t flush;

    remain = inlen;
    vars->zipped += inlen;
    flush = (!inbuf && !inlen);

    while ((vars->error >= 0) && (remain || flush))
    {
	chunk = vars->outremain;
	if (chunk > remain) chunk = remain;
	bcopy(inbuf, &vars->outbuf[vars->outlen - vars->outremain], chunk);
	vars->outremain -= chunk;
	remain          -= chunk;
	inbuf           += chunk;
	
	if (vars->outremain && !flush) break;
	if ((ret = (*vars->outproc)(KDP_DATA, NULL, 
					vars->outlen - vars->outremain, 
					vars->outbuf)) != kIOReturnSuccess)
	{ 
	    DEBG("KDP_DATA(0x%x)\n", ret);
	    vars->error = ret;
	}
	if (flush)
	{
	    DEBG("100..");
	    flush = false;
	}
	vars->outremain = vars->outlen;
    }
    return (inlen);
}

static int
kdp_core_zinput(z_streamp strm, Bytef *buf, unsigned size)
{
    struct kdp_core_out_vars * vars = (typeof(vars)) strm->opaque;
    uint64_t                   percent;
    unsigned                   len;

    len = strm->avail_in;
    if (len > size) len = size;
    if (len == 0) return 0;

    if (strm->next_in != (Bytef *) strm) memcpy(buf, strm->next_in, len);
    else		                 bzero(buf, len);
    strm->adler = z_crc32(strm->adler, buf, len);

    strm->avail_in -= len;
    strm->next_in  += len;
    strm->total_in += len;

    if (0 == (511 & vars->writes++))
    {
	percent = (strm->total_in * 100) / vars->totalbytes;
	if ((percent - vars->lastpercent) >= 10)
	{
	    vars->lastpercent = percent;
	    DEBG("%lld..", percent);
	}
    }

    return (int)len;
}

static IOReturn
kdp_core_stream_output(struct kdp_core_out_vars * vars, uint64_t length, void * data)
{
    z_stream * zs;
    int        zr;
    boolean_t  flush;

    flush = (!length && !data);
    zr = Z_OK;

    zs = &kdp_core_zs;
    assert(!zs->avail_in);

    while (vars->error >= 0)
    {
	if (!zs->avail_in && !flush)
	{
	    if (!length) break;
	    zs->next_in = data ? data : (Bytef *) zs /* zero marker */;
	    zs->avail_in = (uInt)length;
	    length = 0;
	}
	if (!zs->avail_out)
	{
	    zs->next_out  = (Bytef *) zs;
	    zs->avail_out = UINT32_MAX;
	}
	zr = deflate(zs, flush ? Z_FINISH : Z_NO_FLUSH);
	if (Z_STREAM_END == zr) break;
	if (zr != Z_OK) 
	{
	    DEBG("ZERR %d\n", zr);
	    vars->error = zr;
	}
    }

    if (flush) (*vars->zoutput)(zs, NULL, 0);

    return (vars->error);
}

extern vm_offset_t c_buffers;
extern vm_size_t   c_buffers_size;

ppnum_t
kernel_pmap_present_mapping(uint64_t vaddr, uint64_t * pvincr)
{
    ppnum_t ppn;
    uint64_t vincr;
    vincr = PAGE_SIZE_64;

    assert(!(vaddr & PAGE_MASK_64));

    /* VA ranges to exclude */
    if (vaddr == c_buffers)
    {
	/* compressor data */
	ppn = 0;
	vincr = c_buffers_size;
    }
    else if (vaddr == kdp_core_zmem)
    {
	/* zlib working memory */
	ppn = 0;
	vincr = kdp_core_zsize;
    }
    else
    ppn = pmap_find_phys(kernel_pmap, vaddr);

    *pvincr = vincr;
    return (ppn);
}

int
pmap_traverse_present_mappings(pmap_t __unused pmap,
				   vm_map_offset_t start,
				   vm_map_offset_t end,
				   pmap_traverse_callback callback,
				   void *context)
{
    IOReturn        ret;
    vm_map_offset_t vcurstart, vcur;
    uint64_t        vincr;
    vm_map_offset_t debug_start;
    vm_map_offset_t debug_end;
    boolean_t       lastvavalid;

    debug_start = trunc_page((vm_map_offset_t) debug_buf_addr);
    debug_end   = round_page((vm_map_offset_t) (debug_buf_addr + debug_buf_size));

#if defined(__i386__) || defined(__x86_64__)
    assert(!is_ept_pmap(pmap));
#endif

    /* Assumes pmap is locked, or being called from the kernel debugger */
    
    if (start > end) return (KERN_INVALID_ARGUMENT);

    ret = KERN_SUCCESS;
    lastvavalid = FALSE;
    for (vcur = vcurstart = start; (ret == KERN_SUCCESS) && (vcur < end); ) {
	ppnum_t ppn;

	ppn = kernel_pmap_present_mapping(vcur, &vincr);
	if (ppn != 0)
	{
	    if (((vcur < debug_start) || (vcur >= debug_end))
	    	&& !pmap_valid_page(ppn))
	    {
		/* not something we want */
		ppn = 0;
	    }
	}

	if (ppn != 0) {
	    if (!lastvavalid) {
		/* Start of a new virtual region */
		vcurstart = vcur;
		lastvavalid = TRUE;
	    }
	} else {
	    if (lastvavalid) {
		/* end of a virtual region */
		ret = callback(vcurstart, vcur, context);
		lastvavalid = FALSE;
	    }

#if defined(__i386__) || defined(__x86_64__)
	    /* Try to skip by 2MB if possible */
	    if (((vcur & PDMASK) == 0) && cpu_64bit) {
		pd_entry_t *pde;
		pde = pmap_pde(pmap, vcur);
		if (0 == pde || ((*pde & INTEL_PTE_VALID) == 0)) {
		    /* Make sure we wouldn't overflow */
		    if (vcur < (end - NBPD)) {
			vincr = NBPD;
		    }
		}
	    }
#endif /* defined(__i386__) || defined(__x86_64__) */
	}
	vcur += vincr;
    }
    
    if ((ret == KERN_SUCCESS) && lastvavalid) {
	/* send previous run */
	ret = callback(vcurstart, vcur, context);
    }
    return (ret);
}

int
kern_dump_pmap_traverse_preflight_callback(vm_map_offset_t start,
					   vm_map_offset_t end,
					   void *context)
{
    struct kern_dump_preflight_context *kdc = (struct kern_dump_preflight_context *)context;
    IOReturn ret = KERN_SUCCESS;

    kdc->region_count++;
    kdc->dumpable_bytes += (end - start);

    return (ret);
}

int
kern_dump_pmap_traverse_send_seg_callback(vm_map_offset_t start,
					  vm_map_offset_t end,
					  void *context)
{
    struct kern_dump_send_context *kdc = (struct kern_dump_send_context *)context;
    IOReturn ret = KERN_SUCCESS;
    kernel_segment_command_t sc;
    vm_size_t size = (vm_size_t)(end - start);

    if (kdc->hoffset + sizeof(sc) > kdc->header_size) {
	return (KERN_NO_SPACE);
    }

    kdc->region_count++;
    kdc->dumpable_bytes += (end - start);

    /*
     *	Fill in segment command structure.
     */

    sc.cmd = LC_SEGMENT_KERNEL;
    sc.cmdsize = sizeof(kernel_segment_command_t);
    sc.segname[0] = 0;
    sc.vmaddr = (vm_address_t)start;
    sc.vmsize = size;
    sc.fileoff = (vm_address_t)kdc->foffset;
    sc.filesize = size;
    sc.maxprot = VM_PROT_READ;
    sc.initprot = VM_PROT_READ;
    sc.nsects = 0;
    sc.flags = 0;

    if ((ret = kdp_core_stream_output(kdc->outvars, sizeof(kernel_segment_command_t), (caddr_t) &sc)) != kIOReturnSuccess) {
	DEBG("kdp_core_stream_output(0x%x)\n", ret);
	goto out;
    }
    
    kdc->hoffset += sizeof(kernel_segment_command_t);
    kdc->foffset += size;

out:
    return (ret);
}


int
kern_dump_pmap_traverse_send_segdata_callback(vm_map_offset_t start,
					      vm_map_offset_t end,
					      void *context)
{
    struct kern_dump_send_context *kdc = (struct kern_dump_send_context *)context;
    int ret = KERN_SUCCESS;
    vm_size_t size = (vm_size_t)(end - start);

    kdc->region_count++;
    kdc->dumpable_bytes += size;
    if ((ret = kdp_core_stream_output(kdc->outvars, (unsigned int)size, (caddr_t)(uintptr_t)start)) != kIOReturnSuccess)	{
	DEBG("kdp_core_stream_output(0x%x)\n", ret);
	goto out;
    }
    kdc->foffset += size;

out:
    return (ret);
}

static int
do_kern_dump(kern_dump_output_proc outproc, bool local)
{
    struct kern_dump_preflight_context kdc_preflight;
    struct kern_dump_send_context      kdc_sendseg;
    struct kern_dump_send_context      kdc_send;
    struct kdp_core_out_vars           outvars;
    struct mach_core_fileheader         hdr;
    kernel_mach_header_t mh;
    uint32_t	         segment_count, tstate_count;
    size_t		 command_size = 0, header_size = 0, tstate_size = 0;
    uint64_t	         hoffset, foffset;
    int                  ret;
    char *               log_start;
    uint64_t             log_length;
    uint64_t             new_logs;
    boolean_t            opened;

    opened     = false;
    log_start  = debug_buf_ptr;
    log_length = 0;
    if (log_start >= debug_buf_addr)
    {
	log_length = log_start - debug_buf_addr;
	if (log_length <= debug_buf_size) log_length = debug_buf_size - log_length;
	else log_length = 0;
    }

    if (local)
    {
	if ((ret = (*outproc)(KDP_WRQ, NULL, 0, &hoffset)) != kIOReturnSuccess) {
	    DEBG("KDP_WRQ(0x%x)\n", ret);
	    goto out;
	}
    }
    opened = true;

    // init gzip
    bzero(&outvars, sizeof(outvars));
    bzero(&hdr, sizeof(hdr));
    outvars.outproc = outproc;
    kdp_core_zs.avail_in  = 0;
    kdp_core_zs.next_in   = NULL;
    kdp_core_zs.avail_out = 0;
    kdp_core_zs.next_out  = NULL;
    kdp_core_zs.opaque    = &outvars;
    kdc_sendseg.outvars   = &outvars;
    kdc_send.outvars      = &outvars;

    if (local)
    {
	outvars.outbuf      = NULL;
        outvars.outlen      = 0;
        outvars.outremain   = 0;
	outvars.zoutput     = kdp_core_zoutput;
    	// space for file header & log
    	foffset = (4096 + log_length + 4095) & ~4095ULL;
	hdr.log_offset = 4096;
	hdr.gzip_offset = foffset;
	if ((ret = (*outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) { 
		DEBG("KDP_SEEK(0x%x)\n", ret);
		goto out;
	} 
    }
    else
    {
	outvars.outbuf    = (Bytef *) (kdp_core_zmem + kdp_core_zoffset);
	assert((kdp_core_zoffset + kdp_crashdump_pkt_size) <= kdp_core_zsize);
        outvars.outlen    = kdp_crashdump_pkt_size;
        outvars.outremain = outvars.outlen;
	outvars.zoutput  = kdp_core_zoutputbuf;
    }

    deflateResetWithIO(&kdp_core_zs, kdp_core_zinput, outvars.zoutput);


    kdc_preflight.region_count = 0;
    kdc_preflight.dumpable_bytes = 0;

    ret = pmap_traverse_present_mappings(kernel_pmap,
					 VM_MIN_KERNEL_AND_KEXT_ADDRESS,
					 VM_MAX_KERNEL_ADDRESS,
					 kern_dump_pmap_traverse_preflight_callback,
					 &kdc_preflight);
    if (ret)
    {
	DEBG("pmap traversal failed: %d\n", ret);
	return (ret);
    }

    outvars.totalbytes = kdc_preflight.dumpable_bytes;
    assert(outvars.totalbytes);
    segment_count = kdc_preflight.region_count;

    kern_collectth_state_size(&tstate_count, &tstate_size);

    command_size = segment_count * sizeof(kernel_segment_command_t) + tstate_count * tstate_size;

    header_size = command_size + sizeof(kernel_mach_header_t);

    /*
     *	Set up Mach-O header for currently executing kernel.
     */

    mh.magic = _mh_execute_header.magic;
    mh.cputype = _mh_execute_header.cputype;;
    mh.cpusubtype = _mh_execute_header.cpusubtype;
    mh.filetype = MH_CORE;
    mh.ncmds = segment_count + tstate_count;
    mh.sizeofcmds = (uint32_t)command_size;
    mh.flags = 0;
#if defined(__LP64__)
    mh.reserved = 0;
#endif

    hoffset = 0;	                                /* offset into header */
    foffset = (uint64_t) round_page(header_size);	/* offset into file */

    /* Transmit the Mach-O MH_CORE header, and segment and thread commands 
     */
    if ((ret = kdp_core_stream_output(&outvars, sizeof(kernel_mach_header_t), (caddr_t) &mh) != kIOReturnSuccess))
    {
	DEBG("KDP_DATA(0x%x)\n", ret);
	goto out;
    }

    hoffset += sizeof(kernel_mach_header_t);

    DEBG("%s", local ? "Writing local kernel core..." :
    	    	       "Transmitting kernel state, please wait:\n");

    kdc_sendseg.region_count   = 0;
    kdc_sendseg.dumpable_bytes = 0;
    kdc_sendseg.hoffset = hoffset;
    kdc_sendseg.foffset = foffset;
    kdc_sendseg.header_size = header_size;

    if ((ret = pmap_traverse_present_mappings(kernel_pmap,
					 VM_MIN_KERNEL_AND_KEXT_ADDRESS,
					 VM_MAX_KERNEL_ADDRESS,
					 kern_dump_pmap_traverse_send_seg_callback,
					 &kdc_sendseg)) != kIOReturnSuccess)
    {
	DEBG("pmap_traverse_present_mappings(0x%x)\n", ret);
	goto out;
    }

    hoffset = kdc_sendseg.hoffset;
    /*
     * Now send out the LC_THREAD load command, with the thread information
     * for the current activation.
     */

    if (tstate_size > 0)
    {
	void * iter;
	char tstate[tstate_size];
	iter = NULL;
	do {
	    /*
	     * Now send out the LC_THREAD load command, with the thread information
	     */
	    kern_collectth_state (current_thread(), tstate, tstate_size, &iter);

	    if ((ret = kdp_core_stream_output(&outvars, tstate_size, tstate)) != kIOReturnSuccess) {
		    DEBG("kdp_core_stream_output(0x%x)\n", ret);
		    goto out;
	    }
	}
	while (iter);
    }

    kdc_send.region_count   = 0;
    kdc_send.dumpable_bytes = 0;
    foffset = (uint64_t) round_page(header_size);	/* offset into file */
    kdc_send.foffset = foffset;
    kdc_send.hoffset = 0;
    foffset = round_page_64(header_size) - header_size;
    if (foffset)
    {
	// zero fill to page align
	if ((ret = kdp_core_stream_output(&outvars, foffset, NULL)) != kIOReturnSuccess) {
		DEBG("kdp_core_stream_output(0x%x)\n", ret);
		goto out;
	}
    }

    ret = pmap_traverse_present_mappings(kernel_pmap,
					 VM_MIN_KERNEL_AND_KEXT_ADDRESS,
					 VM_MAX_KERNEL_ADDRESS,
					 kern_dump_pmap_traverse_send_segdata_callback,
					 &kdc_send);
    if (ret) {
	DEBG("pmap_traverse_present_mappings(0x%x)\n", ret);
	goto out;
    }

    if ((ret = kdp_core_stream_output(&outvars, 0, NULL) != kIOReturnSuccess)) {
	DEBG("kdp_core_stream_output(0x%x)\n", ret);
	goto out;
    }

out:
    if (kIOReturnSuccess == ret) DEBG("success\n");
    else                         outvars.zipped = 0;

    DEBG("Mach-o header: %lu\n", header_size);
    DEBG("Region counts: [%u, %u, %u]\n", kdc_preflight.region_count,
					  kdc_sendseg.region_count, 
					  kdc_send.region_count);
    DEBG("Byte counts  : [%llu, %llu, %llu, %lu, %llu]\n", kdc_preflight.dumpable_bytes, 
							   kdc_sendseg.dumpable_bytes, 
							   kdc_send.dumpable_bytes, 
							   outvars.zipped, log_length);
    if (local && opened)
    {
    	// write debug log
    	foffset = 4096;
	if ((ret = (*outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) { 
	    DEBG("KDP_SEEK(0x%x)\n", ret);
	    goto exit;
	} 

	new_logs = debug_buf_ptr - log_start;
	if (new_logs > log_length) new_logs = log_length;
    	
	if ((ret = (*outproc)(KDP_DATA, NULL, new_logs, log_start)) != kIOReturnSuccess)
	{ 
	    DEBG("KDP_DATA(0x%x)\n", ret);
	    goto exit;
	} 

    	// write header

    	foffset = 0;
	if ((ret = (*outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) { 
	    DEBG("KDP_SEEK(0x%x)\n", ret);
	    goto exit;
	} 

	hdr.signature  = MACH_CORE_FILEHEADER_SIGNATURE;
	hdr.log_length = new_logs;
        hdr.gzip_length = outvars.zipped;

	if ((ret = (*outproc)(KDP_DATA, NULL, sizeof(hdr), &hdr)) != kIOReturnSuccess)
	{ 
	    DEBG("KDP_DATA(0x%x)\n", ret);
	    goto exit;
	}
    }

exit:
    /* close / last packet */
    if ((ret = (*outproc)(KDP_EOF, NULL, 0, ((void *) 0))) != kIOReturnSuccess)
    {
	DEBG("KDP_EOF(0x%x)\n", ret);
    }	


    return (ret);
}

int
kern_dump(boolean_t local)
{
    static boolean_t dumped_local;
    if (local) {
	if (dumped_local) return (0);
	dumped_local = TRUE;
	return (do_kern_dump(&kern_dump_disk_proc, true));
    }
#if CONFIG_KDP_INTERACTIVE_DEBUGGING
    return (do_kern_dump(&kdp_send_crashdump_data, false));
#else
    return (-1);
#endif
}

static void *
kdp_core_zalloc(void * __unused ref, u_int items, u_int size)
{
    void * result;

    result = (void *) (kdp_core_zmem + kdp_core_zoffset);
    kdp_core_zoffset += ~31L & (31 + (items * size));    // 32b align for vector crc
    assert(kdp_core_zoffset <= kdp_core_zsize);

    return (result);
}

static void
kdp_core_zfree(void * __unused ref, void * __unused ptr) {}


#define LEVEL Z_BEST_SPEED
#define NETBUF 1440

void
kdp_core_init(void)
{
    int wbits = 12;
    int memlevel = 3;
    kern_return_t kr;

    if (kdp_core_zs.zalloc) return;
    kdp_core_zsize = round_page(NETBUF + zlib_deflate_memory_size(wbits, memlevel));
    printf("kdp_core zlib memory 0x%lx\n", kdp_core_zsize);
    kr = kmem_alloc(kernel_map, &kdp_core_zmem, kdp_core_zsize, VM_KERN_MEMORY_DIAG);
    assert (KERN_SUCCESS == kr);

    kdp_core_zoffset = 0;
    kdp_core_zs.zalloc = kdp_core_zalloc;
    kdp_core_zs.zfree  = kdp_core_zfree;

    if (deflateInit2(&kdp_core_zs, LEVEL, Z_DEFLATED,
		     wbits + 16 /*gzip mode*/, memlevel, Z_DEFAULT_STRATEGY))
    {
	/* Allocation failed */
	bzero(&kdp_core_zs, sizeof(kdp_core_zs));
	kdp_core_zoffset = 0;
    }
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
