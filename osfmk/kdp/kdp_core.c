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
#include <machine/cpu_capabilities.h>
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


#if WITH_CONSISTENT_DBG
#include <pexpert/arm/consistent_debug.h>
#endif /* WITH_CONSISTENT_DBG */

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

static uint64_t    kdp_core_total_size;
static uint64_t    kdp_core_total_size_sent_uncomp;
#if WITH_CONSISTENT_DBG
struct xnu_hw_shmem_dbg_command_info *hwsd_info = NULL;

#define KDP_CORE_HW_SHMEM_DBG_NUM_BUFFERS 2
#define KDP_CORE_HW_SHMEM_DBG_TOTAL_BUF_SIZE 64 * 1024

/*
 * Astris can read up to 4064 bytes at a time over
 * the probe, so we should try to make our buffer
 * size a multiple of this to make reads by astris
 * (the bottleneck) most efficient.
 */
#define OPTIMAL_ASTRIS_READSIZE 4064

struct kdp_hw_shmem_dbg_buf_elm {
    vm_offset_t khsd_buf;
    uint32_t    khsd_data_length;
    STAILQ_ENTRY(kdp_hw_shmem_dbg_buf_elm) khsd_elms;
};

static STAILQ_HEAD(, kdp_hw_shmem_dbg_buf_elm) free_hw_shmem_dbg_bufs =
                    STAILQ_HEAD_INITIALIZER(free_hw_shmem_dbg_bufs);
static STAILQ_HEAD(, kdp_hw_shmem_dbg_buf_elm) hw_shmem_dbg_bufs_to_flush =
                     STAILQ_HEAD_INITIALIZER(hw_shmem_dbg_bufs_to_flush);

static struct kdp_hw_shmem_dbg_buf_elm *currently_filling_buf = NULL;
static struct kdp_hw_shmem_dbg_buf_elm *currently_flushing_buf = NULL;

static uint32_t kdp_hw_shmem_dbg_bufsize = 0;

static uint32_t kdp_hw_shmem_dbg_seq_no = 0;
static uint64_t kdp_hw_shmem_dbg_contact_deadline = 0;
static uint64_t kdp_hw_shmem_dbg_contact_deadline_interval = 0;

#define KDP_HW_SHMEM_DBG_TIMEOUT_DEADLINE_SECS 30
#endif /* WITH_CONSISTENT_DBG */

/*
 * These variables will be modified by the BSD layer if the root device is
 * a RAMDisk.
 */
uint64_t kdp_core_ramdisk_addr = 0;
uint64_t kdp_core_ramdisk_size = 0;

#define DEBG	kdb_printf

boolean_t kdp_has_polled_corefile(void)
{
    return (NULL != gIOPolledCoreFileVars);
}

#if WITH_CONSISTENT_DBG
/*
 * Whenever we start a coredump, make sure the buffers
 * are all on the free queue and the state is as expected.
 * The buffers may have been left in a different state if
 * a previous coredump attempt failed.
 */
static void
kern_dump_hw_shmem_dbg_reset()
{
	struct kdp_hw_shmem_dbg_buf_elm *cur_elm = NULL, *tmp_elm = NULL;

	STAILQ_FOREACH(cur_elm, &free_hw_shmem_dbg_bufs, khsd_elms) {
		cur_elm->khsd_data_length = 0;
	}

	if (currently_filling_buf != NULL) {
		currently_filling_buf->khsd_data_length = 0;

		STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, currently_filling_buf, khsd_elms);
		currently_filling_buf = NULL;
	}

	if (currently_flushing_buf != NULL) {
		currently_flushing_buf->khsd_data_length = 0;

		STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, currently_flushing_buf, khsd_elms);
		currently_flushing_buf = NULL;
	}

	STAILQ_FOREACH_SAFE(cur_elm, &hw_shmem_dbg_bufs_to_flush, khsd_elms, tmp_elm) {
		cur_elm->khsd_data_length = 0;

		STAILQ_REMOVE(&hw_shmem_dbg_bufs_to_flush, cur_elm, kdp_hw_shmem_dbg_buf_elm, khsd_elms);
		STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, cur_elm, khsd_elms);
	}

	hwsd_info->xhsdci_status = XHSDCI_COREDUMP_BUF_EMPTY;
	kdp_hw_shmem_dbg_seq_no = 0;
	hwsd_info->xhsdci_buf_phys_addr = 0;
	hwsd_info->xhsdci_buf_data_length = 0;
	hwsd_info->xhsdci_coredump_total_size_uncomp = 0;
	hwsd_info->xhsdci_coredump_total_size_sent_uncomp = 0;
	hwsd_info->xhsdci_page_size = PAGE_SIZE;
	FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));

	kdp_hw_shmem_dbg_contact_deadline = mach_absolute_time() + kdp_hw_shmem_dbg_contact_deadline_interval;
}

/*
 * Tries to move buffers forward in 'progress'. If
 * the hardware debugger is done consuming the current buffer, we
 * can put the next one on it and move the current
 * buffer back to the free queue.
 */
static int
kern_dump_hw_shmem_dbg_process_buffers()
{
	FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
	if (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_ERROR) {
		kdb_printf("Detected remote error, terminating...\n");
		return -1;
	} else if (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_BUF_EMPTY) {
		if (hwsd_info->xhsdci_seq_no != (kdp_hw_shmem_dbg_seq_no + 1)) {
			kdb_printf("Detected stale/invalid seq num. Expected: %d, received %d\n",
					(kdp_hw_shmem_dbg_seq_no + 1), hwsd_info->xhsdci_seq_no);
			hwsd_info->xhsdci_status = XHSDCI_COREDUMP_ERROR;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
			return -1;
		}

		kdp_hw_shmem_dbg_seq_no = hwsd_info->xhsdci_seq_no;

		if (currently_flushing_buf != NULL) {
			currently_flushing_buf->khsd_data_length = 0;
			STAILQ_INSERT_TAIL(&free_hw_shmem_dbg_bufs, currently_flushing_buf, khsd_elms);
		}

		currently_flushing_buf = STAILQ_FIRST(&hw_shmem_dbg_bufs_to_flush);
		if (currently_flushing_buf != NULL) {
			STAILQ_REMOVE_HEAD(&hw_shmem_dbg_bufs_to_flush, khsd_elms);

			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
			hwsd_info->xhsdci_buf_phys_addr = kvtophys(currently_flushing_buf->khsd_buf);
			hwsd_info->xhsdci_buf_data_length = currently_flushing_buf->khsd_data_length;
			hwsd_info->xhsdci_coredump_total_size_uncomp = kdp_core_total_size;
			hwsd_info->xhsdci_coredump_total_size_sent_uncomp = kdp_core_total_size_sent_uncomp;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, KDP_CORE_HW_SHMEM_DBG_TOTAL_BUF_SIZE);
			hwsd_info->xhsdci_seq_no = ++kdp_hw_shmem_dbg_seq_no;
			hwsd_info->xhsdci_status = XHSDCI_COREDUMP_BUF_READY;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		}

		kdp_hw_shmem_dbg_contact_deadline = mach_absolute_time() +
			kdp_hw_shmem_dbg_contact_deadline_interval;

		return 0;
	} else if (mach_absolute_time() > kdp_hw_shmem_dbg_contact_deadline) {
		kdb_printf("Kernel timed out waiting for hardware debugger to update handshake structure.");
		kdb_printf(" No contact in %d seconds\n", KDP_HW_SHMEM_DBG_TIMEOUT_DEADLINE_SECS);

		hwsd_info->xhsdci_status = XHSDCI_COREDUMP_ERROR;
		FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		return -1;
	}

	return 0;
}

/*
 * Populates currently_filling_buf with a new buffer
 * once one becomes available. Returns 0 on success
 * or the value returned by kern_dump_hw_shmem_dbg_process_buffers()
 * if it is non-zero (an error).
 */
static int
kern_dump_hw_shmem_dbg_get_buffer()
{
	int ret = 0;

	assert(currently_filling_buf == NULL);

	while (STAILQ_EMPTY(&free_hw_shmem_dbg_bufs)) {
		ret = kern_dump_hw_shmem_dbg_process_buffers();
		if (ret) {
			return ret;
		}
	}

	currently_filling_buf = STAILQ_FIRST(&free_hw_shmem_dbg_bufs);
	STAILQ_REMOVE_HEAD(&free_hw_shmem_dbg_bufs, khsd_elms);

	assert(currently_filling_buf->khsd_data_length == 0);
	return ret;
}

/*
 * Output procedure for hardware shared memory core dumps
 *
 * Tries to fill up the buffer completely before flushing
 */
static int
kern_dump_hw_shmem_dbg_buffer_proc(unsigned int request, __unused char *corename,
		uint64_t length, void * data)
{
	int ret = 0;

	assert(length < UINT32_MAX);
	uint32_t bytes_remaining =  (uint32_t) length;
	uint32_t bytes_to_copy;

	if (request == KDP_EOF) {
		assert(currently_filling_buf == NULL);

		/*
		 * Wait until we've flushed all the buffers
		 * before setting the connection status to done.
		 */
		while (!STAILQ_EMPTY(&hw_shmem_dbg_bufs_to_flush) ||
				currently_flushing_buf != NULL) {
			ret = kern_dump_hw_shmem_dbg_process_buffers();
			if (ret) {
				return ret;
			}
		}

		/*
		 * If the last status we saw indicates that the buffer was
		 * empty and we didn't flush any new data since then, we expect
		 * the sequence number to still match the last we saw.
		 */
		if (hwsd_info->xhsdci_seq_no < kdp_hw_shmem_dbg_seq_no) {
			kdb_printf("EOF Flush: Detected stale/invalid seq num. Expected: %d, received %d\n",
					kdp_hw_shmem_dbg_seq_no, hwsd_info->xhsdci_seq_no);
			return -1;
		}

		kdp_hw_shmem_dbg_seq_no = hwsd_info->xhsdci_seq_no;

		kdb_printf("Setting coredump status as done!\n");
		hwsd_info->xhsdci_seq_no = ++kdp_hw_shmem_dbg_seq_no;
		hwsd_info->xhsdci_status = XHSDCI_COREDUMP_STATUS_DONE;
		FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));

		return ret;
	}

	assert(request == KDP_DATA);

	/*
	 * The output procedure is called with length == 0 and data == NULL
	 * to flush any remaining output at the end of the coredump before
	 * we call it a final time to mark the dump as done.
	 */
	if (length == 0) {
		assert(data == NULL);

		if (currently_filling_buf != NULL) {
			STAILQ_INSERT_TAIL(&hw_shmem_dbg_bufs_to_flush, currently_filling_buf, khsd_elms);
			currently_filling_buf = NULL;
		}

		/*
		 * Move the current buffer along if possible.
		 */
		ret = kern_dump_hw_shmem_dbg_process_buffers();
		return ret;
	}

	while (bytes_remaining != 0) {
		/*
		 * Make sure we have a buffer to work with.
		 */
		while (currently_filling_buf == NULL) {
			ret = kern_dump_hw_shmem_dbg_get_buffer();
			if (ret) {
				return ret;
			}
		}

		assert(kdp_hw_shmem_dbg_bufsize >= currently_filling_buf->khsd_data_length);
		bytes_to_copy = MIN(bytes_remaining, kdp_hw_shmem_dbg_bufsize -
				currently_filling_buf->khsd_data_length);
		bcopy(data, (void *)(currently_filling_buf->khsd_buf + currently_filling_buf->khsd_data_length),
				bytes_to_copy);

		currently_filling_buf->khsd_data_length += bytes_to_copy;

		if (currently_filling_buf->khsd_data_length == kdp_hw_shmem_dbg_bufsize) {
			STAILQ_INSERT_TAIL(&hw_shmem_dbg_bufs_to_flush, currently_filling_buf, khsd_elms);
			currently_filling_buf = NULL;

			/*
			 * Move it along if possible.
			 */
			ret = kern_dump_hw_shmem_dbg_process_buffers();
			if (ret) {
				return ret;
			}
		}

		bytes_remaining -= bytes_to_copy;
		data = (void *) ((uintptr_t)data + bytes_to_copy);
	}

	return ret;
}
#endif /* WITH_CONSISTENT_DBG */

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

/*
 * flushes any data to the output proc immediately
 */
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

/*
 * tries to fill the buffer with data before flushing it via the output proc.
 */
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
	if (!inbuf) bzero(&vars->outbuf[vars->outlen - vars->outremain], chunk);
	else
	{
	    bcopy(inbuf, &vars->outbuf[vars->outlen - vars->outremain], chunk);
	    inbuf       += chunk;
	}
	vars->outremain -= chunk;
	remain          -= chunk;
	
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
    uint64_t                   percent, total_in = 0;
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
	total_in = strm->total_in;
	kdp_core_total_size_sent_uncomp = strm->total_in;

	percent = (total_in * 100) / vars->totalbytes;
	if ((percent - vars->lastpercent) >= 10)
	{
	    vars->lastpercent = percent;
	    DEBG("%lld..\n", percent);
	}
    }

    return (int)len;
}

static IOReturn
kdp_core_stream_output_chunk(struct kdp_core_out_vars * vars, unsigned length, void * data)
{
    z_stream * zs;
    int        zr;
    boolean_t  flush;

    zs = &kdp_core_zs;

    if (kdp_corezip_disabled) 
    {
	(*vars->zoutput)(zs, data, length);
    }
    else
    {

	flush = (!length && !data);
	zr = Z_OK;

	assert(!zs->avail_in);

	while (vars->error >= 0)
	{
	    if (!zs->avail_in && !flush)
	    {
		if (!length) break;
		zs->next_in = data ? data : (Bytef *) zs /* zero marker */;
		zs->avail_in = length;
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
    }

    return (vars->error);
}

static IOReturn
kdp_core_stream_output(struct kdp_core_out_vars * vars, uint64_t length, void * data)
{
    IOReturn     err;
    unsigned int chunk;
    enum       { kMaxZLibChunk = 1024*1024*1024 };

    do
    {
        if (length <= kMaxZLibChunk) chunk = (typeof(chunk)) length;
        else                         chunk = kMaxZLibChunk;
        err = kdp_core_stream_output_chunk(vars, chunk, data);

        length -= chunk;
        if (data) data = (void *) (((uintptr_t) data) + chunk);
    }
    while (length && (kIOReturnSuccess == err));

    return (err);
}

extern vm_offset_t c_buffers;
extern vm_size_t   c_buffers_size;

ppnum_t
kernel_pmap_present_mapping(uint64_t vaddr, uint64_t * pvincr, uintptr_t * pvphysaddr)
{
    ppnum_t ppn = 0;
    uint64_t vincr = PAGE_SIZE_64;

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
    else if ((kdp_core_ramdisk_addr != 0) && (vaddr == kdp_core_ramdisk_addr))
    {
        ppn = 0;
        vincr = kdp_core_ramdisk_size;
    }
    else
    ppn = pmap_find_phys(kernel_pmap, vaddr);

    *pvincr = round_page_64(vincr);

    if (ppn && pvphysaddr)
    {
        uint64_t phys = ptoa_64(ppn);
        if (physmap_enclosed(phys)) *pvphysaddr = PHYSMAP_PTOV(phys);
        else                        ppn = 0;
    }

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

	ppn = kernel_pmap_present_mapping(vcur, &vincr, NULL);
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
    if ((ret = kdp_core_stream_output(kdc->outvars, size, (caddr_t)(uintptr_t)start)) != kIOReturnSuccess)	{
	DEBG("kdp_core_stream_output(0x%x)\n", ret);
	goto out;
    }
    kdc->foffset += size;

out:
    return (ret);
}

static int
do_kern_dump(kern_dump_output_proc outproc, enum kern_dump_type kd_variant)
{
	struct kern_dump_preflight_context	kdc_preflight = { };
	struct kern_dump_send_context		kdc_sendseg = { };
	struct kern_dump_send_context		kdc_send = { };
	struct kdp_core_out_vars		outvars = { };
	struct mach_core_fileheader		hdr = { };
	struct ident_command                    ident = { };
	kernel_mach_header_t			mh = { };

	uint32_t	segment_count = 0, tstate_count = 0;
	size_t		command_size = 0, header_size = 0, tstate_size = 0;
	uint64_t	hoffset = 0, foffset = 0;
	int		ret = 0;
	char *          log_start;
	char *          buf;
	size_t		log_size;
	uint64_t	new_logs = 0;
	boolean_t	opened;

	opened    = false;
	log_start = debug_buf_ptr;
	log_size  = debug_buf_ptr - debug_buf_addr;
	assert (log_size <= debug_buf_size);
	if (debug_buf_stackshot_start)
	{
            assert(debug_buf_stackshot_end >= debug_buf_stackshot_start);
            log_size -= (debug_buf_stackshot_end - debug_buf_stackshot_start);
	}

	if (kd_variant == KERN_DUMP_DISK)
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

	/*
	 * Initialize zstream variables that point to input and output
	 * buffer info.
	 */
	kdp_core_zs.avail_in  = 0;
	kdp_core_zs.next_in   = NULL;
	kdp_core_zs.avail_out = 0;
	kdp_core_zs.next_out  = NULL;
	kdp_core_zs.opaque    = &outvars;
	kdc_sendseg.outvars   = &outvars;
	kdc_send.outvars      = &outvars;

        enum { kHdrOffset = 4096, kMaxCoreLog = 16384 };

	if (kd_variant == KERN_DUMP_DISK) {
		outvars.outbuf      = NULL;
		outvars.outlen      = 0;
		outvars.outremain   = 0;
		outvars.zoutput     = kdp_core_zoutput;
		// space for file header, panic log, core log
		foffset = (kHdrOffset + log_size + kMaxCoreLog + 4095) & ~4095ULL;
		hdr.log_offset = kHdrOffset;
		hdr.gzip_offset = foffset;
		if ((ret = (*outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) {
			DEBG("KDP_SEEK(0x%x)\n", ret);
			goto out;
		}
	} else if (kd_variant == KERN_DUMP_NET) {
		outvars.outbuf    = (Bytef *) (kdp_core_zmem + kdp_core_zoffset);
		assert((kdp_core_zoffset + kdp_crashdump_pkt_size) <= kdp_core_zsize);
		outvars.outlen    = kdp_crashdump_pkt_size;
		outvars.outremain = outvars.outlen;
		outvars.zoutput  = kdp_core_zoutputbuf;
#if WITH_CONSISTENT_DBG
	} else { /* KERN_DUMP_HW_SHMEM_DBG */
		outvars.outbuf      = NULL;
		outvars.outlen      = 0;
		outvars.outremain   = 0;
		outvars.zoutput     = kdp_core_zoutput;
		kern_dump_hw_shmem_dbg_reset();
#endif
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

    kdp_core_total_size = outvars.totalbytes;
    kdp_core_total_size_sent_uncomp = 0;

    kern_collectth_state_size(&tstate_count, &tstate_size);

    command_size = segment_count * sizeof(kernel_segment_command_t)
                 + tstate_count * tstate_size
                 + sizeof(struct ident_command) + sizeof(kdp_kernelversion_string);

    header_size = command_size + sizeof(kernel_mach_header_t);

    /*
     *	Set up Mach-O header for currently executing kernel.
     */

    mh.magic = _mh_execute_header.magic;
    mh.cputype = _mh_execute_header.cputype;;
    mh.cpusubtype = _mh_execute_header.cpusubtype;
    mh.filetype = MH_CORE;
    mh.ncmds = segment_count + tstate_count + 1;
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

    DEBG("%s", (kd_variant == KERN_DUMP_DISK) ? "Writing local kernel core..." :
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

    ident.cmd = LC_IDENT;
    ident.cmdsize = (uint32_t) (sizeof(struct ident_command) + sizeof(kdp_kernelversion_string));
    if ((ret = kdp_core_stream_output(&outvars, sizeof(ident), &ident)) != kIOReturnSuccess) {
            DEBG("kdp_core_stream_output(0x%x)\n", ret);
            goto out;
    }
    if ((ret = kdp_core_stream_output(&outvars, sizeof(kdp_kernelversion_string), &kdp_kernelversion_string[0])) != kIOReturnSuccess) {
            DEBG("kdp_core_stream_output(0x%x)\n", ret);
            goto out;
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
    DEBG("Byte counts  : [%llu, %llu, %llu, %lu, %lu]\n", kdc_preflight.dumpable_bytes,
							   kdc_sendseg.dumpable_bytes, 
							   kdc_send.dumpable_bytes, 
							   outvars.zipped,
							   (long) (debug_buf_ptr - debug_buf_addr));
    if ((kd_variant == KERN_DUMP_DISK) && opened)
    {
    	// write debug log
	foffset = kHdrOffset;
	if ((ret = (*outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) { 
	    DEBG("KDP_SEEK(0x%x)\n", ret);
	    goto exit;
	}

        new_logs = debug_buf_ptr - log_start;
        if (new_logs > kMaxCoreLog) new_logs = kMaxCoreLog;
        buf = debug_buf_addr;
        if (debug_buf_stackshot_start)
        {
            if ((ret = (*outproc)(KDP_DATA, NULL, (debug_buf_stackshot_start - debug_buf_addr), debug_buf_addr)) != kIOReturnSuccess)
            {
                DEBG("KDP_DATA(0x%x)\n", ret);
                goto exit;
            }
            buf = debug_buf_stackshot_end;
        }
        if ((ret = (*outproc)(KDP_DATA, NULL, (log_start + new_logs - buf), buf)) != kIOReturnSuccess)
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
	hdr.log_length = new_logs + log_size;
	hdr.gzip_length = outvars.zipped;

	if ((ret = (*outproc)(KDP_DATA, NULL, sizeof(hdr), &hdr)) != kIOReturnSuccess)
	{ 
	    DEBG("KDP_DATA(0x%x)\n", ret);
	    goto exit;
	}
    }

exit:
    /* close / last packet */
    if (opened && (ret = (*outproc)(KDP_EOF, NULL, 0, ((void *) 0))) != kIOReturnSuccess)
    {
        DEBG("KDP_EOF(0x%x)\n", ret);
    }


    return (ret);
}

int
kern_dump(enum kern_dump_type kd_variant)
{
	static boolean_t dumped_local;
	if (kd_variant == KERN_DUMP_DISK) {
		if (dumped_local) return (0);
		dumped_local = TRUE;
		return (do_kern_dump(&kern_dump_disk_proc, KERN_DUMP_DISK));
#if WITH_CONSISTENT_DBG
	} else if (kd_variant == KERN_DUMP_HW_SHMEM_DBG) {
		return (do_kern_dump(&kern_dump_hw_shmem_dbg_buffer_proc, KERN_DUMP_HW_SHMEM_DBG));
#endif
	}
#if CONFIG_KDP_INTERACTIVE_DEBUGGING
	return (do_kern_dump(&kdp_send_crashdump_data, KERN_DUMP_NET));
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
#if WITH_CONSISTENT_DBG
	int i = 0;
	vm_offset_t kdp_core_hw_shmem_buf = 0;
	struct kdp_hw_shmem_dbg_buf_elm *cur_elm = NULL;
#endif

	if (kdp_core_zs.zalloc) return;
	kdp_core_zsize = round_page(NETBUF + zlib_deflate_memory_size(wbits, memlevel));
	printf("kdp_core zlib memory 0x%lx\n", kdp_core_zsize);
	kr = kmem_alloc(kernel_map, &kdp_core_zmem, kdp_core_zsize, VM_KERN_MEMORY_DIAG);
	assert (KERN_SUCCESS == kr);

	kdp_core_zoffset = 0;
	kdp_core_zs.zalloc = kdp_core_zalloc;
	kdp_core_zs.zfree  = kdp_core_zfree;

	if (deflateInit2(&kdp_core_zs, LEVEL, Z_DEFLATED,
				wbits + 16 /*gzip mode*/, memlevel, Z_DEFAULT_STRATEGY)) {
		/* Allocation failed */
		bzero(&kdp_core_zs, sizeof(kdp_core_zs));
		kdp_core_zoffset = 0;
	}

#if WITH_CONSISTENT_DBG
	if (!PE_consistent_debug_enabled()) {
		return;
	}

	/*
	 * We need to allocate physically contiguous memory since astris isn't capable
	 * of doing address translations while the CPUs are running.
	 */
	kdp_hw_shmem_dbg_bufsize = KDP_CORE_HW_SHMEM_DBG_TOTAL_BUF_SIZE;
	kr = kmem_alloc_contig(kernel_map, &kdp_core_hw_shmem_buf, kdp_hw_shmem_dbg_bufsize, VM_MAP_PAGE_MASK(kernel_map),
			0, 0, KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
	assert(KERN_SUCCESS == kr);

	/*
	 * Put the connection info structure at the beginning of this buffer and adjust
	 * the buffer size accordingly.
	 */
	hwsd_info = (struct xnu_hw_shmem_dbg_command_info *) kdp_core_hw_shmem_buf;
	hwsd_info->xhsdci_status = XHSDCI_STATUS_NONE;
	hwsd_info->xhsdci_seq_no = 0;
	hwsd_info->xhsdci_buf_phys_addr = 0;
	hwsd_info->xhsdci_buf_data_length = 0;
	hwsd_info->xhsdci_coredump_total_size_uncomp = 0;
	hwsd_info->xhsdci_coredump_total_size_sent_uncomp = 0;
	hwsd_info->xhsdci_page_size = PAGE_SIZE;

	kdp_core_hw_shmem_buf += sizeof(*hwsd_info);
	kdp_hw_shmem_dbg_bufsize -= sizeof(*hwsd_info);
	kdp_hw_shmem_dbg_bufsize = (kdp_hw_shmem_dbg_bufsize / KDP_CORE_HW_SHMEM_DBG_NUM_BUFFERS);
	kdp_hw_shmem_dbg_bufsize -= (kdp_hw_shmem_dbg_bufsize % OPTIMAL_ASTRIS_READSIZE);

	STAILQ_INIT(&free_hw_shmem_dbg_bufs);
	STAILQ_INIT(&hw_shmem_dbg_bufs_to_flush);

	for (i = 0; i < KDP_CORE_HW_SHMEM_DBG_NUM_BUFFERS; i++) {
		cur_elm = kalloc(sizeof(*cur_elm));
		assert(cur_elm != NULL);

		cur_elm->khsd_buf = kdp_core_hw_shmem_buf;
		cur_elm->khsd_data_length = 0;

		kdp_core_hw_shmem_buf += kdp_hw_shmem_dbg_bufsize;

		STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, cur_elm, khsd_elms);
	}

	nanoseconds_to_absolutetime(KDP_HW_SHMEM_DBG_TIMEOUT_DEADLINE_SECS * NSEC_PER_SEC,
			&kdp_hw_shmem_dbg_contact_deadline_interval);

	PE_consistent_debug_register(kDbgIdAstrisConnection, kvtophys((vm_offset_t) hwsd_info), sizeof(pmap_paddr_t));
	PE_consistent_debug_register(kDbgIdAstrisConnectionVers, CUR_XNU_HWSDCI_STRUCT_VERS, sizeof(uint32_t));
#endif /* WITH_CONSISTENT_DBG */
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
