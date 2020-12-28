/*
 * Copyright (c) 2015-2017 Apple Computer, Inc. All rights reserved.
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
#include <kdp/processor_core.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IOBSD.h>
#include <sys/errno.h>
#include <sys/msgbuf.h>
#include <san/kasan.h>

#if defined(__x86_64__)
#include <i386/pmap_internal.h>
#include <kdp/ml/i386/kdp_x86_common.h>
#include <kern/debug.h>
#endif /* defined(__x86_64__) */

#if CONFIG_EMBEDDED
#include <arm/cpuid.h>
#include <arm/caches_internal.h>
#include <pexpert/arm/consistent_debug.h>

#if !defined(ROUNDUP)
#define ROUNDUP(a, b) (((a) + ((b) - 1)) & (~((b) - 1)))
#endif

#if !defined(ROUNDDOWN)
#define ROUNDDOWN(a, b) ((a) & ~((b) - 1))
#endif
#endif /* CONFIG_EMBEDDED */

typedef int (*pmap_traverse_callback)(vm_map_offset_t start,
				      vm_map_offset_t end,
				      void *context);

extern int pmap_traverse_present_mappings(pmap_t pmap,
					  vm_map_offset_t start,
					  vm_map_offset_t end,
					  pmap_traverse_callback callback,
					  void *context);

static int kern_dump_save_summary(void *refcon, core_save_summary_cb callback, void *context);
static int kern_dump_save_seg_descriptions(void *refcon, core_save_segment_descriptions_cb callback, void *context);
static int kern_dump_save_thread_state(void *refcon, void *buf, core_save_thread_state_cb callback, void *context);
static int kern_dump_save_sw_vers(void *refcon, core_save_sw_vers_cb callback, void *context);
static int kern_dump_save_segment_data(void *refcon, core_save_segment_data_cb callback, void *context);

static int
kern_dump_pmap_traverse_preflight_callback(vm_map_offset_t start,
					       vm_map_offset_t end,
					       void *context);
static int
kern_dump_pmap_traverse_send_segdesc_callback(vm_map_offset_t start,
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
     z_output_func         zoutput;
     size_t                zipped;
     uint64_t              totalbytes;
     uint64_t              lastpercent;
     IOReturn              error;
     unsigned              outremain;
     unsigned              outlen;
     unsigned              writes;
     Bytef *               outbuf;
};

extern uint32_t kdp_crashdump_pkt_size;

static vm_offset_t kdp_core_zmem;
static size_t      kdp_core_zsize;
static size_t      kdp_core_zoffset;
static z_stream	   kdp_core_zs;

static uint64_t    kdp_core_total_size;
static uint64_t    kdp_core_total_size_sent_uncomp;
#if CONFIG_EMBEDDED
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
#endif /* CONFIG_EMBEDDED */

static boolean_t kern_dump_successful = FALSE;

struct mach_core_fileheader kdp_core_header = { };

/*
 * These variables will be modified by the BSD layer if the root device is
 * a RAMDisk.
 */
uint64_t kdp_core_ramdisk_addr = 0;
uint64_t kdp_core_ramdisk_size = 0;

boolean_t kdp_has_polled_corefile(void)
{
    return (NULL != gIOPolledCoreFileVars);
}

kern_return_t kdp_polled_corefile_error(void)
{
    return gIOPolledCoreFileOpenRet;
}
#if CONFIG_EMBEDDED
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
		kern_coredump_log(NULL, "Detected remote error, terminating...\n");
		return -1;
	} else if (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_BUF_EMPTY) {
		if (hwsd_info->xhsdci_seq_no != (kdp_hw_shmem_dbg_seq_no + 1)) {
			kern_coredump_log(NULL, "Detected stale/invalid seq num. Expected: %d, received %d\n",
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
		kern_coredump_log(NULL, "Kernel timed out waiting for hardware debugger to update handshake structure.");
		kern_coredump_log(NULL, "No contact in %d seconds\n", KDP_HW_SHMEM_DBG_TIMEOUT_DEADLINE_SECS);

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
			kern_coredump_log(NULL, "EOF Flush: Detected stale/invalid seq num. Expected: %d, received %d\n",
					kdp_hw_shmem_dbg_seq_no, hwsd_info->xhsdci_seq_no);
			return -1;
		}

		kdp_hw_shmem_dbg_seq_no = hwsd_info->xhsdci_seq_no;

		kern_coredump_log(NULL, "Setting coredump status as done!\n");
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
#endif /* CONFIG_EMBEDDED */

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
	    if (kIOReturnSuccess != err) {
		    kern_coredump_log(NULL, "IOPolledFileSeek(gIOPolledCoreFileVars, 0) returned 0x%x\n", err);
		    break;
	    }
	    err = IOPolledFilePollersOpen(gIOPolledCoreFileVars, kIOPolledBeforeSleepState, false);
	    break;

        case KDP_SEEK:
	    noffset = *((uint64_t *) data);
	    err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
	    if (kIOReturnSuccess != err) {
		    kern_coredump_log(NULL, "IOPolledFileWrite (during seek) returned 0x%x\n", err);
		    break;
	    }
	    err = IOPolledFileSeek(gIOPolledCoreFileVars, noffset);
	    if (kIOReturnSuccess != err) {
		kern_coredump_log(NULL, "IOPolledFileSeek(0x%llx) returned 0x%x\n", noffset, err);
	    }
	    break;

        case KDP_DATA:
	    err = IOPolledFileWrite(gIOPolledCoreFileVars, data, length, NULL);
	    if (kIOReturnSuccess != err) {
		    kern_coredump_log(NULL, "IOPolledFileWrite(gIOPolledCoreFileVars, %p, 0x%llx, NULL) returned 0x%x\n",
				    data, length, err);
		    break;
	    }
	    break;

#if CONFIG_EMBEDDED
	/* Only supported on embedded by the underlying polled mode driver */
	case KDP_FLUSH:
	    err = IOPolledFileFlush(gIOPolledCoreFileVars);
	    if (kIOReturnSuccess != err) {
		    kern_coredump_log(NULL, "IOPolledFileFlush() returned 0x%x\n", err);
		    break;
	    }
	    break;
#endif

        case KDP_EOF:
	    err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
	    if (kIOReturnSuccess != err) {
		    kern_coredump_log(NULL, "IOPolledFileWrite (during EOF) returned 0x%x\n", err);
		    break;
	    }
	    err = IOPolledFilePollersClose(gIOPolledCoreFileVars, kIOPolledBeforeSleepState);
	    if (kIOReturnSuccess != err) {
		    kern_coredump_log(NULL, "IOPolledFilePollersClose (during EOF) returned 0x%x\n", err);
		    break;
	    }
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
	    kern_coredump_log(NULL, "(kdp_core_zoutput) outproc(KDP_DATA, NULL, 0x%x, %p) returned 0x%x\n",
			    len, buf, ret);
	    vars->error = ret;
	}
	if (!buf && !len) kern_coredump_log(NULL, "100..");
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
	    kern_coredump_log(NULL, "(kdp_core_zoutputbuf) outproc(KDP_DATA, NULL, 0x%x, %p) returned 0x%x\n",
			    (vars->outlen - vars->outremain), vars->outbuf, ret);
	    vars->error = ret;
	}
	if (flush)
	{
	    kern_coredump_log(NULL, "100..");
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
	    kern_coredump_log(NULL, "%lld..\n", percent);
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
		kern_coredump_log(NULL, "ZERR %d\n", zr);
		vars->error = zr;
	    }
	}

	if (flush) (*vars->zoutput)(zs, NULL, 0);
    }

    return (vars->error);
}

kern_return_t
kdp_core_output(void *kdp_core_out_vars, uint64_t length, void * data)
{
    IOReturn     err;
    unsigned int chunk;
    enum       { kMaxZLibChunk = 1024*1024*1024 };
    struct kdp_core_out_vars *vars = (struct kdp_core_out_vars *)kdp_core_out_vars;

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

#if defined(__arm__) || defined(__arm64__)
extern pmap_paddr_t avail_start, avail_end;
extern struct vm_object pmap_object_store;
#endif
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
#if defined(__arm64__) && defined(CONFIG_XNUPOST)
    if (vaddr == _COMM_HIGH_PAGE64_BASE_ADDRESS)
    {
	/* not readable */
	ppn = 0;
	vincr = _COMM_PAGE_AREA_LENGTH;
    }
    else
#endif /* defined(__arm64__) */
#if defined(__arm__) || defined(__arm64__)
    if (vaddr == phystokv(avail_start))
    {
	/* physical memory map */
	ppn = 0;
	vincr = (avail_end - avail_start);
    }
    else
#endif /* defined(__arm__) || defined(__arm64__) */
    ppn = pmap_find_phys(kernel_pmap, vaddr);

    *pvincr = round_page_64(vincr);

    if (ppn && pvphysaddr)
    {
        uint64_t phys = ptoa_64(ppn);
        if (physmap_enclosed(phys)) {
		*pvphysaddr = phystokv(phys);
        } else {
		ppn = 0;
	}
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
    uint64_t        vincr = 0;
    vm_map_offset_t debug_start = trunc_page((vm_map_offset_t) debug_buf_base);
    vm_map_offset_t debug_end = round_page((vm_map_offset_t) (debug_buf_base + debug_buf_size));
#if defined(XNU_TARGET_OS_BRIDGE)
    vm_map_offset_t macos_panic_start = trunc_page((vm_map_offset_t) macos_panic_base);
    vm_map_offset_t macos_panic_end = round_page((vm_map_offset_t) (macos_panic_base + macos_panic_size));
#endif

    boolean_t       lastvavalid;
#if defined(__arm__) || defined(__arm64__)
    vm_page_t m = VM_PAGE_NULL;
#endif

#if defined(__x86_64__)
    assert(!is_ept_pmap(pmap));
#endif

    /* Assumes pmap is locked, or being called from the kernel debugger */
    
    if (start > end) return (KERN_INVALID_ARGUMENT);

    ret = KERN_SUCCESS;
    lastvavalid = FALSE;
    for (vcur = vcurstart = start; (ret == KERN_SUCCESS) && (vcur < end); ) {
	ppnum_t ppn = 0;

#if defined(__arm__) || defined(__arm64__)
	/* We're at the start of the physmap, so pull out the pagetable pages that
	 * are accessed through that region.*/
	if (vcur == phystokv(avail_start) && vm_object_lock_try_shared(&pmap_object_store))
	    m = (vm_page_t)vm_page_queue_first(&pmap_object_store.memq);

	if (m != VM_PAGE_NULL)
	{
	    vm_map_offset_t vprev = vcur;
	    ppn = (ppnum_t)atop(avail_end);
	    while (!vm_page_queue_end(&pmap_object_store.memq, (vm_page_queue_entry_t)m))
	    {
	        /* Ignore pages that come from the static region and have already been dumped.*/
		if (VM_PAGE_GET_PHYS_PAGE(m) >= atop(avail_start))
	        {
		    ppn = VM_PAGE_GET_PHYS_PAGE(m);
	            break;
	        }
	        m = (vm_page_t)vm_page_queue_next(&m->vmp_listq);
	    }
	    vincr = PAGE_SIZE_64;
	    if (ppn == atop(avail_end))
	    {
	        vm_object_unlock(&pmap_object_store);
	        m = VM_PAGE_NULL;
	        // avail_end is not a valid physical address,
	        // so phystokv(avail_end) may not produce the expected result.
	        vcur = phystokv(avail_start) + (avail_end - avail_start);
	    } else {
	        m = (vm_page_t)vm_page_queue_next(&m->vmp_listq);
	        vcur = phystokv(ptoa(ppn));
	    }
	    if (vcur != vprev)
	    {
	        ret = callback(vcurstart, vprev, context);
	        lastvavalid = FALSE;
	    }
	}
	if (m == VM_PAGE_NULL)
	    ppn = kernel_pmap_present_mapping(vcur, &vincr, NULL);
#else /* defined(__arm__) || defined(__arm64__) */
	ppn = kernel_pmap_present_mapping(vcur, &vincr, NULL);
#endif
	if (ppn != 0)
	{
	    if (((vcur < debug_start) || (vcur >= debug_end))
		&& !(pmap_valid_page(ppn) || bootloader_valid_page(ppn))
#if defined(XNU_TARGET_OS_BRIDGE)
		// include the macOS panic region if it's mapped
		&& ((vcur < macos_panic_start) || (vcur >= macos_panic_end))
#endif
		)
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

#if defined(__x86_64__)
	    /* Try to skip by 2MB if possible */
	    if ((vcur & PDMASK) == 0) {
		pd_entry_t *pde;
		pde = pmap_pde(pmap, vcur);
		if (0 == pde || ((*pde & INTEL_PTE_VALID) == 0)) {
		    /* Make sure we wouldn't overflow */
		    if (vcur < (end - NBPD)) {
			vincr = NBPD;
		    }
		}
	    }
#endif /* defined(__x86_64__) */
	}
	vcur += vincr;
    }
    
    if ((ret == KERN_SUCCESS) && lastvavalid) {
	/* send previous run */
	ret = callback(vcurstart, vcur, context);
    }

#if KASAN
    if (ret == KERN_SUCCESS) {
	ret = kasan_traverse_mappings(callback, context);
    }
#endif

    return (ret);
}

struct kern_dump_preflight_context
{
	uint32_t region_count;
	uint64_t dumpable_bytes;
};

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


struct kern_dump_send_seg_desc_context
{
	core_save_segment_descriptions_cb callback;
	void *context;
};

int
kern_dump_pmap_traverse_send_segdesc_callback(vm_map_offset_t start,
					      vm_map_offset_t end,
					      void *context)
{
	struct kern_dump_send_seg_desc_context *kds_context = (struct kern_dump_send_seg_desc_context *)context;
	uint64_t seg_start = (uint64_t) start;
	uint64_t seg_end = (uint64_t) end;

	return kds_context->callback(seg_start, seg_end, kds_context->context);
}

struct kern_dump_send_segdata_context
{
	core_save_segment_data_cb callback;
	void *context;
};

int
kern_dump_pmap_traverse_send_segdata_callback(vm_map_offset_t start,
					      vm_map_offset_t end,
					      void *context)
{
	struct kern_dump_send_segdata_context *kds_context = (struct kern_dump_send_segdata_context *)context;

	return kds_context->callback((void *)start, (uint64_t)(end - start), kds_context->context);
}

static int
kern_dump_save_summary(__unused void *refcon, core_save_summary_cb callback, void *context)
{
	struct kern_dump_preflight_context kdc_preflight = { };
	uint64_t thread_state_size = 0, thread_count = 0;
	kern_return_t ret;

	ret = pmap_traverse_present_mappings(kernel_pmap,
			VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			VM_MAX_KERNEL_ADDRESS,
			kern_dump_pmap_traverse_preflight_callback,
			&kdc_preflight);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "save_summary: pmap traversal failed: %d\n", ret);
		return ret;
	}

	kern_collectth_state_size(&thread_count, &thread_state_size);

	ret = callback(kdc_preflight.region_count, kdc_preflight.dumpable_bytes,
			thread_count, thread_state_size, 0, context);
	return ret;
}

static int
kern_dump_save_seg_descriptions(__unused void *refcon, core_save_segment_descriptions_cb callback, void *context)
{
	kern_return_t ret;
	struct kern_dump_send_seg_desc_context kds_context;

	kds_context.callback = callback;
	kds_context.context = context;

	ret = pmap_traverse_present_mappings(kernel_pmap,
			VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			VM_MAX_KERNEL_ADDRESS,
			kern_dump_pmap_traverse_send_segdesc_callback,
			&kds_context);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "save_seg_desc: pmap traversal failed: %d\n", ret);
		return ret;
	}

	return KERN_SUCCESS;
}

static int
kern_dump_save_thread_state(__unused void *refcon, void *buf, core_save_thread_state_cb callback, void *context)
{
	kern_return_t ret;
	uint64_t thread_state_size = 0, thread_count = 0;

	kern_collectth_state_size(&thread_count, &thread_state_size);

	if (thread_state_size > 0) {
		void * iter = NULL;
		do {
			kern_collectth_state (current_thread(), buf, thread_state_size, &iter);

			ret = callback(buf, context);
			if (ret != KERN_SUCCESS) {
				return ret;
			}
		} while (iter);
	}

	return KERN_SUCCESS;
}

static int
kern_dump_save_sw_vers(__unused void *refcon, core_save_sw_vers_cb callback, void *context)
{
	return callback(&kdp_kernelversion_string, sizeof(kdp_kernelversion_string), context);
}

static int
kern_dump_save_segment_data(__unused void *refcon, core_save_segment_data_cb callback, void *context)
{
	kern_return_t ret;
	struct kern_dump_send_segdata_context kds_context;

	kds_context.callback = callback;
	kds_context.context = context;

	ret = pmap_traverse_present_mappings(kernel_pmap,
			VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			VM_MAX_KERNEL_ADDRESS, kern_dump_pmap_traverse_send_segdata_callback, &kds_context);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "save_seg_data: pmap traversal failed: %d\n", ret);
		return ret;
	}

	return KERN_SUCCESS;
}

kern_return_t
kdp_reset_output_vars(void *kdp_core_out_vars, uint64_t totalbytes)
{
	struct kdp_core_out_vars *outvars = (struct kdp_core_out_vars *)kdp_core_out_vars;

	/* Re-initialize kdp_outvars */
	outvars->zipped = 0;
	outvars->totalbytes = totalbytes;
	outvars->lastpercent = 0;
	outvars->error = kIOReturnSuccess;
	outvars->outremain = 0;
	outvars->outlen = 0;
	outvars->writes = 0;
	outvars->outbuf = NULL;

	if (outvars->outproc == &kdp_send_crashdump_data) {
		/* KERN_DUMP_NET */
		outvars->outbuf = (Bytef *) (kdp_core_zmem + kdp_core_zoffset);
		outvars->outremain = outvars->outlen = kdp_crashdump_pkt_size;
	}

	kdp_core_total_size = totalbytes;

	/* Re-initialize zstream variables */
	kdp_core_zs.avail_in  = 0;
	kdp_core_zs.next_in   = NULL;
	kdp_core_zs.avail_out = 0;
	kdp_core_zs.next_out  = NULL;
	kdp_core_zs.opaque    = outvars;

	deflateResetWithIO(&kdp_core_zs, kdp_core_zinput, outvars->zoutput);

	return KERN_SUCCESS;
}

static int
kern_dump_update_header(struct kdp_core_out_vars *outvars)
{
	uint64_t foffset;
	int ret;

	/* Write the file header -- first seek to the beginning of the file */
	foffset = 0;
	if ((ret = (outvars->outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
				sizeof(foffset), &foffset, foffset, ret);
		return ret;
	}

	if ((ret = (outvars->outproc)(KDP_DATA, NULL, sizeof(kdp_core_header), &kdp_core_header)) != kIOReturnSuccess) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc(KDP_DATA, NULL, %lu, %p) returned 0x%x\n",
				sizeof(kdp_core_header), &kdp_core_header, ret);
                return ret;
	}

	if ((ret = (outvars->outproc)(KDP_DATA, NULL, 0, NULL)) != kIOReturnSuccess) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc data flush returned 0x%x\n", ret);
		return ret;
	}

#if CONFIG_EMBEDDED
	if ((ret = (outvars->outproc)(KDP_FLUSH, NULL, 0, NULL)) != kIOReturnSuccess) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc explicit flush returned 0x%x\n", ret);
		return ret;
	}
#endif

	return KERN_SUCCESS;
}

int
kern_dump_record_file(void *kdp_core_out_vars, const char *filename, uint64_t file_offset, uint64_t *out_file_length)
{
	int ret = 0;
	struct kdp_core_out_vars *outvars = (struct kdp_core_out_vars *)kdp_core_out_vars;

	assert(kdp_core_header.num_files < KERN_COREDUMP_MAX_CORES);
	assert(out_file_length != NULL);
	*out_file_length = 0;

	kdp_core_header.files[kdp_core_header.num_files].gzip_offset = file_offset;
	kdp_core_header.files[kdp_core_header.num_files].gzip_length = outvars->zipped;
	strncpy((char *)&kdp_core_header.files[kdp_core_header.num_files].core_name, filename,
			MACH_CORE_FILEHEADER_NAMELEN);
	kdp_core_header.files[kdp_core_header.num_files].core_name[MACH_CORE_FILEHEADER_NAMELEN - 1] = '\0';
	kdp_core_header.num_files++;
	kdp_core_header.signature = MACH_CORE_FILEHEADER_SIGNATURE;

	ret = kern_dump_update_header(outvars);
	if (ret == KERN_SUCCESS) {
		*out_file_length = outvars->zipped;
	}

	return ret;
}

int
kern_dump_seek_to_next_file(void *kdp_core_out_vars, uint64_t next_file_offset)
{
	struct kdp_core_out_vars *outvars = (struct kdp_core_out_vars *)kdp_core_out_vars;
	int ret;

	if ((ret = (outvars->outproc)(KDP_SEEK, NULL, sizeof(next_file_offset), &next_file_offset)) != kIOReturnSuccess) {
		kern_coredump_log(NULL, "(kern_dump_seek_to_next_file) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
				sizeof(next_file_offset), &next_file_offset, next_file_offset, ret);
	}

	return ret;
}

static int
do_kern_dump(kern_dump_output_proc outproc, enum kern_dump_type kd_variant)
{
	struct kdp_core_out_vars outvars = { };

	char *log_start = NULL, *buf = NULL;
	size_t existing_log_size = 0, new_log_len = 0;
	uint64_t foffset = 0;
	int ret = 0;
	boolean_t output_opened = FALSE, dump_succeeded = TRUE;

	/*
	 * Record the initial panic log buffer length so we can dump the coredump log
	 * and panic log to disk
	 */
	log_start = debug_buf_ptr;
#if CONFIG_EMBEDDED
	assert(panic_info->eph_other_log_offset != 0);
	assert(panic_info->eph_panic_log_len != 0);
	/* Include any data from before the panic log as well */
	existing_log_size = (panic_info->eph_panic_log_offset - sizeof(struct embedded_panic_header)) +
				panic_info->eph_panic_log_len + panic_info->eph_other_log_len;
#else /* CONFIG_EMBEDDED */
	if (panic_info->mph_panic_log_offset != 0) {
		existing_log_size = (panic_info->mph_panic_log_offset - sizeof(struct macos_panic_header)) +
				panic_info->mph_panic_log_len + panic_info->mph_other_log_len;
	}
#endif /* CONFIG_EMBEDDED */

	assert (existing_log_size <= debug_buf_size);

	if ((kd_variant == KERN_DUMP_DISK) || (kd_variant == KERN_DUMP_STACKSHOT_DISK)) {
		/* Open the file for output */
		if ((ret = (*outproc)(KDP_WRQ, NULL, 0, NULL)) != kIOReturnSuccess) {
			kern_coredump_log(NULL, "outproc(KDP_WRQ, NULL, 0, NULL) returned 0x%x\n", ret);
			dump_succeeded = FALSE;
			goto exit;
		}
	}
	output_opened = true;

	/* Initialize gzip, output context */
	bzero(&outvars, sizeof(outvars));
	outvars.outproc = outproc;

	if ((kd_variant == KERN_DUMP_DISK) || (kd_variant == KERN_DUMP_STACKSHOT_DISK)) {
		outvars.zoutput     = kdp_core_zoutput;
		/* Space for file header, panic log, core log */
		foffset = (KERN_COREDUMP_HEADERSIZE + existing_log_size + KERN_COREDUMP_MAXDEBUGLOGSIZE +
				KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN - 1) & ~(KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN - 1);
		kdp_core_header.log_offset = KERN_COREDUMP_HEADERSIZE;

		/* Seek the calculated offset (we'll scrollback later to flush the logs and header) */
		if ((ret = (*outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) {
			kern_coredump_log(NULL, "(do_kern_dump seek begin) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
					sizeof(foffset), &foffset, foffset, ret);
			dump_succeeded = FALSE;
			goto exit;
		}
	} else if (kd_variant == KERN_DUMP_NET) {
		assert((kdp_core_zoffset + kdp_crashdump_pkt_size) <= kdp_core_zsize);
		outvars.zoutput = kdp_core_zoutputbuf;
#if CONFIG_EMBEDDED
	} else { /* KERN_DUMP_HW_SHMEM_DBG */
		outvars.zoutput = kdp_core_zoutput;
		kern_dump_hw_shmem_dbg_reset();
#endif
	}

#if defined(__arm__) || defined(__arm64__)
	flush_mmu_tlb();
#endif

	kern_coredump_log(NULL, "%s", (kd_variant == KERN_DUMP_DISK) ? "Writing local cores..." :
    	    	       "Transmitting kernel state, please wait:\n");


#if defined(__x86_64__)
	if (((kd_variant == KERN_DUMP_STACKSHOT_DISK) || (kd_variant == KERN_DUMP_DISK)) && ((panic_stackshot_buf != 0) && (panic_stackshot_len != 0))) {
		uint64_t compressed_stackshot_len = 0;

		if ((ret = kdp_reset_output_vars(&outvars, panic_stackshot_len)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "Failed to reset outvars for stackshot with len 0x%zx, returned 0x%x\n", panic_stackshot_len, ret);
			dump_succeeded = FALSE;
		} else if ((ret = kdp_core_output(&outvars, panic_stackshot_len, (void *)panic_stackshot_buf)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "Failed to write panic stackshot to file, kdp_coreoutput(outvars, %lu, %p) returned 0x%x\n",
				       panic_stackshot_len, (void *) panic_stackshot_buf, ret);
			dump_succeeded = FALSE;
		} else if ((ret = kdp_core_output(&outvars, 0, NULL)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "Failed to flush stackshot data : kdp_core_output(%p, 0, NULL) returned 0x%x\n", &outvars, ret);
			dump_succeeded = FALSE;
		} else if ((ret = kern_dump_record_file(&outvars, "panic_stackshot.kcdata", foffset, &compressed_stackshot_len)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "Failed to record panic stackshot in corefile header, kern_dump_record_file returned 0x%x\n", ret);
			dump_succeeded = FALSE;
		} else {
			kern_coredump_log(NULL, "Recorded panic stackshot in corefile at offset 0x%llx, compressed to %llu bytes\n", foffset, compressed_stackshot_len);
			foffset = roundup((foffset + compressed_stackshot_len), KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN);
			if ((ret = kern_dump_seek_to_next_file(&outvars, foffset)) != kIOReturnSuccess) {
				kern_coredump_log(NULL, "Failed to seek to stackshot file offset 0x%llx, kern_dump_seek_to_next_file returned 0x%x\n", foffset, ret);
				dump_succeeded = FALSE;
			}
		}
	}
#endif

	if (kd_variant == KERN_DUMP_DISK) {
		/*
		 * Dump co-processors as well, foffset will be overwritten with the
		 * offset of the next location in the file to be written to.
		 */
		if (kern_do_coredump(&outvars, FALSE, foffset, &foffset) != 0) {
			dump_succeeded = FALSE;
		}
	} else if (kd_variant != KERN_DUMP_STACKSHOT_DISK) {
		/* Only the kernel */
		if (kern_do_coredump(&outvars, TRUE, foffset, &foffset) != 0) {
			dump_succeeded = FALSE;
		}
	}

	if (kd_variant == KERN_DUMP_DISK) {
		/* Write the debug log -- first seek to the end of the corefile header */
		foffset = KERN_COREDUMP_HEADERSIZE;
		if ((ret = (*outproc)(KDP_SEEK, NULL, sizeof(foffset), &foffset)) != kIOReturnSuccess) {
			kern_coredump_log(NULL, "(do_kern_dump seek logfile) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
					sizeof(foffset), &foffset, foffset, ret);
			dump_succeeded = FALSE;
			goto exit;
		}

		new_log_len = debug_buf_ptr - log_start;
		if (new_log_len > KERN_COREDUMP_MAXDEBUGLOGSIZE) {
			new_log_len = KERN_COREDUMP_MAXDEBUGLOGSIZE;
		}

		/* This data is after the panic stackshot, we need to write it separately */
#if CONFIG_EMBEDDED
		existing_log_size -= panic_info->eph_other_log_len;
#else
		if (existing_log_size) {
			existing_log_size -= panic_info->mph_other_log_len;
		}
#endif

		/*
		 * Write out the paniclog (from the beginning of the debug
		 * buffer until the start of the stackshot)
		 */
		buf = debug_buf_base;
		if ((ret = (*outproc)(KDP_DATA, NULL, existing_log_size, buf)) != kIOReturnSuccess) {
				kern_coredump_log(NULL, "(do_kern_dump paniclog) outproc(KDP_DATA, NULL, %lu, %p) returned 0x%x\n",
						existing_log_size, buf, ret);
				dump_succeeded = FALSE;
				goto exit;
		}

		/*
		 * The next part of the log we're interested in is the beginning of the 'other' log.
		 * Include any data after the panic stackshot but before we started the coredump log
		 * (see above)
		 */
#if CONFIG_EMBEDDED
		buf = (char *)(((char *)panic_info) + (uintptr_t) panic_info->eph_other_log_offset);
		new_log_len += panic_info->eph_other_log_len;
#else /* CONFIG_EMBEDDED */
		buf = (char *)(((char *)panic_info) + (uintptr_t) panic_info->mph_other_log_offset);
		new_log_len += panic_info->mph_other_log_len;
#endif /* CONFIG_EMBEDDED */

		/* Write the coredump log */
		if ((ret = (*outproc)(KDP_DATA, NULL, new_log_len, buf)) != kIOReturnSuccess) {
			kern_coredump_log(NULL, "(do_kern_dump coredump log) outproc(KDP_DATA, NULL, %lu, %p) returned 0x%x\n",
					new_log_len, buf, ret);
			dump_succeeded = FALSE;
			goto exit;
		}

		kdp_core_header.log_length = existing_log_size + new_log_len;
		kern_dump_update_header(&outvars);
	}

exit:
	/* close / last packet */
	if (output_opened && (ret = (*outproc)(KDP_EOF, NULL, 0, ((void *) 0))) != kIOReturnSuccess) {
		kern_coredump_log(NULL, "(do_kern_dump close) outproc(KDP_EOF, NULL, 0, 0) returned 0x%x\n", ret);
		dump_succeeded = FALSE;
	}

	/* If applicable, update the panic header and flush it so we update the CRC */
#if CONFIG_EMBEDDED
	panic_info->eph_panic_flags |= (dump_succeeded ? EMBEDDED_PANIC_HEADER_FLAG_COREDUMP_COMPLETE :
			EMBEDDED_PANIC_HEADER_FLAG_COREDUMP_FAILED);
	paniclog_flush();
#else
	if (panic_info->mph_panic_log_offset != 0) {
		panic_info->mph_panic_flags |= (dump_succeeded ? MACOS_PANIC_HEADER_FLAG_COREDUMP_COMPLETE :
			MACOS_PANIC_HEADER_FLAG_COREDUMP_FAILED);
		paniclog_flush();
	}
#endif

	return (dump_succeeded ? 0 : -1);
}

boolean_t
dumped_kernel_core()
{
	return kern_dump_successful;
}

int
kern_dump(enum kern_dump_type kd_variant)
{
	static boolean_t local_dump_in_progress = FALSE, dumped_local = FALSE;
	int ret = -1;
#if KASAN
	kasan_disable();
#endif
	if ((kd_variant == KERN_DUMP_DISK) || (kd_variant == KERN_DUMP_STACKSHOT_DISK)) {
		if (dumped_local) return (0);
		if (local_dump_in_progress) return (-1);
		local_dump_in_progress = TRUE;
#if CONFIG_EMBEDDED
		hwsd_info->xhsdci_status = XHSDCI_STATUS_KERNEL_BUSY;
#endif
		ret = do_kern_dump(&kern_dump_disk_proc, kd_variant);
		if (ret == 0) {
			dumped_local = TRUE;
			kern_dump_successful = TRUE;
			local_dump_in_progress = FALSE;
		}

		return ret;
#if CONFIG_EMBEDDED
	} else if (kd_variant == KERN_DUMP_HW_SHMEM_DBG) {
		ret =  do_kern_dump(&kern_dump_hw_shmem_dbg_buffer_proc, KERN_DUMP_HW_SHMEM_DBG);
		if (ret == 0) {
			kern_dump_successful = TRUE;
		}
		return ret;
#endif
	} else {
		ret = do_kern_dump(&kdp_send_crashdump_data, KERN_DUMP_NET);
		if (ret == 0) {
			kern_dump_successful = TRUE;
		}
		return ret;
	}
}

#if CONFIG_EMBEDDED
void
panic_spin_shmcon()
{
	if (hwsd_info == NULL) {
		kern_coredump_log(NULL, "handshake structure not initialized\n");
		return;
	}

	kern_coredump_log(NULL, "\nPlease go to https://panic.apple.com to report this panic\n");
	kern_coredump_log(NULL, "Waiting for hardware shared memory debugger, handshake structure is at virt: %p, phys %p\n",
			hwsd_info, (void *)kvtophys((vm_offset_t)hwsd_info));

	hwsd_info->xhsdci_status = XHSDCI_STATUS_KERNEL_READY;
	hwsd_info->xhsdci_seq_no = 0;
	FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));

	for (;;) {
		FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		if (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_BEGIN) {
			kern_dump(KERN_DUMP_HW_SHMEM_DBG);
		}

		if ((hwsd_info->xhsdci_status == XHSDCI_COREDUMP_REMOTE_DONE) ||
				(hwsd_info->xhsdci_status == XHSDCI_COREDUMP_ERROR)) {
			hwsd_info->xhsdci_status = XHSDCI_STATUS_KERNEL_READY;
			hwsd_info->xhsdci_seq_no = 0;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		}
	}
}
#endif /* CONFIG_EMBEDDED */

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


#if CONFIG_EMBEDDED
#define LEVEL Z_BEST_SPEED
#define NETBUF 0
#else
#define LEVEL Z_BEST_SPEED
#define NETBUF 1440
#endif

void
kdp_core_init(void)
{
	int wbits = 12;
	int memlevel = 3;
	kern_return_t kr;
#if CONFIG_EMBEDDED
	int i = 0;
	vm_offset_t kdp_core_hw_shmem_buf = 0;
	struct kdp_hw_shmem_dbg_buf_elm *cur_elm = NULL;
	cache_info_t   *cpuid_cache_info = NULL;
#endif
	kern_coredump_callback_config core_config = { };

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

	bzero(&kdp_core_header, sizeof(kdp_core_header));

	core_config.kcc_coredump_init = NULL; /* TODO: consider doing mmu flush from an init function */
	core_config.kcc_coredump_get_summary = kern_dump_save_summary;
	core_config.kcc_coredump_save_segment_descriptions = kern_dump_save_seg_descriptions;
	core_config.kcc_coredump_save_thread_state = kern_dump_save_thread_state;
	core_config.kcc_coredump_save_sw_vers = kern_dump_save_sw_vers;
	core_config.kcc_coredump_save_segment_data = kern_dump_save_segment_data;
	core_config.kcc_coredump_save_misc_data = NULL;

	kr = kern_register_xnu_coredump_helper(&core_config);
	assert(KERN_SUCCESS == kr);

#if CONFIG_EMBEDDED
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

	cpuid_cache_info = cache_info();
	assert(cpuid_cache_info != NULL);

	kdp_core_hw_shmem_buf += sizeof(*hwsd_info);
	/* Leave the handshake structure on its own cache line so buffer writes don't cause flushes of old handshake data */
	kdp_core_hw_shmem_buf = ROUNDUP(kdp_core_hw_shmem_buf, (uint64_t) cpuid_cache_info->c_linesz);
	kdp_hw_shmem_dbg_bufsize -= (uint32_t) (kdp_core_hw_shmem_buf - (vm_offset_t) hwsd_info);
	kdp_hw_shmem_dbg_bufsize /= KDP_CORE_HW_SHMEM_DBG_NUM_BUFFERS;
	/* The buffer size should be a cache-line length multiple */
	kdp_hw_shmem_dbg_bufsize -= (kdp_hw_shmem_dbg_bufsize % ROUNDDOWN(OPTIMAL_ASTRIS_READSIZE, cpuid_cache_info->c_linesz));

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
#endif /* CONFIG_EMBEDDED */
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
