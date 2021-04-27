/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/host.h>

#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/host_info.h>
#include <mach/iocompressionstats_notification_server.h>
#include <mach/mach_host.h>

#include <sys/mount_internal.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>

#include <vfs/vfs_io_compression_stats.h>

#include <vm/lz4.h>
#include <vm/vm_compressor_algorithms.h>
#include <vm/vm_protos.h>


int io_compression_stats_enable = 0;
int io_compression_stats_block_size = IO_COMPRESSION_STATS_DEFAULT_BLOCK_SIZE;

#define LZ4_SCRATCH_ALIGN (64)
typedef struct {
	uint8_t lz4state[lz4_encode_scratch_size]__attribute((aligned(LZ4_SCRATCH_ALIGN)));
} lz4_encode_scratch_t;

lz4_encode_scratch_t **per_cpu_scratch_buf;
uint8_t **per_cpu_compression_buf;
uint32_t io_compression_stats_cpu_count;
char *vnpath_scratch_buf;

LCK_GRP_DECLARE(io_compression_stats_lckgrp, "io_compression_stats");
LCK_RW_DECLARE(io_compression_stats_lock, &io_compression_stats_lckgrp);
LCK_MTX_DECLARE(iocs_store_buffer_lock, &io_compression_stats_lckgrp);

typedef enum io_compression_stats_allocate_type {
	IO_COMPRESSION_STATS_NEW_ALLOC = 0,
	IO_COMPRESSION_STATS_RESIZE = 1
} io_compression_stats_alloc_type_t;

static void io_compression_stats_deallocate_compression_buffers(void);

struct iocs_store_buffer iocs_store_buffer = {
	.buffer = 0,
	.current_position = 0,
	.marked_point = 0
};

int iocs_sb_bytes_since_last_mark = 0;
int iocs_sb_bytes_since_last_notification = 0;

ZONE_DECLARE(io_compression_stats_zone, "io_compression_stats",
    sizeof(struct io_compression_stats), ZC_NOENCRYPT | ZC_NOGC | ZC_ZFREE_CLEARMEM);

static int
io_compression_stats_allocate_compression_buffers(io_compression_stats_alloc_type_t alloc_type, uint32_t block_size)
{
	int err = 0;
	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
#define BSD_HOST 1
	host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

	io_compression_stats_cpu_count = hinfo.max_cpus;
	if (alloc_type == IO_COMPRESSION_STATS_NEW_ALLOC) {
		assert(per_cpu_scratch_buf == NULL);
		per_cpu_scratch_buf = kheap_alloc(KHEAP_DEFAULT, sizeof(lz4_encode_scratch_t *) * io_compression_stats_cpu_count, Z_ZERO);
		if (per_cpu_scratch_buf == NULL) {
			err = ENOMEM;
			goto out;
		}
		assert(per_cpu_compression_buf == NULL);
		per_cpu_compression_buf = kheap_alloc(KHEAP_DEFAULT, sizeof(uint8_t *) * io_compression_stats_cpu_count, Z_ZERO);
		if (per_cpu_compression_buf == NULL) {
			err = ENOMEM;
			goto out;
		}
	}
	for (uint32_t cpu = 0; cpu < io_compression_stats_cpu_count; cpu++) {
		if (alloc_type == IO_COMPRESSION_STATS_NEW_ALLOC) {
			per_cpu_scratch_buf[cpu] = kheap_alloc(KHEAP_DEFAULT, sizeof(lz4_encode_scratch_t), Z_ZERO);
			if (per_cpu_scratch_buf[cpu] == NULL) {
				err = ENOMEM;
				goto out;
			}
		} else {
			kheap_free_addr(KHEAP_DEFAULT, per_cpu_compression_buf[cpu]);
		}
		per_cpu_compression_buf[cpu] = kheap_alloc(KHEAP_DEFAULT, block_size, Z_ZERO);
		if (per_cpu_compression_buf[cpu] == NULL) {
			err = ENOMEM;
			goto out;
		}
	}
	bzero(&iocs_store_buffer, sizeof(struct iocs_store_buffer));
	iocs_store_buffer.buffer = kheap_alloc(KHEAP_DEFAULT, IOCS_STORE_BUFFER_SIZE, Z_ZERO);
	if (iocs_store_buffer.buffer == NULL) {
		err = ENOMEM;
		goto out;
	}
	iocs_store_buffer.current_position = 0;
	iocs_store_buffer.marked_point = 0;

	assert(vnpath_scratch_buf == NULL);
	vnpath_scratch_buf = kheap_alloc(KHEAP_DEFAULT, MAXPATHLEN, Z_ZERO);
	if (vnpath_scratch_buf == NULL) {
		err = ENOMEM;
		goto out;
	}

out:
	if (err) {
		/* In case of any error, irrespective of whether it is new alloc or resize,
		 *  dellocate all buffers and fail */
		io_compression_stats_deallocate_compression_buffers();
	}
	return err;
}

static void
io_compression_stats_deallocate_compression_buffers()
{
	uint32_t cpu;
	if (per_cpu_compression_buf != NULL) {
		for (cpu = 0; cpu < io_compression_stats_cpu_count; cpu++) {
			if (per_cpu_compression_buf[cpu] != NULL) {
				kheap_free_addr(KHEAP_DEFAULT, per_cpu_compression_buf[cpu]);
				per_cpu_compression_buf[cpu] = NULL;
			}
		}
		kheap_free_addr(KHEAP_DEFAULT, per_cpu_compression_buf);
		per_cpu_compression_buf = NULL;
	}

	if (per_cpu_scratch_buf != NULL) {
		for (cpu = 0; cpu < io_compression_stats_cpu_count; cpu++) {
			if (per_cpu_scratch_buf[cpu] != NULL) {
				kheap_free_addr(KHEAP_DEFAULT, per_cpu_scratch_buf[cpu]);
				per_cpu_scratch_buf[cpu] = NULL;
			}
		}
		kheap_free_addr(KHEAP_DEFAULT, per_cpu_scratch_buf);
		per_cpu_scratch_buf = NULL;
	}

	if (iocs_store_buffer.buffer != NULL) {
		kheap_free_addr(KHEAP_DEFAULT, iocs_store_buffer.buffer);
		bzero(&iocs_store_buffer, sizeof(struct iocs_store_buffer));
	}

	iocs_sb_bytes_since_last_mark = 0;
	iocs_sb_bytes_since_last_notification = 0;

	if (vnpath_scratch_buf != NULL) {
		kheap_free_addr(KHEAP_DEFAULT, vnpath_scratch_buf);
		vnpath_scratch_buf = NULL;
	}
}


static int
sysctl_io_compression_stats_enable SYSCTL_HANDLER_ARGS
{
#pragma unused (arg1, arg2, oidp)

	int error = 0;
	int enable = 0;

	error = SYSCTL_OUT(req, &io_compression_stats_enable, sizeof(int));

	if (error || !req->newptr) {
		return error;
	}

	error = SYSCTL_IN(req, &enable, sizeof(int));
	if (error) {
		return error;
	}

	if (!((enable == 1) || (enable == 0))) {
		return EINVAL;
	}

	lck_rw_lock_exclusive(&io_compression_stats_lock);
	lck_mtx_lock(&iocs_store_buffer_lock);
	if ((io_compression_stats_enable == 0) && (enable == 1)) {
		/* Enabling collection of stats. Allocate appropriate buffers */
		error = io_compression_stats_allocate_compression_buffers(IO_COMPRESSION_STATS_NEW_ALLOC, io_compression_stats_block_size);
		if (error == 0) {
			io_compression_stats_enable = enable;
			io_compression_stats_dbg("SUCCESS: setting io_compression_stats_enable to %d", io_compression_stats_enable);
		} else {
			io_compression_stats_dbg("FAILED: setting io_compression_stats_enable to %d", io_compression_stats_enable);
		}
	} else if ((io_compression_stats_enable == 1) && (enable == 0)) {
		io_compression_stats_deallocate_compression_buffers();
		io_compression_stats_enable = 0;
		io_compression_stats_dbg("SUCCESS: setting io_compression_stats_enable to %d", io_compression_stats_enable);
	}
	lck_mtx_unlock(&iocs_store_buffer_lock);
	lck_rw_unlock_exclusive(&io_compression_stats_lock);

	return error;
}
SYSCTL_PROC(_vfs, OID_AUTO, io_compression_stats_enable, CTLTYPE_INT | CTLFLAG_RW, 0, 0, &sysctl_io_compression_stats_enable, "I", "");

static int
sysctl_io_compression_block_size SYSCTL_HANDLER_ARGS
{
#pragma unused (arg1, arg2, oidp)

	int error = 0;
	int block_size = io_compression_stats_block_size;

	error = SYSCTL_OUT(req, &block_size, sizeof(int));

	if (error || !req->newptr) {
		return error;
	}

	error = SYSCTL_IN(req, &block_size, sizeof(int));
	if (error) {
		return error;
	}

	if (block_size < IO_COMPRESSION_STATS_MIN_BLOCK_SIZE || block_size > IO_COMPRESSION_STATS_MAX_BLOCK_SIZE) {
		return EINVAL;
	}

	lck_rw_lock_exclusive(&io_compression_stats_lock);

	if (io_compression_stats_block_size != block_size) {
		if (io_compression_stats_enable == 1) {
			/* IO compression stats is enabled, rellocate buffers. */
			error = io_compression_stats_allocate_compression_buffers(IO_COMPRESSION_STATS_RESIZE, block_size);
			if (error == 0) {
				io_compression_stats_block_size = block_size;
				io_compression_stats_dbg("SUCCESS: setting io_compression_stats_block_size to %d", io_compression_stats_block_size);
			} else {
				/* Failed to allocate buffers, disable IO compression stats */
				io_compression_stats_enable = 0;
				io_compression_stats_dbg("Failed: setting io_compression_stats_block_size to %d", io_compression_stats_block_size);
			}
		} else {
			/* IO compression stats is disabled, only set the io_compression_stats_block_size */
			io_compression_stats_block_size = block_size;
			io_compression_stats_dbg("SUCCESS: setting io_compression_stats_block_size to %d", io_compression_stats_block_size);
		}
	}
	lck_rw_unlock_exclusive(&io_compression_stats_lock);


	return error;
}
SYSCTL_PROC(_vfs, OID_AUTO, io_compression_stats_block_size, CTLTYPE_INT | CTLFLAG_RW, 0, 0, &sysctl_io_compression_block_size, "I", "");


static int32_t
iocs_compress_block(uint8_t *block_ptr, uint32_t block_size)
{
	disable_preemption();

	uint32_t current_cpu = cpu_number();
	if (!(current_cpu < io_compression_stats_cpu_count)) {
		enable_preemption();
		return -1;
	}

	lz4_encode_scratch_t *scratch_buf = per_cpu_scratch_buf[current_cpu];
	uint8_t *dest_buf = per_cpu_compression_buf[current_cpu];

	int compressed_block_size = (int) lz4raw_encode_buffer(dest_buf, block_size,
	    block_ptr, block_size, (lz4_hash_entry_t *) scratch_buf);

	enable_preemption();

	return compressed_block_size;
}
/*
 * Compress buf in chunks of io_compression_stats_block_size
 */
static uint32_t
iocs_compress_buffer(vnode_t vn, uint8_t *buf_ptr, uint32_t buf_size)
{
	uint32_t offset;
	uint32_t compressed_size = 0;
	int block_size = io_compression_stats_block_size;
	int block_stats_scaling_factor = block_size / IOCS_BLOCK_NUM_SIZE_BUCKETS;

	for (offset = 0; offset < buf_size; offset += block_size) {
		int current_block_size = min(block_size, buf_size - offset);
		int current_compressed_block_size = iocs_compress_block(buf_ptr + offset, current_block_size);

		if (current_compressed_block_size == 0) {
			compressed_size += current_block_size;
			vnode_updateiocompressionblockstats(vn, current_block_size / block_stats_scaling_factor);
		} else if (current_compressed_block_size != -1) {
			compressed_size += current_compressed_block_size;
			vnode_updateiocompressionblockstats(vn, current_compressed_block_size / block_stats_scaling_factor);
		}
	}

	return compressed_size;
}

static uint32_t
log2down(uint32_t x)
{
	return 31 - __builtin_clz(x);
}

/*
 * Once we get the IO compression stats for the entire buffer, we update buffer_size_compressibility_dist,
 * which helps us observe distribution across various io sizes and compression factors.
 * The goal of next two functions is to get the index in this buffer_size_compressibility_dist table.
 */

/*
 * Maps IO size to a bucket between 0 - IO_COMPRESSION_STATS_MAX_SIZE_BUCKET
 * for size < 4096 returns 0 and size > 1MB returns IO_COMPRESSION_STATS_MAX_SIZE_BUCKET (9).
 * For IO sizes in-between we arrive at the index based on log2 function.
 * sizes 4097 - 8192 => index = 1,
 * sizes 8193 - 16384 => index = 2, and so on
 */
#define SIZE_COMPRESSION_DIST_SIZE_BUCKET_MIN   4096
#define SIZE_COMPRESSION_DIST_SIZE_BUCKET_MAX   (1024 * 1024)
static uint32_t
get_buffer_size_bucket(uint32_t size)
{
	if (size <= SIZE_COMPRESSION_DIST_SIZE_BUCKET_MIN) {
		return 0;
	}
	if (size > SIZE_COMPRESSION_DIST_SIZE_BUCKET_MAX) {
		return IOCS_BUFFER_MAX_BUCKET;
	}
#define IOCS_INDEX_MAP_OFFSET 11
	return log2down(size - 1) - IOCS_INDEX_MAP_OFFSET;
}

/*
 * Maps compression factor to a bucket between 0 - IO_COMPRESSION_STATS_MAX_COMPRESSION_BUCKET
 */
static uint32_t
get_buffer_compressibility_bucket(uint32_t uncompressed_size, uint32_t compressed_size)
{
	int saved_space_pc = (uncompressed_size - compressed_size) * 100 / uncompressed_size;

	if (saved_space_pc < 0) {
		saved_space_pc = 0;
	}

	/* saved_space_pc lies bw 0 - 100. log2(saved_space_pc) lies bw 0 - 6 */
	return log2down(saved_space_pc);
}

void
io_compression_stats(buf_t bp)
{
	uint8_t *buf_ptr = NULL;
	int bflags = bp->b_flags;
	uint32_t compressed_size = 0;
	uint32_t buf_cnt = buf_count(bp);
	uint64_t duration = 0;
	caddr_t vaddr = NULL;
	vnode_t vn = buf_vnode(bp);
	int err = 0;

	if ((io_compression_stats_enable != 1) || (bflags & B_READ) || (buf_cnt <= 0)) {
		return;
	}

	if (!lck_rw_try_lock_shared(&io_compression_stats_lock)) {
		/* sysctl modifying IO compression stats parameters is in progress.
		 *  Don't block, since malloc might be in progress. */
		return;
	}
	/* re-check io_compression_stats_enable with lock */
	if (io_compression_stats_enable != 1) {
		goto out;
	}

	err = buf_map(bp, &vaddr);
	if (!err) {
		buf_ptr = (uint8_t *) vaddr;
	}

	if (buf_ptr != NULL) {
		int64_t start = mach_absolute_time();
		compressed_size = iocs_compress_buffer(vn, buf_ptr, buf_cnt);
		absolutetime_to_nanoseconds(mach_absolute_time() - start, &duration);

		if (compressed_size != 0) {
			vnode_updateiocompressionbufferstats(vn, buf_cnt, compressed_size,
			    get_buffer_size_bucket(buf_cnt),
			    get_buffer_compressibility_bucket(buf_cnt, compressed_size));
		}
	}

	KDBG_RELEASE(FSDBG_CODE(DBG_VFS, DBG_VFS_IO_COMPRESSION_STATS) | DBG_FUNC_NONE,
	    duration, io_compression_stats_block_size, compressed_size, buf_cnt, 0);

out:
	lck_rw_unlock_shared(&io_compression_stats_lock);
	if (buf_ptr != NULL) {
		buf_unmap(bp);
	}
}

static void
iocs_notify_user(void)
{
	mach_port_t user_port = MACH_PORT_NULL;
	kern_return_t kr = host_get_iocompressionstats_port(host_priv_self(), &user_port);
	if ((kr != KERN_SUCCESS) || !IPC_PORT_VALID(user_port)) {
		return;
	}
	iocompressionstats_notification(user_port, 0);
	ipc_port_release_send(user_port);
}
static void
construct_iocs_sbe_from_vnode(struct vnode *vp, struct iocs_store_buffer_entry *iocs_sbe)
{
	int path_len = MAXPATHLEN;

	vn_getpath(vp, vnpath_scratch_buf, &path_len);
	/*
	 * Total path length is path_len, we can copy out IOCS_SBE_PATH_LEN bytes. We are interested
	 * in first segment of the path to try and figure out the process writing to the file, and we are
	 * interested in the last segment to figure out extention. So, in cases where
	 * IOCS_SBE_PATH_LEN < path_len, lets copy out first IOCS_PATH_START_BYTES_TO_COPY bytes and
	 * last IOCS_PATH_END_BYTES_TO_COPY (last segment includes the null character).
	 */
	if (path_len > IOCS_SBE_PATH_LEN) {
		strncpy(iocs_sbe->path_name, vnpath_scratch_buf, IOCS_PATH_START_BYTES_TO_COPY);
		strncpy(iocs_sbe->path_name + IOCS_PATH_START_BYTES_TO_COPY,
		    vnpath_scratch_buf + path_len - IOCS_PATH_END_BYTES_TO_COPY,
		    IOCS_PATH_END_BYTES_TO_COPY);
	} else {
		strncpy(iocs_sbe->path_name, vnpath_scratch_buf, IOCS_SBE_PATH_LEN);
	}
	memcpy(&iocs_sbe->iocs, vp->io_compression_stats, sizeof(struct io_compression_stats));
}
void
vnode_iocs_record_and_free(struct vnode *vp)
{
	int notify = 0;
	struct iocs_store_buffer_entry *iocs_sbe = NULL;

	if (!lck_mtx_try_lock(&iocs_store_buffer_lock)) {
		goto out;
	}

	if (iocs_store_buffer.buffer == NULL) {
		goto release;
	}

	assert(iocs_store_buffer.current_position + sizeof(struct iocs_store_buffer_entry) <= IOCS_STORE_BUFFER_SIZE);

	iocs_sbe = (struct iocs_store_buffer_entry *)(iocs_store_buffer.buffer + iocs_store_buffer.current_position);

	construct_iocs_sbe_from_vnode(vp, iocs_sbe);

	iocs_store_buffer.current_position += sizeof(struct iocs_store_buffer_entry);

	if (iocs_store_buffer.current_position + sizeof(struct iocs_store_buffer_entry) > IOCS_STORE_BUFFER_SIZE) {
		/* We've reached end of the buffer, move back to the top */
		iocs_store_buffer.current_position = 0;
	}

	iocs_sb_bytes_since_last_mark += sizeof(struct iocs_store_buffer_entry);
	iocs_sb_bytes_since_last_notification += sizeof(struct iocs_store_buffer_entry);

	if ((iocs_sb_bytes_since_last_mark > IOCS_STORE_BUFFER_NOTIFY_AT) &&
	    (iocs_sb_bytes_since_last_notification > IOCS_STORE_BUFFER_NOTIFICATION_INTERVAL)) {
		notify = 1;
		iocs_sb_bytes_since_last_notification = 0;
	}

release:
	lck_mtx_unlock(&iocs_store_buffer_lock);
out:
	/* We need to free io_compression_stats whether or not we were able to record it */
	bzero(vp->io_compression_stats, sizeof(struct io_compression_stats));
	zfree(io_compression_stats_zone, vp->io_compression_stats);
	vp->io_compression_stats = NULL;
	if (notify) {
		iocs_notify_user();
	}
}

struct vnode_iocs_context {
	struct sysctl_req *addr;
	int current_ptr;
};

static int
vnode_iocs_callback(struct vnode *vp, void *vctx)
{
	struct vnode_iocs_context *ctx = vctx;
	struct sysctl_req *req = ctx->addr;
	int current_ptr = ctx->current_ptr;

	if (current_ptr + sizeof(struct iocs_store_buffer_entry) < req->oldlen) {
		if (vp->io_compression_stats != NULL) {
			construct_iocs_sbe_from_vnode(vp, (struct iocs_store_buffer_entry *) (req->oldptr + current_ptr));
			current_ptr += sizeof(struct iocs_store_buffer_entry);
		}
	} else {
		return VNODE_RETURNED_DONE;
	}
	ctx->current_ptr = current_ptr;

	return VNODE_RETURNED;
}

static int
vfs_iocs_callback(mount_t mp, void *arg)
{
	if (mp->mnt_flag & MNT_LOCAL) {
		vnode_iterate(mp, VNODE_ITERATE_ALL, vnode_iocs_callback, arg);
	}

	return VFS_RETURNED;
}

extern long numvnodes;

static int
sysctl_io_compression_dump_stats SYSCTL_HANDLER_ARGS
{
#pragma unused (arg1, arg2, oidp)

	int32_t error = 0;
	uint32_t inp_flag = 0;
	uint32_t ret_len;

	if (io_compression_stats_enable == 0) {
		error = EINVAL;
		goto out;
	}

	if ((req->newptr != USER_ADDR_NULL) && (req->newlen == sizeof(uint32_t))) {
		error = SYSCTL_IN(req, &inp_flag, sizeof(uint32_t));
		if (error) {
			goto out;
		}
		switch (inp_flag) {
		case IOCS_SYSCTL_LIVE:
		case IOCS_SYSCTL_STORE_BUFFER_RD_ONLY:
		case IOCS_SYSCTL_STORE_BUFFER_MARK:
			break;
		default:
			error = EINVAL;
			goto out;
		}
	} else {
		error = EINVAL;
		goto out;
	}

	if (req->oldptr == USER_ADDR_NULL) {
		/* Query to figure out size of the buffer */
		if (inp_flag & IOCS_SYSCTL_LIVE) {
			req->oldidx = numvnodes * sizeof(struct iocs_store_buffer_entry);
		} else {
			/* Buffer size for archived case, let's keep it
			 * simple and return IOCS store buffer size */
			req->oldidx = IOCS_STORE_BUFFER_SIZE;
		}
		goto out;
	}

	if (inp_flag & IOCS_SYSCTL_LIVE) {
		struct vnode_iocs_context ctx;

		bzero(&ctx, sizeof(struct vnode_iocs_context));
		ctx.addr = req;
		vfs_iterate(0, vfs_iocs_callback, &ctx);
		req->oldidx = ctx.current_ptr;
		goto out;
	}

	/* reading from store buffer */
	lck_mtx_lock(&iocs_store_buffer_lock);

	if (iocs_store_buffer.buffer == NULL) {
		error = EINVAL;
		goto release;
	}
	if (iocs_sb_bytes_since_last_mark == 0) {
		req->oldidx = 0;
		goto release;
	}

	int expected_size = 0;
	/* Dry run to figure out amount of space required to copy out the
	 * iocs_store_buffer.buffer */
	if (iocs_store_buffer.marked_point < iocs_store_buffer.current_position) {
		expected_size = iocs_store_buffer.current_position - iocs_store_buffer.marked_point;
	} else {
		expected_size = IOCS_STORE_BUFFER_SIZE - iocs_store_buffer.marked_point;
		expected_size += iocs_store_buffer.current_position;
	}

	if (req->oldlen < expected_size) {
		error = ENOMEM;
		req->oldidx = 0;
		goto release;
	}

	if (iocs_store_buffer.marked_point < iocs_store_buffer.current_position) {
		error = copyout(iocs_store_buffer.buffer + iocs_store_buffer.marked_point,
		    req->oldptr,
		    iocs_store_buffer.current_position - iocs_store_buffer.marked_point);
		if (error) {
			req->oldidx = 0;
			goto release;
		}
		ret_len = iocs_store_buffer.current_position - iocs_store_buffer.marked_point;
	} else {
		error = copyout(iocs_store_buffer.buffer + iocs_store_buffer.marked_point,
		    req->oldptr,
		    IOCS_STORE_BUFFER_SIZE - iocs_store_buffer.marked_point);
		if (error) {
			req->oldidx = 0;
			goto release;
		}
		ret_len = IOCS_STORE_BUFFER_SIZE - iocs_store_buffer.marked_point;

		error = copyout(iocs_store_buffer.buffer,
		    req->oldptr + ret_len,
		    iocs_store_buffer.current_position);
		if (error) {
			req->oldidx = 0;
			goto release;
		}
		ret_len += iocs_store_buffer.current_position;
	}

	req->oldidx = ret_len;
	if ((ret_len != 0) && (inp_flag & IOCS_SYSCTL_STORE_BUFFER_MARK)) {
		iocs_sb_bytes_since_last_mark = 0;
		iocs_store_buffer.marked_point = iocs_store_buffer.current_position;
	}
release:
	lck_mtx_unlock(&iocs_store_buffer_lock);

out:
	return error;
}
SYSCTL_PROC(_vfs, OID_AUTO, io_compression_dump_stats, CTLFLAG_WR | CTLTYPE_NODE, 0, 0, sysctl_io_compression_dump_stats, "-", "");

errno_t
vnode_updateiocompressionblockstats(vnode_t vp, uint32_t size_bucket)
{
	if (vp == NULL) {
		return EINVAL;
	}

	if (size_bucket >= IOCS_BLOCK_NUM_SIZE_BUCKETS) {
		return EINVAL;
	}

	if (vp->io_compression_stats == NULL) {
		io_compression_stats_t iocs = (io_compression_stats_t)zalloc_flags(io_compression_stats_zone, Z_ZERO);
		if (iocs == NULL) {
			return ENOMEM;
		}
		vnode_lock_spin(vp);
		/* Re-check with lock */
		if (vp->io_compression_stats == NULL) {
			vp->io_compression_stats = iocs;
		} else {
			zfree(io_compression_stats_zone, iocs);
		}
		vnode_unlock(vp);
	}
	OSIncrementAtomic((SInt32 *)&vp->io_compression_stats->block_compressed_size_dist[size_bucket]);

	return 0;
}
errno_t
vnode_updateiocompressionbufferstats(__unused vnode_t vp, __unused uint64_t uncompressed_size, __unused uint64_t compressed_size, __unused uint32_t size_bucket, __unused uint32_t compression_bucket)
{
	if (vp == NULL) {
		return EINVAL;
	}

	/* vnode_updateiocompressionblockstats will always be called before vnode_updateiocompressionbufferstats.
	 * Hence vp->io_compression_stats should already be allocated */
	if (vp->io_compression_stats == NULL) {
		return EINVAL;
	}

	if ((size_bucket >= IOCS_BUFFER_NUM_SIZE_BUCKETS) || (compression_bucket >= IOCS_BUFFER_NUM_COMPRESSION_BUCKETS)) {
		return EINVAL;
	}

	OSAddAtomic64(uncompressed_size, &vp->io_compression_stats->uncompressed_size);
	OSAddAtomic64(compressed_size, &vp->io_compression_stats->compressed_size);

	OSIncrementAtomic((SInt32 *)&vp->io_compression_stats->buffer_size_compression_dist[size_bucket][compression_bucket]);

	return 0;
}
