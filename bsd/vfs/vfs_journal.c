/*
 * Copyright (c) 2002-2014 Apple Inc. All rights reserved.
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
//
// This file implements a simple write-ahead journaling layer.  
// In theory any file system can make use of it by calling these 
// functions when the fs wants to modify meta-data blocks.  See
// vfs_journal.h for a more detailed description of the api and
// data structures.
//
// Dominic Giampaolo (dbg@apple.com)
//

#ifdef KERNEL

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/buf_internal.h>
#include <sys/proc_internal.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/ubc.h>
#include <sys/malloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <sys/disk.h>
#include <sys/kdebug.h>
#include <miscfs/specfs/specdev.h>
#include <libkern/OSAtomic.h>	/* OSAddAtomic */

kern_return_t	thread_terminate(thread_t);

/*
 * Set sysctl vfs.generic.jnl.kdebug.trim=1 to enable KERNEL_DEBUG_CONSTANT
 * logging of trim-related calls within the journal.  (They're
 * disabled by default because there can be a lot of these events,
 * and we don't want to overwhelm the kernel debug buffer.  If you
 * want to watch these events in particular, just set the sysctl.)
 */
static int jnl_kdebug = 0;
SYSCTL_DECL(_vfs_generic);
SYSCTL_NODE(_vfs_generic, OID_AUTO, jnl, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Journal");
SYSCTL_NODE(_vfs_generic_jnl, OID_AUTO, kdebug, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Journal kdebug");
SYSCTL_INT(_vfs_generic_jnl_kdebug, OID_AUTO, trim, CTLFLAG_RW|CTLFLAG_LOCKED, &jnl_kdebug, 0, "Enable kdebug logging for journal TRIM");

#define DBG_JOURNAL_FLUSH			FSDBG_CODE(DBG_JOURNAL, 1)
#define DBG_JOURNAL_TRIM_ADD		FSDBG_CODE(DBG_JOURNAL, 2)
#define DBG_JOURNAL_TRIM_REMOVE		FSDBG_CODE(DBG_JOURNAL, 3)
#define DBG_JOURNAL_TRIM_REMOVE_PENDING	FSDBG_CODE(DBG_JOURNAL, 4)
#define DBG_JOURNAL_TRIM_REALLOC	FSDBG_CODE(DBG_JOURNAL, 5)
#define DBG_JOURNAL_TRIM_FLUSH		FSDBG_CODE(DBG_JOURNAL, 6)
#define DBG_JOURNAL_TRIM_UNMAP		FSDBG_CODE(DBG_JOURNAL, 7)

/* 
 * Cap the journal max size to 2GB.  On HFS, it will attempt to occupy
 * a full allocation block if the current size is smaller than the allocation
 * block on which it resides.  Once we hit the exabyte filesystem range, then
 * it will use 2GB allocation blocks.  As a result, make the cap 2GB.
 */
#define MAX_JOURNAL_SIZE 0x80000000U

#include <sys/sdt.h> /* DTRACE_IO1 */
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include "compat.h"

#endif   /* KERNEL */

#include "vfs_journal.h"

#include <sys/kdebug.h>

#if 0
#undef KERNEL_DEBUG
#define KERNEL_DEBUG KERNEL_DEBUG_CONSTANT
#endif


#ifndef CONFIG_HFS_TRIM
#define CONFIG_HFS_TRIM 0
#endif


#if JOURNALING

//
// By default, we grow the list of extents to trim by 4K at a time.
// We'll opt to flush a transaction if it contains at least
// JOURNAL_FLUSH_TRIM_EXTENTS extents to be trimmed (even if the number
// of modified blocks is small).
//
enum {
    JOURNAL_DEFAULT_TRIM_BYTES = 4096,
    JOURNAL_DEFAULT_TRIM_EXTENTS = JOURNAL_DEFAULT_TRIM_BYTES / sizeof(dk_extent_t),
    JOURNAL_FLUSH_TRIM_EXTENTS = JOURNAL_DEFAULT_TRIM_EXTENTS * 15 / 16
};

unsigned int jnl_trim_flush_limit = JOURNAL_FLUSH_TRIM_EXTENTS;
SYSCTL_UINT (_kern, OID_AUTO, jnl_trim_flush, CTLFLAG_RW, &jnl_trim_flush_limit, 0, "number of trimmed extents to cause a journal flush");

/* XXX next prototype should be from libsa/stdlib.h> but conflicts libkern */
__private_extern__ void qsort(
	void * array,
	size_t nmembers,
	size_t member_size,
	int (*)(const void *, const void *));



// number of bytes to checksum in a block_list_header
// NOTE: this should be enough to clear out the header
//       fields as well as the first entry of binfo[]
#define BLHDR_CHECKSUM_SIZE 32

static void lock_condition(journal *jnl, boolean_t *condition, const char *condition_name);
static void wait_condition(journal *jnl, boolean_t *condition, const char *condition_name);
static void unlock_condition(journal *jnl, boolean_t *condition);
static void finish_end_thread(transaction *tr);
static void write_header_thread(journal *jnl);
static int finish_end_transaction(transaction *tr, errno_t (*callback)(void*), void *callback_arg);
static int end_transaction(transaction *tr, int force_it, errno_t (*callback)(void*), void *callback_arg, boolean_t drop_lock, boolean_t must_wait);
static void abort_transaction(journal *jnl, transaction *tr);
static void dump_journal(journal *jnl);

static __inline__ void  lock_oldstart(journal *jnl);
static __inline__ void  unlock_oldstart(journal *jnl);
static __inline__ void  lock_flush(journal *jnl);
static __inline__ void  unlock_flush(journal *jnl);


//
// 3105942 - Coalesce writes to the same block on journal replay
//

typedef struct bucket {
	off_t     block_num;
	uint32_t  jnl_offset;
	uint32_t  block_size;
	int32_t   cksum;
} bucket;

#define STARTING_BUCKETS 256

static int add_block(journal *jnl, struct bucket **buf_ptr, off_t block_num, size_t size, size_t offset, int32_t cksum, int *num_buckets_ptr, int *num_full_ptr);
static int grow_table(struct bucket **buf_ptr, int num_buckets, int new_size);
static int lookup_bucket(struct bucket **buf_ptr, off_t block_num, int num_full);
static int do_overlap(journal *jnl, struct bucket **buf_ptr, int blk_index, off_t block_num, size_t size, size_t offset, int32_t cksum, int *num_buckets_ptr, int *num_full_ptr);
static int insert_block(journal *jnl, struct bucket **buf_ptr, int blk_index, off_t num, size_t size, size_t offset, int32_t cksum, int *num_buckets_ptr, int *num_full_ptr, int overwriting);

#define CHECK_JOURNAL(jnl) \
	do {		   \
	if (jnl == NULL) {					\
		panic("%s:%d: null journal ptr?\n", __FILE__, __LINE__); \
	}								\
	if (jnl->jdev == NULL) {				\
		panic("%s:%d: jdev is null!\n", __FILE__, __LINE__); \
	}							\
	if (jnl->fsdev == NULL) {				\
		panic("%s:%d: fsdev is null!\n", __FILE__, __LINE__);	\
	}								\
	if (jnl->jhdr->magic != JOURNAL_HEADER_MAGIC) {			\
		panic("%s:%d: jhdr magic corrupted (0x%x != 0x%x)\n",	\
		      __FILE__, __LINE__, jnl->jhdr->magic, JOURNAL_HEADER_MAGIC); \
	}								\
	if (   jnl->jhdr->start <= 0					\
	       || jnl->jhdr->start > jnl->jhdr->size) {			\
		panic("%s:%d: jhdr start looks bad (0x%llx max size 0x%llx)\n", \
		      __FILE__, __LINE__, jnl->jhdr->start, jnl->jhdr->size); \
	}								\
	if (   jnl->jhdr->end <= 0					\
	       || jnl->jhdr->end > jnl->jhdr->size) {			\
		panic("%s:%d: jhdr end looks bad (0x%llx max size 0x%llx)\n", \
		      __FILE__, __LINE__, jnl->jhdr->end, jnl->jhdr->size); \
	}								\
	} while(0)

#define CHECK_TRANSACTION(tr) \
	do {		      \
	if (tr == NULL) {					\
		panic("%s:%d: null transaction ptr?\n", __FILE__, __LINE__); \
	}								\
	if (tr->jnl == NULL) {						\
		panic("%s:%d: null tr->jnl ptr?\n", __FILE__, __LINE__); \
	}								\
	if (tr->blhdr != (block_list_header *)tr->tbuffer) {		\
		panic("%s:%d: blhdr (%p) != tbuffer (%p)\n", __FILE__, __LINE__, tr->blhdr, tr->tbuffer); \
	}								\
	if (tr->total_bytes < 0) {					\
		panic("%s:%d: tr total_bytes looks bad: %d\n", __FILE__, __LINE__, tr->total_bytes); \
	}								\
	if (tr->journal_start < 0) {					\
		panic("%s:%d: tr journal start looks bad: 0x%llx\n", __FILE__, __LINE__, tr->journal_start); \
	}								\
	if (tr->journal_end < 0) {					\
		panic("%s:%d: tr journal end looks bad: 0x%llx\n", __FILE__, __LINE__, tr->journal_end); \
	}								\
	if (tr->blhdr && (tr->blhdr->max_blocks <= 0 || tr->blhdr->max_blocks > (tr->jnl->jhdr->size/tr->jnl->jhdr->jhdr_size))) { \
		panic("%s:%d: tr blhdr max_blocks looks bad: %d\n", __FILE__, __LINE__, tr->blhdr->max_blocks);	\
	}								\
	} while(0)



//
// this isn't a great checksum routine but it will do for now.
// we use it to checksum the journal header and the block list
// headers that are at the start of each transaction.
//
static unsigned int
calc_checksum(char *ptr, int len)
{
	int i;
	unsigned int cksum=0;

	// this is a lame checksum but for now it'll do
	for(i = 0; i < len; i++, ptr++) {
		cksum = (cksum << 8) ^ (cksum + *(unsigned char *)ptr);
	}

	return (~cksum);
}

//
// Journal Locking
//
lck_grp_attr_t *  jnl_group_attr;
lck_attr_t *      jnl_lock_attr;
lck_grp_t *       jnl_mutex_group;

void
journal_init(void)
{
	jnl_lock_attr    = lck_attr_alloc_init();
	jnl_group_attr   = lck_grp_attr_alloc_init();
	jnl_mutex_group  = lck_grp_alloc_init("jnl-mutex", jnl_group_attr);
}

__inline__ void
journal_lock(journal *jnl)
{
	lck_mtx_lock(&jnl->jlock);
	if (jnl->owner) {
		panic ("jnl: owner is %p, expected NULL\n", jnl->owner);
	}
	jnl->owner = current_thread();
}

__inline__ void
journal_unlock(journal *jnl)
{
	jnl->owner = NULL;
	lck_mtx_unlock(&jnl->jlock);
}

static __inline__ void
lock_flush(journal *jnl)
{
	lck_mtx_lock(&jnl->flock);
}

static __inline__ void
unlock_flush(journal *jnl)
{
	lck_mtx_unlock(&jnl->flock);
}

static __inline__ void
lock_oldstart(journal *jnl)
{
	lck_mtx_lock(&jnl->old_start_lock);
}

static __inline__ void
unlock_oldstart(journal *jnl)
{
	lck_mtx_unlock(&jnl->old_start_lock);
}



#define JNL_WRITE    0x0001
#define JNL_READ     0x0002
#define JNL_HEADER   0x8000

//
// This function sets up a fake buf and passes it directly to the
// journal device strategy routine (so that it won't get cached in
// the block cache.
//
// It also handles range checking the i/o so that we don't write
// outside the journal boundaries and it will wrap the i/o back
// to the beginning if necessary (skipping over the journal header)
// 
static size_t
do_journal_io(journal *jnl, off_t *offset, void *data, size_t len, int direction)
{
	int	err, curlen=len;
	size_t	io_sz = 0;
	buf_t	bp;
	off_t 	max_iosize;
	struct bufattr *bap;

	if (*offset < 0 || *offset > jnl->jhdr->size) {
		panic("jnl: do_jnl_io: bad offset 0x%llx (max 0x%llx)\n", *offset, jnl->jhdr->size);
	}
	
	if (direction & JNL_WRITE)
		max_iosize = jnl->max_write_size;
	else if (direction & JNL_READ)
		max_iosize = jnl->max_read_size;
	else
		max_iosize = 128 * 1024;

again:
	bp = alloc_io_buf(jnl->jdev, 1);

	if (*offset + (off_t)curlen > jnl->jhdr->size && *offset != 0 && jnl->jhdr->size != 0) {
		if (*offset == jnl->jhdr->size) {
			*offset = jnl->jhdr->jhdr_size;
		} else {
			curlen = (off_t)jnl->jhdr->size - *offset;
		}
	}

	if (curlen > max_iosize) {
		curlen = max_iosize;
	}

	if (curlen <= 0) {
		panic("jnl: do_jnl_io: curlen == %d, offset 0x%llx len %zd\n", curlen, *offset, len);
	}

	if (*offset == 0 && (direction & JNL_HEADER) == 0) {
		panic("jnl: request for i/o to jnl-header without JNL_HEADER flag set! (len %d, data %p)\n", curlen, data);
	}

	/*
	 * As alluded to in the block comment at the top of the function, we use a "fake" iobuf
	 * here and issue directly to the disk device that the journal protects since we don't
	 * want this to enter the block cache.  As a result, we lose the ability to mark it
	 * as a metadata buf_t for the layers below us that may care. If we were to
	 * simply attach the B_META flag into the b_flags this may confuse things further
	 * since this is an iobuf, not a metadata buffer. 
	 *
	 * To address this, we use the extended bufattr struct embedded in the bp. 
	 * Explicitly mark the buf here as a metadata buffer in its bufattr flags.
	 */
	bap = &bp->b_attr;
	bap->ba_flags |= BA_META;
	
	if (direction & JNL_READ)
		buf_setflags(bp, B_READ);
	else {
		/*
		 * don't have to set any flags
		 */
		vnode_startwrite(jnl->jdev);
	}
	buf_setsize(bp, curlen);
	buf_setcount(bp, curlen);
	buf_setdataptr(bp, (uintptr_t)data);
	buf_setblkno(bp, (daddr64_t) ((jnl->jdev_offset + *offset) / (off_t)jnl->jhdr->jhdr_size));
	buf_setlblkno(bp, (daddr64_t) ((jnl->jdev_offset + *offset) / (off_t)jnl->jhdr->jhdr_size));

	if ((direction & JNL_WRITE) && (jnl->flags & JOURNAL_DO_FUA_WRITES)) {
		buf_markfua(bp);
	}

	DTRACE_IO1(journal__start, buf_t, bp);
	err = VNOP_STRATEGY(bp);
	if (!err) {
		err = (int)buf_biowait(bp);
	}
	DTRACE_IO1(journal__done, buf_t, bp);
	free_io_buf(bp);

	if (err) {
		printf("jnl: %s: do_jnl_io: strategy err 0x%x\n", jnl->jdev_name, err);
		return 0;
	}

	*offset += curlen;
	io_sz   += curlen;

	if (io_sz != len) {
		// handle wrap-around
		data    = (char *)data + curlen;
		curlen  = len - io_sz;
		if (*offset >= jnl->jhdr->size) {
			*offset = jnl->jhdr->jhdr_size;
		}
		goto again;
	}

	return io_sz;
}

static size_t
read_journal_data(journal *jnl, off_t *offset, void *data, size_t len)
{
	return do_journal_io(jnl, offset, data, len, JNL_READ);
}

static size_t
write_journal_data(journal *jnl, off_t *offset, void *data, size_t len)
{
	return do_journal_io(jnl, offset, data, len, JNL_WRITE);
}


static size_t
read_journal_header(journal *jnl, void *data, size_t len)
{
	off_t hdr_offset = 0;
	
	return do_journal_io(jnl, &hdr_offset, data, len, JNL_READ|JNL_HEADER);
}

static int
write_journal_header(journal *jnl, int updating_start, uint32_t sequence_num)
{
	static int num_err_prints = 0;
	int ret=0;
	off_t jhdr_offset = 0;
	struct vfs_context context;

	context.vc_thread = current_thread();
	context.vc_ucred = NOCRED;
	// 
	// Flush the track cache if we're not doing force-unit-access
	// writes.
	//
	if (!updating_start && (jnl->flags & JOURNAL_DO_FUA_WRITES) == 0) {
		ret = VNOP_IOCTL(jnl->jdev, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, &context);
	}
	if (ret != 0) {
		//
		// Only print this error if it's a different error than the
		// previous one, or if it's the first time for this device
		// or if the total number of printfs is less than 25.  We
		// allow for up to 25 printfs to insure that some make it
		// into the on-disk syslog.  Otherwise if we only printed
		// one, it's possible it would never make it to the syslog
		// for the root volume and that makes debugging hard.
		//
		if (   ret != jnl->last_flush_err
		       || (jnl->flags & JOURNAL_FLUSHCACHE_ERR) == 0
		       || num_err_prints++ < 25) {
	    
			printf("jnl: %s: flushing fs disk buffer returned 0x%x\n", jnl->jdev_name, ret);
	    
			jnl->flags |= JOURNAL_FLUSHCACHE_ERR;
			jnl->last_flush_err = ret;
		}
	}

	jnl->jhdr->sequence_num = sequence_num;
	jnl->jhdr->checksum = 0;
	jnl->jhdr->checksum = calc_checksum((char *)jnl->jhdr, JOURNAL_HEADER_CKSUM_SIZE);

	if (do_journal_io(jnl, &jhdr_offset, jnl->header_buf, jnl->jhdr->jhdr_size, JNL_WRITE|JNL_HEADER) != (size_t)jnl->jhdr->jhdr_size) {
		printf("jnl: %s: write_journal_header: error writing the journal header!\n", jnl->jdev_name);
		jnl->flags |= JOURNAL_INVALID;
		return -1;
	}	

	// If we're not doing force-unit-access writes, then we
	// have to flush after writing the journal header so that
	// a future transaction doesn't sneak out to disk before
	// the header does and thus overwrite data that the old
	// journal header refers to.  Saw this exact case happen
	// on an IDE bus analyzer with Larry Barras so while it
	// may seem obscure, it's not.
	//
	if (updating_start && (jnl->flags & JOURNAL_DO_FUA_WRITES) == 0) {
		VNOP_IOCTL(jnl->jdev, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, &context);
	}

	return 0;
}



//
// this is a work function used to free up transactions that
// completed. they can't be free'd from buffer_flushed_callback
// because it is called from deep with the disk driver stack
// and thus can't do something that would potentially cause
// paging.  it gets called by each of the journal api entry
// points so stuff shouldn't hang around for too long.
//
static void
free_old_stuff(journal *jnl)
{
	transaction *tr, *next;
	block_list_header  *blhdr=NULL, *next_blhdr=NULL;

	if (jnl->tr_freeme == NULL)
		return;

	lock_oldstart(jnl);
	tr = jnl->tr_freeme;
	jnl->tr_freeme = NULL;
	unlock_oldstart(jnl);

	for(; tr; tr=next) {
		for (blhdr = tr->blhdr; blhdr; blhdr = next_blhdr) {
			next_blhdr = (block_list_header *)((long)blhdr->binfo[0].bnum);
			blhdr->binfo[0].bnum = 0xdeadc0de;
		    
			kmem_free(kernel_map, (vm_offset_t)blhdr, tr->tbuffer_size);

			KERNEL_DEBUG(0xbbbbc01c, jnl, tr, tr->tbuffer_size, 0, 0);
		}
		next = tr->next;
		FREE_ZONE(tr, sizeof(transaction), M_JNL_TR);
	}
}



//
// This is our callback that lets us know when a buffer has been
// flushed to disk.  It's called from deep within the driver stack
// and thus is quite limited in what it can do.  Notably, it can
// not initiate any new i/o's or allocate/free memory.
//
static void
buffer_flushed_callback(struct buf *bp, void *arg)
{
	transaction  *tr;
	journal      *jnl;
	transaction  *ctr, *prev=NULL, *next;
	size_t        i;
	int           bufsize, amt_flushed, total_bytes;


	//printf("jnl: buf flush: bp @ 0x%x l/blkno %qd/%qd vp 0x%x tr @ 0x%x\n",
	//	   bp, buf_lblkno(bp), buf_blkno(bp), buf_vnode(bp), arg);

	// snarf out the bits we want
	bufsize = buf_size(bp);
	tr      = (transaction *)arg;

	// then we've already seen it
	if (tr == NULL) {
		return;
	}

	CHECK_TRANSACTION(tr);

	jnl = tr->jnl;

	CHECK_JOURNAL(jnl);

	amt_flushed = tr->num_killed;
	total_bytes = tr->total_bytes;
    
	// update the number of blocks that have been flushed.
	// this buf may represent more than one block so take
	// that into account.
	//
	// OSAddAtomic() returns the value of tr->num_flushed before the add
	//
	amt_flushed += OSAddAtomic(bufsize, &tr->num_flushed);


	// if this transaction isn't done yet, just return as
	// there is nothing to do.
	//
	// NOTE: we are careful to not reference anything through
	//       the tr pointer after doing the OSAddAtomic().  if
	//       this if statement fails then we are the last one
	//       and then it's ok to dereference "tr".
	//
	if ((amt_flushed + bufsize) < total_bytes) {
		return;
	}

	// this will single thread checking the transaction
	lock_oldstart(jnl);

	if (tr->total_bytes == (int)0xfbadc0de) {
		// then someone beat us to it...
		unlock_oldstart(jnl);
		return;
	}

	// mark this so that we're the owner of dealing with the
	// cleanup for this transaction
	tr->total_bytes = 0xfbadc0de;

	if (jnl->flags & JOURNAL_INVALID)
		goto transaction_done;

	//printf("jnl: tr 0x%x (0x%llx 0x%llx) in jnl 0x%x completed.\n",
	//   tr, tr->journal_start, tr->journal_end, jnl);

	// find this entry in the old_start[] index and mark it completed
	for(i = 0; i < sizeof(jnl->old_start)/sizeof(jnl->old_start[0]); i++) {
	
		if ((off_t)(jnl->old_start[i] & ~(0x8000000000000000ULL)) == tr->journal_start) {
			jnl->old_start[i] &= ~(0x8000000000000000ULL);
			break;
		}
	}

	if (i >= sizeof(jnl->old_start)/sizeof(jnl->old_start[0])) {
		panic("jnl: buffer_flushed: did not find tr w/start @ %lld (tr %p, jnl %p)\n",
		      tr->journal_start, tr, jnl);
	}


	// if we are here then we need to update the journal header
	// to reflect that this transaction is complete
	if (tr->journal_start == jnl->active_start) {
		jnl->active_start = tr->journal_end;
		tr->journal_start = tr->journal_end = (off_t)0;
	}

	// go through the completed_trs list and try to coalesce
	// entries, restarting back at the beginning if we have to.
	for (ctr = jnl->completed_trs; ctr; prev=ctr, ctr=next) {
		if (ctr->journal_start == jnl->active_start) {
			jnl->active_start = ctr->journal_end;
			if (prev) {
				prev->next = ctr->next;
			}
			if (ctr == jnl->completed_trs) {
				jnl->completed_trs = ctr->next;
			}
	    
			next           = jnl->completed_trs;   // this starts us over again
			ctr->next      = jnl->tr_freeme;
			jnl->tr_freeme = ctr;
			ctr            = NULL;
		} else if (tr->journal_end == ctr->journal_start) {
			ctr->journal_start = tr->journal_start;
			next               = jnl->completed_trs;  // this starts us over again
			ctr                = NULL;
			tr->journal_start  = tr->journal_end = (off_t)0;
		} else if (tr->journal_start == ctr->journal_end) {
			ctr->journal_end  = tr->journal_end;
			next              = ctr->next;
			tr->journal_start = tr->journal_end = (off_t)0;
		} else if (ctr->next && ctr->journal_end == ctr->next->journal_start) {
			// coalesce the next entry with this one and link the next
			// entry in at the head of the tr_freeme list
			next              = ctr->next;           // temporarily use the "next" variable
			ctr->journal_end  = next->journal_end;
			ctr->next         = next->next;
			next->next        = jnl->tr_freeme;      // link in the next guy at the head of the tr_freeme list
			jnl->tr_freeme    = next;

			next              = jnl->completed_trs;  // this starts us over again
			ctr               = NULL;
		} else {
			next = ctr->next;
		}
	}
    
	// if this is true then we didn't merge with anyone
	// so link ourselves in at the head of the completed
	// transaction list.
	if (tr->journal_start != 0) {
		// put this entry into the correct sorted place
		// in the list instead of just at the head.
		//
	
		prev = NULL;
		for (ctr = jnl->completed_trs; ctr && tr->journal_start > ctr->journal_start; prev=ctr, ctr=ctr->next) {
			// just keep looping
		}

		if (ctr == NULL && prev == NULL) {
			jnl->completed_trs = tr;
			tr->next = NULL;
		} else if (ctr == jnl->completed_trs) {
			tr->next = jnl->completed_trs;
			jnl->completed_trs = tr;
		} else {
			tr->next = prev->next;
			prev->next = tr;
		}
	} else {
		// if we're here this tr got merged with someone else so
		// put it on the list to be free'd
		tr->next       = jnl->tr_freeme;
		jnl->tr_freeme = tr;
	}
transaction_done:
	unlock_oldstart(jnl);

	unlock_condition(jnl, &jnl->asyncIO);
}


#include <libkern/OSByteOrder.h>

#define SWAP16(x) OSSwapInt16(x)
#define SWAP32(x) OSSwapInt32(x)
#define SWAP64(x) OSSwapInt64(x)


static void
swap_journal_header(journal *jnl)
{
	jnl->jhdr->magic      = SWAP32(jnl->jhdr->magic);
	jnl->jhdr->endian     = SWAP32(jnl->jhdr->endian);
	jnl->jhdr->start      = SWAP64(jnl->jhdr->start);
	jnl->jhdr->end        = SWAP64(jnl->jhdr->end);
	jnl->jhdr->size       = SWAP64(jnl->jhdr->size);
	jnl->jhdr->blhdr_size = SWAP32(jnl->jhdr->blhdr_size);
	jnl->jhdr->checksum   = SWAP32(jnl->jhdr->checksum);
	jnl->jhdr->jhdr_size  = SWAP32(jnl->jhdr->jhdr_size);
	jnl->jhdr->sequence_num  = SWAP32(jnl->jhdr->sequence_num);
}

static void
swap_block_list_header(journal *jnl, block_list_header *blhdr)
{
	int i;
    
	blhdr->max_blocks = SWAP16(blhdr->max_blocks);
	blhdr->num_blocks = SWAP16(blhdr->num_blocks);
	blhdr->bytes_used = SWAP32(blhdr->bytes_used);
	blhdr->checksum   = SWAP32(blhdr->checksum);
	blhdr->flags      = SWAP32(blhdr->flags);

	if (blhdr->num_blocks >= ((jnl->jhdr->blhdr_size / sizeof(block_info)) - 1)) {
		printf("jnl: %s: blhdr num blocks looks suspicious (%d / blhdr size %d).  not swapping.\n", jnl->jdev_name, blhdr->num_blocks, jnl->jhdr->blhdr_size);
		return;
	}

	for(i = 0; i < blhdr->num_blocks; i++) {
		blhdr->binfo[i].bnum    = SWAP64(blhdr->binfo[i].bnum);
		blhdr->binfo[i].u.bi.bsize   = SWAP32(blhdr->binfo[i].u.bi.bsize);
		blhdr->binfo[i].u.bi.b.cksum = SWAP32(blhdr->binfo[i].u.bi.b.cksum);
	}
}


static int
update_fs_block(journal *jnl, void *block_ptr, off_t fs_block, size_t bsize)
{
	int		ret;
	struct buf *oblock_bp=NULL;
    
	// first read the block we want.
	ret = buf_meta_bread(jnl->fsdev, (daddr64_t)fs_block, bsize, NOCRED, &oblock_bp);
	if (ret != 0) {
		printf("jnl: %s: update_fs_block: error reading fs block # %lld! (ret %d)\n", jnl->jdev_name, fs_block, ret);

		if (oblock_bp) {
			buf_brelse(oblock_bp);
			oblock_bp = NULL;
		}

		// let's try to be aggressive here and just re-write the block
		oblock_bp = buf_getblk(jnl->fsdev, (daddr64_t)fs_block, bsize, 0, 0, BLK_META);
		if (oblock_bp == NULL) {
			printf("jnl: %s: update_fs_block: buf_getblk() for %lld failed! failing update.\n", jnl->jdev_name, fs_block);
			return -1;
		}
	}
	    
	// make sure it's the correct size.
	if (buf_size(oblock_bp) != bsize) {
		buf_brelse(oblock_bp);
		return -1;
	}

	// copy the journal data over top of it
	memcpy((char *)buf_dataptr(oblock_bp), block_ptr, bsize);

	if ((ret = VNOP_BWRITE(oblock_bp)) != 0) {
		printf("jnl: %s: update_fs_block: failed to update block %lld (ret %d)\n", jnl->jdev_name, fs_block,ret);
		return ret;
	}

	// and now invalidate it so that if someone else wants to read
	// it in a different size they'll be able to do it.
	ret = buf_meta_bread(jnl->fsdev, (daddr64_t)fs_block, bsize, NOCRED, &oblock_bp);
	if (oblock_bp) {
                buf_markinvalid(oblock_bp);
		buf_brelse(oblock_bp);
	}
	    
	return 0;
}

static int
grow_table(struct bucket **buf_ptr, int num_buckets, int new_size)
{
	struct bucket *newBuf;
	int current_size = num_buckets, i;
    
	// return if newsize is less than the current size
	if (new_size < num_buckets) {
		return current_size;
	}
    
	if ((MALLOC(newBuf, struct bucket *, new_size*sizeof(struct bucket), M_TEMP, M_WAITOK)) == NULL) {
		printf("jnl: grow_table: no memory to expand coalesce buffer!\n");
		return -1;
	}
    
	//  printf("jnl: lookup_bucket: expanded co_buf to %d elems\n", new_size);
    
	// copy existing elements 
	bcopy(*buf_ptr, newBuf, num_buckets*sizeof(struct bucket));
    
	// initialize the new ones
	for(i = num_buckets; i < new_size; i++) {
		newBuf[i].block_num = (off_t)-1;
	}
    
	// free the old container
	FREE(*buf_ptr, M_TEMP);
    
	// reset the buf_ptr
	*buf_ptr = newBuf;
    
	return new_size;
}

static int
lookup_bucket(struct bucket **buf_ptr, off_t block_num, int num_full)
{
	int lo, hi, index, matches, i;
    
	if (num_full == 0) {
		return 0; // table is empty, so insert at index=0
	}
    
	lo = 0;
	hi = num_full - 1;
	index = -1;
    
	// perform binary search for block_num
	do {
		int mid = (hi - lo)/2 + lo;
		off_t this_num = (*buf_ptr)[mid].block_num;
	
		if (block_num == this_num) {
			index = mid;
			break;
		}
	
		if (block_num < this_num) {
			hi = mid;
			continue;
		}
	
		if (block_num > this_num) {
			lo = mid + 1;
			continue;
		}
	} while (lo < hi);
    
	// check if lo and hi converged on the match
	if (block_num == (*buf_ptr)[hi].block_num) {
		index = hi;
	}
    
	// if no existing entry found, find index for new one
	if (index == -1) {
		index = (block_num < (*buf_ptr)[hi].block_num) ? hi : hi + 1;
	} else {
		// make sure that we return the right-most index in the case of multiple matches
		matches = 0;
		i = index + 1;
		while (i < num_full && block_num == (*buf_ptr)[i].block_num) {
			matches++;
			i++;
		}

		index += matches;
	}
    
	return index;
}

static int
insert_block(journal *jnl, struct bucket **buf_ptr, int blk_index, off_t num, size_t size, size_t offset, int32_t cksum, int *num_buckets_ptr, int *num_full_ptr, int overwriting)
{
	if (!overwriting) {
		// grow the table if we're out of space
		if (*num_full_ptr >= *num_buckets_ptr) {
			int new_size = *num_buckets_ptr * 2;
			int grow_size = grow_table(buf_ptr, *num_buckets_ptr, new_size);
	    
			if (grow_size < new_size) {
				printf("jnl: %s: add_block: grow_table returned an error!\n", jnl->jdev_name);
				return -1;
			}
	    
			*num_buckets_ptr = grow_size; //update num_buckets to reflect the new size
		}
	
		// if we're not inserting at the end, we need to bcopy
		if (blk_index != *num_full_ptr) {
			bcopy( (*buf_ptr)+(blk_index), (*buf_ptr)+(blk_index+1), (*num_full_ptr-blk_index)*sizeof(struct bucket) );
		}
	
		(*num_full_ptr)++; // increment only if we're not overwriting
	}

	// sanity check the values we're about to add
	if ((off_t)offset >= jnl->jhdr->size) {
		offset = jnl->jhdr->jhdr_size + (offset - jnl->jhdr->size);
	}
	if (size <= 0) {
		panic("jnl: insert_block: bad size in insert_block (%zd)\n", size);
	}	 

	(*buf_ptr)[blk_index].block_num = num;
	(*buf_ptr)[blk_index].block_size = size;
	(*buf_ptr)[blk_index].jnl_offset = offset;
	(*buf_ptr)[blk_index].cksum = cksum;
    
	return blk_index;
}

static int
do_overlap(journal *jnl, struct bucket **buf_ptr, int blk_index, off_t block_num, size_t size, __unused size_t offset, int32_t cksum, int *num_buckets_ptr, int *num_full_ptr)
{
	int	num_to_remove, index, i, overwrite, err;
	size_t	jhdr_size = jnl->jhdr->jhdr_size, new_offset;
	off_t	overlap, block_start, block_end;

	block_start = block_num*jhdr_size;
	block_end = block_start + size;
	overwrite = (block_num == (*buf_ptr)[blk_index].block_num && size >= (*buf_ptr)[blk_index].block_size);

	// first, eliminate any overlap with the previous entry
	if (blk_index != 0 && !overwrite) {
		off_t prev_block_start = (*buf_ptr)[blk_index-1].block_num*jhdr_size;
		off_t prev_block_end = prev_block_start + (*buf_ptr)[blk_index-1].block_size;
		overlap = prev_block_end - block_start;
		if (overlap > 0) {
			if (overlap % jhdr_size != 0) {
				panic("jnl: do_overlap: overlap with previous entry not a multiple of %zd\n", jhdr_size);
			}

			// if the previous entry completely overlaps this one, we need to break it into two pieces.
			if (prev_block_end > block_end) {
				off_t new_num = block_end / jhdr_size;
				size_t new_size = prev_block_end - block_end;

				new_offset = (*buf_ptr)[blk_index-1].jnl_offset + (block_end - prev_block_start);
		
				err = insert_block(jnl, buf_ptr, blk_index, new_num, new_size, new_offset, cksum, num_buckets_ptr, num_full_ptr, 0);
				if (err < 0) {
					panic("jnl: do_overlap: error inserting during pre-overlap\n");
				}
			}
	    
			// Regardless, we need to truncate the previous entry to the beginning of the overlap
			(*buf_ptr)[blk_index-1].block_size = block_start - prev_block_start;
			(*buf_ptr)[blk_index-1].cksum = 0;   // have to blow it away because there's no way to check it
		}
	}

	// then, bail out fast if there's no overlap with the entries that follow
	if (!overwrite && block_end <= (off_t)((*buf_ptr)[blk_index].block_num*jhdr_size)) {
		return 0; // no overlap, no overwrite
	} else if (overwrite && (blk_index + 1 >= *num_full_ptr || block_end <= (off_t)((*buf_ptr)[blk_index+1].block_num*jhdr_size))) {

		(*buf_ptr)[blk_index].cksum = cksum;   // update this
		return 1; // simple overwrite
	}
    
	// Otherwise, find all cases of total and partial overlap. We use the special
	// block_num of -2 to designate entries that are completely overlapped and must
	// be eliminated. The block_num, size, and jnl_offset of partially overlapped
	// entries must be adjusted to keep the array consistent.
	index = blk_index;
	num_to_remove = 0;
	while (index < *num_full_ptr && block_end > (off_t)((*buf_ptr)[index].block_num*jhdr_size)) {
		if (block_end >= (off_t)(((*buf_ptr)[index].block_num*jhdr_size + (*buf_ptr)[index].block_size))) {
			(*buf_ptr)[index].block_num = -2; // mark this for deletion
			num_to_remove++;
		} else {
			overlap = block_end - (*buf_ptr)[index].block_num*jhdr_size;
			if (overlap > 0) {
				if (overlap % jhdr_size != 0) {
					panic("jnl: do_overlap: overlap of %lld is not multiple of %zd\n", overlap, jhdr_size);
				}
				
				// if we partially overlap this entry, adjust its block number, jnl offset, and size
				(*buf_ptr)[index].block_num += (overlap / jhdr_size); // make sure overlap is multiple of jhdr_size, or round up
				(*buf_ptr)[index].cksum = 0;
		
				new_offset = (*buf_ptr)[index].jnl_offset + overlap; // check for wrap-around
				if ((off_t)new_offset >= jnl->jhdr->size) {
					new_offset = jhdr_size + (new_offset - jnl->jhdr->size);
				}
				(*buf_ptr)[index].jnl_offset = new_offset;
		
				(*buf_ptr)[index].block_size -= overlap; // sanity check for negative value
				if ((*buf_ptr)[index].block_size <= 0) {
					panic("jnl: do_overlap: after overlap, new block size is invalid (%u)\n", (*buf_ptr)[index].block_size);
					// return -1; // if above panic is removed, return -1 for error
				}
			}
			
		}

		index++;
	}

	// bcopy over any completely overlapped entries, starting at the right (where the above loop broke out)
	index--; // start with the last index used within the above loop
	while (index >= blk_index) {
		if ((*buf_ptr)[index].block_num == -2) {
			if (index == *num_full_ptr-1) {
				(*buf_ptr)[index].block_num = -1; // it's the last item in the table... just mark as free
			} else {
				bcopy( (*buf_ptr)+(index+1), (*buf_ptr)+(index), (*num_full_ptr - (index + 1)) * sizeof(struct bucket) );
			}
			(*num_full_ptr)--;
		}
		index--;
	}

	// eliminate any stale entries at the end of the table
	for(i = *num_full_ptr; i < (*num_full_ptr + num_to_remove); i++) {
		(*buf_ptr)[i].block_num = -1;
	}
    
	return 0; // if we got this far, we need to insert the entry into the table (rather than overwrite) 
}

// PR-3105942: Coalesce writes to the same block in journal replay
// We coalesce writes by maintaining a dynamic sorted array of physical disk blocks
// to be replayed and the corresponding location in the journal which contains
// the most recent data for those blocks. The array is "played" once the all the
// blocks in the journal have been coalesced. The code for the case of conflicting/
// overlapping writes to a single block is the most dense. Because coalescing can
// disrupt the existing time-ordering of blocks in the journal playback, care
// is taken to catch any overlaps and keep the array consistent. 
static int
add_block(journal *jnl, struct bucket **buf_ptr, off_t block_num, size_t size, __unused size_t offset, int32_t cksum, int *num_buckets_ptr, int *num_full_ptr)
{
	int	blk_index, overwriting;
    
	// on return from lookup_bucket(), blk_index is the index into the table where block_num should be
	// inserted (or the index of the elem to overwrite). 
	blk_index = lookup_bucket( buf_ptr, block_num, *num_full_ptr);
    
	// check if the index is within bounds (if we're adding this block to the end of
	// the table, blk_index will be equal to num_full)
	if (blk_index < 0 || blk_index > *num_full_ptr) {
		//printf("jnl: add_block: trouble adding block to co_buf\n");
		return -1;
	} // else printf("jnl: add_block: adding block 0x%llx at i=%d\n", block_num, blk_index);
    
	// Determine whether we're overwriting an existing entry by checking for overlap
	overwriting = do_overlap(jnl, buf_ptr, blk_index, block_num, size, offset, cksum, num_buckets_ptr, num_full_ptr);
	if (overwriting < 0) {
		return -1; // if we got an error, pass it along
	}
        
	// returns the index, or -1 on error
	blk_index = insert_block(jnl, buf_ptr, blk_index, block_num, size, offset, cksum, num_buckets_ptr, num_full_ptr, overwriting);
    
	return blk_index;
}

static int
replay_journal(journal *jnl)
{
	int		i, bad_blocks=0;
	unsigned int	orig_checksum, checksum, check_block_checksums = 0;
	size_t		ret;
	size_t		max_bsize = 0;		/* protected by block_ptr */
	block_list_header *blhdr;
	off_t		offset, txn_start_offset=0, blhdr_offset, orig_jnl_start;
	char		*buff, *block_ptr=NULL;
	struct bucket	*co_buf;
	int		num_buckets = STARTING_BUCKETS, num_full, check_past_jnl_end = 1, in_uncharted_territory=0;
	uint32_t	last_sequence_num = 0;
	int 		replay_retry_count = 0;
    
	// wrap the start ptr if it points to the very end of the journal
	if (jnl->jhdr->start == jnl->jhdr->size) {
		jnl->jhdr->start = jnl->jhdr->jhdr_size;
	}
	if (jnl->jhdr->end == jnl->jhdr->size) {
		jnl->jhdr->end = jnl->jhdr->jhdr_size;
	}

	if (jnl->jhdr->start == jnl->jhdr->end) {
		return 0;
	}

	orig_jnl_start = jnl->jhdr->start;

	// allocate memory for the header_block.  we'll read each blhdr into this
	if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&buff, jnl->jhdr->blhdr_size)) {
		printf("jnl: %s: replay_journal: no memory for block buffer! (%d bytes)\n",
		       jnl->jdev_name, jnl->jhdr->blhdr_size);
		return -1;
	}

	// allocate memory for the coalesce buffer
	if ((MALLOC(co_buf, struct bucket *, num_buckets*sizeof(struct bucket), M_TEMP, M_WAITOK)) == NULL) {
		printf("jnl: %s: replay_journal: no memory for coalesce buffer!\n", jnl->jdev_name);
		return -1;
	}

restart_replay:

	// initialize entries
	for(i = 0; i < num_buckets; i++) {
		co_buf[i].block_num = -1;
	}
	num_full = 0; // empty at first


	printf("jnl: %s: replay_journal: from: %lld to: %lld (joffset 0x%llx)\n",
	       jnl->jdev_name, jnl->jhdr->start, jnl->jhdr->end, jnl->jdev_offset);

	while (check_past_jnl_end || jnl->jhdr->start != jnl->jhdr->end) {
		offset = blhdr_offset = jnl->jhdr->start;
		ret = read_journal_data(jnl, &offset, buff, jnl->jhdr->blhdr_size);
		if (ret != (size_t)jnl->jhdr->blhdr_size) {
			printf("jnl: %s: replay_journal: Could not read block list header block @ 0x%llx!\n", jnl->jdev_name, offset);
			bad_blocks = 1;
			goto bad_txn_handling;
		}

		blhdr = (block_list_header *)buff;
		
		orig_checksum = blhdr->checksum;
		blhdr->checksum = 0;
		if (jnl->flags & JOURNAL_NEED_SWAP) {
			// calculate the checksum based on the unswapped data
			// because it is done byte-at-a-time.
			orig_checksum = (unsigned int)SWAP32(orig_checksum);
			checksum = calc_checksum((char *)blhdr, BLHDR_CHECKSUM_SIZE);
			swap_block_list_header(jnl, blhdr);
		} else {
			checksum = calc_checksum((char *)blhdr, BLHDR_CHECKSUM_SIZE);
		}


		//
		// XXXdbg - if these checks fail, we should replay as much
		//          we can in the hopes that it will still leave the
		//          drive in a better state than if we didn't replay
		//          anything
		//
		if (checksum != orig_checksum) {
			if (check_past_jnl_end && in_uncharted_territory) {

				if (blhdr_offset != jnl->jhdr->end) {
					printf("jnl: %s: Extra txn replay stopped @ %lld / 0x%llx\n", jnl->jdev_name, blhdr_offset, blhdr_offset);
				}

				check_past_jnl_end = 0;
				jnl->jhdr->end = blhdr_offset;
				continue;
			}

			printf("jnl: %s: replay_journal: bad block list header @ 0x%llx (checksum 0x%x != 0x%x)\n",
			jnl->jdev_name, blhdr_offset, orig_checksum, checksum);

			if (blhdr_offset == orig_jnl_start) {
				// if there's nothing in the journal at all, just bail out altogether.
				goto bad_replay;
			}

			bad_blocks = 1;
			goto bad_txn_handling;
		}

		if (   (last_sequence_num != 0)
		       && (blhdr->binfo[0].u.bi.b.sequence_num != 0)
		       && (blhdr->binfo[0].u.bi.b.sequence_num != last_sequence_num)
		       && (blhdr->binfo[0].u.bi.b.sequence_num != last_sequence_num+1)) {

			txn_start_offset = jnl->jhdr->end = blhdr_offset;

			if (check_past_jnl_end) {
				check_past_jnl_end = 0;
				printf("jnl: %s: 2: extra replay stopped @ %lld / 0x%llx (seq %d < %d)\n",
				       jnl->jdev_name, blhdr_offset, blhdr_offset, blhdr->binfo[0].u.bi.b.sequence_num, last_sequence_num);
				continue;
			}

			printf("jnl: %s: txn sequence numbers out of order in txn @ %lld / %llx! (%d < %d)\n",
			       jnl->jdev_name, blhdr_offset, blhdr_offset, blhdr->binfo[0].u.bi.b.sequence_num, last_sequence_num);
			bad_blocks = 1;
			goto bad_txn_handling;
		}
		last_sequence_num = blhdr->binfo[0].u.bi.b.sequence_num;

		if (blhdr_offset >= jnl->jhdr->end && jnl->jhdr->start <= jnl->jhdr->end) {
			if (last_sequence_num == 0) {
				check_past_jnl_end = 0;
				printf("jnl: %s: pre-sequence-num-enabled txn's - can not go further than end (%lld %lld).\n",
				       jnl->jdev_name, jnl->jhdr->start, jnl->jhdr->end);
				if (jnl->jhdr->start != jnl->jhdr->end) {
					jnl->jhdr->start = jnl->jhdr->end;
				}
				continue;
			}
			printf("jnl: %s: examining extra transactions starting @ %lld / 0x%llx\n", jnl->jdev_name, blhdr_offset, blhdr_offset);
		}

		if (   blhdr->max_blocks <= 0 || blhdr->max_blocks > (jnl->jhdr->size/jnl->jhdr->jhdr_size)
		       || blhdr->num_blocks <= 0 || blhdr->num_blocks > blhdr->max_blocks) {
			printf("jnl: %s: replay_journal: bad looking journal entry: max: %d num: %d\n",
			       jnl->jdev_name, blhdr->max_blocks, blhdr->num_blocks);
			bad_blocks = 1;
			goto bad_txn_handling;
		}
	
		max_bsize = 0;
		for (i = 1; i < blhdr->num_blocks; i++) {
			if (blhdr->binfo[i].bnum < 0 && blhdr->binfo[i].bnum != (off_t)-1) {
				printf("jnl: %s: replay_journal: bogus block number 0x%llx\n", jnl->jdev_name, blhdr->binfo[i].bnum);
				bad_blocks = 1;
				goto bad_txn_handling;
			}
			
			if ((size_t)blhdr->binfo[i].u.bi.bsize > max_bsize) {
				max_bsize = blhdr->binfo[i].u.bi.bsize;
			}
		}

		if (blhdr->flags & BLHDR_CHECK_CHECKSUMS) {
			check_block_checksums = 1;
			if (kmem_alloc(kernel_map, (vm_offset_t *)&block_ptr, max_bsize)) {
				goto bad_replay;
			}
		} else {
			block_ptr = NULL;
		}

		if (blhdr->flags & BLHDR_FIRST_HEADER) {
			txn_start_offset = blhdr_offset;
		}

		//printf("jnl: replay_journal: adding %d blocks in journal entry @ 0x%llx to co_buf\n", 
		//       blhdr->num_blocks-1, jnl->jhdr->start);
		bad_blocks = 0;
		for (i = 1; i < blhdr->num_blocks; i++) {
			int size, ret_val;
			off_t number;

			size = blhdr->binfo[i].u.bi.bsize;
			number = blhdr->binfo[i].bnum;
			
			// don't add "killed" blocks
			if (number == (off_t)-1) {
				//printf("jnl: replay_journal: skipping killed fs block (index %d)\n", i);
			} else {

				if (check_block_checksums) {
					int32_t disk_cksum;
					off_t block_offset;

					block_offset = offset;

					// read the block so we can check the checksum
					ret = read_journal_data(jnl, &block_offset, block_ptr, size);
					if (ret != (size_t)size) {
						printf("jnl: %s: replay_journal: Could not read journal entry data @ offset 0x%llx!\n", jnl->jdev_name, offset);
						bad_blocks = 1;
						goto bad_txn_handling;
					}
				
					disk_cksum = calc_checksum(block_ptr, size);

					// there is no need to swap the checksum from disk because
					// it got swapped when the blhdr was read in.
					if (blhdr->binfo[i].u.bi.b.cksum != 0 && disk_cksum != blhdr->binfo[i].u.bi.b.cksum) {
						printf("jnl: %s: txn starting at %lld (%lld) @ index %3d bnum %lld (%d) with disk cksum != blhdr cksum (0x%.8x 0x%.8x)\n",
						       jnl->jdev_name, txn_start_offset, blhdr_offset, i, number, size, disk_cksum, blhdr->binfo[i].u.bi.b.cksum);
						printf("jnl: 0x%.8x 0x%.8x 0x%.8x 0x%.8x  0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
						       *(int *)&block_ptr[0*sizeof(int)], *(int *)&block_ptr[1*sizeof(int)], *(int *)&block_ptr[2*sizeof(int)], *(int *)&block_ptr[3*sizeof(int)],
						       *(int *)&block_ptr[4*sizeof(int)], *(int *)&block_ptr[5*sizeof(int)], *(int *)&block_ptr[6*sizeof(int)], *(int *)&block_ptr[7*sizeof(int)]);

						bad_blocks = 1;
						goto bad_txn_handling;
					}
				}


				// add this bucket to co_buf, coalescing where possible
				// printf("jnl: replay_journal: adding block 0x%llx\n", number);
				ret_val = add_block(jnl, &co_buf, number, size, (size_t) offset, blhdr->binfo[i].u.bi.b.cksum, &num_buckets, &num_full);
			    
				if (ret_val == -1) {
					printf("jnl: %s: replay_journal: trouble adding block to co_buf\n", jnl->jdev_name);
					goto bad_replay;
				} // else printf("jnl: replay_journal: added block 0x%llx at i=%d\n", number);
			}
			
			// increment offset
			offset += size;
			
			// check if the last block added puts us off the end of the jnl.
			// if so, we need to wrap to the beginning and take any remainder
			// into account
			//
			if (offset >= jnl->jhdr->size) {
				offset = jnl->jhdr->jhdr_size + (offset - jnl->jhdr->size);
			}
		}

		if (block_ptr) {
			kmem_free(kernel_map, (vm_offset_t)block_ptr, max_bsize);
			block_ptr = NULL;
		}
		
bad_txn_handling:
		if (bad_blocks) {
			/* Journal replay got error before it found any valid 
			 *  transations, abort replay */
			if (txn_start_offset == 0) {
				printf("jnl: %s: no known good txn start offset! aborting journal replay.\n", jnl->jdev_name);
				goto bad_replay;
			}

			/* Repeated error during journal replay, abort replay */
			if (replay_retry_count == 3) {
				printf("jnl: %s: repeated errors replaying journal! aborting journal replay.\n", jnl->jdev_name);
				goto bad_replay;
			}
			replay_retry_count++;

			/* There was an error replaying the journal (possibly 
			 * EIO/ENXIO from the device).  So retry replaying all 
			 * the good transactions that we found before getting 
			 * the error.  
			 */
			jnl->jhdr->start = orig_jnl_start;
			jnl->jhdr->end = txn_start_offset;
			check_past_jnl_end = 0;
			last_sequence_num = 0;
			printf("jnl: %s: restarting journal replay (%lld - %lld)!\n", jnl->jdev_name, jnl->jhdr->start, jnl->jhdr->end);
			goto restart_replay;
		}

		jnl->jhdr->start += blhdr->bytes_used;
		if (jnl->jhdr->start >= jnl->jhdr->size) {
			// wrap around and skip the journal header block
			jnl->jhdr->start = (jnl->jhdr->start % jnl->jhdr->size) + jnl->jhdr->jhdr_size;
		}

		if (jnl->jhdr->start == jnl->jhdr->end) {
			in_uncharted_territory = 1;
		}
	}

	if (jnl->jhdr->start != jnl->jhdr->end) {
		printf("jnl: %s: start %lld != end %lld.  resetting end.\n", jnl->jdev_name, jnl->jhdr->start, jnl->jhdr->end);
		jnl->jhdr->end = jnl->jhdr->start;
	}

	//printf("jnl: replay_journal: replaying %d blocks\n", num_full);
    
	/*
	 * make sure it's at least one page in size, so
	 * start max_bsize at PAGE_SIZE
	 */
	for (i = 0, max_bsize = PAGE_SIZE; i < num_full; i++) {

		if (co_buf[i].block_num == (off_t)-1)
			continue;

		if (co_buf[i].block_size > max_bsize)
			max_bsize = co_buf[i].block_size;
	}
	/*
	 * round max_bsize up to the nearest PAGE_SIZE multiple
	 */
	if (max_bsize & (PAGE_SIZE - 1)) {
		max_bsize = (max_bsize + PAGE_SIZE) & ~(PAGE_SIZE - 1);
	}

	if (kmem_alloc(kernel_map, (vm_offset_t *)&block_ptr, max_bsize)) {
		goto bad_replay;
	}
    
	// Replay the coalesced entries in the co-buf
	for(i = 0; i < num_full; i++) {
		size_t size = co_buf[i].block_size;
		off_t jnl_offset = (off_t) co_buf[i].jnl_offset;
		off_t number = co_buf[i].block_num;
	
	
		// printf("replaying co_buf[%d]: block 0x%llx, size 0x%x, jnl_offset 0x%llx\n", i, co_buf[i].block_num,
		//      co_buf[i].block_size, co_buf[i].jnl_offset);
	
		if (number == (off_t)-1) {
			// printf("jnl: replay_journal: skipping killed fs block\n");
		} else {
	    
			// do journal read, and set the phys. block 
			ret = read_journal_data(jnl, &jnl_offset, block_ptr, size);
			if (ret != size) {
				printf("jnl: %s: replay_journal: Could not read journal entry data @ offset 0x%llx!\n", jnl->jdev_name, offset);
				goto bad_replay;
			}
	    	    
			if (update_fs_block(jnl, block_ptr, number, size) != 0) {
				goto bad_replay;
			}
		}
	}
    
	
	// done replaying; update jnl header
	if (write_journal_header(jnl, 1, jnl->jhdr->sequence_num) != 0) {
		goto bad_replay;
	}

	printf("jnl: %s: journal replay done.\n", jnl->jdev_name);
    
	// free block_ptr
	if (block_ptr) {
		kmem_free(kernel_map, (vm_offset_t)block_ptr, max_bsize);
		block_ptr = NULL;
	}
    
	// free the coalesce buffer
	FREE(co_buf, M_TEMP);
	co_buf = NULL;
  
	kmem_free(kernel_map, (vm_offset_t)buff, jnl->jhdr->blhdr_size);
	return 0;

bad_replay:
	if (block_ptr) {
		kmem_free(kernel_map, (vm_offset_t)block_ptr, max_bsize);
	}
	if (co_buf) {
		FREE(co_buf, M_TEMP);
	}
	kmem_free(kernel_map, (vm_offset_t)buff, jnl->jhdr->blhdr_size);

	return -1;
}


#define DEFAULT_TRANSACTION_BUFFER_SIZE  (128*1024)
#define MAX_TRANSACTION_BUFFER_SIZE      (3072*1024)

// XXXdbg - so I can change it in the debugger
int def_tbuffer_size = 0;


//
// This function sets the size of the tbuffer and the
// size of the blhdr.  It assumes that jnl->jhdr->size
// and jnl->jhdr->jhdr_size are already valid.
//
static void
size_up_tbuffer(journal *jnl, int tbuffer_size, int phys_blksz)
{
	//
	// one-time initialization based on how much memory 
	// there is in the machine.
	//
	if (def_tbuffer_size == 0) {
		if (max_mem < (256*1024*1024)) {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE;
		} else if (max_mem < (512*1024*1024)) {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE * 2;
		} else if (max_mem < (1024*1024*1024)) {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE * 3;
		} else {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE * (max_mem / (256*1024*1024));
		}
	}

	// size up the transaction buffer... can't be larger than the number
	// of blocks that can fit in a block_list_header block.
	if (tbuffer_size == 0) {
		jnl->tbuffer_size = def_tbuffer_size;
	} else {
		// make sure that the specified tbuffer_size isn't too small
		if (tbuffer_size < jnl->jhdr->blhdr_size * 2) {
			tbuffer_size = jnl->jhdr->blhdr_size * 2;
		}
		// and make sure it's an even multiple of the block size
		if ((tbuffer_size % jnl->jhdr->jhdr_size) != 0) {
			tbuffer_size -= (tbuffer_size % jnl->jhdr->jhdr_size);
		}

		jnl->tbuffer_size = tbuffer_size;
	}

	if (jnl->tbuffer_size > (jnl->jhdr->size / 2)) {
		jnl->tbuffer_size = (jnl->jhdr->size / 2);
	}
    
	if (jnl->tbuffer_size > MAX_TRANSACTION_BUFFER_SIZE) {
		jnl->tbuffer_size = MAX_TRANSACTION_BUFFER_SIZE;
	}

	jnl->jhdr->blhdr_size = (jnl->tbuffer_size / jnl->jhdr->jhdr_size) * sizeof(block_info);
	if (jnl->jhdr->blhdr_size < phys_blksz) {
		jnl->jhdr->blhdr_size = phys_blksz;
	} else if ((jnl->jhdr->blhdr_size % phys_blksz) != 0) {
		// have to round up so we're an even multiple of the physical block size
		jnl->jhdr->blhdr_size = (jnl->jhdr->blhdr_size + (phys_blksz - 1)) & ~(phys_blksz - 1);
	}
}

static void
get_io_info(struct vnode *devvp, size_t phys_blksz, journal *jnl, struct vfs_context *context)
{
	off_t	readblockcnt;
	off_t	writeblockcnt;
	off_t	readmaxcnt=0, tmp_readmaxcnt;
	off_t	writemaxcnt=0, tmp_writemaxcnt;
	off_t	readsegcnt, writesegcnt;
	int32_t	features;

	if (VNOP_IOCTL(devvp, DKIOCGETFEATURES, (caddr_t)&features, 0, context) == 0) {
		if (features & DK_FEATURE_FORCE_UNIT_ACCESS) {
			const char *name = vnode_getname_printable(devvp);
			jnl->flags |= JOURNAL_DO_FUA_WRITES;
			printf("jnl: %s: enabling FUA writes (features 0x%x)\n", name, features);
			vnode_putname_printable(name);
		}
		if (features & DK_FEATURE_UNMAP) {
			jnl->flags |= JOURNAL_USE_UNMAP;
		}
	}

	//
	// First check the max read size via several different mechanisms...
	//
	VNOP_IOCTL(devvp, DKIOCGETMAXBYTECOUNTREAD, (caddr_t)&readmaxcnt, 0, context);

	if (VNOP_IOCTL(devvp, DKIOCGETMAXBLOCKCOUNTREAD, (caddr_t)&readblockcnt, 0, context) == 0) {
		tmp_readmaxcnt = readblockcnt * phys_blksz;
		if (readmaxcnt == 0 || (readblockcnt > 0 && tmp_readmaxcnt < readmaxcnt)) {
			readmaxcnt = tmp_readmaxcnt;
		}
	}

	if (VNOP_IOCTL(devvp, DKIOCGETMAXSEGMENTCOUNTREAD, (caddr_t)&readsegcnt, 0, context)) {
		readsegcnt = 0;
	}

	if (readsegcnt > 0 && (readsegcnt * PAGE_SIZE) < readmaxcnt) {
		readmaxcnt = readsegcnt * PAGE_SIZE;
	}
	    
	if (readmaxcnt == 0) {
		readmaxcnt = 128 * 1024;
	} else if (readmaxcnt > UINT32_MAX) {
		readmaxcnt = UINT32_MAX;
	}


	//
	// Now check the max writes size via several different mechanisms...
	//
	VNOP_IOCTL(devvp, DKIOCGETMAXBYTECOUNTWRITE, (caddr_t)&writemaxcnt, 0, context);

	if (VNOP_IOCTL(devvp, DKIOCGETMAXBLOCKCOUNTWRITE, (caddr_t)&writeblockcnt, 0, context) == 0) {
		tmp_writemaxcnt = writeblockcnt * phys_blksz;
		if (writemaxcnt == 0 || (writeblockcnt > 0 && tmp_writemaxcnt < writemaxcnt)) {
			writemaxcnt = tmp_writemaxcnt;
		}
	}

	if (VNOP_IOCTL(devvp, DKIOCGETMAXSEGMENTCOUNTWRITE,	(caddr_t)&writesegcnt, 0, context)) {
		writesegcnt = 0;
	}

	if (writesegcnt > 0 && (writesegcnt * PAGE_SIZE) < writemaxcnt) {
		writemaxcnt = writesegcnt * PAGE_SIZE;
	}

	if (writemaxcnt == 0) {
		writemaxcnt = 128 * 1024;
	} else if (writemaxcnt > UINT32_MAX) {
		writemaxcnt = UINT32_MAX;
	}

	jnl->max_read_size  = readmaxcnt;
	jnl->max_write_size = writemaxcnt;
	// printf("jnl: %s: max read/write: %lld k / %lld k\n",
	//     jnl->jdev_name ? jnl->jdev_name : "unknown",
	//     jnl->max_read_size/1024, jnl->max_write_size/1024);
}


journal *
journal_create(struct vnode *jvp,
			   off_t         offset,
			   off_t         journal_size,
			   struct vnode *fsvp,
			   size_t        min_fs_blksz,
			   int32_t       flags,
			   int32_t       tbuffer_size,
			   void        (*flush)(void *arg),
			   void         *arg,
			   struct mount *fsmount)
{
	journal		*jnl;
	uint32_t	phys_blksz, new_txn_base;
	u_int32_t	min_size;
	struct vfs_context context;
	const char	*jdev_name;
	/* 
	 * Cap the journal max size to 2GB.  On HFS, it will attempt to occupy
	 * a full allocation block if the current size is smaller than the allocation
	 * block on which it resides.  Once we hit the exabyte filesystem range, then
	 * it will use 2GB allocation blocks.  As a result, make the cap 2GB.
	 */
	context.vc_thread = current_thread();
	context.vc_ucred = FSCRED;

	jdev_name = vnode_getname_printable(jvp);

	/* Get the real physical block size. */
	if (VNOP_IOCTL(jvp, DKIOCGETBLOCKSIZE, (caddr_t)&phys_blksz, 0, &context)) {
		goto cleanup_jdev_name;
	}

	if (journal_size < (256*1024) || journal_size > (MAX_JOURNAL_SIZE)) {
		printf("jnl: %s: create: journal size %lld looks bogus.\n", jdev_name, journal_size);
		goto cleanup_jdev_name;
	}

	min_size = phys_blksz * (phys_blksz / sizeof(block_info));
	/* Reject journals that are too small given the sector size of the device */
	if (journal_size < min_size) {
		printf("jnl: %s: create: journal size (%lld) too small given sector size of (%u)\n", 
				jdev_name, journal_size, phys_blksz);
		goto cleanup_jdev_name;
	}

	if (phys_blksz > min_fs_blksz) {
		printf("jnl: %s: create: error: phys blksize %u bigger than min fs blksize %zd\n",
		       jdev_name, phys_blksz, min_fs_blksz);
		goto cleanup_jdev_name;
	}

	if ((journal_size % phys_blksz) != 0) {
		printf("jnl: %s: create: journal size 0x%llx is not an even multiple of block size 0x%ux\n",
		       jdev_name, journal_size, phys_blksz);
		goto cleanup_jdev_name;
	}


	MALLOC_ZONE(jnl, struct journal *, sizeof(struct journal), M_JNL_JNL, M_WAITOK);
	memset(jnl, 0, sizeof(*jnl));

	jnl->jdev         = jvp;
	jnl->jdev_offset  = offset;
	jnl->fsdev        = fsvp;
	jnl->flush        = flush;
	jnl->flush_arg    = arg;
	jnl->flags        = (flags & JOURNAL_OPTION_FLAGS_MASK);
	jnl->jdev_name    = jdev_name;
	lck_mtx_init(&jnl->old_start_lock, jnl_mutex_group, jnl_lock_attr);

	// Keep a point to the mount around for use in IO throttling.
	jnl->fsmount      = fsmount;
	// XXX: This lock discipline looks correct based on dounmount(), but it
	// doesn't seem to be documented anywhere.
	mount_ref(fsmount, 0);

	get_io_info(jvp, phys_blksz, jnl, &context);
	
	if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&jnl->header_buf, phys_blksz)) {
		printf("jnl: %s: create: could not allocate space for header buffer (%u bytes)\n", jdev_name, phys_blksz);
		goto bad_kmem_alloc;
	}
	jnl->header_buf_size = phys_blksz;

	jnl->jhdr = (journal_header *)jnl->header_buf;
	memset(jnl->jhdr, 0, sizeof(journal_header));

	// we have to set this up here so that do_journal_io() will work
	jnl->jhdr->jhdr_size = phys_blksz;

	//
	// We try and read the journal header to see if there is already one
	// out there.  If there is, it's possible that it has transactions
	// in it that we might replay if we happen to pick a sequence number
	// that is a little less than the old one, there is a crash and the 
	// last txn written ends right at the start of a txn from the previous
	// incarnation of this file system.  If all that happens we would
	// replay the transactions from the old file system and that would
	// destroy your disk.  Although it is extremely unlikely for all those
	// conditions to happen, the probability is non-zero and the result is
	// severe - you lose your file system.  Therefore if we find a valid
	// journal header and the sequence number is non-zero we write junk
	// over the entire journal so that there is no way we will encounter
	// any old transactions.  This is slow but should be a rare event
	// since most tools erase the journal.
	//
	if (   read_journal_header(jnl, jnl->jhdr, phys_blksz) == phys_blksz
	       && jnl->jhdr->magic == JOURNAL_HEADER_MAGIC
	       && jnl->jhdr->sequence_num != 0) {

		new_txn_base = (jnl->jhdr->sequence_num + (journal_size / phys_blksz) + (random() % 16384)) & 0x00ffffff;
		printf("jnl: %s: create: avoiding old sequence number 0x%x (0x%x)\n", jdev_name, jnl->jhdr->sequence_num, new_txn_base);

#if 0
		int i;
		off_t pos=0;

		for(i = 1; i < journal_size / phys_blksz; i++) {
			pos = i*phys_blksz;

			// we don't really care what data we write just so long
			// as it's not a valid transaction header.  since we have
			// the header_buf sitting around we'll use that.
			write_journal_data(jnl, &pos, jnl->header_buf, phys_blksz);
		}
		printf("jnl: create: done clearing journal (i=%d)\n", i);
#endif
	} else {
		new_txn_base = random() & 0x00ffffff;
	}

	memset(jnl->header_buf, 0, phys_blksz);
    
	jnl->jhdr->magic      = JOURNAL_HEADER_MAGIC;
	jnl->jhdr->endian     = ENDIAN_MAGIC;
	jnl->jhdr->start      = phys_blksz;    // start at block #1, block #0 is for the jhdr itself
	jnl->jhdr->end        = phys_blksz;
	jnl->jhdr->size       = journal_size;
	jnl->jhdr->jhdr_size  = phys_blksz;
	size_up_tbuffer(jnl, tbuffer_size, phys_blksz);

	jnl->active_start     = jnl->jhdr->start;

	// XXXdbg  - for testing you can force the journal to wrap around
	// jnl->jhdr->start = jnl->jhdr->size - (phys_blksz*3);
	// jnl->jhdr->end   = jnl->jhdr->size - (phys_blksz*3);
    
	jnl->jhdr->sequence_num = new_txn_base;

	lck_mtx_init(&jnl->jlock, jnl_mutex_group, jnl_lock_attr);
	lck_mtx_init(&jnl->flock, jnl_mutex_group, jnl_lock_attr);
	lck_rw_init(&jnl->trim_lock, jnl_mutex_group, jnl_lock_attr);


	jnl->flushing = FALSE;
	jnl->asyncIO = FALSE;
	jnl->flush_aborted = FALSE;
	jnl->writing_header = FALSE;
	jnl->async_trim = NULL;
	jnl->sequence_num = jnl->jhdr->sequence_num;
	
	if (write_journal_header(jnl, 1, jnl->jhdr->sequence_num) != 0) {
		printf("jnl: %s: journal_create: failed to write journal header.\n", jdev_name);
		goto bad_write;
	}

	goto journal_create_complete;


bad_write:
	kmem_free(kernel_map, (vm_offset_t)jnl->header_buf, phys_blksz);
bad_kmem_alloc:
	jnl->jhdr = NULL;
	FREE_ZONE(jnl, sizeof(struct journal), M_JNL_JNL);
	mount_drop(fsmount, 0);
cleanup_jdev_name:
	vnode_putname_printable(jdev_name);
	jnl = NULL;
journal_create_complete:
	return jnl;
}


journal *
journal_open(struct vnode *jvp,
			 off_t         offset,
			 off_t         journal_size,
			 struct vnode *fsvp,
			 size_t        min_fs_blksz,
			 int32_t       flags,
			 int32_t       tbuffer_size,
			 void        (*flush)(void *arg),
			 void         *arg,
			 struct mount *fsmount)
{
	journal		*jnl;
	uint32_t	orig_blksz=0;
	uint32_t	phys_blksz;
	u_int32_t	min_size = 0;
	int		orig_checksum, checksum;
	struct vfs_context context;
	const char	*jdev_name = vnode_getname_printable(jvp);

	context.vc_thread = current_thread();
	context.vc_ucred = FSCRED;

	/* Get the real physical block size. */
	if (VNOP_IOCTL(jvp, DKIOCGETBLOCKSIZE, (caddr_t)&phys_blksz, 0, &context)) {
		goto cleanup_jdev_name;
	}

	if (phys_blksz > min_fs_blksz) {
		printf("jnl: %s: open: error: phys blksize %u bigger than min fs blksize %zd\n",
		       jdev_name, phys_blksz, min_fs_blksz);
		goto cleanup_jdev_name;
	}

	if (journal_size < (256*1024) || journal_size > (1024*1024*1024)) {
		printf("jnl: %s: open: journal size %lld looks bogus.\n", jdev_name, journal_size);
		goto cleanup_jdev_name;
	}

	min_size = phys_blksz * (phys_blksz / sizeof(block_info));
	/* Reject journals that are too small given the sector size of the device */
	if (journal_size < min_size) {
		printf("jnl: %s: open: journal size (%lld) too small given sector size of (%u)\n", 
				jdev_name, journal_size, phys_blksz);
		goto cleanup_jdev_name;
	}
    
	if ((journal_size % phys_blksz) != 0) {
		printf("jnl: %s: open: journal size 0x%llx is not an even multiple of block size 0x%x\n",
		       jdev_name, journal_size, phys_blksz);
		goto cleanup_jdev_name;
	}

	MALLOC_ZONE(jnl, struct journal *, sizeof(struct journal), M_JNL_JNL, M_WAITOK);
	memset(jnl, 0, sizeof(*jnl));

	jnl->jdev         = jvp;
	jnl->jdev_offset  = offset;
	jnl->fsdev        = fsvp;
	jnl->flush        = flush;
	jnl->flush_arg    = arg;
	jnl->flags        = (flags & JOURNAL_OPTION_FLAGS_MASK);
	jnl->jdev_name    = jdev_name;
	lck_mtx_init(&jnl->old_start_lock, jnl_mutex_group, jnl_lock_attr);

	/* We need a reference to the mount to later pass to the throttling code for
	 * IO accounting.
	 */
	jnl->fsmount      = fsmount;
	mount_ref(fsmount, 0);

	get_io_info(jvp, phys_blksz, jnl, &context);

	if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&jnl->header_buf, phys_blksz)) {
		printf("jnl: %s: create: could not allocate space for header buffer (%u bytes)\n", jdev_name, phys_blksz);
		goto bad_kmem_alloc;
	}
	jnl->header_buf_size = phys_blksz;

	jnl->jhdr = (journal_header *)jnl->header_buf;
	memset(jnl->jhdr, 0, sizeof(journal_header));

	// we have to set this up here so that do_journal_io() will work
	jnl->jhdr->jhdr_size = phys_blksz;

	if (read_journal_header(jnl, jnl->jhdr, phys_blksz) != phys_blksz) {
		printf("jnl: %s: open: could not read %u bytes for the journal header.\n",
		       jdev_name, phys_blksz);
		goto bad_journal;
	}

	orig_checksum = jnl->jhdr->checksum;
	jnl->jhdr->checksum = 0;

	if (jnl->jhdr->magic == SWAP32(JOURNAL_HEADER_MAGIC)) {
		// do this before the swap since it's done byte-at-a-time
		orig_checksum = SWAP32(orig_checksum);
		checksum = calc_checksum((char *)jnl->jhdr, JOURNAL_HEADER_CKSUM_SIZE);
		swap_journal_header(jnl);
		jnl->flags |= JOURNAL_NEED_SWAP;
	} else {
		checksum = calc_checksum((char *)jnl->jhdr, JOURNAL_HEADER_CKSUM_SIZE);
	}

	if (jnl->jhdr->magic != JOURNAL_HEADER_MAGIC && jnl->jhdr->magic != OLD_JOURNAL_HEADER_MAGIC) {
		printf("jnl: %s: open: journal magic is bad (0x%x != 0x%x)\n",
		       jnl->jdev_name, jnl->jhdr->magic, JOURNAL_HEADER_MAGIC);
		goto bad_journal;
	}

	// only check if we're the current journal header magic value
	if (jnl->jhdr->magic == JOURNAL_HEADER_MAGIC) {

		if (orig_checksum != checksum) {
			printf("jnl: %s: open: journal checksum is bad (0x%x != 0x%x)\n",
			       jdev_name, orig_checksum, checksum);
				   
			//goto bad_journal;
		}
	}

	// XXXdbg - convert old style magic numbers to the new one
	if (jnl->jhdr->magic == OLD_JOURNAL_HEADER_MAGIC) {
		jnl->jhdr->magic = JOURNAL_HEADER_MAGIC;
	}

	if (phys_blksz != (size_t)jnl->jhdr->jhdr_size && jnl->jhdr->jhdr_size != 0) {
		/*
		 * The volume has probably been resized (such that we had to adjust the
		 * logical sector size), or copied to media with a different logical
		 * sector size.
		 * 
		 * Temporarily change the device's logical block size to match the
		 * journal's header size.  This will allow us to replay the journal
		 * safely.  If the replay succeeds, we will update the journal's header
		 * size (later in this function).
		 */
		orig_blksz = phys_blksz;
		phys_blksz = jnl->jhdr->jhdr_size;
		VNOP_IOCTL(jvp, DKIOCSETBLOCKSIZE, (caddr_t)&phys_blksz, FWRITE, &context);
		printf("jnl: %s: open: temporarily switched block size from %u to %u\n",
			   jdev_name, orig_blksz, phys_blksz);
	}

	if (   jnl->jhdr->start <= 0
	       || jnl->jhdr->start > jnl->jhdr->size
	       || jnl->jhdr->start > 1024*1024*1024) {
		printf("jnl: %s: open: jhdr start looks bad (0x%llx max size 0x%llx)\n",
		       jdev_name, jnl->jhdr->start, jnl->jhdr->size);
		goto bad_journal;
	}

	if (   jnl->jhdr->end <= 0
	       || jnl->jhdr->end > jnl->jhdr->size
	       || jnl->jhdr->end > 1024*1024*1024) {
		printf("jnl: %s: open: jhdr end looks bad (0x%llx max size 0x%llx)\n",
		       jdev_name, jnl->jhdr->end, jnl->jhdr->size);
		goto bad_journal;
	}

	if (jnl->jhdr->size < (256*1024) || jnl->jhdr->size > 1024*1024*1024) {
		printf("jnl: %s: open: jhdr size looks bad (0x%llx)\n", jdev_name, jnl->jhdr->size);
		goto bad_journal;
	}

// XXXdbg - can't do these checks because hfs writes all kinds of
//          non-uniform sized blocks even on devices that have a block size
//          that is larger than 512 bytes (i.e. optical media w/2k blocks).
//          therefore these checks will fail and so we just have to punt and
//          do more relaxed checking...
// XXXdbg    if ((jnl->jhdr->start % jnl->jhdr->jhdr_size) != 0) {
	if ((jnl->jhdr->start % 512) != 0) {
		printf("jnl: %s: open: journal start (0x%llx) not a multiple of 512?\n",
		       jdev_name, jnl->jhdr->start);
		goto bad_journal;
	}

//XXXdbg    if ((jnl->jhdr->end % jnl->jhdr->jhdr_size) != 0) {
	if ((jnl->jhdr->end % 512) != 0) {
		printf("jnl: %s: open: journal end (0x%llx) not a multiple of block size (0x%x)?\n",
		       jdev_name, jnl->jhdr->end, jnl->jhdr->jhdr_size);
		goto bad_journal;
	}

	// take care of replaying the journal if necessary
	if (flags & JOURNAL_RESET) {
		printf("jnl: %s: journal start/end pointers reset! (jnl %p; s 0x%llx e 0x%llx)\n",
		       jdev_name, jnl, jnl->jhdr->start, jnl->jhdr->end);
		jnl->jhdr->start = jnl->jhdr->end;
	} else if (replay_journal(jnl) != 0) {
		printf("jnl: %s: journal_open: Error replaying the journal!\n", jdev_name);
		goto bad_journal;
	}
	
	/*
	 * When we get here, we know that the journal is empty (jnl->jhdr->start ==
	 * jnl->jhdr->end).  If the device's logical block size was different from
	 * the journal's header size, then we can now restore the device's logical
	 * block size and update the journal's header size to match.
	 *
	 * Note that we also adjust the journal's start and end so that they will
	 * be aligned on the new block size.  We pick a new sequence number to
	 * avoid any problems if a replay found previous transactions using the old
	 * journal header size.  (See the comments in journal_create(), above.)
	 */
	
	if (orig_blksz != 0) {
		VNOP_IOCTL(jvp, DKIOCSETBLOCKSIZE, (caddr_t)&orig_blksz, FWRITE, &context);
		phys_blksz = orig_blksz;
		
		orig_blksz = 0;
		
		jnl->jhdr->jhdr_size = phys_blksz;
		jnl->jhdr->start = phys_blksz;
		jnl->jhdr->end = phys_blksz;
		jnl->jhdr->sequence_num = (jnl->jhdr->sequence_num +
								   (journal_size / phys_blksz) +
								   (random() % 16384)) & 0x00ffffff;
		
		if (write_journal_header(jnl, 1, jnl->jhdr->sequence_num)) {
			printf("jnl: %s: open: failed to update journal header size\n", jdev_name);
			goto bad_journal;
		}
	}

	// make sure this is in sync!
	jnl->active_start = jnl->jhdr->start;
	jnl->sequence_num = jnl->jhdr->sequence_num;

	// set this now, after we've replayed the journal
	size_up_tbuffer(jnl, tbuffer_size, phys_blksz);

	// TODO: Does this need to change if the device's logical block size changed?
	if ((off_t)(jnl->jhdr->blhdr_size/sizeof(block_info)-1) > (jnl->jhdr->size/jnl->jhdr->jhdr_size)) {
		printf("jnl: %s: open: jhdr size and blhdr size are not compatible (0x%llx, %d, %d)\n", jdev_name, jnl->jhdr->size,
		       jnl->jhdr->blhdr_size, jnl->jhdr->jhdr_size);
		goto bad_journal;
	}

	lck_mtx_init(&jnl->jlock, jnl_mutex_group, jnl_lock_attr);
	lck_mtx_init(&jnl->flock, jnl_mutex_group, jnl_lock_attr);
	lck_rw_init(&jnl->trim_lock, jnl_mutex_group, jnl_lock_attr);

	goto journal_open_complete;

bad_journal:
	if (orig_blksz != 0) {
		phys_blksz = orig_blksz;
		VNOP_IOCTL(jvp, DKIOCSETBLOCKSIZE, (caddr_t)&orig_blksz, FWRITE, &context);
		printf("jnl: %s: open: restored block size after error\n", jdev_name);
	}
	kmem_free(kernel_map, (vm_offset_t)jnl->header_buf, phys_blksz);
bad_kmem_alloc:
	FREE_ZONE(jnl, sizeof(struct journal), M_JNL_JNL);
	mount_drop(fsmount, 0);
cleanup_jdev_name:
	vnode_putname_printable(jdev_name);
	jnl = NULL;
journal_open_complete:
	return jnl;    
}


int
journal_is_clean(struct vnode *jvp,
		 off_t         offset,
		 off_t         journal_size,
		 struct vnode *fsvp,
                 size_t        min_fs_block_size)
{
	journal		jnl;
	uint32_t	phys_blksz;
	int		ret;
	int		orig_checksum, checksum;
	struct vfs_context context;
	const		char *jdev_name = vnode_getname_printable(jvp);

	context.vc_thread = current_thread();
	context.vc_ucred = FSCRED;

	/* Get the real physical block size. */
	if (VNOP_IOCTL(jvp, DKIOCGETBLOCKSIZE, (caddr_t)&phys_blksz, 0, &context)) {
		printf("jnl: %s: is_clean: failed to get device block size.\n", jdev_name);
		ret = EINVAL;
		goto cleanup_jdev_name;
	}

	if (phys_blksz > (uint32_t)min_fs_block_size) {
		printf("jnl: %s: is_clean: error: phys blksize %d bigger than min fs blksize %zd\n",
		       jdev_name, phys_blksz, min_fs_block_size);
		ret = EINVAL;
		goto cleanup_jdev_name;
	}

	if (journal_size < (256*1024) || journal_size > (MAX_JOURNAL_SIZE)) {
		printf("jnl: %s: is_clean: journal size %lld looks bogus.\n", jdev_name, journal_size);
		ret = EINVAL;
		goto cleanup_jdev_name;
	}
    
	if ((journal_size % phys_blksz) != 0) {
		printf("jnl: %s: is_clean: journal size 0x%llx is not an even multiple of block size 0x%x\n",
		       jdev_name, journal_size, phys_blksz);
		ret = EINVAL;
		goto cleanup_jdev_name;
	}

	memset(&jnl, 0, sizeof(jnl));

	if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&jnl.header_buf, phys_blksz)) {
		printf("jnl: %s: is_clean: could not allocate space for header buffer (%d bytes)\n", jdev_name, phys_blksz);
		ret = ENOMEM;
		goto cleanup_jdev_name;
	}
	jnl.header_buf_size = phys_blksz;

	get_io_info(jvp, phys_blksz, &jnl, &context);
    
	jnl.jhdr = (journal_header *)jnl.header_buf;
	memset(jnl.jhdr, 0, sizeof(journal_header));

	jnl.jdev        = jvp;
	jnl.jdev_offset = offset;
	jnl.fsdev       = fsvp;

	// we have to set this up here so that do_journal_io() will work
	jnl.jhdr->jhdr_size = phys_blksz;

	if (read_journal_header(&jnl, jnl.jhdr, phys_blksz) != (unsigned)phys_blksz) {
		printf("jnl: %s: is_clean: could not read %d bytes for the journal header.\n",
		       jdev_name, phys_blksz);
		ret = EINVAL;
		goto get_out;
	}

	orig_checksum = jnl.jhdr->checksum;
	jnl.jhdr->checksum = 0;

	if (jnl.jhdr->magic == SWAP32(JOURNAL_HEADER_MAGIC)) {
		// do this before the swap since it's done byte-at-a-time
		orig_checksum = SWAP32(orig_checksum);
		checksum = calc_checksum((char *)jnl.jhdr, JOURNAL_HEADER_CKSUM_SIZE);
		swap_journal_header(&jnl);
		jnl.flags |= JOURNAL_NEED_SWAP;
	} else {
		checksum = calc_checksum((char *)jnl.jhdr, JOURNAL_HEADER_CKSUM_SIZE);
	}

	if (jnl.jhdr->magic != JOURNAL_HEADER_MAGIC && jnl.jhdr->magic != OLD_JOURNAL_HEADER_MAGIC) {
		printf("jnl: %s: is_clean: journal magic is bad (0x%x != 0x%x)\n",
		       jdev_name, jnl.jhdr->magic, JOURNAL_HEADER_MAGIC);
		ret = EINVAL;
		goto get_out;
	}

	if (orig_checksum != checksum) {
		printf("jnl: %s: is_clean: journal checksum is bad (0x%x != 0x%x)\n", jdev_name, orig_checksum, checksum);
		ret = EINVAL;
		goto get_out;
	}

	//
	// if the start and end are equal then the journal is clean.
	// otherwise it's not clean and therefore an error.
	//
	if (jnl.jhdr->start == jnl.jhdr->end) {
		ret = 0;
	} else {
		ret = EBUSY;    // so the caller can differentiate an invalid journal from a "busy" one
	}

get_out:
	kmem_free(kernel_map, (vm_offset_t)jnl.header_buf, phys_blksz);
cleanup_jdev_name:
	vnode_putname_printable(jdev_name);
	return ret;
}


void
journal_close(journal *jnl)
{
	volatile off_t *start, *end;
	int             counter=0;

	CHECK_JOURNAL(jnl);

	// set this before doing anything that would block so that
	// we start tearing things down properly.
	//
	jnl->flags |= JOURNAL_CLOSE_PENDING;

	if (jnl->owner != current_thread()) {
		journal_lock(jnl);
	}

	wait_condition(jnl, &jnl->flushing, "journal_close");

	//
	// only write stuff to disk if the journal is still valid
	//
	if ((jnl->flags & JOURNAL_INVALID) == 0) {

		if (jnl->active_tr) {
			/*
			 * "journal_end_transaction" will fire the flush asynchronously
			 */
			journal_end_transaction(jnl);
		}
		
		// flush any buffered transactions
		if (jnl->cur_tr) {
			transaction *tr = jnl->cur_tr;

			jnl->cur_tr = NULL;
			/*
			 * "end_transaction" will wait for any in-progress flush to complete
			 * before flushing "cur_tr" synchronously("must_wait" == TRUE)
			 */
			end_transaction(tr, 1, NULL, NULL, FALSE, TRUE);
		}
		/*
		 * if there was an "active_tr", make sure we wait for
		 * it to flush if there was no "cur_tr" to process
		 */
		wait_condition(jnl, &jnl->flushing, "journal_close");
    
		//start = &jnl->jhdr->start;
		start = &jnl->active_start;
		end   = &jnl->jhdr->end;
    
		while (*start != *end && counter++ < 5000) {
			//printf("jnl: close: flushing the buffer cache (start 0x%llx end 0x%llx)\n", *start, *end);
			if (jnl->flush) {
				jnl->flush(jnl->flush_arg);
			}
			tsleep((caddr_t)jnl, PRIBIO, "jnl_close", 2);
		}

		if (*start != *end) {
			printf("jnl: %s: close: buffer flushing didn't seem to flush out all the transactions! (0x%llx - 0x%llx)\n",
			       jnl->jdev_name, *start, *end);
		}

		// make sure this is in sync when we close the journal
		jnl->jhdr->start = jnl->active_start;

		// if this fails there's not much we can do at this point...
		write_journal_header(jnl, 1, jnl->sequence_num);
	} else {
		// if we're here the journal isn't valid any more.
		// so make sure we don't leave any locked blocks lying around
		printf("jnl: %s: close: journal %p, is invalid.  aborting outstanding transactions\n", jnl->jdev_name, jnl);

		if (jnl->active_tr || jnl->cur_tr) {
			transaction *tr;

			if (jnl->active_tr) {
				tr = jnl->active_tr;
				jnl->active_tr = NULL;
			} else {
				tr = jnl->cur_tr;
				jnl->cur_tr = NULL;
			}
			abort_transaction(jnl, tr);

			if (jnl->active_tr || jnl->cur_tr) {
				panic("jnl: %s: close: jnl @ %p had both an active and cur tr\n", jnl->jdev_name, jnl);
			}
		}
	}
	wait_condition(jnl, &jnl->asyncIO, "journal_close");

	free_old_stuff(jnl);

	kmem_free(kernel_map, (vm_offset_t)jnl->header_buf, jnl->header_buf_size);
	jnl->jhdr = (void *)0xbeefbabe;

	// Release reference on the mount
	if (jnl->fsmount)
		 mount_drop(jnl->fsmount, 0);

	vnode_putname_printable(jnl->jdev_name);

	journal_unlock(jnl);
	lck_mtx_destroy(&jnl->old_start_lock, jnl_mutex_group);
	lck_mtx_destroy(&jnl->jlock, jnl_mutex_group);
	lck_mtx_destroy(&jnl->flock, jnl_mutex_group);
	FREE_ZONE(jnl, sizeof(struct journal), M_JNL_JNL);
}

static void
dump_journal(journal *jnl)
{
	transaction *ctr;

	printf("journal for dev %s:", jnl->jdev_name);
	printf("  jdev_offset %.8llx\n", jnl->jdev_offset);
	printf("  magic: 0x%.8x\n", jnl->jhdr->magic);
	printf("  start: 0x%.8llx\n", jnl->jhdr->start);
	printf("  end:   0x%.8llx\n", jnl->jhdr->end);
	printf("  size:  0x%.8llx\n", jnl->jhdr->size);
	printf("  blhdr size: %d\n", jnl->jhdr->blhdr_size);
	printf("  jhdr size: %d\n", jnl->jhdr->jhdr_size);
	printf("  chksum: 0x%.8x\n", jnl->jhdr->checksum);
    
	printf("  completed transactions:\n");
	for (ctr = jnl->completed_trs; ctr; ctr = ctr->next) {
		printf("    0x%.8llx - 0x%.8llx\n", ctr->journal_start, ctr->journal_end);
	}
}



static off_t
free_space(journal *jnl)
{
	off_t free_space_offset;
	
	if (jnl->jhdr->start < jnl->jhdr->end) {
		free_space_offset = jnl->jhdr->size - (jnl->jhdr->end - jnl->jhdr->start) - jnl->jhdr->jhdr_size;
	} else if (jnl->jhdr->start > jnl->jhdr->end) {
		free_space_offset = jnl->jhdr->start - jnl->jhdr->end;
	} else {
		// journal is completely empty
		free_space_offset = jnl->jhdr->size - jnl->jhdr->jhdr_size;
	}

	return free_space_offset;
}


//
// The journal must be locked on entry to this function.
// The "desired_size" is in bytes.
//
static int
check_free_space(journal *jnl, int desired_size, boolean_t *delayed_header_write, uint32_t sequence_num)
{
	size_t	i;
	int	counter=0;

	//printf("jnl: check free space (desired 0x%x, avail 0x%Lx)\n",
        //	   desired_size, free_space(jnl));

	if (delayed_header_write)
		*delayed_header_write = FALSE;
    
	while (1) {
		int old_start_empty;
		
		// make sure there's space in the journal to hold this transaction
		if (free_space(jnl) > desired_size && jnl->old_start[0] == 0) {
			break;
		}
		if (counter++ == 5000) {
			dump_journal(jnl);
			panic("jnl: check_free_space: buffer flushing isn't working "
			      "(jnl @ %p s %lld e %lld f %lld [active start %lld]).\n", jnl,
			      jnl->jhdr->start, jnl->jhdr->end, free_space(jnl), jnl->active_start);
		}
		if (counter > 7500) {
			printf("jnl: %s: check_free_space: giving up waiting for free space.\n", jnl->jdev_name);
			return ENOSPC;
		}

		//
		// here's where we lazily bump up jnl->jhdr->start.  we'll consume
		// entries until there is enough space for the next transaction.
		//
		old_start_empty = 1;
		lock_oldstart(jnl);

		for (i = 0; i < sizeof(jnl->old_start)/sizeof(jnl->old_start[0]); i++) {
			int   lcl_counter;

			lcl_counter = 0;
			while (jnl->old_start[i] & 0x8000000000000000LL) {
				if (lcl_counter++ > 10000) {
					panic("jnl: check_free_space: tr starting @ 0x%llx not flushing (jnl %p).\n",
					      jnl->old_start[i], jnl);
				}
				
				unlock_oldstart(jnl);
				if (jnl->flush) {
					jnl->flush(jnl->flush_arg);
				}
				tsleep((caddr_t)jnl, PRIBIO, "check_free_space1", 1);
				lock_oldstart(jnl);
			}

			if (jnl->old_start[i] == 0) {
				continue;
			}

			old_start_empty   = 0;
			jnl->jhdr->start  = jnl->old_start[i];
			jnl->old_start[i] = 0;

			if (free_space(jnl) > desired_size) {
				
				if (delayed_header_write)
					*delayed_header_write = TRUE;
				else {
					unlock_oldstart(jnl);
					write_journal_header(jnl, 1, sequence_num);
					lock_oldstart(jnl);
				}
				break;
			}
		}
		unlock_oldstart(jnl);
		
		// if we bumped the start, loop and try again
		if (i < sizeof(jnl->old_start)/sizeof(jnl->old_start[0])) {
			continue;
		} else if (old_start_empty) {
			//
			// if there is nothing in old_start anymore then we can
			// bump the jhdr->start to be the same as active_start
			// since it is possible there was only one very large
			// transaction in the old_start array.  if we didn't do
			// this then jhdr->start would never get updated and we
			// would wind up looping until we hit the panic at the
			// start of the loop.
			//
			jnl->jhdr->start = jnl->active_start;
			
			if (delayed_header_write)
				*delayed_header_write = TRUE;
			else
				write_journal_header(jnl, 1, sequence_num);
			continue;
		}


		// if the file system gave us a flush function, call it to so that
		// it can flush some blocks which hopefully will cause some transactions
		// to complete and thus free up space in the journal.
		if (jnl->flush) {
			jnl->flush(jnl->flush_arg);
		}
	
		// wait for a while to avoid being cpu-bound (this will
		// put us to sleep for 10 milliseconds)
		tsleep((caddr_t)jnl, PRIBIO, "check_free_space2", 1);
	}

	return 0;
}

/*
 * Allocate a new active transaction.
 */
static errno_t
journal_allocate_transaction(journal *jnl)
{
	transaction *tr;
	boolean_t was_vm_privileged;
	
	if (jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) {
		/*
		 * the disk driver can allocate memory on this path...
		 * if we block waiting for memory, and there is enough pressure to
		 * cause us to try and create a new swap file, we may end up deadlocking
		 * due to waiting for the journal on the swap file creation path...
		 * by making ourselves vm_privileged, we give ourselves the best chance
		 * of not blocking
		 */
		was_vm_privileged = set_vm_privilege(TRUE);
	}
	MALLOC_ZONE(tr, transaction *, sizeof(transaction), M_JNL_TR, M_WAITOK);
	memset(tr, 0, sizeof(transaction));

	tr->tbuffer_size = jnl->tbuffer_size;

	if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&tr->tbuffer, tr->tbuffer_size)) {
		FREE_ZONE(tr, sizeof(transaction), M_JNL_TR);
		jnl->active_tr = NULL;
		return ENOMEM;
	}
	if ((jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) && (was_vm_privileged == FALSE))
		set_vm_privilege(FALSE);

	// journal replay code checksum check depends on this.
	memset(tr->tbuffer, 0, BLHDR_CHECKSUM_SIZE);
	// Fill up the rest of the block with unimportant bytes (0x5a 'Z' chosen for visibility)
	memset(tr->tbuffer + BLHDR_CHECKSUM_SIZE, 0x5a, jnl->jhdr->blhdr_size - BLHDR_CHECKSUM_SIZE);

	tr->blhdr = (block_list_header *)tr->tbuffer;
	tr->blhdr->max_blocks = (jnl->jhdr->blhdr_size / sizeof(block_info)) - 1;
	tr->blhdr->num_blocks = 1;      // accounts for this header block
	tr->blhdr->bytes_used = jnl->jhdr->blhdr_size;
	tr->blhdr->flags = BLHDR_CHECK_CHECKSUMS | BLHDR_FIRST_HEADER;

	tr->sequence_num = ++jnl->sequence_num;
	tr->num_blhdrs  = 1;
	tr->total_bytes = jnl->jhdr->blhdr_size;
	tr->jnl         = jnl;

	jnl->active_tr  = tr;
	
	return 0;
}

int
journal_start_transaction(journal *jnl)
{
	int ret;

	CHECK_JOURNAL(jnl);
    
	free_old_stuff(jnl);

	if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
	}
	if (jnl->owner == current_thread()) {
		if (jnl->active_tr == NULL) {
			panic("jnl: start_tr: active_tr is NULL (jnl @ %p, owner %p, current_thread %p\n",
			      jnl, jnl->owner, current_thread());
		}
		jnl->nested_count++;
		return 0;
	}

	journal_lock(jnl);

	if (jnl->nested_count != 0 || jnl->active_tr != NULL) {
		panic("jnl: start_tr: owner %p, nested count %d, active_tr %p jnl @ %p\n",
		      jnl->owner, jnl->nested_count, jnl->active_tr, jnl);
	}

	jnl->nested_count = 1;

#if JOE
	// make sure there's room in the journal
	if (free_space(jnl) < jnl->tbuffer_size) {

		KERNEL_DEBUG(0xbbbbc030 | DBG_FUNC_START, jnl, 0, 0, 0, 0);

		// this is the call that really waits for space to free up
		// as well as updating jnl->jhdr->start
		if (check_free_space(jnl, jnl->tbuffer_size, NULL, jnl->sequence_num) != 0) {
			printf("jnl: %s: start transaction failed: no space\n", jnl->jdev_name);
			ret = ENOSPC;
			goto bad_start;
		}
		KERNEL_DEBUG(0xbbbbc030 | DBG_FUNC_END, jnl, 0, 0, 0, 0);
	}
#endif

	// if there's a buffered transaction, use it.
	if (jnl->cur_tr) {
		jnl->active_tr = jnl->cur_tr;
		jnl->cur_tr    = NULL;

		return 0;
	}

	ret = journal_allocate_transaction(jnl);
	if (ret) {
		goto bad_start;
	}

	// printf("jnl: start_tr: owner 0x%x new tr @ 0x%x\n", jnl->owner, jnl->active_tr);

	return 0;

bad_start:
	jnl->nested_count = 0;
	journal_unlock(jnl);

	return ret;
}


int
journal_modify_block_start(journal *jnl, struct buf *bp)
{
	transaction *tr;
    
	CHECK_JOURNAL(jnl);


	free_old_stuff(jnl);

	if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
	}

	// XXXdbg - for debugging I want this to be true.  later it may
	//          not be necessary.
	if ((buf_flags(bp) & B_META) == 0) {
		panic("jnl: modify_block_start: bp @ %p is not a meta-data block! (jnl %p)\n", bp, jnl);
	}

	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);

	if (jnl->owner != current_thread()) {
		panic("jnl: modify_block_start: called w/out a transaction! jnl %p, owner %p, curact %p\n",
		      jnl, jnl->owner, current_thread());
	}

	//printf("jnl: mod block start (bp 0x%x vp 0x%x l/blkno %qd/%qd bsz %d; total bytes %d)\n",
	//   bp, buf_vnode(bp), buf_lblkno(bp), buf_blkno(bp), buf_size(bp), tr->total_bytes);

	// can't allow blocks that aren't an even multiple of the
	// underlying block size.
	if ((buf_size(bp) % jnl->jhdr->jhdr_size) != 0) {
		uint32_t phys_blksz, bad=0;
	    
		if (VNOP_IOCTL(jnl->jdev, DKIOCGETBLOCKSIZE, (caddr_t)&phys_blksz, 0, vfs_context_kernel())) {
			bad = 1;
		} else if (phys_blksz != (uint32_t)jnl->jhdr->jhdr_size) {
			if (phys_blksz < 512) {
				panic("jnl: mod block start: phys blksz %d is too small (%d, %d)\n",
				      phys_blksz, buf_size(bp), jnl->jhdr->jhdr_size);
			}

			if ((buf_size(bp) % phys_blksz) != 0) {
				bad = 1;
			} else if (phys_blksz < (uint32_t)jnl->jhdr->jhdr_size) {
				jnl->jhdr->jhdr_size = phys_blksz;
			} else {
				// the phys_blksz is now larger... need to realloc the jhdr
				char *new_header_buf;

				printf("jnl: %s: phys blksz got bigger (was: %d/%d now %d)\n",
				       jnl->jdev_name, jnl->header_buf_size, jnl->jhdr->jhdr_size, phys_blksz);
				if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&new_header_buf, phys_blksz)) {
					printf("jnl: modify_block_start: %s: create: phys blksz change (was %d, now %d) but could not allocate space for new header\n",
					       jnl->jdev_name, jnl->jhdr->jhdr_size, phys_blksz);
					bad = 1;
				} else {
					memcpy(new_header_buf, jnl->header_buf, jnl->header_buf_size);
					memset(&new_header_buf[jnl->header_buf_size], 0x18, (phys_blksz - jnl->header_buf_size));
					kmem_free(kernel_map, (vm_offset_t)jnl->header_buf, jnl->header_buf_size);
					jnl->header_buf = new_header_buf;
					jnl->header_buf_size = phys_blksz;
					
					jnl->jhdr = (journal_header *)jnl->header_buf;
					jnl->jhdr->jhdr_size = phys_blksz;
				}
			}
		} else {
			bad = 1;
		}
	    
		if (bad) {
			panic("jnl: mod block start: bufsize %d not a multiple of block size %d\n",
			      buf_size(bp), jnl->jhdr->jhdr_size);
			return -1;
		}
	}

	// make sure that this transaction isn't bigger than the whole journal
	if (tr->total_bytes+buf_size(bp) >= (jnl->jhdr->size - jnl->jhdr->jhdr_size)) {
		panic("jnl: transaction too big (%d >= %lld bytes, bufsize %d, tr %p bp %p)\n",
		      tr->total_bytes, (tr->jnl->jhdr->size - jnl->jhdr->jhdr_size), buf_size(bp), tr, bp);
		return -1;
	}

	// if the block is dirty and not already locked we have to write
	// it out before we muck with it because it has data that belongs
	// (presumably) to another transaction.
	//
	if ((buf_flags(bp) & (B_DELWRI | B_LOCKED)) == B_DELWRI) {

		if (buf_flags(bp) & B_ASYNC) {
			panic("modify_block_start: bp @ %p has async flag set!\n", bp);
		}
		if (bp->b_shadow_ref)
			panic("modify_block_start: dirty bp @ %p has shadows!\n", bp);

		// this will cause it to not be buf_brelse()'d
                buf_setflags(bp, B_NORELSE);
		VNOP_BWRITE(bp);
	}
	buf_setflags(bp, B_LOCKED);

	return 0;
}

int
journal_modify_block_abort(journal *jnl, struct buf *bp)
{
	transaction	*tr;
	block_list_header *blhdr;
	int		i;
    
	CHECK_JOURNAL(jnl);

	free_old_stuff(jnl);

	tr = jnl->active_tr;
	
	//
	// if there's no active transaction then we just want to
	// call buf_brelse() and return since this is just a block
	// that happened to be modified as part of another tr.
	//
	if (tr == NULL) {
		buf_brelse(bp);
		return 0;
	}

	if (jnl->flags & JOURNAL_INVALID) {
    	/* Still need to buf_brelse(). Callers assume we consume the bp. */
    	buf_brelse(bp);
		return EINVAL;
	}

	CHECK_TRANSACTION(tr);
    
	if (jnl->owner != current_thread()) {
		panic("jnl: modify_block_abort: called w/out a transaction! jnl %p, owner %p, curact %p\n",
		      jnl, jnl->owner, current_thread());
	}

	// printf("jnl: modify_block_abort: tr 0x%x bp 0x%x\n", jnl->active_tr, bp);

	// first check if it's already part of this transaction
	for (blhdr = tr->blhdr; blhdr; blhdr = (block_list_header *)((long)blhdr->binfo[0].bnum)) {
		for (i = 1; i < blhdr->num_blocks; i++) {
			if (bp == blhdr->binfo[i].u.bp) {
				break;
			}
		}

		if (i < blhdr->num_blocks) {
			break;
		}
	}

	//
	// if blhdr is null, then this block has only had modify_block_start
	// called on it as part of the current transaction.  that means that
	// it is ok to clear the LOCKED bit since it hasn't actually been
	// modified.  if blhdr is non-null then modify_block_end was called
	// on it and so we need to keep it locked in memory.
	//
	if (blhdr == NULL) { 
		buf_clearflags(bp, B_LOCKED);
	}

	buf_brelse(bp);
	return 0;
}


int
journal_modify_block_end(journal *jnl, struct buf *bp, void (*func)(buf_t bp, void *arg), void *arg)
{
	int		i = 1;
	int		tbuffer_offset=0;
	block_list_header *blhdr, *prev=NULL;
	transaction	*tr;

	CHECK_JOURNAL(jnl);

	free_old_stuff(jnl);

	if (jnl->flags & JOURNAL_INVALID) {
    	/* Still need to buf_brelse(). Callers assume we consume the bp. */
    	buf_brelse(bp);
		return EINVAL;
	}

	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);

	if (jnl->owner != current_thread()) {
		panic("jnl: modify_block_end: called w/out a transaction! jnl %p, owner %p, curact %p\n",
		      jnl, jnl->owner, current_thread());
	}

	//printf("jnl: mod block end:  (bp 0x%x vp 0x%x l/blkno %qd/%qd bsz %d, total bytes %d)\n", 
	//   bp, buf_vnode(bp), buf_lblkno(bp), buf_blkno(bp), buf_size(bp), tr->total_bytes);

	if ((buf_flags(bp) & B_LOCKED) == 0) {
		panic("jnl: modify_block_end: bp %p not locked! jnl @ %p\n", bp, jnl);
	}
	 
	// first check if it's already part of this transaction
	for (blhdr = tr->blhdr; blhdr; prev = blhdr, blhdr = (block_list_header *)((long)blhdr->binfo[0].bnum)) {
		tbuffer_offset = jnl->jhdr->blhdr_size;

		for (i = 1; i < blhdr->num_blocks; i++) {
			if (bp == blhdr->binfo[i].u.bp) {
				break;
			}
			if (blhdr->binfo[i].bnum != (off_t)-1) {
				tbuffer_offset += buf_size(blhdr->binfo[i].u.bp);
			} else {
				tbuffer_offset += blhdr->binfo[i].u.bi.bsize;
			}
		}

		if (i < blhdr->num_blocks) {
			break;
		}
	}

	if (blhdr == NULL
	    && prev
	    && (prev->num_blocks+1) <= prev->max_blocks
	    && (prev->bytes_used+buf_size(bp)) <= (uint32_t)tr->tbuffer_size) {
		blhdr = prev;

	} else if (blhdr == NULL) {
		block_list_header *nblhdr;
		if (prev == NULL) {
			panic("jnl: modify block end: no way man, prev == NULL?!?, jnl %p, bp %p\n", jnl, bp);
		}

		// we got to the end of the list, didn't find the block and there's
		// no room in the block_list_header pointed to by prev
	
		// we allocate another tbuffer and link it in at the end of the list
		// through prev->binfo[0].bnum.  that's a skanky way to do things but
		// avoids having yet another linked list of small data structures to manage.

		if (kmem_alloc_kobject(kernel_map, (vm_offset_t *)&nblhdr, tr->tbuffer_size)) {
			panic("jnl: end_tr: no space for new block tr @ %p (total bytes: %d)!\n",
			      tr, tr->total_bytes);
		}

		// journal replay code checksum check depends on this.
		memset(nblhdr, 0, BLHDR_CHECKSUM_SIZE);
		// Fill up the rest of the block with unimportant bytes
		memset(nblhdr + BLHDR_CHECKSUM_SIZE, 0x5a, jnl->jhdr->blhdr_size - BLHDR_CHECKSUM_SIZE);

		// initialize the new guy
		nblhdr->max_blocks = (jnl->jhdr->blhdr_size / sizeof(block_info)) - 1;
		nblhdr->num_blocks = 1;      // accounts for this header block
		nblhdr->bytes_used = jnl->jhdr->blhdr_size;
		nblhdr->flags = BLHDR_CHECK_CHECKSUMS;
	    
		tr->num_blhdrs++;
		tr->total_bytes += jnl->jhdr->blhdr_size;

		// then link him in at the end
		prev->binfo[0].bnum = (off_t)((long)nblhdr);

		// and finally switch to using the new guy
		blhdr          = nblhdr;
		tbuffer_offset = jnl->jhdr->blhdr_size;
		i              = 1;
	}


	if ((i+1) > blhdr->max_blocks) {
		panic("jnl: modify_block_end: i = %d, max_blocks %d\n", i, blhdr->max_blocks);
	}

	// if this is true then this is a new block we haven't seen
	if (i >= blhdr->num_blocks) {
                int	bsize;
		vnode_t	vp;

		vp = buf_vnode(bp);
		vnode_ref(vp);
		bsize = buf_size(bp);

		blhdr->binfo[i].bnum = (off_t)(buf_blkno(bp));
		blhdr->binfo[i].u.bp = bp;

		KERNEL_DEBUG_CONSTANT(0x3018004, VM_KERNEL_ADDRPERM(vp), blhdr->binfo[i].bnum, bsize, 0, 0);

		if (func) {
			void (*old_func)(buf_t, void *)=NULL, *old_arg=NULL;
			
			buf_setfilter(bp, func, arg, &old_func, &old_arg);
			if (old_func != NULL && old_func != func) {
			    panic("jnl: modify_block_end: old func %p / arg %p (func %p)", old_func, old_arg, func);
			}
		}
		
		blhdr->bytes_used += bsize;
		tr->total_bytes   += bsize;

		blhdr->num_blocks++;
	}
	buf_bdwrite(bp);

	return 0;
}

int
journal_kill_block(journal *jnl, struct buf *bp)
{
	int		i;
	int		bflags;
	block_list_header *blhdr;
	transaction	*tr;

	CHECK_JOURNAL(jnl);

	free_old_stuff(jnl);

	if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
	}

	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);

	if (jnl->owner != current_thread()) {
		panic("jnl: modify_block_end: called w/out a transaction! jnl %p, owner %p, curact %p\n",
		      jnl, jnl->owner, current_thread());
	}

	bflags = buf_flags(bp);

	if ( !(bflags & B_LOCKED))
		panic("jnl: modify_block_end: called with bp not B_LOCKED");

	/*
	 * bp must be BL_BUSY and B_LOCKED
	 * first check if it's already part of this transaction
	 */
	for (blhdr = tr->blhdr; blhdr; blhdr = (block_list_header *)((long)blhdr->binfo[0].bnum)) {

		for (i = 1; i < blhdr->num_blocks; i++) {
			if (bp == blhdr->binfo[i].u.bp) {
			        vnode_t vp;

				buf_clearflags(bp, B_LOCKED);

				// this undoes the vnode_ref() in journal_modify_block_end()
				vp = buf_vnode(bp);
				vnode_rele_ext(vp, 0, 1);

				// if the block has the DELWRI and FILTER bits sets, then
				// things are seriously weird.  if it was part of another
				// transaction then journal_modify_block_start() should
				// have force it to be written.
				//
				//if ((bflags & B_DELWRI) && (bflags & B_FILTER)) {
				//	panic("jnl: kill block: this defies all logic! bp 0x%x\n", bp);
				//} else {
					tr->num_killed += buf_size(bp);
				//}
				blhdr->binfo[i].bnum = (off_t)-1;
				blhdr->binfo[i].u.bp = NULL;
				blhdr->binfo[i].u.bi.bsize = buf_size(bp);

				buf_markinvalid(bp);
				buf_brelse(bp);

				break;
			}
		}

		if (i < blhdr->num_blocks) {
			break;
		}
	}

	return 0;
}

/*
;________________________________________________________________________________
;
; Routine:		journal_trim_set_callback
;
; Function:		Provide the journal with a routine to be called back when a
;				TRIM has (or would have) been issued to the device.  That
;				is, the transaction has been flushed to the device, and the
;				blocks freed by the transaction are now safe for reuse.
;
;				CAUTION: If the journal becomes invalid (eg., due to an I/O
;				error when trying to write to the journal), this callback
;				will stop getting called, even if extents got freed before
;				the journal became invalid!
;
; Input Arguments:
;	jnl			- The journal structure for the filesystem.
;	callback	- The function to call when the TRIM is complete.
;	arg			- An argument to be passed to callback.
;________________________________________________________________________________
*/
__private_extern__ void
journal_trim_set_callback(journal *jnl, jnl_trim_callback_t callback, void *arg)
{
	jnl->trim_callback = callback;
	jnl->trim_callback_arg = arg;
}


/*
;________________________________________________________________________________
;
; Routine:		journal_trim_realloc
;
; Function:		Increase the amount of memory allocated for the list of extents
;				to be unmapped (trimmed).  This routine will be called when
;				adding an extent to the list, and the list already occupies
;				all of the space allocated to it.  This routine returns ENOMEM
;				if unable to allocate more space, or 0 if the extent list was
;				grown successfully.
;
; Input Arguments:
;	trim		- The trim list to be resized.
;
; Output:
;	(result)	- ENOMEM or 0.
;
; Side effects:
;	 The allocated_count and extents fields of tr->trim are updated
;	 if the function returned 0.
;________________________________________________________________________________
*/
static int
trim_realloc(journal *jnl, struct jnl_trim_list *trim)
{
	void *new_extents;
	uint32_t new_allocated_count;
	boolean_t was_vm_privileged;
	
	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_REALLOC | DBG_FUNC_START, VM_KERNEL_ADDRPERM(trim), 0, trim->allocated_count, trim->extent_count, 0);
	
	new_allocated_count = trim->allocated_count + JOURNAL_DEFAULT_TRIM_EXTENTS;

	if (jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) {
		/*
		 * if we block waiting for memory, and there is enough pressure to
		 * cause us to try and create a new swap file, we may end up deadlocking
		 * due to waiting for the journal on the swap file creation path...
		 * by making ourselves vm_privileged, we give ourselves the best chance
		 * of not blocking
		 */
		was_vm_privileged = set_vm_privilege(TRUE);
	}
	new_extents = kalloc(new_allocated_count * sizeof(dk_extent_t));
	if ((jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) && (was_vm_privileged == FALSE))
		set_vm_privilege(FALSE);

	if (new_extents == NULL) {
		printf("jnl: trim_realloc: unable to grow extent list!\n");
		/*
		 * Since we could be called when allocating space previously marked
		 * to be trimmed, we need to empty out the list to be safe.
		 */
		trim->extent_count = 0;
		if (jnl_kdebug)
			KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_REALLOC | DBG_FUNC_END, ENOMEM, 0, trim->allocated_count, 0, 0);
		return ENOMEM;
	}
	
	/* Copy the old extent list to the newly allocated list. */
	if (trim->extents != NULL) {
		memmove(new_extents,
				trim->extents,
				trim->allocated_count * sizeof(dk_extent_t));
		kfree(trim->extents,
			  trim->allocated_count * sizeof(dk_extent_t));
	}
	
	trim->allocated_count = new_allocated_count;
	trim->extents = new_extents;

	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_REALLOC | DBG_FUNC_END, 0, 0, new_allocated_count, trim->extent_count, 0);
	
	return 0;
}

/*
 ;________________________________________________________________________________
 ;
 ; Routine:		trim_search_extent
 ;
 ; Function:		Search the given extent list to see if any of its extents
 ;				overlap the given extent.
 ;
 ; Input Arguments:
 ;	trim		- The trim list to be searched.
 ;	offset		- The first byte of the range to be searched for.
 ;	length		- The number of bytes of the extent being searched for.
 ;  overlap_start - start of the overlapping extent
 ;  overlap_len   - length of the overlapping extent
 ;
 ; Output:
 ;	(result)	- TRUE if one or more extents overlap, FALSE otherwise.
 ;________________________________________________________________________________
 */
static int
trim_search_extent(struct jnl_trim_list *trim, uint64_t offset,
		uint64_t length, uint64_t *overlap_start, uint64_t *overlap_len)
{
	uint64_t end = offset + length;
	uint32_t lower = 0;						/* Lowest index to search */
	uint32_t upper = trim->extent_count;	/* Highest index to search + 1 */
	uint32_t middle;

	/* A binary search over the extent list. */
	while (lower < upper) {
		middle = (lower + upper) / 2;

		if (trim->extents[middle].offset >= end)
			upper = middle;
		else if (trim->extents[middle].offset + trim->extents[middle].length <= offset)
			lower = middle + 1;
		else {
			if (overlap_start) {
				*overlap_start = trim->extents[middle].offset;
			}
			if (overlap_len) {
				*overlap_len = trim->extents[middle].length;
			}
			return TRUE;
		}
	}

	return FALSE;
}


/*
;________________________________________________________________________________
;
; Routine:		journal_trim_add_extent
;
; Function:		Keep track of extents that have been freed as part of this
;				transaction.  If the underlying device supports TRIM (UNMAP),
;				then those extents will be trimmed/unmapped once the
;				transaction has been written to the journal.  (For example,
;				SSDs can support trim/unmap and avoid having to recopy those
;				blocks when doing wear leveling, and may reuse the same
;				phsyical blocks for different logical blocks.)
;
;				HFS also uses this, in combination with journal_trim_set_callback,
;				to add recently freed extents to its free extent cache, but
;				only after the transaction that freed them is committed to
;				disk.  (This reduces the chance of overwriting live data in
;				a way that causes data loss if a transaction never gets
;				written to the journal.)
;
; Input Arguments:
;	jnl			- The journal for the volume containing the byte range.
;	offset		- The first byte of the range to be trimmed.
;	length		- The number of bytes of the extent being trimmed.
;________________________________________________________________________________
*/
__private_extern__ int
journal_trim_add_extent(journal *jnl, uint64_t offset, uint64_t length)
{
	uint64_t end;
	transaction *tr;
	dk_extent_t *extent;
	uint32_t insert_index;
	uint32_t replace_count;
		
	CHECK_JOURNAL(jnl);

	/* TODO: Is it OK to manipulate the trim list even if JOURNAL_INVALID is set?  I think so... */
	if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
	}

	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);

	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_ADD | DBG_FUNC_START, VM_KERNEL_ADDRPERM(jnl), offset, length, tr->trim.extent_count, 0);

	if (jnl->owner != current_thread()) {
		panic("jnl: trim_add_extent: called w/out a transaction! jnl %p, owner %p, curact %p\n",
			  jnl, jnl->owner, current_thread());
	}

	free_old_stuff(jnl);
		
	end = offset + length;
		
	/*
	 * Find the range of existing extents that can be combined with the
	 * input extent.  We start by counting the number of extents that end
	 * strictly before the input extent, then count the number of extents
	 * that overlap or are contiguous with the input extent.
	 */
	extent = tr->trim.extents;
	insert_index = 0;
	while (insert_index < tr->trim.extent_count && extent->offset + extent->length < offset) {
		++insert_index;
		++extent;
	}
	replace_count = 0;
	while (insert_index + replace_count < tr->trim.extent_count && extent->offset <= end) {
		++replace_count;
		++extent;
	}
		
	/*
	 * If none of the existing extents can be combined with the input extent,
	 * then just insert it in the list (before item number insert_index).
	 */
	if (replace_count == 0) {
		/* If the list was already full, we need to grow it. */
		if (tr->trim.extent_count == tr->trim.allocated_count) {
			if (trim_realloc(jnl, &tr->trim) != 0) {
				printf("jnl: trim_add_extent: out of memory!");
				if (jnl_kdebug)
					KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_ADD | DBG_FUNC_END, ENOMEM, 0, 0, tr->trim.extent_count, 0);
				return ENOMEM;
			}
		}
		
		/* Shift any existing extents with larger offsets. */
		if (insert_index < tr->trim.extent_count) {
			memmove(&tr->trim.extents[insert_index+1],
					&tr->trim.extents[insert_index],
					(tr->trim.extent_count - insert_index) * sizeof(dk_extent_t));
		}
		tr->trim.extent_count++;
		
		/* Store the new extent in the list. */
		tr->trim.extents[insert_index].offset = offset;
		tr->trim.extents[insert_index].length = length;
		
		/* We're done. */
		if (jnl_kdebug)
			KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_ADD | DBG_FUNC_END, 0, 0, 0, tr->trim.extent_count, 0);
		return 0;
	}
	
	/*
	 * Update extent number insert_index to be the union of the input extent
	 * and all of the replaced extents.
	 */
	if (tr->trim.extents[insert_index].offset < offset)
		offset = tr->trim.extents[insert_index].offset;
	extent = &tr->trim.extents[insert_index + replace_count - 1];
	if (extent->offset + extent->length > end)
		end = extent->offset + extent->length;
	tr->trim.extents[insert_index].offset = offset;
	tr->trim.extents[insert_index].length = end - offset;
	
	/*
	 * If we were replacing more than one existing extent, then shift any
	 * extents with larger offsets, and update the count of extents.
	 *
	 * We're going to leave extent #insert_index alone since it was just updated, above.
	 * We need to move extents from index (insert_index + replace_count) through the end of
	 * the list by (replace_count - 1) positions so that they overwrite extent #(insert_index + 1).
	 */
	if (replace_count > 1 && (insert_index + replace_count) < tr->trim.extent_count) {
		memmove(&tr->trim.extents[insert_index + 1],
				&tr->trim.extents[insert_index + replace_count],
				(tr->trim.extent_count - insert_index - replace_count) * sizeof(dk_extent_t));
	}
	tr->trim.extent_count -= replace_count - 1;

	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_ADD | DBG_FUNC_END, 0, 0, 0, tr->trim.extent_count, 0);
    return 0;
}

/*
 * journal_trim_extent_overlap
 *
 * Return 1 if there are any pending TRIMs that overlap with the given offset and length
 * Return 0 otherwise.
 */

int journal_trim_extent_overlap (journal *jnl, uint64_t offset, uint64_t length, uint64_t *end) {
	transaction *tr = NULL;
	int overlap = 0;

	uint64_t overlap_start;
	uint64_t overlap_len;
	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);

	/*
	 * There are two lists that need to be examined for potential overlaps:
	 *
	 * The first is the current transaction. Since this function requires that
	 * a transaction be active when this is called, this is the "active_tr"
	 * pointer in the journal struct.  This has a trimlist pointer which needs
	 * to be searched.
	 */
	overlap = trim_search_extent (&tr->trim, offset, length, &overlap_start, &overlap_len);
	if (overlap == 0) {
		/*
		 * The second is the async trim list, which is only done if the current
		 * transaction group (active transaction) did not overlap with our target
		 * extent. This async trim list is the set of all previously
		 * committed transaction groups whose I/Os are now in-flight. We need to hold the
		 * trim lock in order to search this list.  If we grab the list before the
		 * TRIM has completed, then we will compare it. If it is grabbed AFTER the
		 * TRIM has completed, then the pointer will be zeroed out and we won't have
		 * to check anything.
		 */
		lck_rw_lock_shared (&jnl->trim_lock);
		if (jnl->async_trim != NULL) {
			overlap = trim_search_extent(jnl->async_trim, offset, length, &overlap_start, &overlap_len);
		}
		lck_rw_unlock_shared (&jnl->trim_lock);
	}

	if (overlap) {
		/* compute the end (min) of the overlapping range */
		if ( (overlap_start + overlap_len) < (offset + length)) {
			*end = (overlap_start + overlap_len);
		}
		else {
			*end = (offset + length);
		}
	}


	return overlap;
}

/*
 * journal_request_immediate_flush
 *
 * FS requests that the journal flush immediately upon the
 * active transaction's completion.
 *
 * Returns 0 if operation succeeds
 * Returns EPERM if we failed to leave hint
 */
int
journal_request_immediate_flush (journal *jnl) {

	transaction *tr = NULL;
	/*
	 * Is a transaction still in process? You must do
	 * this while there are txns open
	 */
	tr = jnl->active_tr;
	if (tr != NULL) {
		CHECK_TRANSACTION(tr);
		tr->flush_on_completion = TRUE;
	}
	else {
		return EPERM;
	}
	return 0;
}



/*
;________________________________________________________________________________
;
; Routine:		trim_remove_extent
;
; Function:		Indicate that a range of bytes, some of which may have previously
;				been passed to journal_trim_add_extent, is now allocated.
;				Any overlapping ranges currently in the journal's trim list will
;				be removed.  If the underlying device supports TRIM (UNMAP), then
;				these extents will not be trimmed/unmapped when the transaction
;				is written to the journal.
;
;				HFS also uses this to prevent newly allocated space from being
;				added to its free extent cache (if some portion of the newly
;				allocated space was recently freed).
;
; Input Arguments:
;	trim		- The trim list to update.
;	offset		- The first byte of the range to be trimmed.
;	length		- The number of bytes of the extent being trimmed.
;________________________________________________________________________________
*/
static int
trim_remove_extent(journal *jnl, struct jnl_trim_list *trim, uint64_t offset, uint64_t length)
{
	u_int64_t end;
	dk_extent_t *extent;
	u_int32_t keep_before;
	u_int32_t keep_after;
	
	end = offset + length;
	
	/*
	 * Find any existing extents that start before or end after the input
	 * extent.  These extents will be modified if they overlap the input
	 * extent.  Other extents between them will be deleted.
	 */
	extent = trim->extents;
	keep_before = 0;
	while (keep_before < trim->extent_count && extent->offset < offset) {
		++keep_before;
		++extent;
	}
	keep_after = keep_before;
	if (keep_after > 0) {
		/* See if previous extent extends beyond both ends of input extent. */
		--keep_after;
		--extent;
	}
	while (keep_after < trim->extent_count && (extent->offset + extent->length) <= end) {
		++keep_after;
		++extent;
	}
	
	/*
	 * When we get here, the first keep_before extents (0 .. keep_before-1)
	 * start before the input extent, and extents (keep_after .. extent_count-1)
	 * end after the input extent.  We'll need to keep, all of those extents,
	 * but possibly modify #(keep_before-1) and #keep_after to remove the portion
	 * that overlaps with the input extent.
	 */
	
	/*
	 * Does the input extent start after and end before the same existing
	 * extent?  If so, we have to "punch a hole" in that extent and convert
	 * it to two separate extents.
	 */
	if (keep_before >  keep_after) {
		/* If the list was already full, we need to grow it. */
		if (trim->extent_count == trim->allocated_count) {
			if (trim_realloc(jnl, trim) != 0) {
				printf("jnl: trim_remove_extent: out of memory!");
				return ENOMEM;
			}
		}
		
		/*
		 * Make room for a new extent by shifting extents #keep_after and later
		 * down by one extent.  When we're done, extents #keep_before and
		 * #keep_after will be identical, and we can fall through to removing
		 * the portion that overlaps the input extent.
		 */
		memmove(&trim->extents[keep_before],
				&trim->extents[keep_after],
				(trim->extent_count - keep_after) * sizeof(dk_extent_t));
		++trim->extent_count;
		++keep_after;
		
		/*
		 * Fall through.  We now have the case where the length of extent
		 * #(keep_before - 1) needs to be updated, and the start of extent
		 * #(keep_after) needs to be updated.
		 */
	}
	
	/*
	 * May need to truncate the end of extent #(keep_before - 1) if it overlaps
	 * the input extent.
	 */
	if (keep_before > 0) {
		extent = &trim->extents[keep_before - 1];
		if (extent->offset + extent->length > offset) {
			extent->length = offset - extent->offset;
		}
	}
	
	/*
	 * May need to update the start of extent #(keep_after) if it overlaps the
	 * input extent.
	 */
	if (keep_after < trim->extent_count) {
		extent = &trim->extents[keep_after];
		if (extent->offset < end) {
			extent->length = extent->offset + extent->length - end;
			extent->offset = end;
		}
	}
	
	/*
	 * If there were whole extents that overlapped the input extent, get rid
	 * of them by shifting any following extents, and updating the count.
	 */
	if (keep_after > keep_before && keep_after < trim->extent_count) {
		memmove(&trim->extents[keep_before],
				&trim->extents[keep_after],
				(trim->extent_count - keep_after) * sizeof(dk_extent_t));
	}
	trim->extent_count -= keep_after - keep_before;

	return 0;
}

/*
 ;________________________________________________________________________________
 ;
 ; Routine:		journal_trim_remove_extent
 ;
 ; Function:		Make note of a range of bytes, some of which may have previously
 ;				been passed to journal_trim_add_extent, is now in use on the
 ;				volume.  The given bytes will be not be trimmed as part of
 ;				this transaction, or a pending trim of a transaction being
 ;				asynchronously flushed.
 ;
 ; Input Arguments:
 ;	jnl			- The journal for the volume containing the byte range.
 ;	offset		- The first byte of the range to be trimmed.
 ;	length		- The number of bytes of the extent being trimmed.
 ;________________________________________________________________________________
 */
__private_extern__ int
journal_trim_remove_extent(journal *jnl, uint64_t offset, uint64_t length)
{
	int error = 0;
	transaction *tr;
	
	CHECK_JOURNAL(jnl);

	/* TODO: Is it OK to manipulate the trim list even if JOURNAL_INVALID is set?  I think so... */
	if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
	}

	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);

	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_REMOVE | DBG_FUNC_START, VM_KERNEL_ADDRPERM(jnl), offset, length, tr->trim.extent_count, 0);

	if (jnl->owner != current_thread()) {
		panic("jnl: trim_remove_extent: called w/out a transaction! jnl %p, owner %p, curact %p\n",
			  jnl, jnl->owner, current_thread());
	}

	free_old_stuff(jnl);
		
	error = trim_remove_extent(jnl, &tr->trim, offset, length);
	if (error == 0) {
		int found = FALSE;
		
		/*
		 * See if a pending trim has any extents that overlap with the
		 * one we were given.
		 */
		lck_rw_lock_shared(&jnl->trim_lock);
		if (jnl->async_trim != NULL)
			found = trim_search_extent(jnl->async_trim, offset, length, NULL, NULL);
		lck_rw_unlock_shared(&jnl->trim_lock);
		
		if (found) {
			/*
			 * There was an overlap, so avoid trimming the extent we
			 * just allocated.  (Otherwise, it might get trimmed after
			 * we've written to it, which will cause that data to be
			 * corrupted.)
			 */
			uint32_t async_extent_count = 0;
			
			if (jnl_kdebug)
				KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_REMOVE_PENDING | DBG_FUNC_START, VM_KERNEL_ADDRPERM(jnl), offset, length, 0, 0);
			lck_rw_lock_exclusive(&jnl->trim_lock);
			if (jnl->async_trim != NULL) {
				error = trim_remove_extent(jnl, jnl->async_trim, offset, length);
				async_extent_count = jnl->async_trim->extent_count;
			}
			lck_rw_unlock_exclusive(&jnl->trim_lock);
			if (jnl_kdebug)
				KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_REMOVE_PENDING | DBG_FUNC_END, error, 0, 0, async_extent_count, 0);
		}
	}

	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_REMOVE | DBG_FUNC_END, error, 0, 0, tr->trim.extent_count, 0);
	return error;
}


static int
journal_trim_flush(journal *jnl, transaction *tr)
{
	int errno = 0;
	boolean_t was_vm_privileged;
	
	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_FLUSH | DBG_FUNC_START, VM_KERNEL_ADDRPERM(jnl), tr, 0, tr->trim.extent_count, 0);

	if (jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) {
		/*
		 * the disk driver can allocate memory on this path...
		 * if we block waiting for memory, and there is enough pressure to
		 * cause us to try and create a new swap file, we may end up deadlocking
		 * due to waiting for the journal on the swap file creation path...
		 * by making ourselves vm_privileged, we give ourselves the best chance
		 * of not blocking
		 */
		was_vm_privileged = set_vm_privilege(TRUE);
	}
	lck_rw_lock_shared(&jnl->trim_lock);
	if (tr->trim.extent_count > 0) {
		dk_unmap_t unmap;
				
		bzero(&unmap, sizeof(unmap));
		if (CONFIG_HFS_TRIM && (jnl->flags & JOURNAL_USE_UNMAP)) {
			unmap.extents = tr->trim.extents;
			unmap.extentsCount = tr->trim.extent_count;
			if (jnl_kdebug)
				KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_UNMAP | DBG_FUNC_START, VM_KERNEL_ADDRPERM(jnl), tr, 0, tr->trim.extent_count, 0);
			errno = VNOP_IOCTL(jnl->fsdev, DKIOCUNMAP, (caddr_t)&unmap, FWRITE, vfs_context_kernel());
			if (jnl_kdebug)
				KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_UNMAP | DBG_FUNC_END, errno, 0, 0, 0, 0);
		}
		
		/*
		 * Call back into the file system to tell them that we have
		 * trimmed some extents and that they can now be reused.
		 *
		 * CAUTION: If the journal becomes invalid (eg., due to an I/O
		 * error when trying to write to the journal), this callback
		 * will stop getting called, even if extents got freed before
		 * the journal became invalid!
		 */
		if (jnl->trim_callback)
			jnl->trim_callback(jnl->trim_callback_arg, tr->trim.extent_count, tr->trim.extents);
	}
	lck_rw_unlock_shared(&jnl->trim_lock);

	if ((jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) && (was_vm_privileged == FALSE))
		set_vm_privilege(FALSE);
	/*
	 * If the transaction we're flushing was the async transaction, then
	 * tell the current transaction that there is no pending trim
	 * any more.
	 *
	 * NOTE: Since we released the lock, another thread could have
	 * removed one or more extents from our list.  That's not a
	 * problem since any writes to the re-allocated blocks
	 * would get sent to the device after the DKIOCUNMAP.
	 */
	lck_rw_lock_exclusive(&jnl->trim_lock);
	if (jnl->async_trim == &tr->trim)
		jnl->async_trim = NULL;
	lck_rw_unlock_exclusive(&jnl->trim_lock);

	/*
	 * By the time we get here, no other thread can discover the address
	 * of "tr", so it is safe for us to manipulate tr->trim without
	 * holding any locks.
	 */
	if (tr->trim.extents) {			
		kfree(tr->trim.extents, tr->trim.allocated_count * sizeof(dk_extent_t));
		tr->trim.allocated_count = 0;
		tr->trim.extent_count = 0;
		tr->trim.extents = NULL;
	}
	
	if (jnl_kdebug)
		KERNEL_DEBUG_CONSTANT(DBG_JOURNAL_TRIM_FLUSH | DBG_FUNC_END, errno, 0, 0, 0, 0);

	return errno;
}

static int
journal_binfo_cmp(const void *a, const void *b)
{
	const block_info *bi_a = (const struct block_info *)a;
	const block_info *bi_b = (const struct block_info *)b;
	daddr64_t res;

	if (bi_a->bnum == (off_t)-1) {
		return 1;
	}
	if (bi_b->bnum == (off_t)-1) {
		return -1;
	}

	// don't have to worry about negative block
	// numbers so this is ok to do.
	//
	res = (buf_blkno(bi_a->u.bp) - buf_blkno(bi_b->u.bp));

	return (int)res;
}


/*
 * End a transaction.  If the transaction is small enough, and we're not forcing
 * a write to disk, the "active" transaction becomes the "current" transaction,
 * and will be reused for the next transaction that is started (group commit).
 *
 * If the transaction gets written to disk (because force_it is true, or no
 * group commit, or the transaction is sufficiently full), the blocks get
 * written into the journal first, then the are written asynchronously.  When
 * those async writes complete, the transaction can be freed and removed from
 * the journal.
 *
 * An optional callback can be supplied.  If given, it is called after the
 * the blocks have been written to the journal, but before the async writes
 * of those blocks to their normal on-disk locations.  This is used by
 * journal_relocate so that the location of the journal can be changed and
 * flushed to disk before the blocks get written to their normal locations.
 * Note that the callback is only called if the transaction gets written to
 * the journal during this end_transaction call; you probably want to set the
 * force_it flag.
 *
 * Inputs:
 *	tr			 Transaction to add to the journal
 *	force_it	 If true, force this transaction to the on-disk journal immediately.
 *	callback	 See description above.  Pass NULL for no callback.
 *	callback_arg Argument passed to callback routine.
 *
 * Result
 *		 0		No errors
 *		-1		An error occurred.  The journal is marked invalid.
 */
static int
end_transaction(transaction *tr, int force_it, errno_t (*callback)(void*), void *callback_arg, boolean_t drop_lock, boolean_t must_wait)
{
	block_list_header  *blhdr=NULL, *next=NULL;
	int		i, ret_val = 0;
	errno_t		errno;
	journal		*jnl = tr->jnl;
	struct buf	*bp;
	size_t		tbuffer_offset;
	boolean_t	drop_lock_early;

	if (jnl->cur_tr) {
		panic("jnl: jnl @ %p already has cur_tr %p, new tr: %p\n",
			  jnl, jnl->cur_tr, tr);
	}

	// if there weren't any modified blocks in the transaction
	// just save off the transaction pointer and return.
	if (tr->total_bytes == jnl->jhdr->blhdr_size) {
		jnl->cur_tr = tr;
		goto done;
	}
	
    // if our transaction buffer isn't very full, just hang
    // on to it and don't actually flush anything.  this is
    // what is known as "group commit".  we will flush the
    // transaction buffer if it's full or if we have more than
    // one of them so we don't start hogging too much memory.
    //
    // We also check the device supports UNMAP/TRIM, and if so,
    // the number of extents waiting to be trimmed.  If it is
    // small enough, then keep accumulating more (so we can
    // reduce the overhead of trimming).  If there was a prior
    // trim error, then we stop issuing trims for this
    // volume, so we can also coalesce transactions.
	//
    if (   force_it == 0
		   && (jnl->flags & JOURNAL_NO_GROUP_COMMIT) == 0 
		   && tr->num_blhdrs < 3
		   && (tr->total_bytes <= ((tr->tbuffer_size*tr->num_blhdrs) - tr->tbuffer_size/8))
		   && (!(jnl->flags & JOURNAL_USE_UNMAP) || (tr->trim.extent_count < jnl_trim_flush_limit))) {

		jnl->cur_tr = tr;
		goto done;
	}

	KERNEL_DEBUG(0xbbbbc018|DBG_FUNC_START, jnl, tr, drop_lock, must_wait, 0);

	lock_condition(jnl, &jnl->flushing, "end_transaction");

	/*
	 * if the previous 'finish_end_transaction' was being run
	 * asynchronously, it could have encountered a condition
	 * that caused it to mark the journal invalid... if that
	 * occurred while we were waiting for it to finish, we
	 * need to notice and abort the current transaction
	 */
	if ((jnl->flags & JOURNAL_INVALID) || jnl->flush_aborted == TRUE) {
		unlock_condition(jnl, &jnl->flushing);

		abort_transaction(jnl, tr);
		ret_val = -1;
		KERNEL_DEBUG(0xbbbbc018|DBG_FUNC_END, jnl, tr, ret_val, 0, 0);
		goto done;
	}
	
	/*
	 * Store a pointer to this transaction's trim list so that
	 * future transactions can find it.
	 *
	 * Note: if there are no extents in the trim list, then don't
	 * bother saving the pointer since nothing can add new extents
	 * to the list (and other threads/transactions only care if
	 * there is a trim pending).
	 */
	lck_rw_lock_exclusive(&jnl->trim_lock);
	if (jnl->async_trim != NULL)
		panic("jnl: end_transaction: async_trim already non-NULL!");
	if (tr->trim.extent_count > 0)
		jnl->async_trim = &tr->trim;
	lck_rw_unlock_exclusive(&jnl->trim_lock);

	/*
	 * snapshot the transaction sequence number while we are still behind
	 * the journal lock since it will be bumped upon the start of the
	 * next transaction group which may overlap the current journal flush...
	 * we pass the snapshot into write_journal_header during the journal
	 * flush so that it can write the correct version in the header...
	 * because we hold the 'flushing' condition variable for the duration
	 * of the journal flush, 'saved_sequence_num' remains stable
	 */
	jnl->saved_sequence_num = jnl->sequence_num;
	
	/*
	 * if we're here we're going to flush the transaction buffer to disk.
	 * 'check_free_space' will not return untl there is enough free
	 * space for this transaction in the journal and jnl->old_start[0]
	 * is avaiable for use
	 */
	KERNEL_DEBUG(0xbbbbc030 | DBG_FUNC_START, jnl, 0, 0, 0, 0);

	check_free_space(jnl, tr->total_bytes, &tr->delayed_header_write, jnl->saved_sequence_num);

	KERNEL_DEBUG(0xbbbbc030 | DBG_FUNC_END, jnl, tr->delayed_header_write, 0, 0, 0);

	// range check the end index
	if (jnl->jhdr->end <= 0 || jnl->jhdr->end > jnl->jhdr->size) {
		panic("jnl: end_transaction: end is bogus 0x%llx (sz 0x%llx)\n",
			  jnl->jhdr->end, jnl->jhdr->size);
	}
	if (tr->delayed_header_write == TRUE) {
		thread_t	thread = THREAD_NULL;

		lock_condition(jnl, &jnl->writing_header, "end_transaction");
		/*
		 * fire up a thread to write the journal header
		 * asynchronously... when it finishes, it will call
		 * unlock_condition... we can overlap the preparation of
		 * the log and buffers during this time
		 */
		kernel_thread_start((thread_continue_t)write_header_thread, jnl, &thread);
	} else
		jnl->write_header_failed = FALSE;


	// this transaction starts where the current journal ends
	tr->journal_start = jnl->jhdr->end;

	lock_oldstart(jnl);
	/*
	 * Because old_start is locked above, we can cast away the volatile qualifier before passing it to memcpy.
	 * slide everyone else down and put our latest guy in the last
	 * entry in the old_start array
	 */
	memcpy(__CAST_AWAY_QUALIFIER(&jnl->old_start[0], volatile, void *), __CAST_AWAY_QUALIFIER(&jnl->old_start[1], volatile, void *), sizeof(jnl->old_start)-sizeof(jnl->old_start[0]));
	jnl->old_start[sizeof(jnl->old_start)/sizeof(jnl->old_start[0]) - 1] = tr->journal_start | 0x8000000000000000LL;

	unlock_oldstart(jnl);


	for (blhdr = tr->blhdr; blhdr; blhdr = next) {
		char	*blkptr;
		buf_t	sbp;
		int32_t	bsize;

		tbuffer_offset = jnl->jhdr->blhdr_size;

		for (i = 1; i < blhdr->num_blocks; i++) {

			if (blhdr->binfo[i].bnum != (off_t)-1) {
				void (*func)(buf_t, void *);
				void  *arg;

				bp = blhdr->binfo[i].u.bp;

				if (bp == NULL) {
					panic("jnl: inconsistent binfo (NULL bp w/bnum %lld; jnl @ %p, tr %p)\n",
						blhdr->binfo[i].bnum, jnl, tr);
				}
				/*
				 * acquire the bp here so that we can safely
				 * mess around with its data.  buf_acquire()
				 * will return EAGAIN if the buffer was busy,
				 * so loop trying again.
				 */
				do {
					errno = buf_acquire(bp, BAC_REMOVE, 0, 0);
				} while (errno == EAGAIN);
					
				if (errno)
					panic("could not acquire bp %p (err %d)\n", bp, errno);

				if ((buf_flags(bp) & (B_LOCKED|B_DELWRI)) != (B_LOCKED|B_DELWRI)) {
					if (jnl->flags & JOURNAL_CLOSE_PENDING) {
						buf_clearflags(bp, B_LOCKED);
						buf_brelse(bp);
						
						/*
						 * this is an odd case that appears to happen occasionally
						 * make sure we mark this block as no longer valid
						 * so that we don't process it in "finish_end_transaction" since
						 * the bp that is recorded in our array no longer belongs
						 * to us (normally we substitute a shadow bp to be processed
						 * issuing a 'buf_bawrite' on a stale buf_t pointer leads
						 * to all kinds of problems.
						 */
						blhdr->binfo[i].bnum = (off_t)-1;
						continue;
					} else {
						panic("jnl: end_tr: !!!DANGER!!! bp %p flags (0x%x) not LOCKED & DELWRI\n", bp, buf_flags(bp));
					}
				}
				bsize = buf_size(bp);

				buf_setfilter(bp, NULL, NULL, &func, &arg);
				
				blkptr = (char *)&((char *)blhdr)[tbuffer_offset];

				sbp = buf_create_shadow_priv(bp, FALSE, (uintptr_t)blkptr, 0, 0);

				if (sbp == NULL)
					panic("jnl: buf_create_shadow returned NULL");

				/*
				 * copy the data into the transaction buffer...
				 */
				memcpy(blkptr, (char *)buf_dataptr(bp), bsize);

				buf_clearflags(bp, B_LOCKED);
				buf_markclean(bp);
				buf_drop(bp);

				/*
				 * adopt the shadow buffer for this block
				 */
				if (func) {
					/*
					 * transfer FS hook function to the
					 * shadow buffer... it will get called
					 * in finish_end_transaction
					 */
					buf_setfilter(sbp, func, arg, NULL, NULL);
				}
				blhdr->binfo[i].u.bp = sbp;

			} else {
				// bnum == -1, only true if a block was "killed" 
				bsize = blhdr->binfo[i].u.bi.bsize;
			}
			tbuffer_offset += bsize;
		}
		next = (block_list_header *)((long)blhdr->binfo[0].bnum);
	}
	/*
	 * if callback != NULL, we don't want to drop the journal
	 * lock, or complete end_transaction asynchronously, since
	 * the caller is expecting the callback to run in the calling
	 * context
	 *
	 * if drop_lock == FALSE, we can't complete end_transaction
	 * asynchronously
	 */
	if (callback)
		drop_lock_early = FALSE;
	else
		drop_lock_early = drop_lock;

	if (drop_lock_early == FALSE)
		must_wait = TRUE;

	if (drop_lock_early == TRUE) {
		journal_unlock(jnl);
		drop_lock = FALSE;
	}
	if (must_wait == TRUE)
		ret_val = finish_end_transaction(tr, callback, callback_arg);
	else {
		thread_t	thread = THREAD_NULL;

		/*
		 * fire up a thread to complete processing this transaction
		 * asynchronously... when it finishes, it will call
		 * unlock_condition
		 */
		kernel_thread_start((thread_continue_t)finish_end_thread, tr, &thread);
	}
	KERNEL_DEBUG(0xbbbbc018|DBG_FUNC_END, jnl, tr, ret_val, 0, 0);
done:
	if (drop_lock == TRUE) {
		journal_unlock(jnl);
	}
	return (ret_val);
}


static void
finish_end_thread(transaction *tr)
{
	proc_set_task_policy(current_task(), current_thread(),
	                     TASK_POLICY_INTERNAL, TASK_POLICY_IOPOL, IOPOL_PASSIVE);

	finish_end_transaction(tr, NULL, NULL);

	thread_deallocate(current_thread());
	thread_terminate(current_thread());
}

static void
write_header_thread(journal *jnl)
{
	proc_set_task_policy(current_task(), current_thread(),
	                     TASK_POLICY_INTERNAL, TASK_POLICY_IOPOL, IOPOL_PASSIVE);

	if (write_journal_header(jnl, 1, jnl->saved_sequence_num))
		jnl->write_header_failed = TRUE;
	else
		jnl->write_header_failed = FALSE;
	unlock_condition(jnl, &jnl->writing_header);

	thread_deallocate(current_thread());
	thread_terminate(current_thread());
}

static int
finish_end_transaction(transaction *tr, errno_t (*callback)(void*), void *callback_arg)
{
	int		i, amt;
	int		ret = 0;
	off_t		end;
	journal		*jnl = tr->jnl;
	buf_t		bp, *bparray;
	vnode_t		vp;
	block_list_header  *blhdr=NULL, *next=NULL;
	size_t		tbuffer_offset;
	int		bufs_written = 0;
	int		ret_val = 0;

	KERNEL_DEBUG(0xbbbbc028|DBG_FUNC_START, jnl, tr, 0, 0, 0);

	end  = jnl->jhdr->end;

	for (blhdr = tr->blhdr; blhdr; blhdr = (block_list_header *)((long)blhdr->binfo[0].bnum)) {
		boolean_t was_vm_privileged;

		amt = blhdr->bytes_used;

		blhdr->binfo[0].u.bi.b.sequence_num = tr->sequence_num;

		blhdr->checksum = 0;
		blhdr->checksum = calc_checksum((char *)blhdr, BLHDR_CHECKSUM_SIZE);

		if (jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) {
			/*
			 * if we block waiting for memory, and there is enough pressure to
			 * cause us to try and create a new swap file, we may end up deadlocking
			 * due to waiting for the journal on the swap file creation path...
			 * by making ourselves vm_privileged, we give ourselves the best chance
			 * of not blocking
			 */
			was_vm_privileged = set_vm_privilege(TRUE);
		}
		if (kmem_alloc(kernel_map, (vm_offset_t *)&bparray, blhdr->num_blocks * sizeof(struct buf *))) {
			panic("can't allocate %zd bytes for bparray\n", blhdr->num_blocks * sizeof(struct buf *));
		}
		if ((jnl->fsmount->mnt_kern_flag & MNTK_SWAP_MOUNT) && (was_vm_privileged == FALSE))
			set_vm_privilege(FALSE);

		tbuffer_offset = jnl->jhdr->blhdr_size;

		for (i = 1; i < blhdr->num_blocks; i++) {
			void (*func)(buf_t, void *);
			void	*arg;
			int32_t	bsize;
		    
			/*
			 * finish preparing the shadow buf_t before 
			 * calculating the individual block checksums
			 */
			if (blhdr->binfo[i].bnum != (off_t)-1) {
				daddr64_t blkno;
				daddr64_t lblkno;

				bp = blhdr->binfo[i].u.bp;
				
				vp = buf_vnode(bp);
				blkno = buf_blkno(bp);
				lblkno = buf_lblkno(bp);

				if (vp == NULL && lblkno == blkno) {
					printf("jnl: %s: end_tr: bad news! bp @ %p w/null vp and l/blkno = %qd/%qd.  aborting the transaction (tr %p jnl %p).\n",
					       jnl->jdev_name, bp, lblkno, blkno, tr, jnl);
					ret_val = -1;
					goto bad_journal;
				}
	    
				// if the lblkno is the same as blkno and this bp isn't
				// associated with the underlying file system device then
				// we need to call bmap() to get the actual physical block.
				//
				if ((lblkno == blkno) && (vp != jnl->fsdev)) {
					off_t	f_offset;
					size_t 	contig_bytes;

					if (VNOP_BLKTOOFF(vp, lblkno, &f_offset)) {
						printf("jnl: %s: end_tr: vnop_blktooff failed @ %p, jnl %p\n", jnl->jdev_name, bp, jnl);
						ret_val = -1;
						goto bad_journal;
					}
					if (VNOP_BLOCKMAP(vp, f_offset, buf_count(bp), &blkno, &contig_bytes, NULL, 0, NULL)) {
						printf("jnl: %s: end_tr: can't blockmap the bp @ %p, jnl %p\n", jnl->jdev_name, bp, jnl);
						ret_val = -1;
						goto bad_journal;
					}
					if ((uint32_t)contig_bytes < buf_count(bp)) {
						printf("jnl: %s: end_tr: blk not physically contiguous on disk@ %p, jnl %p\n", jnl->jdev_name, bp, jnl);
						ret_val = -1;
						goto bad_journal;
					}
					buf_setblkno(bp, blkno);
				}
				// update this so we write out the correct physical block number!
				blhdr->binfo[i].bnum = (off_t)(blkno);

				/*
				 * pick up the FS hook function (if any) and prepare
				 * to fire this buffer off in the next pass
				 */
				buf_setfilter(bp, buffer_flushed_callback, tr, &func, &arg);

				if (func) {
					/*
					 * call the hook function supplied by the filesystem...
					 * this needs to happen BEFORE cacl_checksum in case
					 * the FS morphs the data in the buffer
					 */
					func(bp, arg);
				}
				bparray[i] = bp;
				bsize = buf_size(bp);
				blhdr->binfo[i].u.bi.bsize = bsize;
				blhdr->binfo[i].u.bi.b.cksum = calc_checksum(&((char *)blhdr)[tbuffer_offset], bsize);
			} else {
				bparray[i] = NULL;
				bsize = blhdr->binfo[i].u.bi.bsize;
				blhdr->binfo[i].u.bi.b.cksum = 0;
			}
			tbuffer_offset += bsize;
		}
		/*
		 * if we fired off the journal_write_header asynchronously in
		 * 'end_transaction', we need to wait for its completion
		 * before writing the actual journal data
		 */
		wait_condition(jnl, &jnl->writing_header, "finish_end_transaction");

		if (jnl->write_header_failed == FALSE)
			ret = write_journal_data(jnl, &end, blhdr, amt);
		else 
			ret_val = -1;
		/*
		 * put the bp pointers back so that we can 
		 * make the final pass on them
		 */
		for (i = 1; i < blhdr->num_blocks; i++)
			blhdr->binfo[i].u.bp = bparray[i];

		kmem_free(kernel_map, (vm_offset_t)bparray, blhdr->num_blocks * sizeof(struct buf *));

		if (ret_val == -1)
			goto bad_journal;

		if (ret != amt) {
			printf("jnl: %s: end_transaction: only wrote %d of %d bytes to the journal!\n",
			       jnl->jdev_name, ret, amt);

			ret_val = -1;
			goto bad_journal;
		}
	}
	jnl->jhdr->end  = end;    // update where the journal now ends
	tr->journal_end = end;    // the transaction ends here too

	if (tr->journal_start == 0 || tr->journal_end == 0) {
		panic("jnl: end_transaction: bad tr journal start/end: 0x%llx 0x%llx\n",
		      tr->journal_start, tr->journal_end);
	}

	if (write_journal_header(jnl, 0, jnl->saved_sequence_num) != 0) {
		ret_val = -1;
		goto bad_journal;
	}
	/*
	 * If the caller supplied a callback, call it now that the blocks have been
	 * written to the journal.  This is used by journal_relocate so, for example,
	 * the file system can change its pointer to the new journal.
	 */
	if (callback != NULL && callback(callback_arg) != 0) {
		ret_val = -1;
		goto bad_journal;
	}
	
	//
	// Send a DKIOCUNMAP for the extents trimmed by this transaction, and
	// free up the extent list.
	//
	journal_trim_flush(jnl, tr);
	
	// the buffer_flushed_callback will only be called for the 
	// real blocks that get flushed so we have to account for 
	// the block_list_headers here.
	//
	tr->num_flushed = tr->num_blhdrs * jnl->jhdr->blhdr_size;

	lock_condition(jnl, &jnl->asyncIO, "finish_end_transaction");

	//
	// setup for looping through all the blhdr's.
	//
	for (blhdr = tr->blhdr; blhdr; blhdr = next) {
		uint16_t	num_blocks;

		/*
		 * grab this info ahead of issuing the buf_bawrites...
		 * once the last one goes out, its possible for blhdr
		 * to be freed (especially if we get preempted) before
		 * we do the last check of num_blocks or
		 * grab the next blhdr pointer...
		 */
		next = (block_list_header *)((long)blhdr->binfo[0].bnum);
		num_blocks = blhdr->num_blocks;

		/*
		 * we can re-order the buf ptrs because everything is written out already
		 */
		qsort(&blhdr->binfo[1], num_blocks-1, sizeof(block_info), journal_binfo_cmp);

		/*
		 * need to make sure that the loop issuing the buf_bawrite's
		 * does not touch blhdr once the last buf_bawrite has been
		 * issued... at that point, we no longer have a legitmate
		 * reference on the associated storage since it will be
		 * released upon the completion of that last buf_bawrite
		 */
		for (i = num_blocks-1; i >= 1; i--) {
			if (blhdr->binfo[i].bnum != (off_t)-1)
				break;
			num_blocks--;
		}
		for (i = 1; i < num_blocks; i++) {

			if ((bp = blhdr->binfo[i].u.bp)) {
				vp = buf_vnode(bp);
		    
				buf_bawrite(bp);
				
				// this undoes the vnode_ref() in journal_modify_block_end()
				vnode_rele_ext(vp, 0, 1);

				bufs_written++;
			}
		}
	}
	if (bufs_written == 0) {
		/*
		 * since we didn't issue any buf_bawrite's, there is no
		 * async trigger to cause the memory associated with this
		 * transaction to be freed... so, move it to the garbage
		 * list now
		 */
		lock_oldstart(jnl);

		tr->next       = jnl->tr_freeme;
		jnl->tr_freeme = tr;

		unlock_oldstart(jnl);

		unlock_condition(jnl, &jnl->asyncIO);
	}

	//printf("jnl: end_tr: tr @ 0x%x, jnl-blocks: 0x%llx - 0x%llx. exit!\n",
	//   tr, tr->journal_start, tr->journal_end);

bad_journal:
	if (ret_val == -1) {
		/*
		 * 'flush_aborted' is protected by the flushing condition... we need to
		 * set it before dropping the condition so that it will be
		 * noticed in 'end_transaction'... we add this additional
		 * aborted condition so that we can drop the 'flushing' condition
		 * before grabbing the journal lock... this avoids a deadlock
		 * in 'end_transaction' which is holding the journal lock while
		 * waiting for the 'flushing' condition to clear...
		 * everyone else will notice the JOURNAL_INVALID flag
		 */
		jnl->flush_aborted = TRUE;

		unlock_condition(jnl, &jnl->flushing);
		journal_lock(jnl);

		jnl->flags |= JOURNAL_INVALID;
		jnl->old_start[sizeof(jnl->old_start)/sizeof(jnl->old_start[0]) - 1] &= ~0x8000000000000000LL;
		abort_transaction(jnl, tr);		// cleans up list of extents to be trimmed

		journal_unlock(jnl);
	} else
		unlock_condition(jnl, &jnl->flushing);

	KERNEL_DEBUG(0xbbbbc028|DBG_FUNC_END, jnl, tr, bufs_written, ret_val, 0);

	return (ret_val);
}


static void
lock_condition(journal *jnl, boolean_t *condition, const char *condition_name)
{

	KERNEL_DEBUG(0xbbbbc020|DBG_FUNC_START, jnl, condition, 0, 0, 0);

	lock_flush(jnl);

	while (*condition == TRUE)
		msleep(condition, &jnl->flock, PRIBIO, condition_name, NULL);

	*condition = TRUE;
	unlock_flush(jnl);

	KERNEL_DEBUG(0xbbbbc020|DBG_FUNC_END, jnl, condition, 0, 0, 0);
}

static void
wait_condition(journal *jnl, boolean_t *condition, const char *condition_name)
{

	if (*condition == FALSE)
		return;

	KERNEL_DEBUG(0xbbbbc02c|DBG_FUNC_START, jnl, condition, 0, 0, 0);

	lock_flush(jnl);

	while (*condition == TRUE)
		msleep(condition, &jnl->flock, PRIBIO, condition_name, NULL);

	unlock_flush(jnl);

	KERNEL_DEBUG(0xbbbbc02c|DBG_FUNC_END, jnl, condition, 0, 0, 0);
}

static void
unlock_condition(journal *jnl, boolean_t *condition)
{
	lock_flush(jnl);

	*condition = FALSE;
	wakeup(condition);

	unlock_flush(jnl);
}

static void
abort_transaction(journal *jnl, transaction *tr)
{
	block_list_header *blhdr, *next;

	// for each block list header, iterate over the blocks then
	// free up the memory associated with the block list.
	//
	// find each of the primary blocks (i.e. the list could
	// contain a mix of shadowed and real buf_t's depending
	// on when the abort condition was detected) and mark them
	// clean and locked in the cache... this at least allows 
	// the FS a consistent view between it's incore data structures
	// and the meta-data held in the cache
	//
	KERNEL_DEBUG(0xbbbbc034|DBG_FUNC_START, jnl, tr, 0, 0, 0);

	for (blhdr = tr->blhdr; blhdr; blhdr = next) {
		int	i;
		
		for (i = 1; i < blhdr->num_blocks; i++) {
			buf_t		bp, tbp, sbp;
			vnode_t		bp_vp;
			errno_t		errno;

			if (blhdr->binfo[i].bnum == (off_t)-1)
				continue;

			tbp = blhdr->binfo[i].u.bp;

			bp_vp = buf_vnode(tbp);

			buf_setfilter(tbp, NULL, NULL, NULL, NULL);

			if (buf_shadow(tbp))
				sbp = tbp;
			else
				sbp = NULL;

			if (bp_vp) {
				errno = buf_meta_bread(bp_vp,
						       buf_lblkno(tbp),
						       buf_size(tbp),
						       NOCRED,
						       &bp);
				if (errno == 0) {
					if (sbp == NULL && bp != tbp && (buf_flags(tbp) & B_LOCKED)) {
						panic("jnl: abort_tr: got back a different bp! (bp %p should be %p, jnl %p\n",
						      bp, tbp, jnl);
					}
					/*
					 * once the journal has been marked INVALID and aborted,
					 * NO meta data can be written back to the disk, so 
					 * mark the buf_t clean and make sure it's locked in the cache
					 * note: if we found a shadow, the real buf_t needs to be relocked
					 */
					buf_setflags(bp, B_LOCKED);
					buf_markclean(bp);
					buf_brelse(bp);

					KERNEL_DEBUG(0xbbbbc034|DBG_FUNC_NONE, jnl, tr, bp, 0, 0);

					/*
					 * this undoes the vnode_ref() in journal_modify_block_end()
					 */
					vnode_rele_ext(bp_vp, 0, 1);
				} else {
					printf("jnl: %s: abort_tr: could not find block %lld vp %p!\n",
					       jnl->jdev_name, blhdr->binfo[i].bnum, tbp);
					if (bp) {
						buf_brelse(bp);
					}
				}
			}
			if (sbp)
				buf_brelse(sbp);
		}
		next = (block_list_header *)((long)blhdr->binfo[0].bnum);

		// we can free blhdr here since we won't need it any more
		blhdr->binfo[0].bnum = 0xdeadc0de;
		kmem_free(kernel_map, (vm_offset_t)blhdr, tr->tbuffer_size);
	}

	/*
	 * If the transaction we're aborting was the async transaction, then
	 * tell the current transaction that there is no pending trim
	 * any more.
	 */
	lck_rw_lock_exclusive(&jnl->trim_lock);
	if (jnl->async_trim == &tr->trim)
		jnl->async_trim = NULL;
	lck_rw_unlock_exclusive(&jnl->trim_lock);
	
	
	if (tr->trim.extents) {
		kfree(tr->trim.extents, tr->trim.allocated_count * sizeof(dk_extent_t));
	}
	tr->trim.allocated_count = 0;
	tr->trim.extent_count = 0;
	tr->trim.extents = NULL;
	tr->tbuffer     = NULL;
	tr->blhdr       = NULL;
	tr->total_bytes = 0xdbadc0de;
	FREE_ZONE(tr, sizeof(transaction), M_JNL_TR);

	KERNEL_DEBUG(0xbbbbc034|DBG_FUNC_END, jnl, tr, 0, 0, 0);
}


int
journal_end_transaction(journal *jnl)
{
	int ret;
	transaction *tr;
    
	CHECK_JOURNAL(jnl);

	free_old_stuff(jnl);

	if ((jnl->flags & JOURNAL_INVALID) && jnl->owner == NULL) {
		return 0;
	}

	if (jnl->owner != current_thread()) {
		panic("jnl: end_tr: I'm not the owner! jnl %p, owner %p, curact %p\n",
		      jnl, jnl->owner, current_thread());
	}
	jnl->nested_count--;

	if (jnl->nested_count > 0) {
		return 0;
	} else if (jnl->nested_count < 0) {
		panic("jnl: jnl @ %p has negative nested count (%d). bad boy.\n", jnl, jnl->nested_count);
	}
    
	if (jnl->flags & JOURNAL_INVALID) {
		if (jnl->active_tr) {
			if (jnl->cur_tr != NULL) {
				panic("jnl: journal @ %p has active tr (%p) and cur tr (%p)\n",
				      jnl, jnl->active_tr, jnl->cur_tr);
			}
			tr             = jnl->active_tr;
			jnl->active_tr = NULL;

			abort_transaction(jnl, tr);
		}
		journal_unlock(jnl);

		return EINVAL;
	}

	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);

	// clear this out here so that when check_free_space() calls
	// the FS flush function, we don't panic in journal_flush()
	// if the FS were to call that.  note: check_free_space() is
	// called from end_transaction().
	// 
	jnl->active_tr = NULL;
	
	/* Examine the force-journal-flush state in the active txn */
	if (tr->flush_on_completion == TRUE) {
		/*
		 * If the FS requested it, disallow group commit and force the
		 * transaction out to disk immediately.
		 */
		ret = end_transaction(tr, 1, NULL, NULL, TRUE, TRUE);
	}
	else {
		/* in the common path we can simply use the double-buffered journal */
		ret = end_transaction(tr, 0, NULL, NULL, TRUE, FALSE);
	}

	return ret;
}


/* 
 * Flush the contents of the journal to the disk. 
 *
 *  Input: 
 *  	wait_for_IO - 
 *  	If TRUE, wait to write in-memory journal to the disk 
 *  	consistently, and also wait to write all asynchronous 
 *  	metadata blocks to its corresponding locations
 *  	consistently on the disk.  This means that the journal 
 *  	is empty at this point and does not contain any 
 *  	transactions.  This is overkill in normal scenarios  
 *  	but is useful whenever the metadata blocks are required 
 *  	to be consistent on-disk instead of just the journal 
 *  	being consistent; like before live verification 
 *  	and live volume resizing.  
 *
 *  	If FALSE, only wait to write in-memory journal to the 
 *  	disk consistently.  This means that the journal still 
 *  	contains uncommitted transactions and the file system 
 *  	metadata blocks in the journal transactions might be 
 *  	written asynchronously to the disk.  But there is no 
 *  	guarantee that they are written to the disk before 
 *  	returning to the caller.  Note that this option is 
 *  	sufficient for file system data integrity as it 
 *  	guarantees consistent journal content on the disk.
 */
int
journal_flush(journal *jnl, boolean_t wait_for_IO)
{
	boolean_t drop_lock = FALSE;
    
	CHECK_JOURNAL(jnl);
    
	free_old_stuff(jnl);

	if (jnl->flags & JOURNAL_INVALID) {
		return -1;
	}

	KERNEL_DEBUG(DBG_JOURNAL_FLUSH | DBG_FUNC_START, jnl, 0, 0, 0, 0);

	if (jnl->owner != current_thread()) {
		journal_lock(jnl);
		drop_lock = TRUE;
	}

	// if we're not active, flush any buffered transactions
	if (jnl->active_tr == NULL && jnl->cur_tr) {
		transaction *tr = jnl->cur_tr;

		jnl->cur_tr = NULL;

		if (wait_for_IO) {
			wait_condition(jnl, &jnl->flushing, "journal_flush");
			wait_condition(jnl, &jnl->asyncIO, "journal_flush");
		}
		/*
		 * "end_transction" will wait for any current async flush
		 * to complete, before flushing "cur_tr"... because we've
		 * specified the 'must_wait' arg as TRUE, it will then
		 * synchronously flush the "cur_tr"
		 */
		end_transaction(tr, 1, NULL, NULL, drop_lock, TRUE);   // force it to get flushed

	} else  { 
		if (drop_lock == TRUE) {
			journal_unlock(jnl);
		}

		/* Because of pipelined journal, the journal transactions 
		 * might be in process of being flushed on another thread.  
		 * If there is nothing to flush currently, we should 
		 * synchronize ourselves with the pipelined journal thread 
		 * to ensure that all inflight transactions, if any, are 
		 * flushed before we return success to caller.
		 */
		wait_condition(jnl, &jnl->flushing, "journal_flush");
	}
	if (wait_for_IO) {
		wait_condition(jnl, &jnl->asyncIO, "journal_flush");
	}

	KERNEL_DEBUG(DBG_JOURNAL_FLUSH | DBG_FUNC_END, jnl, 0, 0, 0, 0);

	return 0;
}

int
journal_active(journal *jnl)
{
	if (jnl->flags & JOURNAL_INVALID) {
		return -1;
	}
    
	return (jnl->active_tr == NULL) ? 0 : 1;
}

void *
journal_owner(journal *jnl)
{
	return jnl->owner;
}

int journal_uses_fua(journal *jnl)
{
	if (jnl->flags & JOURNAL_DO_FUA_WRITES)
		return 1;
	return 0;
}

/*
 * Relocate the journal.
 * 
 * You provide the new starting offset and size for the journal. You may
 * optionally provide a new tbuffer_size; passing zero defaults to not
 * changing the tbuffer size except as needed to fit within the new journal
 * size.
 * 
 * You must have already started a transaction. The transaction may contain
 * modified blocks (such as those needed to deallocate the old journal,
 * allocate the new journal, and update the location and size of the journal
 * in filesystem-private structures). Any transactions prior to the active
 * transaction will be flushed to the old journal. The new journal will be
 * initialized, and the blocks from the active transaction will be written to
 * the new journal.
 *
 * The caller will need to update the structures that identify the location
 * and size of the journal.  These updates should be made in the supplied
 * callback routine.  These updates must NOT go into a transaction.  You should
 * force these updates to the media before returning from the callback.  In the
 * even of a crash, either the old journal will be found, with an empty journal,
 * or the new journal will be found with the contents of the active transaction.
 *
 * Upon return from the callback, the blocks from the active transaction are
 * written to their normal locations on disk.
 *
 * (Remember that we have to ensure that blocks get committed to the journal
 * before being committed to their normal locations.  But the blocks don't count
 * as committed until the new journal is pointed at.)
 *
 * Upon return, there is still an active transaction: newly allocated, and
 * with no modified blocks.  Call journal_end_transaction as normal.  You may
 * modifiy additional blocks before calling journal_end_transaction, and those
 * blocks will (eventually) go to the relocated journal.
 *
 * Inputs:
 *	jnl				The (opened) journal to relocate.
 *	offset			The new journal byte offset (from start of the journal device).
 *	journal_size	The size, in bytes, of the new journal.
 *	tbuffer_size	The new desired transaction buffer size.  Pass zero to keep
 *					the same size as the current journal.  The size will be
 *					modified as needed to fit the new journal.
 *	callback		Routine called after the new journal has been initialized,
 *					and the active transaction written to the new journal, but
 *					before the blocks are written to their normal locations.
 *					Pass NULL for no callback.
 *	callback_arg	An argument passed to the callback routine.
 *
 * Result:
 *	0				No errors
 *	EINVAL			The offset is not block aligned
 *	EINVAL			The journal_size is not a multiple of the block size
 *	EINVAL			The journal is invalid
 *	(any)			An error returned by journal_flush.
 *
 */
int journal_relocate(journal *jnl, off_t offset, off_t journal_size, int32_t tbuffer_size,
	errno_t (*callback)(void *), void *callback_arg)
{
	int		ret;
	transaction	*tr;
	size_t i = 0;

	/*
	 * Sanity check inputs, and adjust the size of the transaction buffer.
	 */
	if ((offset % jnl->jhdr->jhdr_size) != 0) {
		printf("jnl: %s: relocate: offset 0x%llx is not an even multiple of block size 0x%x\n",
		       jnl->jdev_name, offset, jnl->jhdr->jhdr_size);
		return EINVAL;
	}
	if ((journal_size % jnl->jhdr->jhdr_size) != 0) {
		printf("jnl: %s: relocate: journal size 0x%llx is not an even multiple of block size 0x%x\n",
		       jnl->jdev_name, journal_size, jnl->jhdr->jhdr_size);
		return EINVAL;
	}

	CHECK_JOURNAL(jnl);

	/* Guarantee we own the active transaction. */
	if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
	}
	if (jnl->owner != current_thread()) {
		panic("jnl: relocate: Not the owner! jnl %p, owner %p, curact %p\n",
		      jnl, jnl->owner, current_thread());
	}
	
	if (tbuffer_size == 0)
		tbuffer_size = jnl->tbuffer_size;
	size_up_tbuffer(jnl, tbuffer_size, jnl->jhdr->jhdr_size);
	
	/*
	 * Flush any non-active transactions.  We have to temporarily hide the
	 * active transaction to make journal_flush flush out non-active but
	 * current (unwritten) transactions.
	 */
	tr = jnl->active_tr;
	CHECK_TRANSACTION(tr);
	jnl->active_tr = NULL;
	ret = journal_flush(jnl, TRUE);
	jnl->active_tr = tr;

	if (ret) {
		return ret;
	}
	wait_condition(jnl, &jnl->flushing, "end_transaction");

	/*
	 * At this point, we have completely flushed the contents of the current
	 * journal to disk (and have asynchronously written all of the txns to 
	 * their actual desired locations).  As a result, we can (and must) clear 
	 * out the old_start array.  If we do not, then if the last written transaction
	 * started at the beginning of the journal (starting 1 block into the 
	 * journal file) it could confuse the buffer_flushed callback. This is
	 * because we're about to reset the start/end pointers of the journal header
	 * below. 
	 */
	lock_oldstart(jnl); 
	for (i = 0; i < sizeof (jnl->old_start) / sizeof(jnl->old_start[0]); i++) { 
		jnl->old_start[i] = 0; 
	}
	unlock_oldstart(jnl);

	/* Update the journal's offset and size in memory. */
	jnl->jdev_offset = offset;
	jnl->jhdr->start = jnl->jhdr->end = jnl->jhdr->jhdr_size;
	jnl->jhdr->size = journal_size;
	jnl->active_start = jnl->jhdr->start;
	
	/*
	 * Force the active transaction to be written to the new journal.  Call the
	 * supplied callback after the blocks have been written to the journal, but
	 * before they get written to their normal on-disk locations.
	 */
	jnl->active_tr = NULL;
	ret = end_transaction(tr, 1, callback, callback_arg, FALSE, TRUE);
	if (ret) {
		printf("jnl: %s: relocate: end_transaction failed (%d)\n", jnl->jdev_name, ret);
		goto bad_journal;
	}
	
	/*
	 * Create a new, empty transaction to be the active transaction.  This way
	 * our caller can use journal_end_transaction as usual.
	 */
	ret = journal_allocate_transaction(jnl);
	if (ret) {
		printf("jnl: %s: relocate: could not allocate new transaction (%d)\n", jnl->jdev_name, ret);
		goto bad_journal;
	}
	
	return 0;

bad_journal:
	jnl->flags |= JOURNAL_INVALID;
	abort_transaction(jnl, tr);
	return ret;
}


#else   // !JOURNALING - so provide stub functions

int journal_uses_fua(__unused journal *jnl)
{
	return 0;
}

journal *
journal_create(__unused struct vnode *jvp,
	       __unused off_t         offset,
	       __unused off_t         journal_size,
	       __unused struct vnode *fsvp,
	       __unused size_t        min_fs_blksz,
	       __unused int32_t       flags,
	       __unused int32_t       tbuffer_size,
	       __unused void        (*flush)(void *arg),
	       __unused void         *arg,
	       __unused struct mount *fsmount)
{
    return NULL;
}

journal *
journal_open(__unused struct vnode *jvp,
	     __unused off_t         offset,
	     __unused off_t         journal_size,
	     __unused struct vnode *fsvp,
	     __unused size_t        min_fs_blksz,
	     __unused int32_t       flags,
	     __unused int32_t       tbuffer_size,
	     __unused void        (*flush)(void *arg),
	     __unused void         *arg,
	     __unused struct mount *fsmount)
{
	return NULL;
}


int
journal_modify_block_start(__unused journal *jnl, __unused struct buf *bp)
{
	return EINVAL;
}

int
journal_modify_block_end(__unused journal *jnl,
			 __unused struct buf *bp,
			 __unused void (*func)(struct buf *bp, void *arg),
			 __unused void *arg)
{
	return EINVAL;
}

int
journal_kill_block(__unused journal *jnl, __unused struct buf *bp)
{
	return EINVAL;
}

int journal_relocate(__unused journal *jnl,
		     __unused off_t offset,
		     __unused off_t journal_size,
		     __unused int32_t tbuffer_size,
		     __unused errno_t (*callback)(void *),
		     __unused void *callback_arg)
{
	return EINVAL;
}

void
journal_close(__unused journal *jnl)
{
}

int
journal_start_transaction(__unused journal *jnl)
{
	return EINVAL;
}

int
journal_end_transaction(__unused journal *jnl)
{
	return EINVAL;
}

int
journal_flush(__unused journal *jnl, __unused boolean_t wait_for_IO)
{
	return EINVAL;
}

int
journal_is_clean(__unused struct vnode *jvp,
		 __unused off_t         offset,
		 __unused off_t         journal_size,
		 __unused struct vnode *fsvp,
                 __unused size_t        min_fs_block_size)
{
	return 0;
}


void *
journal_owner(__unused journal *jnl)
{
	return NULL;
}

void 
journal_lock(__unused journal *jnl) 
{
	return;
}

void 
journal_unlock(__unused journal *jnl)
{
	return;
}

__private_extern__ int
journal_trim_add_extent(__unused journal *jnl, 
			__unused uint64_t offset, 
			__unused uint64_t length)
{
	return 0;
}

int
journal_request_immediate_flush(__unused journal *jnl) 
{
	return 0;
}

__private_extern__ int
journal_trim_remove_extent(__unused journal *jnl, 
			   __unused uint64_t offset, 
			   __unused uint64_t length)
{
	return 0;
}

int journal_trim_extent_overlap(__unused journal *jnl, 
				__unused uint64_t offset, 
				__unused uint64_t length, 
				__unused uint64_t *end) 
{
	return 0;
}

#endif  // !JOURNALING
