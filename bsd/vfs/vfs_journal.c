/*
 * Copyright (c) 1995-2002 Apple Computer, Inc. All rights reserved.
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
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/ubc.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <kern/thread_act.h>
#include <sys/disk.h>
#include <miscfs/specfs/specdev.h>

extern task_t kernel_task;

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


// number of bytes to checksum in a block_list_header
// NOTE: this should be enough to clear out the header
//       fields as well as the first entry of binfo[]
#define BLHDR_CHECKSUM_SIZE 32



static int  end_transaction(transaction *tr, int force_it);
static void abort_transaction(journal *jnl, transaction *tr);
static void dump_journal(journal *jnl);


#define CHECK_JOURNAL(jnl) \
    do { \
    if (jnl == NULL) {\
	panic("%s:%d: null journal ptr?\n", __FILE__, __LINE__);\
    }\
    if (jnl->jdev == NULL) { \
	panic("%s:%d: jdev is null!\n", __FILE__, __LINE__);\
    } \
    if (jnl->fsdev == NULL) { \
	panic("%s:%d: fsdev is null!\n", __FILE__, __LINE__);\
    } \
    if (jnl->jhdr->magic != JOURNAL_HEADER_MAGIC) {\
	panic("%s:%d: jhdr magic corrupted (0x%x != 0x%x)\n",\
	__FILE__, __LINE__, jnl->jhdr->magic, JOURNAL_HEADER_MAGIC);\
    }\
    if (   jnl->jhdr->start <= 0 \
	|| jnl->jhdr->start > jnl->jhdr->size\
	|| jnl->jhdr->start > 128*1024*1024) {\
	panic("%s:%d: jhdr start looks bad (0x%llx max size 0x%llx)\n", \
	__FILE__, __LINE__, jnl->jhdr->start, jnl->jhdr->size);\
    }\
    if (   jnl->jhdr->end <= 0 \
	|| jnl->jhdr->end > jnl->jhdr->size\
	|| jnl->jhdr->end > 128*1024*1024) {\
	panic("%s:%d: jhdr end looks bad (0x%llx max size 0x%llx)\n", \
	__FILE__, __LINE__, jnl->jhdr->end, jnl->jhdr->size);\
    }\
    if (jnl->jhdr->size > 128*1024*1024) {\
	panic("%s:%d: jhdr size looks bad (0x%llx)\n",\
	__FILE__, __LINE__, jnl->jhdr->size);\
    } \
    } while(0)

#define CHECK_TRANSACTION(tr) \
    do {\
    if (tr == NULL) {\
	panic("%s:%d: null transaction ptr?\n", __FILE__, __LINE__);\
    }\
    if (tr->jnl == NULL) {\
	panic("%s:%d: null tr->jnl ptr?\n", __FILE__, __LINE__);\
    }\
    if (tr->blhdr != (block_list_header *)tr->tbuffer) {\
	panic("%s:%d: blhdr (0x%x) != tbuffer (0x%x)\n", __FILE__, __LINE__, tr->blhdr, tr->tbuffer);\
    }\
    if (tr->total_bytes < 0) {\
	panic("%s:%d: tr total_bytes looks bad: %d\n", __FILE__, __LINE__, tr->total_bytes);\
    }\
    if (tr->journal_start < 0 || tr->journal_start > 128*1024*1024) {\
	panic("%s:%d: tr journal start looks bad: 0x%llx\n", __FILE__, __LINE__, tr->journal_start);\
    }\
    if (tr->journal_end < 0 || tr->journal_end > 128*1024*1024) {\
	panic("%s:%d: tr journal end looks bad: 0x%llx\n", __FILE__, __LINE__, tr->journal_end);\
    }\
    if (tr->blhdr && (tr->blhdr->max_blocks <= 0 || tr->blhdr->max_blocks > 2048)) {\
	panic("%s:%d: tr blhdr max_blocks looks bad: %d\n", __FILE__, __LINE__, tr->blhdr->max_blocks);\
    }\
    } while(0)



//
// this isn't a great checksum routine but it will do for now.
// we use it to checksum the journal header and the block list
// headers that are at the start of each transaction.
//
static int
calc_checksum(char *ptr, int len)
{
    int i, cksum=0;

    // this is a lame checksum but for now it'll do
    for(i=0; i < len; i++, ptr++) {
		cksum = (cksum << 8) ^ (cksum + *(unsigned char *)ptr);
    }

    return (~cksum);
}


#define JNL_WRITE 1
#define JNL_READ  2

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
    int         err, io_sz=0, curlen=len;
    struct buf *bp;
	int max_iosize=0, max_vectors;

    if (*offset < 0 || *offset > jnl->jhdr->size) {
		panic("jnl: do_jnl_io: bad offset 0x%llx (max 0x%llx)\n", *offset, jnl->jhdr->size);
    }

  again:
    bp = alloc_io_buf(jnl->jdev, 1);

    if (direction == JNL_WRITE) {
		bp->b_flags  |= 0;   // don't have to set any flags (was: B_WRITEINPROG)
		jnl->jdev->v_numoutput++;
		vfs_io_attributes(jnl->jdev, B_WRITE, &max_iosize, &max_vectors);
    } else if (direction == JNL_READ) {
		bp->b_flags  |= B_READ;
		vfs_io_attributes(jnl->jdev, B_READ, &max_iosize, &max_vectors);
    }

	if (max_iosize == 0) {
		max_iosize = 128 * 1024;
	}

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
		panic("jnl: do_jnl_io: curlen == %d, offset 0x%llx len %d\n", curlen, *offset, len);
    }

    bp->b_bufsize = curlen;
    bp->b_bcount  = curlen;
    bp->b_data    = data;
    bp->b_blkno   = (daddr_t) ((jnl->jdev_offset + *offset) / (off_t)jnl->jhdr->jhdr_size);
    bp->b_lblkno  = (daddr_t) ((jnl->jdev_offset + *offset) / (off_t)jnl->jhdr->jhdr_size);

    err = VOP_STRATEGY(bp);
    if (!err) {
		err = biowait(bp);
    }
    
    bp->b_data    = NULL;
    bp->b_bufsize = bp->b_bcount = 0;
    bp->b_blkno   = bp->b_lblkno = -1;

    free_io_buf(bp);

    if (err) {
		printf("jnl: do_jnl_io: strategy err 0x%x\n", err);
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


static int
write_journal_header(journal *jnl)
{
    int ret;
    off_t jhdr_offset = 0;
    
    // 
    // XXXdbg note: this ioctl doesn't seem to do anything on firewire disks.
    //
    ret = VOP_IOCTL(jnl->jdev, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, NOCRED, current_proc());
    if (ret != 0) {
		printf("jnl: flushing fs disk buffer returned 0x%x\n", ret);
    }


    jnl->jhdr->checksum = 0;
    jnl->jhdr->checksum = calc_checksum((char *)jnl->jhdr, sizeof(struct journal_header));
    if (write_journal_data(jnl, &jhdr_offset, jnl->header_buf, jnl->jhdr->jhdr_size) != jnl->jhdr->jhdr_size) {
		printf("jnl: write_journal_header: error writing the journal header!\n");
		jnl->flags |= JOURNAL_INVALID;
		return -1;
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

    for(tr=jnl->tr_freeme; tr; tr=next) {
		next = tr->next;
		FREE_ZONE(tr, sizeof(transaction), M_JNL_TR);
    }

    jnl->tr_freeme = NULL;
}



//
// This is our callback that lets us know when a buffer has been
// flushed to disk.  It's called from deep within the driver stack
// and thus is quite limited in what it can do.  Notably, it can
// not initiate any new i/o's or allocate/free memory.
//
static void
buffer_flushed_callback(struct buf *bp)
{
    transaction  *tr;
    journal      *jnl;
    transaction  *ctr, *prev=NULL, *next;
    int           i, bufsize;


    //printf("jnl: buf flush: bp @ 0x%x l/blkno %d/%d vp 0x%x tr @ 0x%x\n",
    //	   bp, bp->b_lblkno, bp->b_blkno, bp->b_vp, bp->b_transaction);

    // snarf out the bits we want
    bufsize = bp->b_bufsize;
    tr      = bp->b_transaction;

    bp->b_iodone      = NULL;   // don't call us for this guy again
    bp->b_transaction = NULL;

    //
    // This is what biodone() would do if it didn't call us.
    // NOTE: THIS CODE *HAS* TO BE HERE!
    //
    if (ISSET(bp->b_flags, B_ASYNC)) {	/* if async, release it */
		brelse(bp);
    } else {		                        /* or just wakeup the buffer */	
		CLR(bp->b_flags, B_WANTED);
		wakeup(bp);
    }

    // NOTE: from here on out we do *NOT* touch bp anymore.


    // then we've already seen it
    if (tr == NULL) {
		return;
    }

    CHECK_TRANSACTION(tr);

    jnl = tr->jnl;
    if (jnl->flags & JOURNAL_INVALID) {
		return;
    }

    CHECK_JOURNAL(jnl);

    // update the number of blocks that have been flushed.
    // this buf may represent more than one block so take
    // that into account.
    tr->num_flushed += bufsize;


    // if this transaction isn't done yet, just return as
    // there is nothing to do.
    if ((tr->num_flushed + tr->num_killed) < tr->total_bytes) {
		return;
    }

    //printf("jnl: tr 0x%x (0x%llx 0x%llx) in jnl 0x%x completed.\n",
    //   tr, tr->journal_start, tr->journal_end, jnl);

	// find this entry in the old_start[] index and mark it completed
	simple_lock(&jnl->old_start_lock);
	for(i=0; i < sizeof(jnl->old_start)/sizeof(jnl->old_start[0]); i++) {

		if ((jnl->old_start[i] & ~(0x8000000000000000LL)) == tr->journal_start) {
			jnl->old_start[i] &= ~(0x8000000000000000LL);
			break;
		}
	}
	if (i >= sizeof(jnl->old_start)/sizeof(jnl->old_start[0])) {
		panic("jnl: buffer_flushed: did not find tr w/start @ %lld (tr 0x%x, jnl 0x%x)\n",
			  tr->journal_start, tr, jnl);
	}
	simple_unlock(&jnl->old_start_lock);


    // if we are here then we need to update the journal header
    // to reflect that this transaction is complete
    if (tr->journal_start == jnl->active_start) {
		jnl->active_start = tr->journal_end;
		tr->journal_start = tr->journal_end = (off_t)0;
    }

    // go through the completed_trs list and try to coalesce
    // entries, restarting back at the beginning if we have to.
    for(ctr=jnl->completed_trs; ctr; prev=ctr, ctr=next) {
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
		} else {
			next = ctr->next;
		}
    }
    
    // at this point no one should be using this guy anymore
    tr->total_bytes = 0xfbadc0de;

    // if this is true then we didn't merge with anyone
    // so link ourselves in at the head of the completed
    // transaction list.
    if (tr->journal_start != 0) {
		// put this entry into the correct sorted place
		// in the list instead of just at the head.
		//
	
		prev = NULL;
		for(ctr=jnl->completed_trs; ctr && tr->journal_start > ctr->journal_start; prev=ctr, ctr=ctr->next) {
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
}

static int
update_fs_block(journal *jnl, void *block_ptr, off_t fs_block, size_t bsize)
{
    int         ret;
    struct buf *oblock_bp=NULL;
    
    // first read the block we want.
    ret = meta_bread(jnl->fsdev, (daddr_t)fs_block, bsize, NOCRED, &oblock_bp);
    if (ret != 0) {
		printf("jnl: update_fs_block: error reading fs block # %lld! (ret %d)\n", fs_block, ret);

		if (oblock_bp) {
			brelse(oblock_bp);
			oblock_bp = NULL;
		}

		// let's try to be aggressive here and just re-write the block
		oblock_bp = getblk(jnl->fsdev, (daddr_t)fs_block, bsize, 0, 0, BLK_META);
		if (oblock_bp == NULL) {
			printf("jnl: update_fs_block: getblk() for %lld failed! failing update.\n", fs_block);
			return -1;
		}
    }
	    
    // make sure it's the correct size.
    if (oblock_bp->b_bufsize != bsize) {
		brelse(oblock_bp);
		return -1;
    }

    // copy the journal data over top of it
    memcpy(oblock_bp->b_data, block_ptr, bsize);

    if ((ret = VOP_BWRITE(oblock_bp)) != 0) {
		printf("jnl: update_fs_block: failed to update block %lld (ret %d)\n", fs_block,ret);
		return ret;
    }

    // and now invalidate it so that if someone else wants to read
    // it in a different size they'll be able to do it.
    ret = meta_bread(jnl->fsdev, (daddr_t)fs_block, bsize, NOCRED, &oblock_bp);
    if (oblock_bp) {
		oblock_bp->b_flags |= B_INVAL;
		brelse(oblock_bp);
    }
	    
    return 0;
}


static int
replay_journal(journal *jnl)
{
    int i, ret, checksum, max_bsize;
    struct buf *oblock_bp;
    block_list_header *blhdr;
    off_t offset;
    char *buf, *block_ptr=NULL;
    
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

    // allocate memory for the header_block.  we'll read each blhdr into this
    if (kmem_alloc(kernel_map, (vm_offset_t *)&buf, jnl->jhdr->blhdr_size)) {
		printf("jnl: replay_journal: no memory for block buffer! (%d bytes)\n",
			   jnl->jhdr->blhdr_size);
		return -1;
    }
    

    printf("jnl: replay_journal: from: %lld to: %lld (joffset 0x%llx)\n",
		   jnl->jhdr->start, jnl->jhdr->end, jnl->jdev_offset);

    while(jnl->jhdr->start != jnl->jhdr->end) {
		offset = jnl->jhdr->start;
		ret = read_journal_data(jnl, &offset, buf, jnl->jhdr->blhdr_size);
		if (ret != jnl->jhdr->blhdr_size) {
			printf("jnl: replay_journal: Could not read block list header block @ 0x%llx!\n", offset);
			goto bad_replay;
		}

		blhdr = (block_list_header *)buf;
		checksum = blhdr->checksum;
		blhdr->checksum = 0;
		if (checksum != calc_checksum((char *)blhdr, BLHDR_CHECKSUM_SIZE)) {
			printf("jnl: replay_journal: bad block list header @ 0x%llx (checksum 0x%x != 0x%x)\n",
				   offset, checksum, calc_checksum((char *)blhdr, BLHDR_CHECKSUM_SIZE));
			goto bad_replay;
		}
		if (   blhdr->max_blocks <= 0 || blhdr->max_blocks > 2048
			   || blhdr->num_blocks <= 0 || blhdr->num_blocks > blhdr->max_blocks) {
			printf("jnl: replay_journal: bad looking journal entry: max: %d num: %d\n",
				   blhdr->max_blocks, blhdr->num_blocks);
			goto bad_replay;
		}
	
		for(i=1,max_bsize=0; i < blhdr->num_blocks; i++) {
			if (blhdr->binfo[i].bnum < 0 && blhdr->binfo[i].bnum != (off_t)-1) {
				printf("jnl: replay_journal: bogus block number 0x%llx\n", blhdr->binfo[i].bnum);
				goto bad_replay;
			}
			if (blhdr->binfo[i].bsize > max_bsize) {
				max_bsize = blhdr->binfo[i].bsize;
			}
		}

		// make sure it's at least one page in size.
		if (max_bsize & (PAGE_SIZE - 1)) {
			max_bsize = (max_bsize + PAGE_SIZE) & ~(PAGE_SIZE - 1);
		}

		if (kmem_alloc(kernel_map, (vm_offset_t *)&block_ptr, max_bsize)) {
			goto bad_replay;
		}

		//printf("jnl: replay_journal: %d blocks in journal entry @ 0x%llx\n", blhdr->num_blocks-1,
		//	   jnl->jhdr->start);
		for(i=1; i < blhdr->num_blocks; i++) {
			int size;

			size = blhdr->binfo[i].bsize;

			ret = read_journal_data(jnl, &offset, block_ptr, size);
			if (ret != size) {
				printf("jnl: replay_journal: Could not read journal entry data @ offset 0x%llx!\n", offset);
				goto bad_replay;
			}

			// don't replay "killed" blocks
			if (blhdr->binfo[i].bnum == (off_t)-1) {
				// printf("jnl: replay_journal: skipping killed fs block (slot %d)\n", i);
			} else {
				//printf("jnl: replay_journal: fixing fs block # %lld (%d)\n",
				//	   blhdr->binfo[i].bnum, blhdr->binfo[i].bsize);

				if (update_fs_block(jnl, block_ptr, blhdr->binfo[i].bnum, blhdr->binfo[i].bsize) != 0) {
					goto bad_replay;
				}
			}

			// check if we need to wrap offset back to the beginning
			// (which is just past the journal header)
			//
			if (offset >= jnl->jhdr->size) {
				offset = jnl->jhdr->jhdr_size;
			}
		}

		kmem_free(kernel_map, (vm_offset_t)block_ptr, max_bsize);
		block_ptr = NULL;

		jnl->jhdr->start += blhdr->bytes_used;
		if (jnl->jhdr->start >= jnl->jhdr->size) {
			// wrap around and skip the journal header block
			jnl->jhdr->start = (jnl->jhdr->start % jnl->jhdr->size) + jnl->jhdr->jhdr_size;
		}

		// only update the on-disk journal header if we've reached the
		// last chunk of updates from this transaction.  if binfo[0].bnum
		// is zero then we know we're at the end.
		if (blhdr->binfo[0].bnum == 0) {
			if (write_journal_header(jnl) != 0) {
				goto bad_replay;
			}
		}
    }

    kmem_free(kernel_map, (vm_offset_t)buf, jnl->jhdr->blhdr_size);
    return 0;

  bad_replay:
    if (block_ptr) {
		kmem_free(kernel_map, (vm_offset_t)block_ptr, max_bsize);
    }
    kmem_free(kernel_map, (vm_offset_t)buf, jnl->jhdr->blhdr_size);
    return -1;
}


#define DEFAULT_TRANSACTION_BUFFER_SIZE  (128*1024)
//#define DEFAULT_TRANSACTION_BUFFER_SIZE  (256*1024)  // better performance but uses more mem
#define MAX_TRANSACTION_BUFFER_SIZE      (512*1024)

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
		if (mem_size < (256*1024*1024)) {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE;
		} else if (mem_size < (512*1024*1024)) {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE * 2;
		} else if (mem_size < (1024*1024*1024)) {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE * 3;
		} else if (mem_size >= (1024*1024*1024)) {
			def_tbuffer_size = DEFAULT_TRANSACTION_BUFFER_SIZE * 4;
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
	}
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
			   void         *arg)
{
    journal *jnl;
    int      ret, phys_blksz;

    /* Get the real physical block size. */
    if (VOP_IOCTL(jvp, DKIOCGETBLOCKSIZE, (caddr_t)&phys_blksz, 0, FSCRED, NULL)) {
		return NULL;
    }

    if (phys_blksz > min_fs_blksz) {
		printf("jnl: create: error: phys blksize %d bigger than min fs blksize %d\n",
			   phys_blksz, min_fs_blksz);
		return NULL;
    }

    if ((journal_size % phys_blksz) != 0) {
		printf("jnl: create: journal size 0x%llx is not an even multiple of block size 0x%x\n",
			   journal_size, phys_blksz);
		return NULL;
    }

    MALLOC_ZONE(jnl, struct journal *, sizeof(struct journal), M_JNL_JNL, M_WAITOK);
    memset(jnl, 0, sizeof(*jnl));

    jnl->jdev         = jvp;
    jnl->jdev_offset  = offset;
    jnl->fsdev        = fsvp;
    jnl->flush        = flush;
    jnl->flush_arg    = arg;
    jnl->flags        = (flags & JOURNAL_OPTION_FLAGS_MASK);
	simple_lock_init(&jnl->old_start_lock);
	
    if (kmem_alloc(kernel_map, (vm_offset_t *)&jnl->header_buf, phys_blksz)) {
		printf("jnl: create: could not allocate space for header buffer (%d bytes)\n", phys_blksz);
		goto bad_kmem_alloc;
    }

    memset(jnl->header_buf, 0, phys_blksz);
    
    jnl->jhdr             = (journal_header *)jnl->header_buf;
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
    
    if (semaphore_create(kernel_task, &jnl->jsem, SYNC_POLICY_FIFO, 1) != 0) {
		printf("jnl: journal_create: failed to create journal semaphore..\n");
		goto bad_sem;
    }

    if (write_journal_header(jnl) != 0) {
		printf("jnl: journal_create: failed to write journal header.\n");
		goto bad_write;
    }

    return jnl;


  bad_write:
    semaphore_destroy(kernel_task, jnl->jsem);
  bad_sem:
    kmem_free(kernel_map, (vm_offset_t)jnl->header_buf, phys_blksz);
  bad_kmem_alloc:
    jnl->jhdr = NULL;
	FREE_ZONE(jnl, sizeof(struct journal), M_JNL_JNL);
    return NULL;
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
			 void         *arg)
{
    journal *jnl;
    int      orig_blksz=0, phys_blksz, blhdr_size;
    off_t    hdr_offset=0;

    /* Get the real physical block size. */
    if (VOP_IOCTL(jvp, DKIOCGETBLOCKSIZE, (caddr_t)&phys_blksz, 0, FSCRED, NULL)) {
		return NULL;
    }

    if (phys_blksz > min_fs_blksz) {
		printf("jnl: create: error: phys blksize %d bigger than min fs blksize %d\n",
			   phys_blksz, min_fs_blksz);
		return NULL;
    }

    if ((journal_size % phys_blksz) != 0) {
		printf("jnl: open: journal size 0x%llx is not an even multiple of block size 0x%x\n",
			   journal_size, phys_blksz);
		return NULL;
    }

    MALLOC_ZONE(jnl, struct journal *, sizeof(struct journal), M_JNL_JNL, M_WAITOK);
    memset(jnl, 0, sizeof(*jnl));

    jnl->jdev         = jvp;
    jnl->jdev_offset  = offset;
    jnl->fsdev        = fsvp;
    jnl->flush        = flush;
    jnl->flush_arg    = arg;
    jnl->flags        = (flags & JOURNAL_OPTION_FLAGS_MASK);
	simple_lock_init(&jnl->old_start_lock);

    if (kmem_alloc(kernel_map, (vm_offset_t *)&jnl->header_buf, phys_blksz)) {
		printf("jnl: create: could not allocate space for header buffer (%d bytes)\n", phys_blksz);
		goto bad_kmem_alloc;
    }

    jnl->jhdr = (journal_header *)jnl->header_buf;
    memset(jnl->jhdr, 0, sizeof(journal_header)+4);

    // we have to set this up here so that do_journal_io() will work
    jnl->jhdr->jhdr_size = phys_blksz;

    if (read_journal_data(jnl, &hdr_offset, jnl->jhdr, phys_blksz) != phys_blksz) {
		printf("jnl: open: could not read %d bytes for the journal header.\n",
			   phys_blksz);
		goto bad_journal;
    }

    if (jnl->jhdr->magic != JOURNAL_HEADER_MAGIC && jnl->jhdr->magic != OLD_JOURNAL_HEADER_MAGIC) {
		printf("jnl: open: journal magic is bad (0x%x != 0x%x)\n",
			   jnl->jhdr->magic, JOURNAL_HEADER_MAGIC);
		goto bad_journal;
    }

	// only check if we're the current journal header magic value
	if (jnl->jhdr->magic == JOURNAL_HEADER_MAGIC) {
		int orig_checksum = jnl->jhdr->checksum;

		jnl->jhdr->checksum = 0;
		if (orig_checksum != calc_checksum((char *)jnl->jhdr, sizeof(struct journal_header))) {
			printf("jnl: open: journal checksum is bad (0x%x != 0x%x)\n", orig_checksum,
				   calc_checksum((char *)jnl->jhdr, sizeof(struct journal_header)));
			//goto bad_journal;
		}
	}

	// XXXdbg - convert old style magic numbers to the new one
	if (jnl->jhdr->magic == OLD_JOURNAL_HEADER_MAGIC) {
		jnl->jhdr->magic = JOURNAL_HEADER_MAGIC;
	}

    if (phys_blksz != jnl->jhdr->jhdr_size && jnl->jhdr->jhdr_size != 0) {
		printf("jnl: open: phys_blksz %d does not match journal header size %d\n",
			   phys_blksz, jnl->jhdr->jhdr_size);

		orig_blksz = phys_blksz;
		phys_blksz = jnl->jhdr->jhdr_size;
		if (VOP_IOCTL(jvp, DKIOCSETBLOCKSIZE, (caddr_t)&phys_blksz, FWRITE, FSCRED, NULL)) {
			printf("jnl: could not set block size to %d bytes.\n", phys_blksz);
			goto bad_journal;
		}
//		goto bad_journal;
    }

    if (   jnl->jhdr->start <= 0
		   || jnl->jhdr->start > jnl->jhdr->size
		   || jnl->jhdr->start > 128*1024*1024) {
		printf("jnl: open: jhdr start looks bad (0x%llx max size 0x%llx)\n",
			   jnl->jhdr->start, jnl->jhdr->size);
		goto bad_journal;
    }

    if (   jnl->jhdr->end <= 0
		   || jnl->jhdr->end > jnl->jhdr->size
		   || jnl->jhdr->end > 128*1024*1024) {
		printf("jnl: open: jhdr end looks bad (0x%llx max size 0x%llx)\n",
			   jnl->jhdr->end, jnl->jhdr->size);
		goto bad_journal;
    }

    if (jnl->jhdr->size > 128*1024*1024) {
		printf("jnl: open: jhdr size looks bad (0x%llx)\n", jnl->jhdr->size);
		goto bad_journal;
    }

// XXXdbg - can't do these checks because hfs writes all kinds of
//          non-uniform sized blocks even on devices that have a block size
//          that is larger than 512 bytes (i.e. optical media w/2k blocks).
//          therefore these checks will fail and so we just have to punt and
//          do more relaxed checking...
// XXXdbg    if ((jnl->jhdr->start % jnl->jhdr->jhdr_size) != 0) {
    if ((jnl->jhdr->start % 512) != 0) {
		printf("jnl: open: journal start (0x%llx) not a multiple of 512?\n",
			   jnl->jhdr->start);
		goto bad_journal;
    }

//XXXdbg    if ((jnl->jhdr->end % jnl->jhdr->jhdr_size) != 0) {
    if ((jnl->jhdr->end % 512) != 0) {
		printf("jnl: open: journal end (0x%llx) not a multiple of block size (0x%x)?\n",
			   jnl->jhdr->end, jnl->jhdr->jhdr_size);
		goto bad_journal;
    }

    // take care of replaying the journal if necessary
	if (flags & JOURNAL_RESET) {
		printf("jnl: journal start/end pointers reset! (jnl 0x%x; s 0x%llx e 0x%llx)\n",
			   jnl, jnl->jhdr->start, jnl->jhdr->end);
		jnl->jhdr->start = jnl->jhdr->end;
	} else if (replay_journal(jnl) != 0) {
		printf("jnl: journal_open: Error replaying the journal!\n");
		goto bad_journal;
    }

	if (orig_blksz != 0) {
		VOP_IOCTL(jvp, DKIOCSETBLOCKSIZE, (caddr_t)&orig_blksz, FWRITE, FSCRED, NULL);
		phys_blksz = orig_blksz;
	}

	// make sure this is in sync!
	jnl->active_start = jnl->jhdr->start;

    // set this now, after we've replayed the journal
    size_up_tbuffer(jnl, tbuffer_size, phys_blksz);

    if (semaphore_create(kernel_task, &jnl->jsem, SYNC_POLICY_FIFO, 1) != 0) {
		printf("jnl: journal_create: failed to create journal semaphore..\n");
		goto bad_journal;
    }

    return jnl;

  bad_journal:
	if (orig_blksz != 0) {
		phys_blksz = orig_blksz;
		VOP_IOCTL(jvp, DKIOCSETBLOCKSIZE, (caddr_t)&orig_blksz, FWRITE, FSCRED, NULL);
	}
    kmem_free(kernel_map, (vm_offset_t)jnl->header_buf, phys_blksz);
  bad_kmem_alloc:
	FREE_ZONE(jnl, sizeof(struct journal), M_JNL_JNL);
    return NULL;    
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

    if (jnl->owner != current_act()) {
		int ret;

		while ((ret = semaphore_wait(jnl->jsem)) == KERN_ABORTED) {
			// just keep trying if we've been ^C'ed
		}
		if (ret != 0) {
			printf("jnl: close: sem wait failed.\n");
			return;
		}
    }

    //
    // only write stuff to disk if the journal is still valid
    //
    if ((jnl->flags & JOURNAL_INVALID) == 0) {

		if (jnl->active_tr) {
			journal_end_transaction(jnl);
		}
		
		// flush any buffered transactions
		if (jnl->cur_tr) {
			transaction *tr = jnl->cur_tr;

			jnl->cur_tr = NULL;
			end_transaction(tr, 1);   // force it to get flushed
		}
    
		//start = &jnl->jhdr->start;
		start = &jnl->active_start;
		end   = &jnl->jhdr->end;
    
		while (*start != *end && counter++ < 500) {
			printf("jnl: close: flushing the buffer cache (start 0x%llx end 0x%llx)\n", *start, *end);
			if (jnl->flush) {
				jnl->flush(jnl->flush_arg);
			}
			tsleep((caddr_t)jnl, PRIBIO, "jnl_close", 1);
		}

		if (*start != *end) {
			printf("jnl: close: buffer flushing didn't seem to flush out all the transactions! (0x%llx - 0x%llx)\n",
				   *start, *end);
		}

		// make sure this is in sync when we close the journal
		jnl->jhdr->start = jnl->active_start;

		// if this fails there's not much we can do at this point...
		write_journal_header(jnl);
    } else {
		// if we're here the journal isn't valid any more.
		// so make sure we don't leave any locked blocks lying around
		printf("jnl: close: journal 0x%x, is invalid.  aborting outstanding transactions\n", jnl);
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
				panic("jnl: close: jnl @ 0x%x had both an active and cur tr\n", jnl);
			}
		}
    }

    free_old_stuff(jnl);

    kmem_free(kernel_map, (vm_offset_t)jnl->header_buf, jnl->jhdr->jhdr_size);
    jnl->jhdr = (void *)0xbeefbabe;

    semaphore_destroy(kernel_task, jnl->jsem);
	FREE_ZONE(jnl, sizeof(struct journal), M_JNL_JNL);
}

static void
dump_journal(journal *jnl)
{
    transaction *ctr;

    printf("journal:");
    printf("  jdev_offset %.8llx\n", jnl->jdev_offset);
    printf("  magic: 0x%.8x\n", jnl->jhdr->magic);
    printf("  start: 0x%.8llx\n", jnl->jhdr->start);
    printf("  end:   0x%.8llx\n", jnl->jhdr->end);
    printf("  size:  0x%.8llx\n", jnl->jhdr->size);
    printf("  blhdr size: %d\n", jnl->jhdr->blhdr_size);
    printf("  jhdr size: %d\n", jnl->jhdr->jhdr_size);
    printf("  chksum: 0x%.8x\n", jnl->jhdr->checksum);
    
    printf("  completed transactions:\n");
    for(ctr=jnl->completed_trs; ctr; ctr=ctr->next) {
		printf("    0x%.8llx - 0x%.8llx\n", ctr->journal_start, ctr->journal_end);
    }
}



static off_t
free_space(journal *jnl)
{
    off_t free_space;
	
    if (jnl->jhdr->start < jnl->jhdr->end) {
		free_space = jnl->jhdr->size - (jnl->jhdr->end - jnl->jhdr->start) - jnl->jhdr->jhdr_size;
    } else if (jnl->jhdr->start > jnl->jhdr->end) {
		free_space = jnl->jhdr->start - jnl->jhdr->end;
    } else {
		// journal is completely empty
		free_space = jnl->jhdr->size - jnl->jhdr->jhdr_size;
    }

    return free_space;
}


//
// The journal must be locked on entry to this function.
// The "desired_size" is in bytes.
//
static int
check_free_space(journal *jnl, int desired_size)
{
    int    i, counter=0;

    //printf("jnl: check free space (desired 0x%x, avail 0x%Lx)\n",
//	   desired_size, free_space(jnl));
    
    while (1) {
		if (counter++ == 5000) {
			dump_journal(jnl);
			panic("jnl: check_free_space: buffer flushing isn't working "
				  "(jnl @ 0x%x s %lld e %lld f %lld [active start %lld]).\n", jnl,
				  jnl->jhdr->start, jnl->jhdr->end, free_space(jnl), jnl->active_start);
		}
		if (counter > 7500) {
			printf("jnl: check_free_space: giving up waiting for free space.\n");
			return ENOSPC;
		}

		// make sure there's space in the journal to hold this transaction
		if (free_space(jnl) > desired_size) {
			break;
		}

		//
		// here's where we lazily bump up jnl->jhdr->start.  we'll consume
		// entries until there is enough space for the next transaction.
		//
		simple_lock(&jnl->old_start_lock);
		for(i=0; i < sizeof(jnl->old_start)/sizeof(jnl->old_start[0]); i++) {
			int   counter;

			counter = 0;
			while (jnl->old_start[i] & 0x8000000000000000LL) {
				if (counter++ > 100) {
					panic("jnl: check_free_space: tr starting @ 0x%llx not flushing (jnl 0x%x).\n",
						  jnl->old_start[i], jnl);
				}
				
				simple_unlock(&jnl->old_start_lock);
				if (jnl->flush) {
					jnl->flush(jnl->flush_arg);
				}
				tsleep((caddr_t)jnl, PRIBIO, "check_free_space1", 1);
				simple_lock(&jnl->old_start_lock);
			}

			if (jnl->old_start[i] == 0) {
				continue;
			}

			jnl->jhdr->start  = jnl->old_start[i];
			jnl->old_start[i] = 0;
			if (free_space(jnl) > desired_size) {
				write_journal_header(jnl);
				break;
			}
		}
		simple_unlock(&jnl->old_start_lock);
		
		// if we bumped the start, loop and try again
		if (i < sizeof(jnl->old_start)/sizeof(jnl->old_start[0])) {
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

int
journal_start_transaction(journal *jnl)
{
    int ret;
    transaction *tr;

    CHECK_JOURNAL(jnl);
    
    if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
    }

    if (jnl->owner == current_act()) {
		if (jnl->active_tr == NULL) {
			panic("jnl: start_tr: active_tr is NULL (jnl @ 0x%x, owner 0x%x, current_act 0x%x\n",
				  jnl, jnl->owner, current_act());
		}
		jnl->nested_count++;
		return 0;
    }

    while ((ret = semaphore_wait(jnl->jsem)) == KERN_ABORTED) {
		// just keep looping if we've been ^C'ed
    }
    if (ret != 0) {
		printf("jnl: start_tr: sem wait failed.\n");
		return EINVAL;
    }

    if (jnl->owner != NULL || jnl->nested_count != 0 || jnl->active_tr != NULL) {
		panic("jnl: start_tr: owner 0x%x, nested count 0x%x, active_tr 0x%x jnl @ 0x%x\n",
			  jnl->owner, jnl->nested_count, jnl->active_tr, jnl);
    }

    jnl->owner        = current_act();
    jnl->nested_count = 1;

    free_old_stuff(jnl);

    // make sure there's room in the journal
    if (check_free_space(jnl, jnl->tbuffer_size) != 0) {
		printf("jnl: start transaction failed: no space\n");
		ret = ENOSPC;
		goto bad_start;
    }

    // if there's a buffered transaction, use it.
    if (jnl->cur_tr) {
		jnl->active_tr = jnl->cur_tr;
		jnl->cur_tr    = NULL;

		return 0;
    }

	MALLOC_ZONE(tr, transaction *, sizeof(transaction), M_JNL_TR, M_WAITOK);
    memset(tr, 0, sizeof(transaction));

    tr->tbuffer_size = jnl->tbuffer_size;
    if (kmem_alloc(kernel_map, (vm_offset_t *)&tr->tbuffer, tr->tbuffer_size)) {
		FREE_ZONE(tr, sizeof(transaction), M_JNL_TR);
		printf("jnl: start transaction failed: no tbuffer mem\n");
		ret = ENOMEM;
		goto bad_start;
    }

    // journal replay code checksum check depends on this.
    memset(tr->tbuffer, 0, BLHDR_CHECKSUM_SIZE);

    tr->blhdr = (block_list_header *)tr->tbuffer;
    tr->blhdr->max_blocks = (jnl->jhdr->blhdr_size / sizeof(block_info)) - 1;
    tr->blhdr->num_blocks = 1;      // accounts for this header block
    tr->blhdr->bytes_used = jnl->jhdr->blhdr_size;

    tr->num_blhdrs  = 1;
    tr->total_bytes = jnl->jhdr->blhdr_size;
    tr->jnl         = jnl;

    jnl->active_tr    = tr;

    // printf("jnl: start_tr: owner 0x%x new tr @ 0x%x\n", jnl->owner, tr);

    return 0;

  bad_start:
	jnl->owner        = NULL;
	jnl->nested_count = 0;
	semaphore_signal(jnl->jsem);
	return ret;
}


int
journal_modify_block_start(journal *jnl, struct buf *bp)
{
    transaction *tr;
    
    CHECK_JOURNAL(jnl);

    if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
    }

    // XXXdbg - for debugging I want this to be true.  later it may
    //          not be necessary.
    if ((bp->b_flags & B_META) == 0) {
		panic("jnl: modify_block_start: bp @ 0x%x is not a meta-data block! (jnl 0x%x)\n", bp, jnl);
    }

    tr = jnl->active_tr;
    CHECK_TRANSACTION(tr);

    if (jnl->owner != current_act()) {
		panic("jnl: modify_block_start: called w/out a transaction! jnl 0x%x, owner 0x%x, curact 0x%x\n",
			  jnl, jnl->owner, current_act());
    }

    free_old_stuff(jnl);

    //printf("jnl: mod block start (bp 0x%x vp 0x%x l/blkno %d/%d bsz %d; total bytes %d)\n",
    //   bp, bp->b_vp, bp->b_lblkno, bp->b_blkno, bp->b_bufsize, tr->total_bytes);

    // can't allow blocks that aren't an even multiple of the
    // underlying block size.
    if ((bp->b_bufsize % jnl->jhdr->jhdr_size) != 0) {
		panic("jnl: mod block start: bufsize %d not a multiple of block size %d\n",
			  bp->b_bufsize, jnl->jhdr->jhdr_size);
		return -1;
    }

    // make sure that this transaction isn't bigger than the whole journal
    if (tr->total_bytes+bp->b_bufsize >= (jnl->jhdr->size - jnl->jhdr->jhdr_size)) {
		panic("jnl: transaction too big (%d >= %lld bytes, bufsize %d, tr 0x%x bp 0x%x)\n",
			  tr->total_bytes, (tr->jnl->jhdr->size - jnl->jhdr->jhdr_size), bp->b_bufsize, tr, bp);
		return -1;
    }

    // if the block is dirty and not already locked we have to write
    // it out before we muck with it because it has data that belongs
    // (presumably) to another transaction.
    //
    if ((bp->b_flags & B_DELWRI) && (bp->b_flags & B_LOCKED) == 0) {

		// this will cause it to not be brelse()'d
		bp->b_flags |= B_NORELSE;
		VOP_BWRITE(bp);
    }

    bp->b_flags |= B_LOCKED;
	
    return 0;
}

int
journal_modify_block_abort(journal *jnl, struct buf *bp)
{
    transaction *tr;
	block_list_header *blhdr;
	int i, j;
    
    CHECK_JOURNAL(jnl);

    tr = jnl->active_tr;
	
	//
	// if there's no active transaction then we just want to
	// call brelse() and return since this is just a block
	// that happened to be modified as part of another tr.
	//
	if (tr == NULL) {
		brelse(bp);
		return 0;
	}

    if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
    }

    CHECK_TRANSACTION(tr);
    
    if (jnl->owner != current_act()) {
		panic("jnl: modify_block_abort: called w/out a transaction! jnl 0x%x, owner 0x%x, curact 0x%x\n",
			  jnl, jnl->owner, current_act());
    }

    free_old_stuff(jnl);

    // printf("jnl: modify_block_abort: tr 0x%x bp 0x%x\n", jnl->active_tr, bp);

    // first check if it's already part of this transaction
    for(blhdr=tr->blhdr; blhdr; blhdr=(block_list_header *)((long)blhdr->binfo[0].bnum)) {
		for(i=1; i < blhdr->num_blocks; i++) {
			if (bp == blhdr->binfo[i].bp) {
				if (bp->b_bufsize != blhdr->binfo[i].bsize) {
					panic("jnl: bp @ 0x%x changed size on me! (%d vs. %d, jnl 0x%x)\n",
						  bp, bp->b_bufsize, blhdr->binfo[i].bsize, jnl);
				}
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
		bp->b_flags &= ~(B_LOCKED);
	}

    brelse(bp);
    return 0;
}


int
journal_modify_block_end(journal *jnl, struct buf *bp)
{
    int                i, j, tbuffer_offset;
    char              *blkptr;
    block_list_header *blhdr, *prev=NULL;
    transaction       *tr;

    CHECK_JOURNAL(jnl);

    if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
    }

    tr = jnl->active_tr;
    CHECK_TRANSACTION(tr);

    if (jnl->owner != current_act()) {
		panic("jnl: modify_block_end: called w/out a transaction! jnl 0x%x, owner 0x%x, curact 0x%x\n",
			  jnl, jnl->owner, current_act());
    }

    free_old_stuff(jnl);

    //printf("jnl: mod block end:  (bp 0x%x vp 0x%x l/blkno %d/%d bsz %d, total bytes %d)\n", 
    //   bp, bp->b_vp, bp->b_lblkno, bp->b_blkno, bp->b_bufsize, tr->total_bytes);

    if ((bp->b_flags & B_LOCKED) == 0) {
		panic("jnl: modify_block_end: bp 0x%x not locked! jnl @ 0x%x\n", bp, jnl);
		bp->b_flags |= B_LOCKED;
    }
	 
    // first check if it's already part of this transaction
    for(blhdr=tr->blhdr; blhdr; prev=blhdr,blhdr=(block_list_header *)((long)blhdr->binfo[0].bnum)) {
		tbuffer_offset = jnl->jhdr->blhdr_size;

		for(i=1; i < blhdr->num_blocks; i++) {
			if (bp == blhdr->binfo[i].bp) {
				if (bp->b_bufsize != blhdr->binfo[i].bsize) {
					panic("jnl: bp @ 0x%x changed size on me! (%d vs. %d, jnl 0x%x)\n",
						  bp, bp->b_bufsize, blhdr->binfo[i].bsize, jnl);
				}
				break;
			}
			tbuffer_offset += blhdr->binfo[i].bsize;
		}

		if (i < blhdr->num_blocks) {
			break;
		}
    }

    if (blhdr == NULL
		&& prev
		&& (prev->num_blocks+1) <= prev->max_blocks
		&& (prev->bytes_used+bp->b_bufsize) <= tr->tbuffer_size) {
		blhdr = prev;
    } else if (blhdr == NULL) {
		block_list_header *nblhdr;

		if (prev == NULL) {
			panic("jnl: modify block end: no way man, prev == NULL?!?, jnl 0x%x, bp 0x%x\n", jnl, bp);
		}

		// we got to the end of the list, didn't find the block and there's
		// no room in the block_list_header pointed to by prev
	
		// we allocate another tbuffer and link it in at the end of the list
		// through prev->binfo[0].bnum.  that's a skanky way to do things but
		// avoids having yet another linked list of small data structures to manage.

		if (kmem_alloc(kernel_map, (vm_offset_t *)&nblhdr, tr->tbuffer_size)) {
			panic("jnl: end_tr: no space for new block tr @ 0x%x (total bytes: %d)!\n",
				  tr, tr->total_bytes);
		}

		// journal replay code checksum check depends on this.
		memset(nblhdr, 0, BLHDR_CHECKSUM_SIZE);

		// initialize the new guy
		nblhdr->max_blocks = (jnl->jhdr->blhdr_size / sizeof(block_info)) - 1;
		nblhdr->num_blocks = 1;      // accounts for this header block
		nblhdr->bytes_used = jnl->jhdr->blhdr_size;
	    
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

    // copy the data into the in-memory transaction buffer
    blkptr = (char *)&((char *)blhdr)[tbuffer_offset];
    memcpy(blkptr, bp->b_data, bp->b_bufsize);

    // if this is true then this is a new block we haven't seen
    if (i >= blhdr->num_blocks) {
		vget(bp->b_vp, 0, current_proc());

		blhdr->binfo[i].bnum  = bp->b_blkno;
		blhdr->binfo[i].bsize = bp->b_bufsize;
		blhdr->binfo[i].bp    = bp;

		blhdr->bytes_used += bp->b_bufsize;
		tr->total_bytes   += bp->b_bufsize;

		blhdr->num_blocks++;
    }

    bdwrite(bp);

    return 0;
}

int
journal_kill_block(journal *jnl, struct buf *bp)
{
    int                i;
    block_list_header *blhdr;
    transaction       *tr;

    CHECK_JOURNAL(jnl);

    if (jnl->flags & JOURNAL_INVALID) {
		return EINVAL;
    }

    tr = jnl->active_tr;
    CHECK_TRANSACTION(tr);

    if (jnl->owner != current_act()) {
		panic("jnl: modify_block_end: called w/out a transaction! jnl 0x%x, owner 0x%x, curact 0x%x\n",
			  jnl, jnl->owner, current_act());
    }

    free_old_stuff(jnl);

    if ((bp->b_flags & B_LOCKED) == 0) {
		panic("jnl: kill block: bp 0x%x not locked! jnl @ 0x%x\n", bp, jnl);
    }

    // first check if it's already part of this transaction
    for(blhdr=tr->blhdr; blhdr; blhdr=(block_list_header *)((long)blhdr->binfo[0].bnum)) {

		for(i=1; i < blhdr->num_blocks; i++) {
			if (bp == blhdr->binfo[i].bp) {
				bp->b_flags &= ~B_LOCKED;

				// this undoes the vget() in journal_modify_block_end()
				vrele(bp->b_vp);

				// if the block has the DELWRI and CALL bits sets, then
				// things are seriously weird.  if it was part of another
				// transaction then journal_modify_block_start() should
				// have force it to be written.
				//
				if ((bp->b_flags & B_DELWRI) && (bp->b_flags & B_CALL)) {
					panic("jnl: kill block: this defies all logic! bp 0x%x\n", bp);
				} else {
					tr->num_killed += bp->b_bufsize;
				}

				if (bp->b_flags & B_BUSY) {
					brelse(bp);
				}

				blhdr->binfo[i].bp   = NULL;
				blhdr->binfo[i].bnum = (off_t)-1;
				break;
			}
		}

		if (i < blhdr->num_blocks) {
			break;
		}
    }

    return 0;
}


static int
journal_binfo_cmp(void *a, void *b)
{
    block_info *bi_a = (struct block_info *)a,
 *bi_b = (struct block_info *)b;
    daddr_t res;

    if (bi_a->bp == NULL) {
		return 1;
    }
    if (bi_b->bp == NULL) {
		return -1;
    }

    // don't have to worry about negative block
    // numbers so this is ok to do.
    //
    res = (bi_a->bp->b_blkno - bi_b->bp->b_blkno);

    return (int)res;
}


static int
end_transaction(transaction *tr, int force_it)
{
    int                 i, j, ret, amt;
    off_t               end;
    journal            *jnl = tr->jnl;
    struct buf         *bp;
    block_list_header  *blhdr=NULL, *next=NULL;

	if (jnl->cur_tr) {
		panic("jnl: jnl @ 0x%x already has cur_tr 0x%x, new tr: 0x%x\n",
			  jnl, jnl->cur_tr, tr);
	}

    // if there weren't any modified blocks in the transaction
    // just save off the transaction pointer and return.
    if (tr->total_bytes == jnl->jhdr->blhdr_size) {
		jnl->cur_tr = tr;
		return;
    }

    // if our transaction buffer isn't very full, just hang
    // on to it and don't actually flush anything.  this is
    // what is known as "group commit".  we will flush the
    // transaction buffer if it's full or if we have more than
    // one of them so we don't start hogging too much memory.
    //
    if (   force_it == 0
		   && (jnl->flags & JOURNAL_NO_GROUP_COMMIT) == 0 
		   && tr->num_blhdrs < 3
		   && (tr->total_bytes <= ((tr->tbuffer_size*tr->num_blhdrs) - tr->tbuffer_size/8))) {

		jnl->cur_tr = tr;
		return;
    }


    // if we're here we're going to flush the transaction buffer to disk.
    // make sure there is room in the journal first.
    check_free_space(jnl, tr->total_bytes);

    // range check the end index
    if (jnl->jhdr->end <= 0 || jnl->jhdr->end > jnl->jhdr->size) {
		panic("jnl: end_transaction: end is bogus 0x%llx (sz 0x%llx)\n",
			  jnl->jhdr->end, jnl->jhdr->size);
    }

    // this transaction starts where the current journal ends
    tr->journal_start = jnl->jhdr->end;
    end               = jnl->jhdr->end;

	//
	// if the first entry in old_start[] isn't free yet, loop calling the
	// file system flush routine until it is (or we panic).
	//
	i = 0;
	simple_lock(&jnl->old_start_lock);
	while ((jnl->old_start[0] & 0x8000000000000000LL) != 0) {
		if (jnl->flush) {
			simple_unlock(&jnl->old_start_lock);

			if (jnl->flush) {
				jnl->flush(jnl->flush_arg);
			}

			// yield the cpu so others can get in to clear the lock bit
			(void)tsleep((void *)jnl, PRIBIO, "jnl-old-start-sleep", 1);

			simple_lock(&jnl->old_start_lock);
		}
		if (i++ >= 100) {
			panic("jnl: transaction that started at 0x%llx is not completing! jnl 0x%x\n",
				  jnl->old_start[0] & (~0x8000000000000000LL), jnl);
		}
	}

	//
	// slide everyone else down and put our latest guy in the last
	// entry in the old_start array
	//
	memcpy(&jnl->old_start[0], &jnl->old_start[1], sizeof(jnl->old_start)-sizeof(jnl->old_start[0]));
	jnl->old_start[sizeof(jnl->old_start)/sizeof(jnl->old_start[0]) - 1] = tr->journal_start | 0x8000000000000000LL;

	simple_unlock(&jnl->old_start_lock);


    // for each block, make sure that the physical block # is set
    for(blhdr=tr->blhdr; blhdr; blhdr=next) {

		for(i=1; i < blhdr->num_blocks; i++) {
	    
			bp = blhdr->binfo[i].bp;
			if (bp == NULL) {   // only true if a block was "killed" 
				if (blhdr->binfo[i].bnum != (off_t)-1) {
					panic("jnl: inconsistent binfo (NULL bp w/bnum %lld; jnl @ 0x%x, tr 0x%x)\n",
						  blhdr->binfo[i].bnum, jnl, tr);
				}
				continue;
			}

			if (bp->b_vp == NULL && bp->b_lblkno == bp->b_blkno) {
				panic("jnl: end_tr: DANGER! bp @ 0x%x w/null vp and l/blkno = %d/%d\n",
					  bp, bp->b_lblkno, bp->b_blkno);
			}
	    
			// if the lblkno is the same as blkno and this bp isn't
			// associated with the underlying file system device then
			// we need to call bmap() to get the actual physical block.
			//
			if ((bp->b_lblkno == bp->b_blkno) && (bp->b_vp != jnl->fsdev)) {
				if (VOP_BMAP(bp->b_vp, bp->b_lblkno, NULL, &bp->b_blkno, NULL) != 0) {
					printf("jnl: end_tr: can't bmap the bp @ 0x%x, jnl 0x%x\n", bp, jnl);
					goto bad_journal;
				}
			}
	    
			// update this so we write out the correct physical block number!
			blhdr->binfo[i].bnum = bp->b_blkno;
		}

		next = (block_list_header *)((long)blhdr->binfo[0].bnum);
    }
    
    for(blhdr=tr->blhdr; blhdr; blhdr=(block_list_header *)((long)blhdr->binfo[0].bnum)) {

		amt = blhdr->bytes_used;

		blhdr->checksum = 0;
		blhdr->checksum = calc_checksum((char *)blhdr, BLHDR_CHECKSUM_SIZE);
	
		ret = write_journal_data(jnl, &end, blhdr, amt);
		if (ret != amt) {
			printf("jnl: end_transaction: only wrote %d of %d bytes to the journal!\n",
				   ret, amt);

			goto bad_journal;
		}
    }

    jnl->jhdr->end  = end;    // update where the journal now ends
    tr->journal_end = end;    // the transaction ends here too
    if (tr->journal_start == 0 || tr->journal_end == 0) {
		panic("jnl: end_transaction: bad tr journal start/end: 0x%llx 0x%llx\n",
			  tr->journal_start, tr->journal_end);
    }

    if (write_journal_header(jnl) != 0) {
		goto bad_journal;
    }

    //
    // setup for looping through all the blhdr's.  we null out the
    // tbuffer and blhdr fields so that they're not used any more.
    //
    blhdr       = tr->blhdr;
    tr->tbuffer = NULL;
    tr->blhdr   = NULL;

    // the buffer_flushed_callback will only be called for the 
    // real blocks that get flushed so we have to account for 
    // the block_list_headers here.
    //
    tr->num_flushed = tr->num_blhdrs * jnl->jhdr->blhdr_size;

    // for each block, set the iodone callback and unlock it
    for(; blhdr; blhdr=next) {

		// we can re-order the buf ptrs because everything is written out already
		qsort(&blhdr->binfo[1], blhdr->num_blocks-1, sizeof(block_info), journal_binfo_cmp);

		for(i=1; i < blhdr->num_blocks; i++) {
			if (blhdr->binfo[i].bp == NULL) {
				continue;
			}

			ret = meta_bread(blhdr->binfo[i].bp->b_vp,
							 (daddr_t)blhdr->binfo[i].bp->b_lblkno,
							 blhdr->binfo[i].bp->b_bufsize,
							 NOCRED,
							 &bp);
			if (ret == 0 && bp != NULL) {
				struct vnode *save_vp;
		
				if (bp != blhdr->binfo[i].bp) {
					panic("jnl: end_tr: got back a different bp! (bp 0x%x should be 0x%x, jnl 0x%x\n",
						  bp, blhdr->binfo[i].bp, jnl);
				}

				if ((bp->b_flags & (B_LOCKED|B_DELWRI)) != (B_LOCKED|B_DELWRI)) {
					if (jnl->flags & JOURNAL_CLOSE_PENDING) {
						brelse(bp);
						continue;
					} else {
						panic("jnl: end_tr: !!!DANGER!!! bp 0x%x flags (0x%x) not LOCKED & DELWRI\n", bp, bp->b_flags);
					}
				}

				if (bp->b_iodone != NULL) {
					panic("jnl: bp @ 0x%x (blkno %d, vp 0x%x) has non-null iodone (0x%x) buffflushcb 0x%x\n",
						  bp, bp->b_blkno, bp->b_vp, bp->b_iodone, buffer_flushed_callback);
				}

				save_vp = bp->b_vp;

				bp->b_iodone       = buffer_flushed_callback;
				bp->b_transaction  = tr;
				bp->b_flags       |= B_CALL;
				bp->b_flags       &= ~(B_LOCKED);

				// kicking off the write here helps performance
				bawrite(bp);
				// XXXdbg this is good for testing: bdwrite(bp);
				//bdwrite(bp);
				
				// this undoes the vget() in journal_modify_block_end()
				vrele(save_vp);

			} else {
				printf("jnl: end_transaction: could not find block %Ld vp 0x%x!\n",
					   blhdr->binfo[i].bnum, blhdr->binfo[i].bp);
				if (bp) {
					brelse(bp);
				}
			}
		}

		next = (block_list_header *)((long)blhdr->binfo[0].bnum);

		// we can free blhdr here since we won't need it any more
		blhdr->binfo[0].bnum = 0xdeadc0de;
		kmem_free(kernel_map, (vm_offset_t)blhdr, tr->tbuffer_size);
    }

    //printf("jnl: end_tr: tr @ 0x%x, jnl-blocks: 0x%llx - 0x%llx. exit!\n",
    //   tr, tr->journal_start, tr->journal_end);
    return 0;


  bad_journal:
    jnl->flags |= JOURNAL_INVALID;
    abort_transaction(jnl, tr);
    return -1;
}

static void
abort_transaction(journal *jnl, transaction *tr)
{
    int                i, ret;
    block_list_header *blhdr, *next;
    struct buf        *bp;

    // for each block list header, iterate over the blocks then
    // free up the memory associated with the block list.
    //
    // for each block, clear the lock bit and release it.
    //
    for(blhdr=tr->blhdr; blhdr; blhdr=next) {

		for(i=1; i < blhdr->num_blocks; i++) {
			if (blhdr->binfo[i].bp == NULL) {
				continue;
			}
	    
			ret = meta_bread(blhdr->binfo[i].bp->b_vp,
							 (daddr_t)blhdr->binfo[i].bp->b_lblkno,
							 blhdr->binfo[i].bp->b_bufsize,
							 NOCRED,
							 &bp);
			if (ret == 0) {
				if (bp != blhdr->binfo[i].bp) {
					panic("jnl: abort_tr: got back a different bp! (bp 0x%x should be 0x%x, jnl 0x%x\n",
						  bp, blhdr->binfo[i].bp, jnl);
				}

				// clear the locked bit and the delayed-write bit.  we
				// don't want these blocks going to disk.
				bp->b_flags &= ~(B_LOCKED|B_DELWRI);
				bp->b_flags |= B_INVAL;

				brelse(bp);

			} else {
				printf("jnl: abort_tr: could not find block %Ld vp 0x%x!\n",
					   blhdr->binfo[i].bnum, blhdr->binfo[i].bp);
				if (bp) {
					brelse(bp);
				}
			}
		}

		next = (block_list_header *)((long)blhdr->binfo[0].bnum);

		// we can free blhdr here since we won't need it any more
		blhdr->binfo[0].bnum = 0xdeadc0de;
		kmem_free(kernel_map, (vm_offset_t)blhdr, tr->tbuffer_size);
    }

    tr->tbuffer     = NULL;
    tr->blhdr       = NULL;
    tr->total_bytes = 0xdbadc0de;
	FREE_ZONE(tr, sizeof(transaction), M_JNL_TR);
}


int
journal_end_transaction(journal *jnl)
{
    int ret;
    transaction *tr;
    
    CHECK_JOURNAL(jnl);

	if ((jnl->flags & JOURNAL_INVALID) && jnl->owner == NULL) {
		return 0;
	}

    if (jnl->owner != current_act()) {
		panic("jnl: end_tr: I'm not the owner! jnl 0x%x, owner 0x%x, curact 0x%x\n",
			  jnl, jnl->owner, current_act());
    }

    free_old_stuff(jnl);

    jnl->nested_count--;
    if (jnl->nested_count > 0) {
		return 0;
    } else if (jnl->nested_count < 0) {
		panic("jnl: jnl @ 0x%x has negative nested count (%d). bad boy.\n", jnl, jnl->nested_count);
    }
    
    if (jnl->flags & JOURNAL_INVALID) {
		if (jnl->active_tr) {
			transaction *tr;

			if (jnl->cur_tr != NULL) {
				panic("jnl: journal @ 0x%x has active tr (0x%x) and cur tr (0x%x)\n",
					  jnl, jnl->active_tr, jnl->cur_tr);
			}
	    
			tr             = jnl->active_tr;
			jnl->active_tr = NULL;
			abort_transaction(jnl, tr);
		}

		jnl->owner = NULL;
		semaphore_signal(jnl->jsem);

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
    ret = end_transaction(tr, 0);

    jnl->owner = NULL;
    semaphore_signal(jnl->jsem);

    return ret;
}


int
journal_flush(journal *jnl)
{
    int need_signal = 0;
    
    CHECK_JOURNAL(jnl);
    
    if (jnl->flags & JOURNAL_INVALID) {
		return -1;
    }

    if (jnl->owner != current_act()) {
		int ret;

		while ((ret = semaphore_wait(jnl->jsem)) == KERN_ABORTED) {
			// just keep looping if we've ben ^C'ed 
		}
		if (ret != 0) {
			printf("jnl: flush: sem wait failed.\n");
			return -1;
		}
		need_signal = 1;
    }

    free_old_stuff(jnl);

    // if we're not active, flush any buffered transactions
    if (jnl->active_tr == NULL && jnl->cur_tr) {
		transaction *tr = jnl->cur_tr;

		jnl->cur_tr = NULL;
		end_transaction(tr, 1);   // force it to get flushed
    }

    if (need_signal) {
		semaphore_signal(jnl->jsem);
    }

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
