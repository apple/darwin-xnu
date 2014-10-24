
/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
 * This header contains the structures and function prototypes
 * for the vfs journaling code.  The data types are not meant
 * to be modified by user code.  Just use the functions and do
 * not mess around with the structs.
 */ 
#ifndef _SYS_VFS_JOURNAL_H_
#define _SYS_VFS_JOURNAL_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>

#ifdef __APPLE_API_UNSTABLE

#include <sys/types.h>
#include <kern/locks.h>
#include <sys/disk.h>


typedef struct _blk_info {
    int32_t    bsize;
    union {
	int32_t    cksum;
	uint32_t   sequence_num;
    } b;
} _blk_info;

typedef struct block_info {
    off_t       bnum;                // block # on the file system device
    union {
	_blk_info   bi;
	struct buf *bp;
    } u;
} __attribute__((__packed__)) block_info;

typedef struct block_list_header {
    u_int16_t   max_blocks;          // max number of blocks in this chunk
    u_int16_t   num_blocks;          // number of valid block numbers in block_nums
    int32_t     bytes_used;          // how many bytes of this tbuffer are used
    uint32_t     checksum;            // on-disk: checksum of this header and binfo[0]
    int32_t     flags;               // check-checksums, initial blhdr, etc
    block_info  binfo[1];            // so we can reference them by name
} block_list_header;

#define BLHDR_CHECK_CHECKSUMS   0x0001
#define BLHDR_FIRST_HEADER      0x0002


struct journal;

struct jnl_trim_list {
	uint32_t	allocated_count;
	uint32_t	extent_count;
	dk_extent_t *extents;
};

typedef void (*jnl_trim_callback_t)(void *arg, uint32_t extent_count, const dk_extent_t *extents);

typedef struct transaction {
    int                 tbuffer_size;  // in bytes
    char               *tbuffer;       // memory copy of the transaction
    block_list_header  *blhdr;         // points to the first byte of tbuffer
    int                 num_blhdrs;    // how many buffers we've allocated
    int                 total_bytes;   // total # of bytes in transaction
    int                 num_flushed;   // how many bytes have been flushed
    int                 num_killed;    // how many bytes were "killed"
    off_t               journal_start; // where in the journal this transaction starts
    off_t               journal_end;   // where in the journal this transaction ends
    struct journal     *jnl;           // ptr back to the journal structure
    struct transaction *next;          // list of tr's (either completed or to be free'd)
    uint32_t            sequence_num;
	struct jnl_trim_list trim;
    boolean_t		delayed_header_write;
	boolean_t       flush_on_completion; //flush transaction immediately upon txn end.
} transaction;


/*
 * This is written to block zero of the journal and it
 * maintains overall state about the journal.
 */
typedef struct journal_header {
    int32_t        magic;
    int32_t        endian;
    volatile off_t start;         // zero-based byte offset of the start of the first transaction
    volatile off_t end;           // zero-based byte offset of where free space begins
    off_t          size;          // size in bytes of the entire journal
    int32_t        blhdr_size;    // size in bytes of each block_list_header in the journal
    uint32_t        checksum;
    int32_t        jhdr_size;     // block size (in bytes) of the journal header
    uint32_t       sequence_num;  // NEW FIELD: a monotonically increasing value assigned to all txn's
} journal_header;

#define JOURNAL_HEADER_MAGIC  0x4a4e4c78   // 'JNLx'
#define ENDIAN_MAGIC          0x12345678

//
// we only checksum the original size of the journal_header to remain
// backwards compatible.  the size of the original journal_heade is
// everything up to the the sequence_num field, hence we use the
// offsetof macro to calculate the size.
//
#define JOURNAL_HEADER_CKSUM_SIZE  (offsetof(struct journal_header, sequence_num))

#define OLD_JOURNAL_HEADER_MAGIC  0x4a484452   // 'JHDR'


/*
 * In memory structure about the journal.
 */
typedef struct journal {
    lck_mtx_t           jlock;             // protects the struct journal data
    lck_mtx_t		flock;             // serializes flushing of journal
	lck_rw_t            trim_lock;         // protects the async_trim field, below


    struct vnode       *jdev;              // vnode of the device where the journal lives
    off_t               jdev_offset;       // byte offset to the start of the journal
    const char         *jdev_name;

    struct vnode       *fsdev;             // vnode of the file system device
    struct mount       *fsmount;           // mount of the file system
    
    void              (*flush)(void *arg); // fs callback to flush meta data blocks
    void               *flush_arg;         // arg that's passed to flush()

    int32_t             flags;
    int32_t             tbuffer_size;      // default transaction buffer size
    boolean_t		flush_aborted;
    boolean_t		flushing;
    boolean_t		asyncIO;
    boolean_t		writing_header;
    boolean_t		write_header_failed;
	
    struct jnl_trim_list *async_trim;      // extents to be trimmed by transaction being asynchronously flushed
    jnl_trim_callback_t	trim_callback;
    void				*trim_callback_arg;
    
    char               *header_buf;        // in-memory copy of the journal header
    int32_t             header_buf_size;
    journal_header     *jhdr;              // points to the first byte of header_buf

	uint32_t		saved_sequence_num;
	uint32_t		sequence_num;

    off_t               max_read_size;
    off_t               max_write_size;

    transaction        *cur_tr;            // for group-commit
    transaction        *completed_trs;     // out-of-order transactions that completed
    transaction        *active_tr;         // for nested transactions
    int32_t             nested_count;      // for nested transactions
    void               *owner;             // a ptr that's unique to the calling process

    transaction        *tr_freeme;         // transaction structs that need to be free'd

    volatile off_t      active_start;      // the active start that we only keep in memory
    lck_mtx_t           old_start_lock;    // protects the old_start
    volatile off_t      old_start[16];     // this is how we do lazy start update

    int                 last_flush_err;    // last error from flushing the cache
} journal;

/* internal-only journal flags (top 16 bits) */
#define JOURNAL_CLOSE_PENDING     0x00010000
#define JOURNAL_INVALID           0x00020000
#define JOURNAL_FLUSHCACHE_ERR    0x00040000   // means we already printed this err
#define JOURNAL_NEED_SWAP         0x00080000   // swap any data read from disk
#define JOURNAL_DO_FUA_WRITES     0x00100000   // do force-unit-access writes
#define JOURNAL_USE_UNMAP         0x00200000   // device supports UNMAP (TRIM)


/* journal_open/create options are always in the low-16 bits */
#define JOURNAL_OPTION_FLAGS_MASK 0x0000ffff

__BEGIN_DECLS
/*
 * Prototypes.
 */

/*
 * Call journal_init() to initialize the journaling code (sets up lock attributes)
 */
void      journal_init(void);

/*
 * Call journal_create() to create a new journal.  You only
 * call this once, typically at file system creation time.
 *
 * The "jvp" argument is the vnode where the journal is written.
 * The journal starts at "offset" and is "journal_size" bytes long.
 *
 * The "fsvp" argument is the vnode of your file system.  It may be
 * the same as "jvp".
 *
 * The "min_fs_block_size" argument is the minimum block size
 * (in bytes) that the file system will ever write.  Typically
 * this is the block size of the file system (1k, 4k, etc) but
 * on HFS+ it is the minimum block size of the underlying device.
 *
 * The flags argument lets you disable group commit if you
 * want tighter guarantees on transactions (in exchange for
 * lower performance).
 *
 * The tbuffer_size is the size of the transaction buffer
 * used by the journal. If you specify zero, the journal code
 * will use a reasonable defaults.  The tbuffer_size should 
 * be an integer multiple of the min_fs_block_size.
 *
 * Returns a valid journal pointer or NULL if one could not
 * be created.
 */
journal *journal_create(struct vnode *jvp,
						off_t         offset,
						off_t         journal_size,
						struct vnode *fsvp,
						size_t        min_fs_block_size,
						int32_t       flags,
						int32_t       tbuffer_size,
						void        (*flush)(void *arg),
						void         *arg,
						struct mount *fsmount);

/*
 * Call journal_open() when mounting an existing file system
 * that has a previously created journal.  It will take care
 * of validating the journal and replaying it if necessary.
 *
 * See journal_create() for a description of the arguments.
 *
 * Returns a valid journal pointer of NULL if it runs into
 * trouble reading/playing back the journal.
 */
journal  *journal_open(struct vnode *jvp,
					   off_t         offset,
					   off_t         journal_size,
					   struct vnode *fsvp,
					   size_t        min_fs_block_size,
					   int32_t       flags,
					   int32_t       tbuffer_size,
					   void        (*flush)(void *arg),
					   void         *arg,
					   struct mount *fsmount);

/*
 * Test whether the journal is clean or not.  This is intended
 * to be used when you're mounting read-only.  If the journal
 * is not clean for some reason then you should not mount the
 * volume as your data structures may be in an unknown state.
 */
int journal_is_clean(struct vnode *jvp,
		     off_t         offset,
		     off_t         journal_size,
		     struct vnode *fsvp,
                     size_t        min_fs_block_size);


/*
 * Call journal_close() just before your file system is unmounted.
 * It flushes any outstanding transactions and makes sure the
 * journal is in a consistent state.
 */
void      journal_close(journal *journalp);

/*
 * flags for journal_create/open.  only can use 
 * the low 16 bits for flags because internal 
 * bits go in the high 16.
 */
#define JOURNAL_NO_GROUP_COMMIT   0x00000001
#define JOURNAL_RESET             0x00000002

/*
 * Transaction related functions.
 *
 * Before you start modifying file system meta data, you
 * should call journal_start_transaction().  Then before
 * you modify each block, call journal_modify_block_start()
 * and when you're done, journal_modify_block_end().  When
 * you've modified the last block as part of a transaction,
 * call journal_end_transaction() to commit the changes.
 *
 * If you decide to abort the modifications to a block you
 * should call journal_modify_block_abort().
 *
 * If as part of a transaction you need want to throw out
 * any previous copies of a block (because it got deleted)
 * then call journal_kill_block().  This will mark it so
 * that the journal does not play it back (effectively
 * dropping it).
 *
 * journal_trim_add_extent() marks a range of bytes on the device which should
 * be trimmed (invalidated, unmapped).  journal_trim_remove_extent() marks a
 * range of bytes which should no longer be trimmed.  Accumulated extents
 * will be trimmed when the transaction is flushed to the on-disk journal.
 */
int   journal_start_transaction(journal *jnl);
int   journal_modify_block_start(journal *jnl, struct buf *bp);
int   journal_modify_block_abort(journal *jnl, struct buf *bp);
int   journal_modify_block_end(journal *jnl, struct buf *bp, void (*func)(struct buf *bp, void *arg), void *arg);
int   journal_kill_block(journal *jnl, struct buf *bp);
#ifdef BSD_KERNEL_PRIVATE
int   journal_trim_add_extent(journal *jnl, uint64_t offset, uint64_t length);
int   journal_trim_remove_extent(journal *jnl, uint64_t offset, uint64_t length);
void  journal_trim_set_callback(journal *jnl, jnl_trim_callback_t callback, void *arg);
int   journal_trim_extent_overlap (journal *jnl, uint64_t offset, uint64_t length, uint64_t *end);
/* Mark state in the journal that requests an immediate journal flush upon txn completion */
int   journal_request_immediate_flush (journal *jnl);
#endif
int   journal_end_transaction(journal *jnl);

int   journal_active(journal *jnl);
int   journal_flush(journal *jnl, boolean_t wait_for_IO);
void *journal_owner(journal *jnl);    // compare against current_thread()
int   journal_uses_fua(journal *jnl);
void  journal_lock(journal *jnl);
void  journal_unlock(journal *jnl);


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
 * the new journal. The caller will need to update the structures that
 * identify the location and size of the journal from the callback routine.
 */
int journal_relocate(journal *jnl, off_t offset, off_t journal_size, int32_t tbuffer_size,
	errno_t (*callback)(void *), void *callback_arg);

__END_DECLS

#endif /* __APPLE_API_UNSTABLE */
#endif /* !_SYS_VFS_JOURNAL_H_ */
