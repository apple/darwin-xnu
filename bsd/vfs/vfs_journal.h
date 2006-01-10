
/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

typedef struct block_info {
    off_t       bnum;                // block # on the file system device
    size_t      bsize;               // in bytes
    struct buf *bp;
} block_info;

typedef struct block_list_header {
    u_int16_t   max_blocks;          // max number of blocks in this chunk
    u_int16_t   num_blocks;          // number of valid block numbers in block_nums
    int32_t     bytes_used;          // how many bytes of this tbuffer are used
    int32_t     checksum;            // on-disk: checksum of this header and binfo[0]
    int32_t     pad;                 // pad out to 16 bytes
    block_info  binfo[1];            // so we can reference them by name
} block_list_header;


struct journal;

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
    int32_t        checksum;
    int32_t        jhdr_size;     // block size (in bytes) of the journal header
} journal_header;

#define JOURNAL_HEADER_MAGIC  0x4a4e4c78   // 'JNLx'
#define ENDIAN_MAGIC          0x12345678

#define OLD_JOURNAL_HEADER_MAGIC  0x4a484452   // 'JHDR'


/*
 * In memory structure about the journal.
 */
typedef struct journal {
    lck_mtx_t           jlock;             // protects the struct journal data

    struct vnode       *jdev;              // vnode of the device where the journal lives
    off_t               jdev_offset;       // byte offset to the start of the journal

    struct vnode       *fsdev;             // vnode of the file system device
    
    void              (*flush)(void *arg); // fs callback to flush meta data blocks
    void               *flush_arg;         // arg that's passed to flush()

    int32_t             flags;
    int32_t             tbuffer_size;      // default transaction buffer size

    char               *header_buf;        // in-memory copy of the journal header
    journal_header     *jhdr;              // points to the first byte of header_buf

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
						void         *arg);

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
					   void         *arg);

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
 */
int   journal_start_transaction(journal *jnl);
int   journal_modify_block_start(journal *jnl, struct buf *bp);
int   journal_modify_block_abort(journal *jnl, struct buf *bp);
int   journal_modify_block_end(journal *jnl, struct buf *bp);
int   journal_kill_block(journal *jnl, struct buf *bp);
int   journal_end_transaction(journal *jnl);

int   journal_active(journal *jnl);
int   journal_flush(journal *jnl);
void *journal_owner(journal *jnl);    // compare against current_thread()

__END_DECLS

#endif /* __APPLE_API_UNSTABLE */
#endif /* !_SYS_VFS_JOURNAL_H_ */
