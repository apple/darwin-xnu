/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

#if HFS_EXTENTS_TEST

#include "hfs_extents_test.h"
#include "hfs_extents.h"

#else

#include "hfs_extents.h"

// In this file, group refers to a set of 8 extents

static uint32_t hfs_total_blocks(const HFSPlusExtentDescriptor *ext, int count);
static errno_t hfs_ext_iter_next_group(struct hfs_ext_iter *iter);
static errno_t hfs_ext_iter_update(struct hfs_ext_iter *iter,
								   HFSPlusExtentDescriptor *extents,
								   int count,
								   HFSPlusExtentRecord cat_extents);
static errno_t hfs_ext_iter_check_group(hfs_ext_iter_t *iter);

#endif

#define CHECK(x, var, goto_label)									\
	do {															\
		var = (x);													\
		if (var) {													\
			printf("%s:%u error: %d\n", __func__, __LINE__, var);	\
			goto goto_label;										\
		}															\
	} while (0)

#define min(a,b) \
	({ typeof (a) _a = (a); typeof (b) _b = (b); _a < _b ? _a : _b; })

static __attribute__((pure))
const HFSPlusExtentKey *hfs_ext_iter_key(const hfs_ext_iter_t *iter)
{
	return (const HFSPlusExtentKey *)&iter->bt_iter.key;
}

static __attribute__((pure))
HFSPlusExtentKey *hfs_ext_iter_key_mut(hfs_ext_iter_t *iter)
{
	return (HFSPlusExtentKey *)&iter->bt_iter.key;
}

// Returns the total number of blocks for the @count extents provided
uint32_t hfs_total_blocks(const HFSPlusExtentDescriptor *extents, int count)
{
	uint32_t block_count = 0;
	for (int i = 0; i < count; ++i)
		block_count += extents[i].blockCount;
	return block_count;
}

/*
 * Checks a group of extents: makes sure that if it's the last group
 * for a fork, that all the remaining extents are properly zeroed and
 * if it's not then checks that all extents are set.  This also sets
 * @group_block_count and @last_in_fork.  Returns ESTALE if
 * inconsistent.
 */
errno_t hfs_ext_iter_check_group(hfs_ext_iter_t *iter)
{
	filefork_t *ff = VTOF(iter->vp);
	const HFSPlusExtentKey *key = hfs_ext_iter_key(iter);
	uint32_t count = 0;
	int i;

	for (i = 0; i < kHFSPlusExtentDensity; ++i) {
		if (!iter->group[i].blockCount)
			break;
		count += iter->group[i].blockCount;
	}

	if (i < kHFSPlusExtentDensity) {
		iter->last_in_fork = true;
		if (key->startBlock + count != ff_allocblocks(ff))
			goto bad;

		// Check remainder of extents
		for (++i; i < kHFSPlusExtentDensity; ++i) {
			if (iter->group[i].blockCount)
				goto bad;
		}
	} else {
		if (key->startBlock + count > ff_allocblocks(ff))
			goto bad;

		iter->last_in_fork = (key->startBlock + count == ff_allocblocks(ff));
	}

	iter->group_block_count = count;

	return 0;

bad:

#if DEBUG
	printf("hfs_ext_iter_check_group: bad group; start: %u, total blocks: %u\n",
		   key->startBlock, ff_allocblocks(ff));

	for (int j = 0; j < kHFSPlusExtentDensity; ++j) {
		printf("%s<%u, %u>", j ? ", " : "",
			   iter->group[j].startBlock, iter->group[j].blockCount);
	}

	printf("\n");
#endif

	return ESTALE;
}

// NOTE: doesn't copy group data
static void hfs_ext_iter_copy(const hfs_ext_iter_t *src, hfs_ext_iter_t *dst)
{
	dst->vp = src->vp;
	memcpy(&dst->bt_iter.key, &src->bt_iter.key, sizeof(HFSPlusExtentKey));

	dst->file_block = src->file_block;
	dst->ndx = src->ndx;

	dst->bt_iter.hint			= src->bt_iter.hint;
	dst->bt_iter.version		= 0;
	dst->bt_iter.reserved		= 0;
	dst->bt_iter.hitCount		= 0;
	dst->bt_iter.maxLeafRecs	= 0;
}

bool hfs_ext_iter_is_catalog_extents(hfs_ext_iter_t *iter)
{
	return hfs_ext_iter_key(iter)->startBlock == 0;
}

#if !HFS_EXTENTS_TEST

/*
 * Finds the extent for offset.  It might be in the catalog or the extents
 * file.
 */
errno_t hfs_ext_find(vnode_t vp, off_t offset, hfs_ext_iter_t *iter)
{
	errno_t ret;
	hfsmount_t *hfsmp = VTOHFS(vp);

	iter->vp = vp;

	uint32_t end_block, index;
	HFSPlusExtentKey *key = hfs_ext_iter_key_mut(iter);

	filefork_t *ff = VTOF(vp);

	CHECK(SearchExtentFile(hfsmp, ff, offset,
						   key, iter->group, &index,
						   &iter->bt_iter.hint.nodeNum, &end_block), ret, exit);

	iter->ndx = index;
	iter->file_block = end_block - iter->group[index].blockCount;

	if (!key->keyLength) {
		// We're pointing at the catalog record extents so fix up the key
		key->keyLength	= kHFSPlusExtentKeyMaximumLength;
		key->forkType	= (VNODE_IS_RSRC(iter->vp)
						   ? kHFSResourceForkType : kHFSDataForkType);
		key->pad		= 0;
		key->fileID		= VTOC(iter->vp)->c_fileid;
		key->startBlock = 0;
	}

	CHECK(hfs_ext_iter_check_group(iter), ret, exit);

	ret = 0;

exit:

	return MacToVFSError(ret);
}

static uint32_t hfs_ext_iter_next_group_block(const hfs_ext_iter_t *iter)
{
	const HFSPlusExtentKey *key = hfs_ext_iter_key(iter);

	return key->startBlock + iter->group_block_count;
}

/*
 * Move the iterator to the next group.  Don't call if there's a chance
 * there is no entry; the caller should check last_in_fork instead.
 */
static errno_t hfs_ext_iter_next_group(hfs_ext_iter_t *iter)
{
	errno_t ret;
	hfsmount_t *hfsmp = VTOHFS(iter->vp);
	filefork_t * const tree = hfsmp->hfs_extents_cp->c_datafork;
	HFSPlusExtentKey *key = hfs_ext_iter_key_mut(iter);
	const bool catalog_extents = hfs_ext_iter_is_catalog_extents(iter);
	const uint32_t next_block = hfs_ext_iter_next_group_block(iter);

	FSBufferDescriptor fbd = {
		.bufferAddress = &iter->group,
		.itemCount = 1,
		.itemSize = sizeof(iter->group)
	};

	if (catalog_extents) {
		key->startBlock = next_block;

		CHECK(BTSearchRecord(tree, &iter->bt_iter, &fbd, NULL,
							 &iter->bt_iter), ret, exit);
	} else {
		const uint32_t	 file_id = key->fileID;
		const uint8_t 	 fork_type = key->forkType;

		CHECK(BTIterateRecord(tree, kBTreeNextRecord, &iter->bt_iter,
							  &fbd, NULL), ret, exit);

		if (key->fileID != file_id
			|| key->forkType != fork_type
			|| key->startBlock != next_block) {
			// This indicates an inconsistency
			ret = ESTALE;
			goto exit;
		}
	}

	iter->file_block = key->startBlock;
	iter->ndx = 0;

	CHECK(hfs_ext_iter_check_group(iter), ret, exit);

	ret = 0;

exit:

	return MacToVFSError(ret);
}

/*
 * Updates with the extents provided and sets the key up for the next group.
 * It is assumed that any previous record that might collide has been deleted.
 * NOTE: @extents must point to a buffer that can be zero padded to multiple
 * of 8 extents.
 */
errno_t hfs_ext_iter_update(hfs_ext_iter_t *iter,
							HFSPlusExtentDescriptor *extents,
							int count,
							HFSPlusExtentRecord cat_extents)
{
	errno_t				 ret;
	hfsmount_t			*hfsmp	= VTOHFS(iter->vp);
	cnode_t				*cp		= VTOC(iter->vp);
	HFSPlusExtentKey	*key	= hfs_ext_iter_key_mut(iter);
	int					 ndx	= 0;

	if (!extents)
		extents = iter->group;

	if (count % kHFSPlusExtentDensity) {
		// Zero out last group
		bzero(&extents[count], (kHFSPlusExtentDensity
								- (count % 8)) * sizeof(*extents));
	}

	if (hfs_ext_iter_is_catalog_extents(iter)) {
		// Caller is responsible for in-memory updates

		if (cat_extents)
			hfs_ext_copy_rec(extents, cat_extents);

		struct cat_fork fork;

		hfs_fork_copy(&fork, &VTOF(iter->vp)->ff_data, extents);
		hfs_prepare_fork_for_update(VTOF(iter->vp), &fork, &fork, hfsmp->blockSize);

		bool is_rsrc = VNODE_IS_RSRC(iter->vp);
		CHECK(cat_update(hfsmp, &cp->c_desc, &cp->c_attr,
						 is_rsrc ? NULL : &fork,
						 is_rsrc ? &fork : NULL), ret, exit);

		// Set the key to the next group
		key->startBlock = hfs_total_blocks(extents, kHFSPlusExtentDensity);

		ndx += 8;
	}

	// Deal with the remainder which must be overflow extents
	for (; ndx < count; ndx += 8) {
		filefork_t * const tree = hfsmp->hfs_extents_cp->c_datafork;

		FSBufferDescriptor fbd = {
			.bufferAddress = &extents[ndx],
			.itemCount = 1,
			.itemSize = sizeof(HFSPlusExtentRecord)
		};

		CHECK(BTInsertRecord(tree, &iter->bt_iter, &fbd,
							 sizeof(HFSPlusExtentRecord)), ret, exit);

		// Set the key to the next group
		key->startBlock += hfs_total_blocks(&extents[ndx], kHFSPlusExtentDensity);
	}

	ret = 0;

exit:

	return ret;
}

#endif // !HFS_EXTENTS_TEST

static void push_ext(HFSPlusExtentDescriptor *extents, int *count,
					 const HFSPlusExtentDescriptor *ext)
{
	if (!ext->blockCount)
		return;

	if (*count && hfs_ext_end(&extents[*count - 1]) == ext->startBlock)
		extents[*count - 1].blockCount += ext->blockCount;
	else
		extents[(*count)++] = *ext;
}

/*
 * NOTE: Here we rely on the replacement extents not being too big as
 * otherwise the number of BTree records that we have to delete could be
 * too large.
 */
errno_t hfs_ext_replace(hfsmount_t *hfsmp, vnode_t vp,
						uint32_t file_block,
						const HFSPlusExtentDescriptor *repl,
						int repl_count,
						HFSPlusExtentRecord catalog_extents)
{
	errno_t						 ret;
	filefork_t * const			 tree = hfsmp->hfs_extents_cp->c_datafork;
	hfs_ext_iter_t				*iter_in = NULL, *iter_out;
	HFSPlusExtentDescriptor		*extents = NULL;
	HFSPlusExtentDescriptor		*roll_back_extents = NULL;
	int							 roll_back_count = 0;
	const uint32_t				 end_file_block = file_block + hfs_total_blocks(repl, repl_count);
	filefork_t					*ff = VTOF(vp);

	// Indicate we haven't touched catalog extents
	catalog_extents[0].blockCount = 0;

	if (end_file_block > ff_allocblocks(ff)) {
		ret = EINVAL;
		goto exit;
	}

	MALLOC(iter_in, hfs_ext_iter_t *, sizeof(*iter_in) * 2, M_TEMP, M_WAITOK);
	iter_out = iter_in + 1;
	HFSPlusExtentKey *key_in = hfs_ext_iter_key_mut(iter_in);

	// Get to where we want to start
	off_t offset = hfs_blk_to_bytes(file_block, hfsmp->blockSize);

	/*
	 * If the replacement is at the start of a group, we want to pull in the
	 * group before so that we tidy up any padding that we might have done
	 * in a prior hfs_ext_replace call.
	 */
	if (offset > 0)
		--offset;

	CHECK(hfs_ext_find(vp, offset, iter_in), ret, exit);

	const uint32_t start_group_block = key_in->startBlock;

	const int max_roll_back_extents = 128 * 1024 / sizeof(HFSPlusExtentDescriptor);
	MALLOC(roll_back_extents, HFSPlusExtentDescriptor *, 128 * 1024, M_TEMP, M_WAITOK);

	// Move to the first extent in this group
	iter_in->ndx = 0;

	hfs_ext_iter_copy(iter_in, iter_out);

	// Create a buffer for our extents
	const int buffered_extents = roundup(3 * kHFSPlusExtentDensity + repl_count,
										 kHFSPlusExtentDensity);
	MALLOC(extents, HFSPlusExtentDescriptor *,
		   sizeof(*extents) * buffered_extents, M_TEMP, M_WAITOK);
	int count = 0;

	/*
	 * Iterate through the extents that are affected by this replace operation.
	 * We cannot push more than 16 + repl_count extents here; 8 for the group
	 * containing the replacement start, repl_count for the replacements and 8
	 * for the group containing the end.  If we went back a group due to
	 * decrementing the offset above, it's still the same because we know in 
	 * that case the replacement starts at the beginning of the next group.
	 */
	uint32_t block = start_group_block;
	for (;;) {
		if (!iter_in->ndx) {
			hfs_ext_copy_rec(iter_in->group, &roll_back_extents[roll_back_count]);
			roll_back_count += kHFSPlusExtentDensity;

			if (!hfs_ext_iter_is_catalog_extents(iter_in)) {
				// Delete this extent group; we're going to replace it
				CHECK(BTDeleteRecord(tree, &iter_in->bt_iter), ret, exit);
			}
		}

		HFSPlusExtentDescriptor *ext = &iter_in->group[iter_in->ndx];
		if (!ext->blockCount) {
		    /*
			 * We ran out of existing extents so we just write the
			 * extents and we're done.
			 */
			goto finish;
		}

		// If the current extent does not overlap replacement...
		if (block + ext->blockCount <= file_block || block >= end_file_block) {
			// Keep the current extent exactly as it is
			push_ext(extents, &count, ext);
		} else {
			HFSPlusExtentDescriptor dealloc_ext = *ext;

			if (block <= file_block) {
				/*
				 * The middle or tail of the current extent overlaps
				 * the replacement extents.  Keep the non-overlapping
				 * head of the current extent.
				 */
				uint32_t trimmed_len = file_block - block;

				if (trimmed_len) {
					// Push (keep) non-overlapping head of current extent
					push_ext(extents, &count,
							 &(HFSPlusExtentDescriptor){ ext->startBlock,
								 trimmed_len });

					/*
					 * Deallocate the part of the current extent that
					 * overlaps the replacement extents.  That starts
					 * at @file_block.  For now, assume it goes
					 * through the end of the current extent.  (If the
					 * current extent extends beyond the end of the
					 * replacement extents, we'll update the
					 * blockCount below.)
					 */
					dealloc_ext.startBlock += trimmed_len;
					dealloc_ext.blockCount -= trimmed_len;
				}

				// Insert the replacements
				for (int i = 0; i < repl_count; ++i)
					push_ext(extents, &count, &repl[i]);
			}

			if (block + ext->blockCount > end_file_block) {
				/*
				 * The head or middle of the current extent overlaps
				 * the replacement extents.  Keep the non-overlapping
				 * tail of the current extent.
				 */
				uint32_t overlap = end_file_block - block;

				// Push (keep) non-overlapping tail of current extent
				push_ext(extents, &count,
						 &(HFSPlusExtentDescriptor){ ext->startBlock + overlap,
							 ext->blockCount - overlap });

				/*
				 * Deallocate the part of current extent that overlaps
				 * the replacements.
				 */
				dealloc_ext.blockCount = (ext->startBlock + overlap
										  - dealloc_ext.startBlock);
			}

			CHECK(BlockDeallocate(hfsmp, dealloc_ext.startBlock,
								  dealloc_ext.blockCount, 0), ret, exit);
		}

		// Move to next (existing) extent from iterator
		block += ext->blockCount;

		if (++iter_in->ndx >= kHFSPlusExtentDensity) {
			if (block >= end_file_block) {
				if (iter_in->last_in_fork || !(count % kHFSPlusExtentDensity)) {
					/*
					 * This is the easy case.  We've hit the end or we have a 
					 * multiple of 8, so we can just write out the extents we 
					 * have and it should all fit within a transaction.
					 */

					goto finish;
				}

				if (count + kHFSPlusExtentDensity > buffered_extents
					|| (roll_back_count
						+ kHFSPlusExtentDensity > max_roll_back_extents)) {
					/*
					 * We've run out of room for the next group, so drop out
					 * and take a different strategy.
					 */
					break;
				}
			}

			CHECK(hfs_ext_iter_next_group(iter_in), ret, exit);
		}
	} // for (;;)

	/*
	 * We're not at the end so we need to try and pad to a multiple of 8
	 * so that we don't have to touch all the subsequent records.  We pad
	 * by stealing single blocks.
	 */

	int stop_at = 0;

	for (;;) {
		// @in points to the record we're stealing from
		int in = count - 1;

		count = roundup(count, kHFSPlusExtentDensity);

		// @out is where we put the stolen single blocks
		int out = count - 1;

		do {
			if (out <= in) {
				// We suceeded in padding; we're done
				goto finish;
			}

			/*
			 * "Steal" a block, or move a one-block extent within the
			 * @extents array.
			 *
			 * If the extent we're "stealing" from (@in) is only one
			 * block long, we'll end up copying it to @out, setting
			 * @in's blockCount to zero, and decrementing @in.  So, we
			 * either split a multi-block extent; or move it within
			 * the @extents array.
			 */
			extents[out].blockCount = 1;
			extents[out].startBlock = (extents[in].startBlock
									   + extents[in].blockCount - 1);
			--out;
		} while (--extents[in].blockCount || --in >= stop_at);

		// We ran out of extents
		if (roll_back_count + kHFSPlusExtentDensity > max_roll_back_extents) {
			ret = ENOSPC;
			goto exit;
		}

		// Need to shift extents starting at out + 1
		++out;
		memmove(&extents[stop_at], &extents[out],
				(count - out) * sizeof(*extents));
		count -= out - stop_at;

		// Pull in the next group
		CHECK(hfs_ext_iter_next_group(iter_in), ret, exit);

		// Take a copy of these extents for roll back purposes
		hfs_ext_copy_rec(iter_in->group, &roll_back_extents[roll_back_count]);
		roll_back_count += kHFSPlusExtentDensity;

		// Delete this group; we're going to replace it
		CHECK(BTDeleteRecord(tree, &iter_in->bt_iter), ret, exit);

		if (iter_in->last_in_fork) {
			// Great!  We've hit the end.  Coalesce and write out.
			int old_count = count;
			count = 0;

			/*
			 * First coalesce the extents we already have.  Takes
			 * advantage of push_ext coalescing the input extent with
			 * the last extent in @extents.  If the extents are not
			 * contiguous, then this just copies the extents over
			 * themselves and sets @count back to @old_count.
			 */
			for (int i = 0; i < old_count; ++i)
				push_ext(extents, &count, &extents[i]);

			// Make room if necessary
			const int flush_count = buffered_extents - kHFSPlusExtentDensity;
			if (count > flush_count) {
				CHECK(hfs_ext_iter_update(iter_out, extents,
										  flush_count, catalog_extents), ret, exit);

				memmove(&extents[0], &extents[flush_count],
						(count - flush_count) * sizeof(*extents));

				count -= flush_count;
			}

			// Add in the extents we just read in
			for (int i = 0; i < kHFSPlusExtentDensity; ++i) {
				HFSPlusExtentDescriptor *ext = &iter_in->group[i];
				if (!ext->blockCount)
					break;
				push_ext(extents, &count, ext);
			}

			goto finish;
		} // if (iter_in->last_in_fork)

		/*
		 * Otherwise, we're not at the end, so we add these extents and then
		 * try and pad out again to a multiple of 8.  We start by making room.
		 */
		if (count > buffered_extents - kHFSPlusExtentDensity) {
			// Only write out one group here
			CHECK(hfs_ext_iter_update(iter_out, extents,
									  kHFSPlusExtentDensity,
									  catalog_extents), ret, exit);

			memmove(&extents[0], &extents[kHFSPlusExtentDensity],
					(count - kHFSPlusExtentDensity) * sizeof(*extents));

			count -= kHFSPlusExtentDensity;
		}

		// Record where to stop when padding above
		stop_at = count;

		// Copy in the new extents
		hfs_ext_copy_rec(iter_in->group, &extents[count]);
		count += kHFSPlusExtentDensity;
	} // for (;;)

finish:

	// Write the remaining extents
	CHECK(hfs_ext_iter_update(iter_out, extents, count,
							  catalog_extents), ret, exit);

	CHECK(BTFlushPath(hfsmp->hfs_catalog_cp->c_datafork), ret, exit);
	CHECK(BTFlushPath(hfsmp->hfs_extents_cp->c_datafork), ret, exit);

exit:

	if (ret && roll_back_count) {

#define RB_FAILED														\
	do {																\
		printf("hfs_ext_replace:%u: roll back failed\n", __LINE__);		\
		hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);				\
		goto roll_back_failed;											\
	} while (0)

		// First delete any groups we inserted
		HFSPlusExtentKey *key_out = hfs_ext_iter_key_mut(iter_out);

		key_in->startBlock = start_group_block;
		if (!key_in->startBlock && key_out->startBlock > key_in->startBlock) {
			key_in->startBlock += hfs_total_blocks(catalog_extents,
												   kHFSPlusExtentDensity);
		}

		if (key_out->startBlock > key_in->startBlock) {
			FSBufferDescriptor fbd = {
				.bufferAddress = &iter_in->group,
				.itemCount = 1,
				.itemSize = sizeof(iter_in->group)
			};

			if (BTSearchRecord(tree, &iter_in->bt_iter, &fbd, NULL,
							   &iter_in->bt_iter)) {
				RB_FAILED;
			}

			for (;;) {
				if (BTDeleteRecord(tree, &iter_in->bt_iter))
					RB_FAILED;

				key_in->startBlock += hfs_total_blocks(iter_in->group,
													   kHFSPlusExtentDensity);

				if (key_in->startBlock >= key_out->startBlock)
					break;

				if (BTSearchRecord(tree, &iter_in->bt_iter, &fbd, NULL,
								   &iter_in->bt_iter)) {
					RB_FAILED;
				}
			}
		}

		// Position iter_out
		key_out->startBlock = start_group_block;

		// Roll back all the extents
		if (hfs_ext_iter_update(iter_out, roll_back_extents, roll_back_count,
								catalog_extents)) {
			RB_FAILED;
		}

		// And we need to reallocate the blocks we deallocated
		const uint32_t end_block = min(block, end_file_block);
		block = start_group_block;
		for (int i = 0; i < roll_back_count && block < end_block; ++i) {
			HFSPlusExtentDescriptor *ext = &roll_back_extents[i];

			if (block + ext->blockCount <= file_block)
				continue;

			HFSPlusExtentDescriptor alloc_ext = *ext;

			if (block <= file_block) {
				uint32_t trimmed_len = file_block - block;

				alloc_ext.startBlock += trimmed_len;
				alloc_ext.blockCount -= trimmed_len;
			}

			if (block + ext->blockCount > end_file_block) {
				uint32_t overlap = end_file_block - block;

				alloc_ext.blockCount = (ext->startBlock + overlap
										- alloc_ext.startBlock);
			}

			if (hfs_block_alloc(hfsmp, &alloc_ext, HFS_ALLOC_ROLL_BACK, NULL))
				RB_FAILED;

			block += ext->blockCount;
		}

		if (BTFlushPath(hfsmp->hfs_catalog_cp->c_datafork)
			|| BTFlushPath(hfsmp->hfs_extents_cp->c_datafork)) {
			RB_FAILED;
		}
	} // if (ret && roll_back_count)

roll_back_failed:

	FREE(iter_in, M_TEMP);
	FREE(extents, M_TEMP);
	FREE(roll_back_extents, M_TEMP);

	return MacToVFSError(ret);
}
