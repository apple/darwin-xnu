/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

// -- Document ID Tombstone Support --

#include <stdint.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/vfs_context.h>
#include <sys/doc_tombstone.h>
#include <sys/vnode_internal.h>
#include <sys/fsevents.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <string.h>

//
// This function gets the doc_tombstone structure for the
// current thread.  If the thread doesn't have one, the
// structure is allocated.
//
struct doc_tombstone *
doc_tombstone_get(void)
{
	struct  uthread *ut;
	ut = get_bsdthread_info(current_thread());

	if (ut->t_tombstone == NULL) {
		ut->t_tombstone = kalloc(sizeof(struct doc_tombstone));
		if (ut->t_tombstone) {
			memset(ut->t_tombstone, 0, sizeof(struct doc_tombstone));
		}
	}

	return ut->t_tombstone;
}

//
// This routine clears out the current tombstone for the
// current thread and if necessary passes the doc-id of
// the tombstone on to the dst_cnode.
//
// The caller is responsible for generating the appropriate
// fsevents.
//
void
doc_tombstone_clear(struct doc_tombstone *ut, vnode_t *old_vpp)
{
	uint32_t old_id = ut->t_lastop_document_id;

	ut->t_lastop_document_id = 0;
	ut->t_lastop_parent = NULL;
	ut->t_lastop_parent_vid = 0;
	ut->t_lastop_filename[0] = '\0';

	//
	// If the lastop item is still the same and needs to be cleared,
	// clear it.  The following isn't ideal because the vnode might
	// have been recycled.
	//
	if (old_vpp) {
		*old_vpp = NULL;
		if (old_id && ut->t_lastop_item
			&& vnode_vid(ut->t_lastop_item) == ut->t_lastop_item_vid) {
			int res = vnode_get(ut->t_lastop_item);
			if (!res) {
				// Need to check vid again
				if (vnode_vid(ut->t_lastop_item) == ut->t_lastop_item_vid
					&& !ISSET(ut->t_lastop_item->v_lflag, VL_TERMINATE))
					*old_vpp = ut->t_lastop_item;
				else
					vnode_put(ut->t_lastop_item);
			}
		}
	}

	// last, clear these now that we're all done
	ut->t_lastop_item     = NULL;
	ut->t_lastop_fileid   = 0;
	ut->t_lastop_item_vid = 0;
}


//
// This function is used to filter out operations on temp
// filenames.  We have to filter out operations on certain
// temp filenames to work-around questionable application
// behavior from apps like Autocad that perform unusual
// sequences of file system operations for a "safe save".
bool doc_tombstone_should_ignore_name(const char *nameptr, int len)
{
	if (len == 0) {
		len = strlen(nameptr);
	}

	if (   strncmp(nameptr, "atmp", 4) == 0
		|| (len > 4 && strncmp(nameptr+len-4, ".bak", 4) == 0)
		|| (len > 4 && strncmp(nameptr+len-4, ".tmp", 4) == 0)) {
		return true;
	}

	return false;
}

//
// Decide if we need to save a tombstone or not.  Normally we always
// save a tombstone - but if there already is one and the name we're
// given is an ignorable name, then we will not save a tombstone.
//
bool doc_tombstone_should_save(struct doc_tombstone *ut, struct vnode *vp,
							   struct componentname *cnp)
{
	if (cnp->cn_nameptr == NULL) {
		return false;
	}

	if (ut->t_lastop_document_id && ut->t_lastop_item == vp
		&& doc_tombstone_should_ignore_name(cnp->cn_nameptr, cnp->cn_namelen)) {
		return false;
	}

	return true;
}

//
// This function saves a tombstone for the given vnode and name.  The
// tombstone represents the parent directory and name where the document
// used to live and the document-id of that file.  This info is recorded
// in the doc_tombstone structure hanging off the uthread (which assumes
// that all safe-save operations happen on the same thread).
//
// If later on the same parent/name combo comes back into existence then
// we'll preserve the doc-id from this vnode onto the new vnode.
//
// The caller is responsible for generating the appropriate
// fsevents.
//
void
doc_tombstone_save(struct vnode *dvp, struct vnode *vp,
				   struct componentname *cnp, uint64_t doc_id,
				   ino64_t file_id)
{
	struct  doc_tombstone *ut;
	ut = doc_tombstone_get();

	ut->t_lastop_parent         = dvp;
	ut->t_lastop_parent_vid     = vnode_vid(dvp);
	ut->t_lastop_fileid         = file_id;
	ut->t_lastop_item           = vp;
	ut->t_lastop_item_vid       = vp ? vnode_vid(vp) : 0;
    ut->t_lastop_document_id    = doc_id;

	strlcpy((char *)&ut->t_lastop_filename[0], cnp->cn_nameptr, sizeof(ut->t_lastop_filename));
}
