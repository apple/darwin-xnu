/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

#ifndef _BSM_KLIB_H_
#define _BSM_KLIB_H_

#define AU_PRS_SUCCESS  1
#define AU_PRS_FAILURE  2
#define AU_PRS_BOTH     (AU_PRS_SUCCESS|AU_PRS_FAILURE)

#ifdef KERNEL
int au_preselect(au_event_t event, au_mask_t *mask_p, int sorf);
au_event_t flags_to_openevent(int oflags);
void fill_vattr(struct vattr *v, struct vnode_au_info *vn_info);
void canon_path(struct proc *p, char *path, char *cpath);
/*
 * Define a system call to audit event mapping table.
 */
extern au_event_t sys_au_event[];
extern int nsys_au_event;	/* number of entries in this table */

#endif /*KERNEL*/

#endif /* ! _BSM_KLIB_H_ */
