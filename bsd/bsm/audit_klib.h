/*
 * @APPLE_BSD_LICENSE_HEADER_START@
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer. 
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution. 
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * @APPLE_BSD_LICENSE_HEADER_END@
 */

#ifndef _BSM_AUDIT_KLIB_H_
#define _BSM_AUDIT_KLIB_H_

#define AU_PRS_SUCCESS  1
#define AU_PRS_FAILURE  2
#define AU_PRS_BOTH     (AU_PRS_SUCCESS|AU_PRS_FAILURE)

#ifdef KERNEL
#include <bsm/audit_kernel.h>
/*
 * Some of the BSM tokenizer functions take different parameters in the
 * kernel implementations in order to save the copying of large kernel
 * data structures. The prototypes of these functions are declared here.
 */
token_t *kau_to_socket(struct socket_au_info *soi);
token_t *kau_to_attr32(struct vnode_au_info *vni);
token_t *kau_to_attr64(struct vnode_au_info *vni);
int auditon_command_event(int cmd);
int au_preselect(au_event_t event, au_mask_t *mask_p, int sorf);
au_event_t flags_and_error_to_openevent(int oflags, int error);
au_event_t ctlname_to_sysctlevent(int name[], uint64_t valid_arg);
au_event_t msgctl_to_event(int cmd);
au_event_t semctl_to_event(int cmd);
void au_evclassmap_init(void);
void au_evclassmap_insert(au_event_t event, au_class_t class);
au_class_t au_event_class(au_event_t event);

int canon_path(struct proc *p, char *path, char *cpath);




/*
 * Define a system call to audit event mapping table.
 */
extern au_event_t sys_au_event[];
extern int nsys_au_event;	/* number of entries in this table */

#endif /*KERNEL*/

#endif /* ! _BSM_AUDIT_KLIB_H_ */
