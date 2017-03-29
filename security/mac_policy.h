/*
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2007 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/sys/mac_policy.h,v 1.39 2003/04/18 19:57:37 rwatson Exp $
 */

/**
  @file mac_policy.h
  @brief Kernel Interfaces for MAC policy modules

  This header defines the list of operations that are defined by the
  TrustedBSD MAC Framwork on Darwin.  MAC Policy modules register
  with the framework to declare interest in a specific set of
  operations.  If interest in an entry point is not declared, then
  the policy will be ignored when the Framework evaluates that entry
  point.
*/

#ifndef _SECURITY_MAC_POLICY_H_
#define _SECURITY_MAC_POLICY_H_

#ifndef PRIVATE
#warning "MAC policy is not KPI, see Technical Q&A QA1574, this header will be removed in next version"
#endif

#include <security/_label.h>

struct attrlist;
struct auditinfo;
struct bpf_d;
struct cs_blob;
struct devnode;
struct exception_action;
struct fileglob;
struct ifnet;
struct inpcb;
struct ipq;
struct label;
struct mac_module_data;
struct mac_policy_conf;
struct mbuf;
struct mount;
struct msg;
struct msqid_kernel;
struct pipe;
struct pseminfo;
struct pshminfo;
struct sbuf;
struct semid_kernel;
struct shmid_kernel;
struct socket;
struct sockopt;
struct task;
struct thread;
struct tty;
struct ucred;
struct vfs_attr;
struct vnode;
/** @struct dummy */



#ifndef _KAUTH_CRED_T
#define	_KAUTH_CRED_T
typedef struct ucred *kauth_cred_t;
#endif	/* !_KAUTH_CRED_T */

#ifndef __IOKIT_PORTS_DEFINED__
#define __IOKIT_PORTS_DEFINED__
#ifdef __cplusplus
class OSObject;
typedef OSObject *io_object_t;
#else
struct OSObject;
typedef struct OSObject *io_object_t;
#endif
#endif /* __IOKIT_PORTS_DEFINED__ */

/*-
 * MAC entry points are generally named using the following template:
 *
 *   mpo_<object>_<operation>()
 *
 * or:
 *
 *   mpo_<object>_check_<operation>()
 *
 * Entry points are sorted by object type.
 *
 * It may be desirable also to consider some subsystems as "objects", such
 * as system, iokit, etc.
 */

/**
  @name Entry Points for Label Management

  These are the entry points corresponding to the life cycle events for
  kernel objects, such as initialization, creation, and destruction.

  Most policies (that use labels) will initialize labels by allocating
  space for policy-specific data.  In most cases, it is permitted to
  sleep during label initialization operations; it will be noted when
  it is not permitted.

  Initialization usually will not require doing more than allocating a
  generic label for the given object.  What follows initialization is
  creation, where a label is made specific to the object it is associated
  with.  Destruction occurs when the label is no longer needed, such as
  when the corresponding object is destroyed.  All necessary cleanup should
  be performed in label destroy operations.

  Where possible, the label entry points have identical parameters.  If
  the policy module does not require structure-specific label
  information, the same function may be registered in the policy
  operation vector.  Many policies will implement two such generic
  allocation calls: one to handle sleepable requests, and one to handle
  potentially non-sleepable requests.
*/


/**
  @brief Audit event postselection
  @param cred Subject credential
  @param syscode Syscall number
  @param args Syscall arguments
  @param error Syscall errno
  @param retval Syscall return value

  This is the MAC Framework audit postselect, which is called before
  exiting a syscall to determine if an audit event should be committed.
  A return value of MAC_AUDIT_NO forces the audit record to be suppressed.
  Any other return value results in the audit record being committed.

  @warning The suppression behavior will probably go away in Apple's
  future version of the audit implementation.

  @return Return MAC_AUDIT_NO to force suppression of the audit record.
  Any other value results in the audit record being committed.

*/
typedef int mpo_audit_check_postselect_t(
	kauth_cred_t cred,
	unsigned short syscode,
	void *args,
	int error,
	int retval
);
/**
  @brief Audit event preselection
  @param cred Subject credential
  @param syscode Syscall number
  @param args Syscall arguments

  This is the MAC Framework audit preselect, which is called before a
  syscall is entered to determine if an audit event should be created.
  If the MAC policy forces the syscall to be audited, MAC_AUDIT_YES should be
  returned. A return value of MAC_AUDIT_NO causes the audit record to
  be suppressed. Returning MAC_POLICY_DEFAULT indicates that the policy wants
  to defer to the system's existing preselection mechanism.

  When policies return different preferences, the Framework decides what action
  to take based on the following policy.  If any policy returns MAC_AUDIT_YES,
  then create an audit record, else if any policy returns MAC_AUDIT_NO, then
  suppress the creations of an audit record, else defer to the system's
  existing preselection mechanism.

  @warning The audit implementation in Apple's current version is
  incomplete, so the MAC policies have priority over the system's existing
  mechanisms. This will probably change in the future version where
  the audit implementation is more complete.

  @return Return MAC_AUDIT_YES to force auditing of the syscall,
  MAC_AUDIT_NO to force no auditing of the syscall, MAC_AUDIT_DEFAULT
  to allow auditing mechanisms to determine if the syscall is audited.

*/
typedef int mpo_audit_check_preselect_t(
	kauth_cred_t cred,
	unsigned short syscode,
	void *args
);
/**
  @brief Initialize BPF descriptor label
  @param label New label to initialize

  Initialize the label for a newly instantiated BPF descriptor.
  Sleeping is permitted.
*/
typedef void mpo_bpfdesc_label_init_t(
	struct label *label
);
/**
  @brief Destroy BPF descriptor label
  @param label The label to be destroyed

  Destroy a BPF descriptor label.  Since the BPF descriptor
  is going out of scope, policy modules should free any internal
  storage associated with the label so that it may be destroyed.
*/
typedef void mpo_bpfdesc_label_destroy_t(
	struct label *label
);
/**
  @brief Associate a BPF descriptor with a label
  @param cred User credential creating the BPF descriptor
  @param bpf_d The BPF descriptor
  @param bpflabel The new label

  Set the label on a newly created BPF descriptor from the passed
  subject credential. This call will be made when a BPF device node
  is opened by a process with the passed subject credential.
*/
typedef void mpo_bpfdesc_label_associate_t(
	kauth_cred_t cred,
	struct bpf_d *bpf_d,
	struct label *bpflabel
);
/**
  @brief Check whether BPF can read from a network interface
  @param bpf_d Subject; the BPF descriptor
  @param bpflabel Policy label for bpf_d 
  @param ifp Object; the network interface 
  @param ifnetlabel Policy label for ifp

  Determine whether the MAC framework should permit datagrams from
  the passed network interface to be delivered to the buffers of
  the passed BPF descriptor.  Return (0) for success, or an errno
  value for failure.  Suggested failure: EACCES for label mismatches,
  EPERM for lack of privilege.
*/
typedef int mpo_bpfdesc_check_receive_t(
	struct bpf_d *bpf_d,
	struct label *bpflabel,
	struct ifnet *ifp,
	struct label *ifnetlabel
);
/**
  @brief Indicate desire to change the process label at exec time
  @param old Existing subject credential
  @param vp File being executed
  @param offset Offset of binary within file being executed
  @param scriptvp Script being executed by interpreter, if any.
  @param vnodelabel Label corresponding to vp
  @param scriptvnodelabel Script vnode label
  @param execlabel Userspace provided execution label
  @param p Object process
  @param macpolicyattr MAC policy-specific spawn attribute data
  @param macpolicyattrlen Length of policy-specific spawn attribute data
  @see mac_execve
  @see mpo_cred_label_update_execve_t
  @see mpo_vnode_check_exec_t

  Indicate whether this policy intends to update the label of a newly
  created credential from the existing subject credential (old).  This
  call occurs when a process executes the passed vnode.  If a policy
  returns success from this entry point, the mpo_cred_label_update_execve
  entry point will later be called with the same parameters.  Access
  has already been checked via the mpo_vnode_check_exec entry point,
  this entry point is necessary to preserve kernel locking constraints
  during program execution.

  The supplied vnode and vnodelabel correspond with the file actually
  being executed; in the case that the file is interpreted (for
  example, a script), the label of the original exec-time vnode has
  been preserved in scriptvnodelabel.

  The final label, execlabel, corresponds to a label supplied by a
  user space application through the use of the mac_execve system call.

  The vnode lock is held during this operation.  No changes should be
  made to the old credential structure.

  @warning Even if a policy returns 0, it should behave correctly in
  the presence of an invocation of mpo_cred_label_update_execve, as that
  call may happen as a result of another policy requesting a transition.

  @return Non-zero if a transition is required, 0 otherwise.
*/
typedef int mpo_cred_check_label_update_execve_t(
	kauth_cred_t old,
	struct vnode *vp,
	off_t offset,
	struct vnode *scriptvp,
	struct label *vnodelabel,
	struct label *scriptvnodelabel,
	struct label *execlabel,
	struct proc *p,
	void *macpolicyattr,
	size_t macpolicyattrlen
);
/**
  @brief Access control check for relabelling processes
  @param cred Subject credential
  @param newlabel New label to apply to the user credential
  @see mpo_cred_label_update_t
  @see mac_set_proc

  Determine whether the subject identified by the credential can relabel
  itself to the supplied new label (newlabel).  This access control check
  is called when the mac_set_proc system call is invoked.  A user space
  application will supply a new value, the value will be internalized
  and provided in newlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_cred_check_label_update_t(
	kauth_cred_t cred,
	struct label *newlabel
);
/**
  @brief Access control check for visibility of other subjects
  @param u1 Subject credential
  @param u2 Object credential

  Determine whether the subject identified by the credential u1 can
  "see" other subjects with the passed subject credential u2. This call
  may be made in a number of situations, including inter-process status
  sysctls used by ps, and in procfs lookups.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to hide visibility.
*/
typedef int mpo_cred_check_visible_t(
	kauth_cred_t u1,
	kauth_cred_t u2
);
/**
  @brief Associate a credential with a new process at fork
  @param cred credential to inherited by new process
  @param proc the new process

  Allow a process to associate the credential with a new
  process for reference countng purposes.
  NOTE: the credential can be dis-associated in ways other
        than exit - so this strategy is flawed - should just
	catch label destroy callback.
*/
typedef void mpo_cred_label_associate_fork_t(
	kauth_cred_t cred,
	proc_t proc
);
/**
  @brief Create the first process
  @param cred Subject credential to be labeled

  Create the subject credential of process 0, the parent of all BSD
  kernel processes.  Policies should update the label in the
  previously initialized credential structure.
*/
typedef void mpo_cred_label_associate_kernel_t(
	kauth_cred_t cred
);
/**
  @brief Create a credential label
  @param parent_cred Parent credential
  @param child_cred Child credential

  Set the label of a newly created credential, most likely using the
  information in the supplied parent credential.

  @warning This call is made when crcopy or crdup is invoked on a
  newly created struct ucred, and should not be confused with a
  process fork or creation event.
*/
typedef void mpo_cred_label_associate_t(
	kauth_cred_t parent_cred,
	kauth_cred_t child_cred
);
/**
  @brief Create the first process
  @param cred Subject credential to be labeled

  Create the subject credential of process 1, the parent of all BSD
  user processes.  Policies should update the label in the previously
  initialized credential structure.  This is the 'init' process.
*/
typedef void mpo_cred_label_associate_user_t(
	kauth_cred_t cred
);
/**
  @brief Destroy credential label
  @param label The label to be destroyed

  Destroy a user credential label.  Since the user credential
  is going out of scope, policy modules should free any internal
  storage associated with the label so that it may be destroyed.
*/
typedef void mpo_cred_label_destroy_t(
	struct label *label
);
/**
  @brief Externalize a user credential label for auditing
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a user credential for
  inclusion in an audit record.  An externalized label consists of a text
  representation of the label contents that will be added to the audit record
  as part of a text token.  Policy-agnostic user space tools will display
  this externalized version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data.

*/
typedef int mpo_cred_label_externalize_audit_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Externalize a user credential label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a user
  credential.  An externalized label consists of a text representation
  of the label contents that can be used with user applications.
  Policy-agnostic user space tools will display this externalized
  version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data.

*/
typedef int mpo_cred_label_externalize_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Initialize user credential label
  @param label New label to initialize

  Initialize the label for a newly instantiated user credential.
  Sleeping is permitted.
*/
typedef void mpo_cred_label_init_t(
	struct label *label
);
/**
  @brief Internalize a user credential label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce a user credential label from an external representation.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data.

*/
typedef int mpo_cred_label_internalize_t(
	struct label *label,
	char *element_name,
	char *element_data
);
/**
  @brief Update credential at exec time
  @param old_cred Existing subject credential
  @param new_cred New subject credential to be labeled
  @param p Object process.
  @param vp File being executed
  @param offset Offset of binary within file being executed
  @param scriptvp Script being executed by interpreter, if any.
  @param vnodelabel Label corresponding to vp
  @param scriptvnodelabel Script vnode label
  @param execlabel Userspace provided execution label
  @param csflags Code signing flags to be set after exec
  @param macpolicyattr MAC policy-specific spawn attribute data.
  @param macpolicyattrlen Length of policy-specific spawn attribute data.
  @see mac_execve
  @see mpo_cred_check_label_update_execve_t
  @see mpo_vnode_check_exec_t

  Update the label of a newly created credential (new) from the
  existing subject credential (old).  This call occurs when a process
  executes the passed vnode and one of the loaded policy modules has
  returned success from the mpo_cred_check_label_update_execve entry point.
  Access has already been checked via the mpo_vnode_check_exec entry
  point, this entry point is only used to update any policy state.

  The supplied vnode and vnodelabel correspond with the file actually
  being executed; in the case that the file is interpreted (for
  example, a script), the label of the original exec-time vnode has
  been preserved in scriptvnodelabel.

  The final label, execlabel, corresponds to a label supplied by a
  user space application through the use of the mac_execve system call.

  If non-NULL, the value pointed to by disjointp will be set to 0 to
  indicate that the old and new credentials are not disjoint, or 1 to
  indicate that they are.

  The vnode lock is held during this operation.  No changes should be
  made to the old credential structure.
  @return 0 on success, Otherwise, return non-zero if update results in
  termination of child.
*/
typedef int mpo_cred_label_update_execve_t(
	kauth_cred_t old_cred,
	kauth_cred_t new_cred,
	struct proc *p,
	struct vnode *vp,
	off_t offset,
	struct vnode *scriptvp,
	struct label *vnodelabel,
	struct label *scriptvnodelabel,
	struct label *execlabel,
	u_int *csflags,
	void *macpolicyattr,
	size_t macpolicyattrlen,
	int *disjointp
);
/**
  @brief Update a credential label
  @param cred The existing credential
  @param newlabel A new label to apply to the credential
  @see mpo_cred_check_label_update_t
  @see mac_set_proc

  Update the label on a user credential, using the supplied new label.
  This is called as a result of a process relabel operation.  Access
  control was already confirmed by mpo_cred_check_label_update.
*/
typedef void mpo_cred_label_update_t(
	kauth_cred_t cred,
	struct label *newlabel
);
/**
  @brief Create a new devfs device
  @param dev Major and minor numbers of special file
  @param de "inode" of new device file
  @param label Destination label
  @param fullpath Path relative to mount (e.g. /dev) of new device file

  This entry point labels a new devfs device. The label will likely be based
  on the path to the device, or the major and minor numbers.
  The policy should store an appropriate label into 'label'.
*/
typedef void mpo_devfs_label_associate_device_t(
	dev_t dev,
	struct devnode *de,
	struct label *label,
	const char *fullpath
);
/**
  @brief Create a new devfs directory
  @param dirname Name of new directory
  @param dirnamelen Length of 'dirname'
  @param de "inode" of new directory
  @param label Destination label
  @param fullpath Path relative to mount (e.g. /dev) of new directory

  This entry point labels a new devfs directory. The label will likely be
  based on the path of the new directory. The policy should store an appropriate
  label into 'label'. The devfs root directory is labelled in this way.
*/
typedef void mpo_devfs_label_associate_directory_t(
	const char *dirname,
	int dirnamelen,
	struct devnode *de,
	struct label *label,
	const char *fullpath
);
/**
  @brief Copy a devfs label
  @param src Source devfs label
  @param dest Destination devfs label

  Copy the label information from src to dest.  The devfs file system
  often duplicates (splits) existing device nodes rather than creating
  new ones.
*/
typedef void mpo_devfs_label_copy_t(
	struct label *src,
	struct label *dest
);
/**
  @brief Destroy devfs label
  @param label The label to be destroyed

  Destroy a devfs entry label.  Since the object is going out
  of scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_devfs_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize devfs label
  @param label New label to initialize

  Initialize the label for a newly instantiated devfs entry.  Sleeping
  is permitted.
*/
typedef void mpo_devfs_label_init_t(
	struct label *label
);
/**
  @brief Update a devfs label after relabelling its vnode
  @param mp Devfs mount point
  @param de Affected devfs directory entry
  @param delabel Label of devfs directory entry
  @param vp Vnode associated with de
  @param vnodelabel New label of vnode

  Update a devfs label when its vnode is manually relabelled,
  for example with setfmac(1). Typically, this will simply copy
  the vnode label into the devfs label.
*/
typedef void mpo_devfs_label_update_t(
	struct mount *mp,
	struct devnode *de,
	struct label *delabel,
	struct vnode *vp,
	struct label *vnodelabel
);
/**
  @brief Access control for sending an exception to an exception action
  @param crashlabel The crashing process's label
  @param action Exception action
  @param exclabel Policy label for exception action

  Determine whether the the exception message caused by the victim
  process can be sent to the exception action.

  @return Return 0 if the message can be sent, otherwise an
  appropriate value for errno should be returned.
*/
typedef int mpo_exc_action_check_exception_send_t(
	struct label *crashlabel,
	struct exception_action *action,
	struct label *exclabel
);
/**
  @brief Create an exception action label
  @param action Exception action to label
  @param exclabel Policy label to be filled in for exception action

  Set the label on an exception action.
*/
typedef void mpo_exc_action_label_associate_t(
	struct exception_action *action,
	struct label *exclabel
);
/**
  @brief Copy an exception action label
  @param src Source exception action label
  @param dest Destination exception action label

  Copy the label information from src to dest.
  Exception actions are often inherited, e.g. from parent to child.
  In that case, the labels are copied instead of created fresh.
*/
typedef void mpo_exc_action_label_copy_t(
	struct label *src,
	struct label *dest
);
/**
 @brief Destroy exception action label
 @param label The label to be destroyed

 Destroy the label on an exception action.  In this entry point, a
 policy module should free any internal storage associated with
 label so that it may be destroyed.
*/
typedef void mpo_exc_action_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize exception action label
  @param label New label to initialize

  Initialize a label for an exception action.
*/
typedef int mpo_exc_action_label_init_t(
	struct label *label
);
/**
  @brief Update the label on an exception action
  @param p Process to update the label from
  @param exclabel Policy label to be updated for exception action

  Update the credentials of an exception action with the given task.
*/
typedef void mpo_exc_action_label_update_t(
	struct proc *p,
	struct label *exclabel
);
/**
  @brief Access control for changing the offset of a file descriptor
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg

  Determine whether the subject identified by the credential can
  change the offset of the file represented by fg.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_file_check_change_offset_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label
);
/**
  @brief Access control for creating a file descriptor
  @param cred Subject credential

  Determine whether the subject identified by the credential can
  allocate a new file descriptor.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_file_check_create_t(
	kauth_cred_t cred
);
/**
  @brief Access control for duplicating a file descriptor
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg
  @param newfd New file descriptor number

  Determine whether the subject identified by the credential can
  duplicate the fileglob structure represented by fg and as file
  descriptor number newfd.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_file_check_dup_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label,
	int newfd
);
/**
  @brief Access control check for fcntl
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg
  @param cmd Control operation to be performed; see fcntl(2)
  @param arg fcnt arguments; see fcntl(2)

  Determine whether the subject identified by the credential can perform
  the file control operation indicated by cmd.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_file_check_fcntl_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label,
	int cmd,
	user_long_t arg
);
/**
  @brief Access control check for mac_get_fd
  @param cred Subject credential
  @param fg Fileglob structure
  @param elements Element buffer
  @param len Length of buffer

  Determine whether the subject identified by the credential should be allowed
  to get an externalized version of the label on the object indicated by fd.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_file_check_get_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	char *elements,
	int len
);
/**
  @brief Access control for getting the offset of a file descriptor
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg

  Determine whether the subject identified by the credential can
  get the offset of the file represented by fg.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_file_check_get_offset_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label
);
/**
  @brief Access control for inheriting a file descriptor
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg

  Determine whether the subject identified by the credential can
  inherit the fileglob structure represented by fg.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_file_check_inherit_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label
);
/**
  @brief Access control check for file ioctl
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg
  @param cmd The ioctl command; see ioctl(2)

  Determine whether the subject identified by the credential can perform
  the ioctl operation indicated by cmd.

  @warning Since ioctl data is opaque from the standpoint of the MAC
  framework, policies must exercise extreme care when implementing
  access control checks.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_file_check_ioctl_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label,
	unsigned int cmd
);
/**
  @brief Access control check for file locking
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg
  @param op The lock operation (F_GETLK, F_SETLK, F_UNLK)
  @param fl The flock structure

  Determine whether the subject identified by the credential can perform
  the lock operation indicated by op and fl on the file represented by fg.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_file_check_lock_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label,
	int op,
	struct flock *fl
);
/**
  @brief Check with library validation if a macho slice is allowed to be combined into a proc.
  @param p Subject process
  @param fg Fileglob structure
  @param slice_offset offset of the code slice
  @param error_message error message returned to user-space in case of error (userspace pointer)
  @param error_message_size error message size

  Its a little odd that the MAC/kext writes into userspace since this
  implies there is only one MAC module that implements this, however
  the alterantive is to allocate memory in xnu, on the hope that
  the MAC module will use it, or allocated in the MAC module and then
  free it in xnu. Either of these are very appeling, so lets go with
  the slightly more hacky way.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_file_check_library_validation_t(
	struct proc *p,
	struct fileglob *fg,
	off_t slice_offset,
	user_long_t error_message,
	size_t error_message_size
);
/**
  @brief Access control check for mapping a file
  @param cred Subject credential
  @param fg fileglob representing file to map
  @param label Policy label associated with vp
  @param prot mmap protections; see mmap(2)
  @param flags Type of mapped object; see mmap(2)
  @param maxprot Maximum rights

  Determine whether the subject identified by the credential should be
  allowed to map the file represented by fg with the protections specified
  in prot.  The maxprot field holds the maximum permissions on the new
  mapping, a combination of VM_PROT_READ, VM_PROT_WRITE, and VM_PROT_EXECUTE.
  To avoid overriding prior access control checks, a policy should only
  remove flags from maxprot.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_file_check_mmap_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label,
	int prot,
	int flags,
	uint64_t file_pos,
	int *maxprot
);
/**
  @brief Downgrade the mmap protections
  @param cred Subject credential
  @param fg file to map
  @param label Policy label associated with vp
  @param prot mmap protections to be downgraded

  Downgrade the mmap protections based on the subject and object labels.
*/
typedef void mpo_file_check_mmap_downgrade_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label,
	int *prot
);
/**
  @brief Access control for receiving a file descriptor
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg

  Determine whether the subject identified by the credential can
  receive the fileglob structure represented by fg.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_file_check_receive_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label
);
/**
  @brief Access control check for mac_set_fd
  @param cred Subject credential
  @param fg Fileglob structure
  @param elements Elements buffer
  @param len Length of elements buffer

  Determine whether the subject identified by the credential can
  perform the mac_set_fd operation.  The mac_set_fd operation is used
  to associate a MAC label with a file.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_file_check_set_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	char *elements,
	int len
);
/**
  @brief Create file label
  @param cred Subject credential
  @param fg Fileglob structure
  @param label Policy label for fg
*/
typedef void mpo_file_label_associate_t(
	kauth_cred_t cred,
	struct fileglob *fg,
	struct label *label
);
/**
 @brief Destroy file label
 @param label The label to be destroyed

 Destroy the label on a file descriptor.  In this entry point, a
 policy module should free any internal storage associated with
 label so that it may be destroyed.
*/
typedef void mpo_file_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize file label
  @param label New label to initialize
*/
typedef void mpo_file_label_init_t(
	struct label *label
);
/**
  @brief Access control check for relabeling network interfaces
  @param cred Subject credential
  @param ifp network interface being relabeled
  @param ifnetlabel Current label of the network interfaces
  @param newlabel New label to apply to the network interfaces
  @see mpo_ifnet_label_update_t

  Determine whether the subject identified by the credential can
  relabel the network interface represented by ifp to the supplied
  new label (newlabel).

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_ifnet_check_label_update_t(
	kauth_cred_t cred,
	struct ifnet *ifp,
	struct label *ifnetlabel,
	struct label *newlabel
);
/**
  @brief Access control check for relabeling network interfaces
  @param ifp Network interface mbuf will be transmitted through
  @param ifnetlabel Label of the network interfaces
  @param m The mbuf to be transmitted
  @param mbuflabel Label of the mbuf to be transmitted
  @param family Address Family, AF_*
  @param type Type of socket, SOCK_{STREAM,DGRAM,RAW}

  Determine whether the mbuf with label mbuflabel may be transmitted
  through the network interface represented by ifp that has the
  label ifnetlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_ifnet_check_transmit_t(
	struct ifnet *ifp,
	struct label *ifnetlabel,
	struct mbuf *m,
	struct label *mbuflabel,
	int family,
	int type
);
/**
  @brief Create a network interface label
  @param ifp Network interface labeled
  @param ifnetlabel Label for the network interface

  Set the label of a newly created network interface, most likely
  using the information in the supplied network interface struct.
*/
typedef void mpo_ifnet_label_associate_t(
	struct ifnet *ifp,
	struct label *ifnetlabel
);
/**
  @brief Copy an ifnet label
  @param src Source ifnet label
  @param dest Destination ifnet label

  Copy the label information from src to dest.
*/
typedef void mpo_ifnet_label_copy_t(
	struct label *src,
	struct label *dest
);
/**
 @brief Destroy ifnet label
 @param label The label to be destroyed

 Destroy the label on an ifnet label.  In this entry point, a
 policy module should free any internal storage associated with
 label so that it may be destroyed.
*/
typedef void mpo_ifnet_label_destroy_t(
	struct label *label
);
/**
  @brief Externalize an ifnet label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on an interface.
  An externalized label consists of a text representation of the
  label contents that can be used with user applications.
  Policy-agnostic user space tools will display this externalized
  version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data.

*/
typedef int mpo_ifnet_label_externalize_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Initialize ifnet label
  @param label New label to initialize
*/
typedef void mpo_ifnet_label_init_t(
	struct label *label
);
/**
  @brief Internalize an interface label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce an interface label from an external representation.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data.

*/
typedef int mpo_ifnet_label_internalize_t(
	struct label *label,
	char *element_name,
	char *element_data
);
/**
  @brief Recycle up a network interface label
  @param label The label to be recycled

  Recycle a network interface label.  Darwin caches the struct ifnet
  of detached ifnets in a "free pool".  Before ifnets are returned
  to the "free pool", policies can cleanup or overwrite any information
  present in the label.
*/
typedef void mpo_ifnet_label_recycle_t(
	struct label *label
);
/**
  @brief Update a network interface label
  @param cred Subject credential
  @param ifp The network interface to be relabeled
  @param ifnetlabel The current label of the network interface
  @param newlabel A new label to apply to the network interface
  @see mpo_ifnet_check_label_update_t

  Update the label on a network interface, using the supplied new label.
*/
typedef void mpo_ifnet_label_update_t(
	kauth_cred_t cred,
	struct ifnet *ifp,
	struct label *ifnetlabel,
	struct label *newlabel
);
/**
  @brief Access control check for delivering a packet to a socket
  @param inp inpcb the socket is associated with
  @param inplabel Label of the inpcb
  @param m The mbuf being received
  @param mbuflabel Label of the mbuf being received
  @param family Address family, AF_*
  @param type Type of socket, SOCK_{STREAM,DGRAM,RAW}

  Determine whether the mbuf with label mbuflabel may be received
  by the socket associated with inpcb that has the label inplabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_inpcb_check_deliver_t(
	struct inpcb *inp,
	struct label *inplabel,
	struct mbuf *m,
	struct label *mbuflabel,
	int family,
	int type
);
/**
  @brief Create an inpcb label
  @param so Socket containing the inpcb to be labeled
  @param solabel Label of the socket
  @param inp inpcb to be labeled
  @param inplabel Label for the inpcb

  Set the label of a newly created inpcb, most likely
  using the information in the socket and/or socket label.
*/
typedef void mpo_inpcb_label_associate_t(
	struct socket *so,
	struct label *solabel,
	struct inpcb *inp,
	struct label *inplabel
);
/**
 @brief Destroy inpcb label
 @param label The label to be destroyed

 Destroy the label on an inpcb label.  In this entry point, a
 policy module should free any internal storage associated with
 label so that it may be destroyed.
*/
typedef void mpo_inpcb_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize inpcb label
  @param label New label to initialize
  @param flag M_WAITOK or M_NOWAIT
*/
typedef int mpo_inpcb_label_init_t(
	struct label *label,
	int flag
);
/**
  @brief Recycle up an inpcb label
  @param label The label to be recycled

  Recycle an inpcb label.  Darwin allocates the inpcb as part of
  the socket structure in some cases.  For this case we must recycle
  rather than destroy the inpcb as it will be reused later.
*/
typedef void mpo_inpcb_label_recycle_t(
	struct label *label
);
/**
  @brief Update an inpcb label from a socket label
  @param so Socket containing the inpcb to be relabeled
  @param solabel New label of the socket
  @param inp inpcb to be labeled
  @param inplabel Label for the inpcb

  Set the label of a newly created inpcb due to a change in the
  underlying socket label.
*/
typedef void mpo_inpcb_label_update_t(
	struct socket *so,
	struct label *solabel,
	struct inpcb *inp,
	struct label *inplabel
);
/**
  @brief Device hardware access control
  @param devtype Type of device connected

  This is the MAC Framework device access control, which is called by the I/O
  Kit when a new device is connected to the system to determine whether that
  device should be trusted.  A list of properties associated with the device
  is passed as an XML-formatted string.  The routine should examine these
  properties to determine the trustworthiness of the device.  A return value
  of EPERM forces the device to be claimed by a special device driver that
  will prevent its operation.

  @warning This is an experimental interface and may change in the future.

  @return Return EPERM to indicate that the device is untrusted and should
  not be allowed to operate.  Return zero to indicate that the device is
  trusted and should be allowed to operate normally.

*/
typedef int mpo_iokit_check_device_t(
	char *devtype,
	struct mac_module_data *mdata
);
/**
  @brief Access control check for opening an I/O Kit device
  @param cred Subject credential
  @param user_client User client instance
  @param user_client_type User client type

  Determine whether the subject identified by the credential can open an
  I/O Kit device at the passed path of the passed user client class and
  type.

  @return Return 0 if access is granted, or an appropriate value for
  errno should be returned.
*/
typedef int mpo_iokit_check_open_t(
	kauth_cred_t cred,
	io_object_t user_client,
	unsigned int user_client_type
);
/**
  @brief Access control check for setting I/O Kit device properties
  @param cred Subject credential
  @param entry Target device
  @param properties Property list

  Determine whether the subject identified by the credential can set
  properties on an I/O Kit device.

  @return Return 0 if access is granted, or an appropriate value for
  errno should be returned.
*/
typedef int mpo_iokit_check_set_properties_t(
	kauth_cred_t cred,
	io_object_t entry,
	io_object_t properties
);
/**
  @brief Indicate desire to filter I/O Kit devices properties
  @param cred Subject credential
  @param entry Target device
  @see mpo_iokit_check_get_property_t

  Indicate whether this policy may restrict the subject credential
  from reading properties of the target device.
  If a policy returns success from this entry point, the
  mpo_iokit_check_get_property entry point will later be called
  for each property that the subject credential tries to read from
  the target device.

  This entry point is primarilly to optimize bulk property reads
  by skipping calls to the mpo_iokit_check_get_property entry point
  for credentials / devices no MAC policy is interested in.

  @warning Even if a policy returns 0, it should behave correctly in
  the presence of an invocation of mpo_iokit_check_get_property, as that
  call may happen as a result of another policy requesting a transition.

  @return Non-zero if a transition is required, 0 otherwise.
 */
typedef int mpo_iokit_check_filter_properties_t(
	kauth_cred_t cred,
	io_object_t entry
);
/**
  @brief Access control check for getting I/O Kit device properties
  @param cred Subject credential
  @param entry Target device
  @param name Property name 

  Determine whether the subject identified by the credential can get
  properties on an I/O Kit device.

  @return Return 0 if access is granted, or an appropriate value for
  errno.
*/
typedef int mpo_iokit_check_get_property_t(
	kauth_cred_t cred,
	io_object_t entry,
	const char *name
);
/**
  @brief Access control check for software HID control
  @param cred Subject credential

  Determine whether the subject identified by the credential can
  control the HID (Human Interface Device) subsystem, such as to
  post synthetic keypresses, pointer movement and clicks.

  @return Return 0 if access is granted, or an appropriate value for
  errno.
*/
typedef int mpo_iokit_check_hid_control_t(
	kauth_cred_t cred
);
/**
  @brief Create an IP reassembly queue label
  @param fragment First received IP fragment
  @param fragmentlabel Policy label for fragment
  @param ipq IP reassembly queue to be labeled
  @param ipqlabel Policy label to be filled in for ipq

  Set the label on a newly created IP reassembly queue from
  the mbuf header of the first received fragment.
*/
typedef void mpo_ipq_label_associate_t(
	struct mbuf *fragment,
	struct label *fragmentlabel,
	struct ipq *ipq,
	struct label *ipqlabel
);
/**
  @brief Compare an mbuf header label to an ipq label
  @param fragment IP datagram fragment
  @param fragmentlabel Policy label for fragment
  @param ipq IP fragment reassembly queue
  @param ipqlabel Policy label for ipq

  Compare the label of the mbuf header containing an IP datagram
  (fragment) fragment with the label of the passed IP fragment
  reassembly queue (ipq). Return (1) for a successful match, or (0)
  for no match. This call is made when the IP stack attempts to
  find an existing fragment reassembly queue for a newly received
  fragment; if this fails, a new fragment reassembly queue may be
  instantiated for the fragment. Policies may use this entry point
  to prevent the reassembly of otherwise matching IP fragments if
  policy does not permit them to be reassembled based on the label
  or other information.
*/
typedef int mpo_ipq_label_compare_t(
	struct mbuf *fragment,
	struct label *fragmentlabel,
	struct ipq *ipq,
	struct label *ipqlabel
);
/**
 @brief Destroy IP reassembly queue label
 @param label The label to be destroyed

 Destroy the label on an IP fragment queue.  In this entry point, a
 policy module should free any internal storage associated with
 label so that it may be destroyed.
*/
typedef void mpo_ipq_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize IP reassembly queue label
  @param label New label to initialize
  @param flag M_WAITOK or M_NOWAIT

  Initialize the label on a newly instantiated IP fragment reassembly
  queue.  The flag field may be one of M_WAITOK and M_NOWAIT, and
  should be employed to avoid performing a sleeping malloc(9) during
  this initialization call. IP fragment reassembly queue allocation
  frequently occurs in performance sensitive environments, and the
  implementation should be careful to avoid sleeping or long-lived
  operations. This entry point is permitted to fail resulting in
  the failure to allocate the IP fragment reassembly queue.
*/
typedef int mpo_ipq_label_init_t(
	struct label *label,
	int flag
);
/**
  @brief Update the label on an IP fragment reassembly queue
  @param fragment IP fragment
  @param fragmentlabel Policy label for fragment
  @param ipq IP fragment reassembly queue
  @param ipqlabel Policy label to be updated for ipq

  Update the label on an IP fragment reassembly queue (ipq) based
  on the acceptance of the passed IP fragment mbuf header (fragment).
*/
typedef void mpo_ipq_label_update_t(
	struct mbuf *fragment,
	struct label *fragmentlabel,
	struct ipq *ipq,
	struct label *ipqlabel
);
/**
 @brief Assign a label to a new mbuf
 @param bpf_d BPF descriptor
 @param b_label Policy label for bpf_d
 @param m Object; mbuf
 @param m_label Policy label to fill in for m

 Set the label on the mbuf header of a newly created datagram
 generated using the passed BPF descriptor. This call is made when
 a write is performed to the BPF device associated with the passed
 BPF descriptor.
*/
typedef void mpo_mbuf_label_associate_bpfdesc_t(
	struct bpf_d *bpf_d,
	struct label *b_label,
	struct mbuf *m,
	struct label *m_label
);
/**
 @brief Assign a label to a new mbuf
 @param ifp Interface descriptor
 @param i_label Existing label of ifp
 @param m Object; mbuf
 @param m_label Policy label to fill in for m

 Label an mbuf based on the interface from which it was received.
*/
typedef void mpo_mbuf_label_associate_ifnet_t(
	struct ifnet *ifp,
	struct label *i_label,
	struct mbuf *m,
	struct label *m_label
);
/**
 @brief Assign a label to a new mbuf
 @param inp inpcb structure
 @param i_label Existing label of inp
 @param m Object; mbuf
 @param m_label Policy label to fill in for m

 Label an mbuf based on the inpcb from which it was derived.
*/
typedef void mpo_mbuf_label_associate_inpcb_t(
	struct inpcb *inp,
	struct label *i_label,
	struct mbuf *m,
	struct label *m_label
);
/**
  @brief Set the label on a newly reassembled IP datagram
  @param ipq IP fragment reassembly queue
  @param ipqlabel Policy label for ipq
  @param mbuf IP datagram to be labeled
  @param mbuflabel Policy label to be filled in for mbuf

  Set the label on a newly reassembled IP datagram (mbuf) from the IP
  fragment reassembly queue (ipq) from which it was generated.
*/
typedef void mpo_mbuf_label_associate_ipq_t(
	struct ipq *ipq,
	struct label *ipqlabel,
	struct mbuf *mbuf,
	struct label *mbuflabel
);
/**
 @brief Assign a label to a new mbuf
 @param ifp Subject; network interface
 @param i_label Existing label of ifp
 @param m Object; mbuf
 @param m_label Policy label to fill in for m

 Set the label on the mbuf header of a newly created datagram
 generated for the purposes of a link layer response for the passed
 interface. This call may be made in a number of situations, including
 for ARP or ND6 responses in the IPv4 and IPv6 stacks.
*/
typedef void mpo_mbuf_label_associate_linklayer_t(
	struct ifnet *ifp,
	struct label *i_label,
	struct mbuf *m,
	struct label *m_label
);
/**
 @brief Assign a label to a new mbuf
 @param oldmbuf mbuf headerder for existing datagram for existing datagram
 @param oldmbuflabel Policy label for oldmbuf
 @param ifp Network interface
 @param ifplabel Policy label for ifp
 @param newmbuf mbuf header to be labeled for new datagram
 @param newmbuflabel Policy label for newmbuf

 Set the label on the mbuf header of a newly created datagram
 generated from the existing passed datagram when it is processed
 by the passed multicast encapsulation interface. This call is made
 when an mbuf is to be delivered using the virtual interface.
*/
typedef void mpo_mbuf_label_associate_multicast_encap_t(
	struct mbuf *oldmbuf,
	struct label *oldmbuflabel,
	struct ifnet *ifp,
	struct label *ifplabel,
	struct mbuf *newmbuf,
	struct label *newmbuflabel
);
/**
 @brief Assign a label to a new mbuf
 @param oldmbuf Received datagram
 @param oldmbuflabel Policy label for oldmbuf
 @param newmbuf Newly created datagram
 @param newmbuflabel Policy label for newmbuf

 Set the label on the mbuf header of a newly created datagram generated
 by the IP stack in response to an existing received datagram (oldmbuf).
 This call may be made in a number of situations, including when responding
 to ICMP request datagrams.
*/
typedef void mpo_mbuf_label_associate_netlayer_t(
	struct mbuf *oldmbuf,
	struct label *oldmbuflabel,
	struct mbuf *newmbuf,
	struct label *newmbuflabel
);
/**
  @brief Assign a label to a new mbuf
  @param so Socket to label
  @param so_label Policy label for socket
  @param m Object; mbuf
  @param m_label Policy label to fill in for m

  An mbuf structure is used to store network traffic in transit.
  When an application sends data to a socket or a pipe, it is wrapped
  in an mbuf first.  This function sets the label on a newly created mbuf header
  based on the socket sending the data.  The contents of the label should be
  suitable for performing an access check on the receiving side of the
  communication.

  Only labeled MBUFs will be presented to the policy via this entrypoint.
*/
typedef void mpo_mbuf_label_associate_socket_t(
	socket_t so,
	struct label *so_label,
	struct mbuf *m,
	struct label *m_label
);
/**
  @brief Copy a mbuf label
  @param src Source label
  @param dest Destination label

  Copy the mbuf label information in src into dest.

  Only called when both source and destination mbufs have labels.
*/
typedef void mpo_mbuf_label_copy_t(
	struct label *src,
	struct label *dest
);
/**
  @brief Destroy mbuf label
  @param label The label to be destroyed

  Destroy a mbuf label.  Since the
  object is going out of scope, policy modules should free any
  internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_mbuf_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize mbuf label
  @param label New label to initialize
  @param flag Malloc flags

  Initialize the label for a newly instantiated mbuf.

  @warning Since it is possible for the flags to be set to
  M_NOWAIT, the malloc operation may fail.

  @return On success, 0, otherwise, an appropriate errno return value.
*/
typedef int mpo_mbuf_label_init_t(
	struct label *label,
	int flag
);
/**
  @brief Access control check for fsctl
  @param cred Subject credential
  @param mp The mount point
  @param label Label associated with the mount point
  @param cmd Filesystem-dependent request code; see fsctl(2)

  Determine whether the subject identified by the credential can perform
  the volume operation indicated by com.

  @warning The fsctl() system call is directly analogous to ioctl(); since
  the associated data is opaque from the standpoint of the MAC framework
  and since these operations can affect many aspects of system operation,
  policies must exercise extreme care when implementing access control checks.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_mount_check_fsctl_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *label,
	unsigned int cmd
);
/**
  @brief Access control check for the retrieval of file system attributes
  @param cred Subject credential
  @param mp The mount structure of the file system
  @param vfa The attributes requested

  This entry point determines whether given subject can get information
  about the given file system.  This check happens during statfs() syscalls,
  but is also used by other parts within the kernel such as the audit system.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

  @note Policies may change the contents of vfa to alter the list of
  file system attributes returned.
*/

typedef int mpo_mount_check_getattr_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mp_label,
	struct vfs_attr *vfa
);
/**
  @brief Access control check for mount point relabeling
  @param cred Subject credential
  @param mp Object file system mount point
  @param mntlabel Policy label for fle system mount point

  Determine whether the subject identified by the credential can relabel
  the mount point. This call is made when a file system mount is updated.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch
  or EPERM for lack of privilege.
*/
typedef int mpo_mount_check_label_update_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mntlabel
);
/**
  @brief Access control check for mounting a file system
  @param cred Subject credential
  @param vp Vnode that is to be the mount point
  @param vlabel Label associated with the vnode
  @param cnp Component name for vp
  @param vfc_name Filesystem type name

  Determine whether the subject identified by the credential can perform
  the mount operation on the target vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_mount_check_mount_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	struct componentname *cnp,
	const char *vfc_name
);
/**
  @brief Access control check for fs_snapshot_create
  @param cred Subject credential
  @mp Filesystem mount point to create snapshot of
  @name Name of snapshot to create

  Determine whether the subject identified by the credential can
  create a snapshot of the filesystem at the given mount point.

  @return Return 0 if access is granted, otherwise an appropriate value
  for errno should be returned.
*/
typedef int mpo_mount_check_snapshot_create_t(
	kauth_cred_t cred,
	struct mount *mp,
	const char *name
);
/**
  @brief Access control check for fs_snapshot_delete
  @param cred Subject credential
  @mp Filesystem mount point to delete snapshot of
  @name Name of snapshot to delete

  Determine whether the subject identified by the credential can
  delete the named snapshot from the filesystem at the given
  mount point.

  @return Return 0 if access is granted, otherwise an appropriate value
  for errno should be returned.
*/
typedef int mpo_mount_check_snapshot_delete_t(
	kauth_cred_t cred,
	struct mount *mp,
	const char *name
);
/**
  @brief Access control check for fs_snapshot_revert
  @param cred Subject credential
  @mp Filesystem mount point to revert to snapshot
  @name Name of snapshot to revert to

  Determine whether the subject identified by the credential can
  revert the filesystem at the given mount point to the named snapshot.

  @return Return 0 if access is granted, otherwise an appropriate value
  for errno should be returned.
*/
typedef int mpo_mount_check_snapshot_revert_t(
	kauth_cred_t cred,
	struct mount *mp,
	const char *name
);
/**
  @brief Access control check remounting a filesystem
  @param cred Subject credential
  @param mp The mount point
  @param mlabel Label currently associated with the mount point

  Determine whether the subject identified by the credential can perform
  the remount operation on the target vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_mount_check_remount_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mlabel
);
/**
  @brief Access control check for the settting of file system attributes
  @param cred Subject credential
  @param mp The mount structure of the file system
  @param vfa The attributes requested

  This entry point determines whether given subject can set information
  about the given file system, for example the volume name.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/

typedef int mpo_mount_check_setattr_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mp_label,
	struct vfs_attr *vfa
);
/**
  @brief Access control check for file system statistics
  @param cred Subject credential
  @param mp Object file system mount
  @param mntlabel Policy label for mp

  Determine whether the subject identified by the credential can see
  the results of a statfs performed on the file system. This call may
  be made in a number of situations, including during invocations of
  statfs(2) and related calls, as well as to determine what file systems
  to exclude from listings of file systems, such as when getfsstat(2)
  is invoked.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch
  or EPERM for lack of privilege.
*/
typedef int mpo_mount_check_stat_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mntlabel
);
/**
  @brief Access control check for unmounting a filesystem
  @param cred Subject credential
  @param mp The mount point
  @param mlabel Label associated with the mount point

  Determine whether the subject identified by the credential can perform
  the unmount operation on the target vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_mount_check_umount_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mlabel
);
/**
  @brief Create mount labels
  @param cred Subject credential
  @param mp Mount point of file system being mounted
  @param mntlabel Label to associate with the new mount point
  @see mpo_mount_label_init_t

  Fill out the labels on the mount point being created by the supplied
  user credential.  This call is made when file systems are first mounted.
*/
typedef void mpo_mount_label_associate_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mntlabel
);
/**
  @brief Destroy mount label
  @param label The label to be destroyed

  Destroy a file system mount label.  Since the
  object is going out of scope, policy modules should free any
  internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_mount_label_destroy_t(
	struct label *label
);
/**
  @brief Externalize a mount point label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the mount point label.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will display this externalized version.

  The policy's externalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data.

*/
typedef int mpo_mount_label_externalize_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Initialize mount point label
  @param label New label to initialize

  Initialize the label for a newly instantiated mount structure.
  This label is typically used to store a default label in the case
  that the file system has been mounted singlelabel.  Since some
  file systems do not support persistent labels (extended attributes)
  or are read-only (such as CD-ROMs), it is often necessary to store
  a default label separately from the label of the mount point
  itself.  Sleeping is permitted.
*/
typedef void mpo_mount_label_init_t(
	struct label *label
);
/**
  @brief Internalize a mount point label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce a mount point file system label from an external representation.
  An externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data.

*/
typedef int mpo_mount_label_internalize_t(
	struct label *label,
	char *element_name,
	char *element_data
);
/**
  @brief Set the label on an IPv4 datagram fragment
  @param datagram Datagram being fragmented
  @param datagramlabel Policy label for datagram
  @param fragment New fragment
  @param fragmentlabel Policy label for fragment

  Called when an IPv4 datagram is fragmented into several smaller datagrams.
  Policies implementing mbuf labels will typically copy the label from the
  source datagram to the new fragment.
*/
typedef void mpo_netinet_fragment_t(
	struct mbuf *datagram,
	struct label *datagramlabel,
	struct mbuf *fragment,
	struct label *fragmentlabel
);
/**
  @brief Set the label on an ICMP reply
  @param m mbuf containing the ICMP reply
  @param mlabel Policy label for m

  A policy may wish to update the label of an mbuf that refers to
  an ICMP packet being sent in response to an IP packet.  This may
  be called in response to a bad packet or an ICMP request.
*/
typedef void mpo_netinet_icmp_reply_t(
	struct mbuf *m,
	struct label *mlabel
);
/**
  @brief Set the label on a TCP reply
  @param m mbuf containing the TCP reply
  @param mlabel Policy label for m

  Called for outgoing TCP packets not associated with an actual socket.
*/
typedef void mpo_netinet_tcp_reply_t(
	struct mbuf *m,
	struct label *mlabel
);
/**
  @brief Access control check for pipe ioctl
  @param cred Subject credential
  @param cpipe Object to be accessed
  @param pipelabel The label on the pipe
  @param cmd The ioctl command; see ioctl(2)

  Determine whether the subject identified by the credential can perform
  the ioctl operation indicated by cmd.

  @warning Since ioctl data is opaque from the standpoint of the MAC
  framework, policies must exercise extreme care when implementing
  access control checks.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_pipe_check_ioctl_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *pipelabel,
	unsigned int cmd
);
/**
  @brief Access control check for pipe kqfilter
  @param cred Subject credential
  @param kn Object knote
  @param cpipe Object to be accessed
  @param pipelabel Policy label for the pipe

  Determine whether the subject identified by the credential can
  receive the knote on the passed pipe.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_pipe_check_kqfilter_t(
	kauth_cred_t cred,
	struct knote *kn,
	struct pipe *cpipe,
	struct label *pipelabel
);
/**
  @brief Access control check for pipe relabel
  @param cred Subject credential
  @param cpipe Object to be accessed
  @param pipelabel The current label on the pipe
  @param newlabel The new label to be used

  Determine whether the subject identified by the credential can
  perform a relabel operation on the passed pipe.  The cred object holds
  the credentials of the subject performing the operation.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_pipe_check_label_update_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *pipelabel,
	struct label *newlabel
);
/**
  @brief Access control check for pipe read
  @param cred Subject credential
  @param cpipe Object to be accessed
  @param pipelabel The label on the pipe

  Determine whether the subject identified by the credential can
  perform a read operation on the passed pipe.  The cred object holds
  the credentials of the subject performing the operation.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_pipe_check_read_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *pipelabel
);
/**
  @brief Access control check for pipe select
  @param cred Subject credential
  @param cpipe Object to be accessed
  @param pipelabel The label on the pipe
  @param which The operation selected on: FREAD or FWRITE

  Determine whether the subject identified by the credential can
  perform a select operation on the passed pipe.  The cred object holds
  the credentials of the subject performing the operation.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_pipe_check_select_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *pipelabel,
	int which
);
/**
  @brief Access control check for pipe stat
  @param cred Subject credential
  @param cpipe Object to be accessed
  @param pipelabel The label on the pipe

  Determine whether the subject identified by the credential can
  perform a stat operation on the passed pipe.  The cred object holds
  the credentials of the subject performing the operation.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_pipe_check_stat_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *pipelabel
);
/**
  @brief Access control check for pipe write
  @param cred Subject credential
  @param cpipe Object to be accessed
  @param pipelabel The label on the pipe

  Determine whether the subject identified by the credential can
  perform a write operation on the passed pipe.  The cred object holds
  the credentials of the subject performing the operation.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

*/
typedef int mpo_pipe_check_write_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *pipelabel
);
/**
  @brief Create a pipe label
  @param cred Subject credential
  @param cpipe object to be labeled
  @param pipelabel Label for the pipe object

  Create a label for the pipe object being created by the supplied
  user credential. This call is made when the pipe is being created
  XXXPIPE(for one or both sides of the pipe?).

*/
typedef void mpo_pipe_label_associate_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *pipelabel
);
/**
  @brief Copy a pipe label
  @param src Source pipe label
  @param dest Destination pipe label

  Copy the pipe label associated with src to dest.
  XXXPIPE Describe when this is used: most likely during pipe creation to
          copy from rpipe to wpipe.
*/
typedef void mpo_pipe_label_copy_t(
	struct label *src,
	struct label *dest
);
/**
  @brief Destroy pipe label
  @param label The label to be destroyed

  Destroy a pipe label.  Since the object is going out of scope,
  policy modules should free any internal storage associated with the
  label so that it may be destroyed.
*/
typedef void mpo_pipe_label_destroy_t(
	struct label *label
);
/**
  @brief Externalize a pipe label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a pipe.
  An externalized label consists of a text representation
  of the label contents that can be used with user applications.
  Policy-agnostic user space tools will display this externalized
  version.

  The policy's externalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data.

*/
typedef int mpo_pipe_label_externalize_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Initialize pipe label
  @param label New label to initialize

  Initialize label storage for use with a newly instantiated pipe object.
  Sleeping is permitted.
*/
typedef void mpo_pipe_label_init_t(
	struct label *label
);
/**
  @brief Internalize a pipe label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce a pipe label from an external representation.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data.

*/
typedef int mpo_pipe_label_internalize_t(
	struct label *label,
	char *element_name,
	char *element_data
);
/**
  @brief Update a pipe label
  @param cred Subject credential
  @param cpipe Object to be labeled
  @param oldlabel Existing pipe label
  @param newlabel New label to replace existing label
  @see mpo_pipe_check_label_update_t

  The subject identified by the credential has previously requested
  and was authorized to relabel the pipe; this entry point allows
  policies to perform the actual relabel operation.  Policies should
  update oldlabel using the label stored in the newlabel parameter.

*/
typedef void mpo_pipe_label_update_t(
	kauth_cred_t cred,
	struct pipe *cpipe,
	struct label *oldlabel,
	struct label *newlabel
);
/**
  @brief Policy unload event
  @param mpc MAC policy configuration

  This is the MAC Framework policy unload event.  This entry point will
  only be called if the module's policy configuration allows unload (if
  the MPC_LOADTIME_FLAG_UNLOADOK is set).  Most security policies won't
  want to be unloaded; they should set their flags to prevent this
  entry point from being called.

  @warning During this call, the mac policy list mutex is held, so
  sleep operations cannot be performed, and calls out to other kernel
  subsystems must be made with caution.

  @see MPC_LOADTIME_FLAG_UNLOADOK
*/
typedef void mpo_policy_destroy_t(
	struct mac_policy_conf *mpc
);
/**
  @brief Policy initialization event
  @param mpc MAC policy configuration
  @see mac_policy_register
  @see mpo_policy_initbsd_t

  This is the MAC Framework policy initialization event.  This entry
  point is called during mac_policy_register, when the policy module
  is first registered with the MAC Framework.  This is often done very
  early in the boot process, after the kernel Mach subsystem has been
  initialized, but prior to the BSD subsystem being initialized.
  Since the kernel BSD services are not yet available, it is possible
  that some initialization must occur later, possibly in the
  mpo_policy_initbsd_t policy entry point, such as registering BSD system
  controls (sysctls).  Policy modules loaded at boot time will be
  registered and initialized before labeled Mach objects are created.

  @warning During this call, the mac policy list mutex is held, so
  sleep operations cannot be performed, and calls out to other kernel
  subsystems must be made with caution.
*/
typedef void mpo_policy_init_t(
	struct mac_policy_conf *mpc
);
/**
  @brief Policy BSD initialization event
  @param mpc MAC policy configuration
  @see mpo_policy_init_t

  This entry point is called after the kernel BSD subsystem has been
  initialized.  By this point, the module should already be loaded,
  registered, and initialized.  Since policy modules are initialized
  before kernel BSD services are available, this second initialization
  phase is necessary.  At this point, BSD services (memory management,
  synchronization primitives, vfs, etc.) are available, but the first
  process has not yet been created.  Mach-related objects and tasks
  will already be fully initialized and may be in use--policies requiring
  ubiquitous labeling may also want to implement mpo_policy_init_t.

  @warning During this call, the mac policy list mutex is held, so
  sleep operations cannot be performed, and calls out to other kernel
  subsystems must be made with caution.
*/
typedef void mpo_policy_initbsd_t(
	struct mac_policy_conf *mpc
);
/**
  @brief Policy extension service
  @param p Calling process
  @param call Policy-specific syscall number
  @param arg Pointer to syscall arguments

  This entry point provides a policy-multiplexed system call so that
  policies may provide additional services to user processes without
  registering specific system calls. The policy name provided during
  registration is used to demux calls from userland, and the arguments
  will be forwarded to this entry point.  When implementing new
  services, security modules should be sure to invoke appropriate
  access control checks from the MAC framework as needed.  For
  example, if a policy implements an augmented signal functionality,
  it should call the necessary signal access control checks to invoke
  the MAC framework and other registered policies.

  @warning Since the format and contents of the policy-specific
  arguments are unknown to the MAC Framework, modules must perform the
  required copyin() of the syscall data on their own.  No policy
  mediation is performed, so policies must perform any necessary
  access control checks themselves.  If multiple policies are loaded,
  they will currently be unable to mediate calls to other policies.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_policy_syscall_t(
	struct proc *p,
	int call,
	user_addr_t arg
);
/**
  @brief Access control check for POSIX semaphore create
  @param cred Subject credential
  @param name String name of the semaphore

  Determine whether the subject identified by the credential can create
  a POSIX semaphore specified by name.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixsem_check_create_t(
	kauth_cred_t cred,
	const char *name
);
/**
  @brief Access control check for POSIX semaphore open
  @param cred Subject credential
  @param ps Pointer to semaphore information structure
  @param semlabel Label associated with the semaphore

  Determine whether the subject identified by the credential can open
  the named POSIX semaphore with label semlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixsem_check_open_t(
	kauth_cred_t cred,
	struct pseminfo *ps,
	struct label *semlabel
);
/**
  @brief Access control check for POSIX semaphore post
  @param cred Subject credential
  @param ps Pointer to semaphore information structure
  @param semlabel Label associated with the semaphore

  Determine whether the subject identified by the credential can unlock
  the named POSIX semaphore with label semlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixsem_check_post_t(
	kauth_cred_t cred,
	struct pseminfo *ps,
	struct label *semlabel
);
/**
  @brief Access control check for POSIX semaphore unlink
  @param cred Subject credential
  @param ps Pointer to semaphore information structure
  @param semlabel Label associated with the semaphore
  @param name String name of the semaphore

  Determine whether the subject identified by the credential can remove
  the named POSIX semaphore with label semlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixsem_check_unlink_t(
	kauth_cred_t cred,
	struct pseminfo *ps,
	struct label *semlabel,
	const char *name
);
/**
  @brief Access control check for POSIX semaphore wait
  @param cred Subject credential
  @param ps Pointer to semaphore information structure
  @param semlabel Label associated with the semaphore

  Determine whether the subject identified by the credential can lock
  the named POSIX semaphore with label semlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixsem_check_wait_t(
	kauth_cred_t cred,
	struct pseminfo *ps,
	struct label *semlabel
);
/**
  @brief Create a POSIX semaphore label
  @param cred Subject credential
  @param ps Pointer to semaphore information structure
  @param semlabel Label to associate with the new semaphore
  @param name String name of the semaphore

  Label a new POSIX semaphore.  The label was previously
  initialized and associated with the semaphore.  At this time, an
  appropriate initial label value should be assigned to the object and
  stored in semalabel.
*/
typedef void mpo_posixsem_label_associate_t(
	kauth_cred_t cred,
	struct pseminfo *ps,
	struct label *semlabel,
	const char *name
);
/**
  @brief Destroy POSIX semaphore label
  @param label The label to be destroyed

  Destroy a POSIX semaphore label.  Since the object is
  going out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_posixsem_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize POSIX semaphore label
  @param label New label to initialize

  Initialize the label for a newly instantiated POSIX semaphore. Sleeping
  is permitted.
*/
typedef void mpo_posixsem_label_init_t(
	struct label *label
);
/**
  @brief Access control check for POSIX shared memory region create
  @param cred Subject credential
  @param name String name of the shared memory region

  Determine whether the subject identified by the credential can create
  the POSIX shared memory region referenced by name.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixshm_check_create_t(
	kauth_cred_t cred,
	const char *name
);
/**
  @brief Access control check for mapping POSIX shared memory
  @param cred Subject credential
  @param ps Pointer to shared memory information structure
  @param shmlabel Label associated with the shared memory region
  @param prot mmap protections; see mmap(2)
  @param flags shmat flags; see shmat(2)

  Determine whether the subject identified by the credential can map
  the POSIX shared memory segment associated with shmlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixshm_check_mmap_t(
	kauth_cred_t cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	int prot,
	int flags
);
/**
  @brief Access control check for POSIX shared memory region open
  @param cred Subject credential
  @param ps Pointer to shared memory information structure
  @param shmlabel Label associated with the shared memory region
  @param fflags shm_open(2) open flags ('fflags' encoded)

  Determine whether the subject identified by the credential can open
  the POSIX shared memory region.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixshm_check_open_t(
	kauth_cred_t cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	int fflags
);
/**
  @brief Access control check for POSIX shared memory stat
  @param cred Subject credential
  @param ps Pointer to shared memory information structure
  @param shmlabel Label associated with the shared memory region

  Determine whether the subject identified by the credential can obtain
  status for the POSIX shared memory segment associated with shmlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixshm_check_stat_t(
	kauth_cred_t cred,
	struct pshminfo *ps,
	struct label *shmlabel
);
/**
  @brief Access control check for POSIX shared memory truncate
  @param cred Subject credential
  @param ps Pointer to shared memory information structure
  @param shmlabel Label associated with the shared memory region
  @param len Length to truncate or extend shared memory segment

  Determine whether the subject identified by the credential can truncate
  or extend (to len) the POSIX shared memory segment associated with shmlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixshm_check_truncate_t(
	kauth_cred_t cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	off_t len
);
/**
  @brief Access control check for POSIX shared memory unlink
  @param cred Subject credential
  @param ps Pointer to shared memory information structure
  @param shmlabel Label associated with the shared memory region
  @param name String name of the shared memory region

  Determine whether the subject identified by the credential can delete
  the POSIX shared memory segment associated with shmlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_posixshm_check_unlink_t(
	kauth_cred_t cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	const char *name
);
/**
  @brief Create a POSIX shared memory region label
  @param cred Subject credential
  @param ps Pointer to shared memory information structure
  @param shmlabel Label to associate with the new shared memory region
  @param name String name of the shared memory region

  Label a new POSIX shared memory region.  The label was previously
  initialized and associated with the shared memory region.  At this
  time, an appropriate initial label value should be assigned to the
  object and stored in shmlabel.
*/
typedef void mpo_posixshm_label_associate_t(
	kauth_cred_t cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	const char *name
);
/**
  @brief Destroy POSIX shared memory label
  @param label The label to be destroyed

  Destroy a POSIX shared memory region label.  Since the
  object is going out of scope, policy modules should free any
  internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_posixshm_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize POSIX Shared Memory region label
  @param label New label to initialize

  Initialize the label for newly a instantiated POSIX Shared Memory
  region. Sleeping is permitted.
*/
typedef void mpo_posixshm_label_init_t(
	struct label *label
);
/**
 @brief Access control check for privileged operations
 @param cred Subject credential
 @param priv Requested privilege (see sys/priv.h)

 Determine whether the subject identified by the credential can perform
 a privileged operation.  Privileged operations are allowed if the cred
 is the superuser or any policy returns zero for mpo_priv_grant, unless
 any policy returns nonzero for mpo_priv_check.

 @return Return 0 if access is granted, otherwise EPERM should be returned.
*/
typedef int mpo_priv_check_t(
	kauth_cred_t cred,
	int priv
);
/**
 @brief Grant regular users the ability to perform privileged operations
 @param cred Subject credential
 @param priv Requested privilege (see sys/priv.h)

 Determine whether the subject identified by the credential should be
 allowed to perform a privileged operation that in the absense of any
 MAC policy it would not be able to perform.  Privileged operations are
 allowed if the cred is the superuser or any policy returns zero for
 mpo_priv_grant, unless any policy returns nonzero for mpo_priv_check.

 Unlike other MAC hooks which can only reduce the privilege of a
 credential, this hook raises the privilege of a credential when it
 returns 0.  Extreme care must be taken when implementing this hook to
 avoid undermining the security of the system.

 @return Return 0 if additional privilege is granted, otherwise EPERM
 should be returned.
*/
typedef int mpo_priv_grant_t(
	kauth_cred_t cred,
	int priv
);
/**
  @brief Access control check for debugging process
  @param cred Subject credential
  @param proc Object process

  Determine whether the subject identified by the credential can debug
  the passed process. This call may be made in a number of situations,
  including use of the ptrace(2) and ktrace(2) APIs, as well as for some
  types of procfs operations.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to hide visibility of the target.
*/
typedef int mpo_proc_check_debug_t(
	kauth_cred_t cred,
	struct proc *proc
);
/**
  @brief Access control over fork
  @param cred Subject credential
  @param proc Subject process trying to fork

  Determine whether the subject identified is allowed to fork.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_fork_t(
	kauth_cred_t cred,
	struct proc *proc
);
/**
  @brief Access control check for setting host special ports.
  @param cred Subject credential
  @param id The host special port to set
  @param port The new value to set for the special port

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_set_host_special_port_t(
	kauth_cred_t cred,
	int id,
	struct ipc_port	*port
);
/**
  @brief Access control check for setting host exception ports.
  @param cred Subject credential
  @param exception Exception port to set

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_set_host_exception_port_t(
	kauth_cred_t cred,
	unsigned int exception
);
/**
  @brief Access control over pid_suspend and pid_resume
  @param cred Subject credential
  @param proc Subject process trying to run pid_suspend or pid_resume 
  @param sr Call is suspend (0) or resume (1)

  Determine whether the subject identified is allowed to suspend or resume
  other processes.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_suspend_resume_t(
	kauth_cred_t cred,
	struct proc *proc,
	int sr
);
/**
  @brief Access control check for retrieving audit information
  @param cred Subject credential

  Determine whether the subject identified by the credential can get
  audit information such as the audit user ID, the preselection mask,
  the terminal ID and the audit session ID, using the getaudit() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_getaudit_t(
	kauth_cred_t cred
);
/**
  @brief Access control check for retrieving audit user ID
  @param cred Subject credential

  Determine whether the subject identified by the credential can get
  the user identity being used by the auditing system, using the getauid()
  system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_getauid_t(
	kauth_cred_t cred
);
/**
  @brief Access control check for retrieving Login Context ID
  @param p0 Calling process
  @param p Effected process
  @param pid syscall PID argument

  Determine if getlcid(2) system call is permitted.

  Information returned by this system call is similar to that returned via
  process listings etc.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_getlcid_t(
	struct proc *p0,
	struct proc *p,
	pid_t pid
);
/**
  @brief Access control check for retrieving ledger information
  @param cred Subject credential
  @param target Object process
  @param op ledger operation

  Determine if ledger(2) system call is permitted.

  Information returned by this system call is similar to that returned via
  process listings etc.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_ledger_t(
	kauth_cred_t cred,
	struct proc *target,
	int op
);
/**
  @brief Access control check for escaping default CPU usage monitor parameters.
  @param cred Subject credential
  
  Determine if a credential has permission to program CPU usage monitor parameters
  that are less restrictive than the global system-wide defaults.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_cpumon_t(
  kauth_cred_t cred
);
/**
  @brief Access control check for retrieving process information.
  @param cred Subject credential
  @param target Target process (may be null, may be zombie)

  Determine if a credential has permission to access process information as defined
  by call number and flavor on target process

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_proc_info_t(
	kauth_cred_t cred,
	struct proc *target,
	int callnum,
	int flavor
);
/**
  @brief Access control check for retrieving code signing information.
  @param cred Subject credential
  @param target Target process
  @param op Code signing operation being performed

  Determine whether the subject identified by the credential should be
  allowed to get code signing information about the target process.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_get_cs_info_t(
	kauth_cred_t cred,
	struct proc *target,
	unsigned int op
);
/**
  @brief Access control check for setting code signing information.
  @param cred Subject credential
  @param target Target process
  @param op Code signing operation being performed.

  Determine whether the subject identified by the credential should be
  allowed to set code signing information about the target process.

  @return Return 0 if permission is granted, otherwise an appropriate
  value of errno should be returned.
*/
typedef int mpo_proc_check_set_cs_info_t(
	kauth_cred_t cred,
	struct proc *target,
	unsigned int op
);
/**
  @brief Access control check for mmap MAP_ANON
  @param proc User process requesting the memory
  @param cred Subject credential
  @param u_addr Start address of the memory range
  @param u_size Length address of the memory range
  @param prot mmap protections; see mmap(2)
  @param flags Type of mapped object; see mmap(2)
  @param maxprot Maximum rights

  Determine whether the subject identified by the credential should be
  allowed to obtain anonymous memory using the specified flags and 
  protections on the new mapping. MAP_ANON will always be present in the
  flags. Certain combinations of flags with a non-NULL addr may
  cause a mapping to be rejected before this hook is called. The maxprot field
  holds the maximum permissions on the new mapping, a combination of
  VM_PROT_READ, VM_PROT_WRITE and VM_PROT_EXECUTE. To avoid overriding prior
  access control checks, a policy should only remove flags from maxprot.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EPERM for lack of privilege.
*/
typedef int mpo_proc_check_map_anon_t(
	struct proc *proc,
	kauth_cred_t cred,
	user_addr_t u_addr,
	user_size_t u_size,
	int prot,
	int flags,
	int *maxprot
);
/**
  @brief Access control check for setting memory protections
  @param cred Subject credential
  @param proc User process requesting the change
  @param addr Start address of the memory range
  @param size Length address of the memory range
  @param prot Memory protections, see mmap(2)

  Determine whether the subject identified by the credential should
  be allowed to set the specified memory protections on memory mapped
  in the process proc.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_mprotect_t(
	kauth_cred_t cred,
	struct proc *proc,
	user_addr_t addr,
	user_size_t size,
	int prot
);
/**
  @brief Access control check for changing scheduling parameters
  @param cred Subject credential
  @param proc Object process

  Determine whether the subject identified by the credential can change
  the scheduling parameters of the passed process.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to limit visibility.
*/
typedef int mpo_proc_check_sched_t(
	kauth_cred_t cred,
	struct proc *proc
);
/**
  @brief Access control check for setting audit information
  @param cred Subject credential
  @param ai Audit information

  Determine whether the subject identified by the credential can set
  audit information such as the the preselection mask, the terminal ID
  and the audit session ID, using the setaudit() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_setaudit_t(
	kauth_cred_t cred,
	struct auditinfo_addr *ai
);
/**
  @brief Access control check for setting audit user ID
  @param cred Subject credential
  @param auid Audit user ID

  Determine whether the subject identified by the credential can set
  the user identity used by the auditing system, using the setauid()
  system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_setauid_t(
	kauth_cred_t cred,
	uid_t auid
);
/**
  @brief Access control check for setting the Login Context
  @param p0 Calling process
  @param p Effected process
  @param pid syscall PID argument
  @param lcid syscall LCID argument

  Determine if setlcid(2) system call is permitted.

  See xnu/bsd/kern/kern_prot.c:setlcid() implementation for example of
  decoding syscall arguments to determine action desired by caller.

  Five distinct actions are possible: CREATE JOIN LEAVE ADOPT ORPHAN

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_setlcid_t(
	struct proc *p0,
	struct proc *p,
	pid_t pid,
	pid_t lcid
);
/**
  @brief Access control check for delivering signal
  @param cred Subject credential
  @param proc Object process
  @param signum Signal number; see kill(2)

  Determine whether the subject identified by the credential can deliver
  the passed signal to the passed process.

  @warning Programs typically expect to be able to send and receive
  signals as part or their normal process lifecycle; caution should be
  exercised when implementing access controls over signal events.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to limit visibility.
*/
typedef int mpo_proc_check_signal_t(
	kauth_cred_t cred,
	struct proc *proc,
	int signum
);
/**
  @brief Access control check for wait
  @param cred Subject credential
  @param proc Object process

  Determine whether the subject identified by the credential can wait
  for process termination.

  @warning Caution should be exercised when implementing access
  controls for wait, since programs often wait for child processes to
  exit.  Failure to be notified of a child process terminating may
  cause the parent process to hang, or may produce zombie processes.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_proc_check_wait_t(
	kauth_cred_t cred,
	struct proc *proc
);
/**
  @brief Destroy process label
  @param label The label to be destroyed

  Destroy a process label.  Since the object is going
  out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_proc_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize process label
  @param label New label to initialize
  @see mpo_cred_label_init_t

  Initialize the label for a newly instantiated BSD process structure.
  Normally, security policies will store the process label in the user
  credential rather than here in the process structure.  However,
  there are some floating label policies that may need to temporarily
  store a label in the process structure until it is safe to update
  the user credential label.  Sleeping is permitted.
*/
typedef void mpo_proc_label_init_t(
	struct label *label
);
/**
  @brief Access control check for socket accept
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can accept()
  a new connection on the socket from the host specified by addr.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_accept_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel
);
/**
  @brief Access control check for a pending socket accept
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket
  @param addr Address of the listening socket (coming soon)

  Determine whether the subject identified by the credential can accept()
  a pending connection on the socket from the host specified by addr.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_accepted_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel,
	struct sockaddr *addr
);
/**
  @brief Access control check for socket bind
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket
  @param addr Name to assign to the socket

  Determine whether the subject identified by the credential can bind()
  the name (addr) to the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_bind_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel,
	struct sockaddr *addr
);
/**
  @brief Access control check for socket connect
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket
  @param addr Name to assign to the socket

  Determine whether the subject identified by the credential can
  connect() the passed socket to the remote host specified by addr.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_connect_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel,
	struct sockaddr *addr
);
/**
  @brief Access control check for socket() system call.
  @param cred Subject credential
  @param domain communication domain
  @param type socket type
  @param protocol socket protocol

  Determine whether the subject identified by the credential can
  make the socket() call.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_create_t(
	kauth_cred_t cred,
	int domain,
	int type,
	int protocol
);
/**
  @brief Access control check for delivering data to a user's receieve queue
  @param so The socket data is being delivered to
  @param so_label The label of so
  @param m The mbuf whose data will be deposited into the receive queue
  @param m_label The label of the sender of the data.

  A socket has a queue for receiving incoming data.  When a packet arrives
  on the wire, it eventually gets deposited into this queue, which the
  owner of the socket drains when they read from the socket's file descriptor.

  This function determines whether the socket can receive data from
  the sender specified by m_label.

  @warning There is an outstanding design issue surrounding the placement
  of this function.  The check must be placed either before or after the
  TCP sequence and ACK counters are updated.  Placing the check before
  the counters are updated causes the incoming packet to be resent by
  the remote if the check rejects it.  Placing the check after the counters
  are updated results in a completely silent drop.  As far as each TCP stack
  is concerned the packet was received, however, the data will not be in the
  socket's receive queue.  Another consideration is that the current design
  requires using the "failed label" occasionally.  In that case, on rejection,
  we want the remote TCP to resend the data.  Because of this, we chose to
  place this check before the counters are updated, so rejected packets will be
  resent by the remote host.

  If a policy keeps rejecting the same packet, eventually the connection will
  be dropped.  Policies have several options if this design causes problems.
  For example, one options is to sanitize the mbuf such that it is acceptable,
  then accept it.  That may require negotiation between policies as the
  Framework will not know to re-check the packet.

  The policy must handle NULL MBUF labels.  This will likely be the case
  for non-local TCP sockets for example.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_deliver_t(
	socket_t so,
	struct label *so_label,
	struct mbuf *m,
	struct label *m_label
);
/**
  @brief Access control check for socket kqfilter
  @param cred Subject credential
  @param kn Object knote
  @param so Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can
  receive the knote on the passed socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_kqfilter_t(
	kauth_cred_t cred,
	struct knote *kn,
	socket_t so,
	struct label *socklabel
);
/**
  @brief Access control check for socket relabel
  @param cred Subject credential
  @param so Object socket
  @param so_label The current label of so
  @param newlabel The label to be assigned to so

  Determine whether the subject identified by the credential can
  change the label on the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_label_update_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *so_label,
	struct label *newlabel
);
/**
  @brief Access control check for socket listen
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can
  listen() on the passed socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_listen_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel
);
/**
  @brief Access control check for socket receive
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can
  receive data from the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_receive_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel
);

/**                                                                                               
  @brief Access control check for socket receive                                                  
  @param cred Subject credential                                                                  
  @param sock Object socket                                                                     
  @param socklabel Policy label for socket                                                        
  @param saddr Name of the remote socket                                                           
                                                                                                  
  Determine whether the subject identified by the credential can                                  
  receive data from the remote host specified by addr.                                            
                                                                                                  
  @return Return 0 if access if granted, otherwise an appropriate                                 
  value for errno should be returned.                                                             
*/
typedef int mpo_socket_check_received_t(
					kauth_cred_t cred,
					struct socket *sock,
					struct label *socklabel,
					struct sockaddr *saddr
					);


/**
  @brief Access control check for socket select
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket
  @param which The operation selected on: FREAD or FWRITE

  Determine whether the subject identified by the credential can use the
  socket in a call to select().

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_select_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel,
	int which
);
/**
  @brief Access control check for socket send
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket
  @param addr Address being sent to

  Determine whether the subject identified by the credential can send
  data to the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_send_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel,
	struct sockaddr *addr
);
/**
  @brief Access control check for retrieving socket status
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for so

  Determine whether the subject identified by the credential can
  execute the stat() system call on the given socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_stat_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel
);
/**
  @brief Access control check for setting socket options
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for so
  @param sopt The options being set

  Determine whether the subject identified by the credential can
  execute the setsockopt system call on the given socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_setsockopt_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel,
	struct sockopt *sopt
);
/**
  @brief Access control check for getting socket options
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for so
  @param sopt The options to get

  Determine whether the subject identified by the credential can
  execute the getsockopt system call on the given socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_socket_check_getsockopt_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *socklabel,
	struct sockopt *sopt
);
/**
  @brief Label a socket
  @param oldsock Listening socket
  @param oldlabel Policy label associated with oldsock
  @param newsock New socket
  @param newlabel Policy label associated with newsock

  A new socket is created when a connection is accept(2)ed.  This
  function labels the new socket based on the existing listen(2)ing
  socket.
*/
typedef void mpo_socket_label_associate_accept_t(
	socket_t oldsock,
	struct label *oldlabel,
	socket_t newsock,
	struct label *newlabel
);
/**
  @brief Assign a label to a new socket
  @param cred Credential of the owning process
  @param so The socket being labeled
  @param solabel The label
  @warning cred can be NULL

  Set the label on a newly created socket from the passed subject
  credential.  This call is made when a socket is created.  The
  credentials may be null if the socket is being created by the
  kernel.
*/
typedef void mpo_socket_label_associate_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *solabel
);
/**
  @brief Copy a socket label
  @param src Source label
  @param dest Destination label

  Copy the socket label information in src into dest.
*/
typedef void mpo_socket_label_copy_t(
	struct label *src,
	struct label *dest
);
/**
  @brief Destroy socket label
  @param label The label to be destroyed

  Destroy a socket label.  Since the object is going out of
  scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_socket_label_destroy_t(
	struct label *label
);
/**
  @brief Externalize a socket label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of label

  Produce an externalized socket label based on the label structure passed.
  An externalized label consists of a text representation of the label
  contents that can be used with userland applications and read by the
  user.  If element_name does not match a namespace managed by the policy,
  simply return 0. Only return nonzero if an error occurs while externalizing
  the label data.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_socket_label_externalize_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Initialize socket label
  @param label New label to initialize
  @param waitok Malloc flags

  Initialize the label of a newly instantiated socket.  The waitok
  field may be one of M_WAITOK and M_NOWAIT, and should be employed to
  avoid performing a sleeping malloc(9) during this initialization
  call.  It it not always safe to sleep during this entry point.

  @warning Since it is possible for the waitok flags to be set to
  M_NOWAIT, the malloc operation may fail.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_socket_label_init_t(
	struct label *label,
	int waitok
);
/**
  @brief Internalize a socket label
  @param label Label to be filled in
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce an internal socket label structure based on externalized label
  data in text format.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_socket_label_internalize_t(
	struct label *label,
	char *element_name,
	char *element_data
);
/**
  @brief Relabel socket
  @param cred Subject credential
  @param so Object; socket
  @param so_label Current label of the socket
  @param newlabel The label to be assigned to so

  The subject identified by the credential has previously requested
  and was authorized to relabel the socket; this entry point allows
  policies to perform the actual label update operation.

  @warning XXX This entry point will likely change in future versions.
*/
typedef void mpo_socket_label_update_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *so_label,
	struct label *newlabel
);
/**
  @brief Set the peer label on a socket from mbuf
  @param m Mbuf chain received on socket so
  @param m_label Label for m
  @param so Current label for the socket
  @param so_label Policy label to be filled out for the socket

  Set the peer label of a socket based on the label of the sender of the
  mbuf.

  This is called for every TCP/IP packet received.  The first call for a given
  socket operates on a newly initialized label, and subsequent calls operate
  on existing label data.

  @warning Because this can affect performance significantly, it has
  different sematics than other 'set' operations.  Typically, 'set' operations
  operate on newly initialzed labels and policies do not need to worry about
  clobbering existing values.  In this case, it is too inefficient to
  initialize and destroy a label every time data is received for the socket.
  Instead, it is up to the policies to determine how to replace the label data.
  Most policies should be able to replace the data inline.
*/
typedef void mpo_socketpeer_label_associate_mbuf_t(
	struct mbuf *m,
	struct label *m_label,
	socket_t so,
	struct label *so_label
);
/**
  @brief Set the peer label on a socket from socket
  @param source Local socket
  @param sourcelabel Policy label for source
  @param target Peer socket
  @param targetlabel Policy label to fill in for target

  Set the peer label on a stream UNIX domain socket from the passed
  remote socket endpoint. This call will be made when the socket pair
  is connected, and will be made for both endpoints.

  Note that this call is only made on connection; it is currently not updated
  during communication.
*/
typedef void mpo_socketpeer_label_associate_socket_t(
	socket_t source,
	struct label *sourcelabel,
	socket_t target,
	struct label *targetlabel
);
/**
  @brief Destroy socket peer label
  @param label The peer label to be destroyed

  Destroy a socket peer label.  Since the object is going out of
  scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_socketpeer_label_destroy_t(
	struct label *label
);
/**
  @brief Externalize a socket peer label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of label

  Produce an externalized socket peer label based on the label structure
  passed. An externalized label consists of a text representation of the
  label contents that can be used with userland applications and read by the
  user.  If element_name does not match a namespace managed by the policy,
  simply return 0. Only return nonzero if an error occurs while externalizing
  the label data.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_socketpeer_label_externalize_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Initialize socket peer label
  @param label New label to initialize
  @param waitok Malloc flags

  Initialize the peer label of a newly instantiated socket.  The
  waitok field may be one of M_WAITOK and M_NOWAIT, and should be
  employed to avoid performing a sleeping malloc(9) during this
  initialization call.  It it not always safe to sleep during this
  entry point.

  @warning Since it is possible for the waitok flags to be set to
  M_NOWAIT, the malloc operation may fail.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_socketpeer_label_init_t(
	struct label *label,
	int waitok
);
/**
  @brief Access control check for enabling accounting
  @param cred Subject credential
  @param vp Accounting file
  @param vlabel Label associated with vp

  Determine whether the subject should be allowed to enable accounting,
  based on its label and the label of the accounting log file.  See
  acct(5) for more information.

  As accounting is disabled by passing NULL to the acct(2) system call,
  the policy should be prepared for both 'vp' and 'vlabel' to be NULL.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_acct_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Access control check for audit
  @param cred Subject credential
  @param record Audit record
  @param length Audit record length

  Determine whether the subject identified by the credential can submit
  an audit record for inclusion in the audit log via the audit() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_audit_t(
	kauth_cred_t cred,
	void *record,
	int length
);
/**
  @brief Access control check for controlling audit
  @param cred Subject credential
  @param vp Audit file
  @param vl Label associated with vp

  Determine whether the subject should be allowed to enable auditing using
  the auditctl() system call, based on its label and the label of the proposed
  audit file.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_auditctl_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vl
);
/**
  @brief Access control check for manipulating auditing
  @param cred Subject credential
  @param cmd Audit control command

  Determine whether the subject identified by the credential can perform
  the audit subsystem control operation cmd via the auditon() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_auditon_t(
	kauth_cred_t cred,
	int cmd
);
/**
  @brief Access control check for using CHUD facilities
  @param cred Subject credential

  Determine whether the subject identified by the credential can perform
  performance-related tasks using the CHUD system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_chud_t(
	kauth_cred_t cred
);
/**
  @brief Access control check for obtaining the host control port
  @param cred Subject credential

  Determine whether the subject identified by the credential can
  obtain the host control port.

  @return Return 0 if access is granted, or non-zero otherwise.
*/
typedef int mpo_system_check_host_priv_t(
	kauth_cred_t cred
);
/**
  @brief Access control check for obtaining system information
  @param cred Subject credential
  @param info_type A description of the information requested

  Determine whether the subject identified by the credential should be
  allowed to obtain information about the system.

  This is a generic hook that can be used in a variety of situations where
  information is being returned that might be considered sensitive.
  Rather than adding a new MAC hook for every such interface, this hook can
  be called with a string identifying the type of information requested.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_info_t(
	kauth_cred_t cred,
	const char *info_type
);
/**
  @brief Access control check for calling NFS services
  @param cred Subject credential

  Determine whether the subject identified by the credential should be
  allowed to call nfssrv(2).

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_nfsd_t(
	kauth_cred_t cred
);
/**
  @brief Access control check for reboot
  @param cred Subject credential
  @param howto howto parameter from reboot(2)

  Determine whether the subject identified by the credential should be
  allowed to reboot the system in the specified manner.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_reboot_t(
	kauth_cred_t cred,
	int howto
);
/**
  @brief Access control check for setting system clock
  @param cred Subject credential

  Determine whether the subject identified by the credential should be
  allowed to set the system clock.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_settime_t(
	kauth_cred_t cred
);
/**
  @brief Access control check for removing swap devices
  @param cred Subject credential
  @param vp Swap device
  @param label Label associated with vp

  Determine whether the subject identified by the credential should be
  allowed to remove vp as a swap device.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_swapoff_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for adding swap devices
  @param cred Subject credential
  @param vp Swap device
  @param label Label associated with vp

  Determine whether the subject identified by the credential should be
  allowed to add vp as a swap device.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_swapon_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for sysctl
  @param cred Subject credential
  @param namestring String representation of sysctl name.
  @param name Integer name; see sysctl(3)
  @param namelen Length of name array of integers; see sysctl(3)
  @param old 0 or address where to store old value; see sysctl(3)
  @param oldlen Length of old buffer; see sysctl(3)
  @param newvalue 0 or address of new value; see sysctl(3)
  @param newlen Length of new buffer; see sysctl(3)

  Determine whether the subject identified by the credential should be
  allowed to make the specified sysctl(3) transaction.

  The sysctl(3) call specifies that if the old value is not desired,
  oldp and oldlenp should be set to NULL.  Likewise, if a new value is
  not to be set, newp should be set to NULL and newlen set to 0.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_sysctlbyname_t(
	kauth_cred_t cred,
	const char *namestring,
	int *name,
	u_int namelen,
	user_addr_t old,	/* NULLOK */
	size_t oldlen,
	user_addr_t newvalue,	/* NULLOK */
	size_t newlen
);
/**
  @brief Access control check for kas_info
  @param cred Subject credential
  @param selector Category of information to return. See kas_info.h

  Determine whether the subject identified by the credential can perform
  introspection of the kernel address space layout for
  debugging/performance analysis.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_system_check_kas_info_t(
	kauth_cred_t cred,
	int selector
);
/**
  @brief Create a System V message label
  @param cred Subject credential
  @param msqptr The message queue the message will be placed in
  @param msqlabel The label of the message queue
  @param msgptr The message
  @param msglabel The label of the message

  Label the message as its placed in the message queue.
*/
typedef void mpo_sysvmsg_label_associate_t(
	kauth_cred_t cred,
	struct msqid_kernel *msqptr,
	struct label *msqlabel,
	struct msg *msgptr,
	struct label *msglabel
);
/**
  @brief Destroy System V message label
  @param label The label to be destroyed

  Destroy a System V message label.  Since the object is
  going out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_sysvmsg_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize System V message label
  @param label New label to initialize

  Initialize the label for a newly instantiated System V message.
*/
typedef void mpo_sysvmsg_label_init_t(
	struct label *label
);
/**
  @brief Clean up a System V message label
  @param label The label to be destroyed

  Clean up a System V message label.  Darwin pre-allocates
  messages at system boot time and re-uses them rather than
  allocating new ones.  Before messages are returned to the "free
  pool", policies can cleanup or overwrite any information present in
  the label.
*/
typedef void mpo_sysvmsg_label_recycle_t(
	struct label *label
);
/**
  @brief Access control check for System V message enqueuing
  @param cred Subject credential
  @param msgptr The message
  @param msglabel The message's label
  @param msqptr The message queue
  @param msqlabel The message queue's label

  Determine whether the subject identified by the credential can add the
  given message to the given message queue.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvmsq_check_enqueue_t(
	kauth_cred_t cred,
	struct msg *msgptr,
	struct label *msglabel,
	struct msqid_kernel *msqptr,
	struct label *msqlabel
);
/**
  @brief Access control check for System V message reception
  @param cred The credential of the intended recipient
  @param msgptr The message
  @param msglabel The message's label

  Determine whether the subject identified by the credential can receive
  the given message.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvmsq_check_msgrcv_t(
	kauth_cred_t cred,
	struct msg *msgptr,
	struct label *msglabel
);
/**
  @brief Access control check for System V message queue removal
  @param cred The credential of the caller
  @param msgptr The message
  @param msglabel The message's label

  System V message queues are removed using the msgctl() system call.
  The system will iterate over each messsage in the queue, calling this
  function for each, to determine whether the caller has the appropriate
  credentials.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvmsq_check_msgrmid_t(
	kauth_cred_t cred,
	struct msg *msgptr,
	struct label *msglabel
);
/**
  @brief Access control check for msgctl()
  @param cred The credential of the caller
  @param msqptr The message queue
  @param msqlabel The message queue's label

  This access check is performed to validate calls to msgctl().

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvmsq_check_msqctl_t(
	kauth_cred_t cred,
	struct msqid_kernel *msqptr,
	struct label *msqlabel,
	int cmd
);
/**
  @brief Access control check to get a System V message queue
  @param cred The credential of the caller
  @param msqptr The message queue requested
  @param msqlabel The message queue's label

  On a call to msgget(), if the queue requested already exists,
  and it is a public queue, this check will be performed before the
  queue's ID is returned to the user.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvmsq_check_msqget_t(
	kauth_cred_t cred,
	struct msqid_kernel *msqptr,
	struct label *msqlabel
);
/**
  @brief Access control check to receive a System V message from the given queue
  @param cred The credential of the caller
  @param msqptr The message queue to receive from
  @param msqlabel The message queue's label

  On a call to msgrcv(), this check is performed to determine whether the
  caller has receive rights on the given queue.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvmsq_check_msqrcv_t(
	kauth_cred_t cred,
	struct msqid_kernel *msqptr,
	struct label *msqlabel
);
/**
  @brief Access control check to send a System V message to the given queue
  @param cred The credential of the caller
  @param msqptr The message queue to send to
  @param msqlabel The message queue's label

  On a call to msgsnd(), this check is performed to determine whether the
  caller has send rights on the given queue.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvmsq_check_msqsnd_t(
	kauth_cred_t cred,
	struct msqid_kernel *msqptr,
	struct label *msqlabel
);
/**
  @brief Create a System V message queue label
  @param cred Subject credential
  @param msqptr The message queue
  @param msqlabel The label of the message queue

*/
typedef void mpo_sysvmsq_label_associate_t(
	kauth_cred_t cred,
	struct msqid_kernel *msqptr,
	struct label *msqlabel
);
/**
  @brief Destroy System V message queue label
  @param label The label to be destroyed

  Destroy a System V message queue label.  Since the object is
  going out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_sysvmsq_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize System V message queue label
  @param label New label to initialize

  Initialize the label for a newly instantiated System V message queue.
*/
typedef void mpo_sysvmsq_label_init_t(
	struct label *label
);
/**
  @brief Clean up a System V message queue label
  @param label The label to be destroyed

  Clean up a System V message queue label.  Darwin pre-allocates
  message queues at system boot time and re-uses them rather than
  allocating new ones.  Before message queues are returned to the "free
  pool", policies can cleanup or overwrite any information present in
  the label.
*/
typedef void mpo_sysvmsq_label_recycle_t(
	struct label *label
);
/**
  @brief Access control check for System V semaphore control operation
  @param cred Subject credential
  @param semakptr Pointer to semaphore identifier
  @param semaklabel Label associated with semaphore
  @param cmd Control operation to be performed; see semctl(2)

  Determine whether the subject identified by the credential can perform
  the operation indicated by cmd on the System V semaphore semakptr.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvsem_check_semctl_t(
	kauth_cred_t cred,
	struct semid_kernel *semakptr,
	struct label *semaklabel,
	int cmd
);
/**
  @brief Access control check for obtaining a System V semaphore
  @param cred Subject credential
  @param semakptr Pointer to semaphore identifier
  @param semaklabel Label to associate with the semaphore

  Determine whether the subject identified by the credential can
  obtain a System V semaphore.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvsem_check_semget_t(
	kauth_cred_t cred,
	struct semid_kernel *semakptr,
	struct label *semaklabel
);
/**
  @brief Access control check for System V semaphore operations
  @param cred Subject credential
  @param semakptr Pointer to semaphore identifier
  @param semaklabel Label associated with the semaphore
  @param accesstype Flags to indicate access (read and/or write)

  Determine whether the subject identified by the credential can
  perform the operations on the System V semaphore indicated by
  semakptr.  The accesstype flags hold the maximum set of permissions
  from the sem_op array passed to the semop system call.  It may
  contain SEM_R for read-only operations or SEM_A for read/write
  operations.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvsem_check_semop_t(
	kauth_cred_t cred,
	struct semid_kernel *semakptr,
	struct label *semaklabel,
	size_t accesstype
);
/**
  @brief Create a System V semaphore label
  @param cred Subject credential
  @param semakptr The semaphore being created
  @param semalabel Label to associate with the new semaphore

  Label a new System V semaphore.  The label was previously
  initialized and associated with the semaphore.  At this time, an
  appropriate initial label value should be assigned to the object and
  stored in semalabel.
*/
typedef void mpo_sysvsem_label_associate_t(
	kauth_cred_t cred,
	struct semid_kernel *semakptr,
	struct label *semalabel
);
/**
  @brief Destroy System V semaphore label
  @param label The label to be destroyed

  Destroy a System V semaphore label.  Since the object is
  going out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_sysvsem_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize System V semaphore label
  @param label New label to initialize

  Initialize the label for a newly instantiated System V semaphore.  Sleeping
  is permitted.
*/
typedef void mpo_sysvsem_label_init_t(
	struct label *label
);
/**
  @brief Clean up a System V semaphore label
  @param label The label to be cleaned

  Clean up a System V semaphore label.  Darwin pre-allocates
  semaphores at system boot time and re-uses them rather than
  allocating new ones.  Before semaphores are returned to the "free
  pool", policies can cleanup or overwrite any information present in
  the label.
*/
typedef void mpo_sysvsem_label_recycle_t(
	struct label *label
);
/**
  @brief Access control check for mapping System V shared memory
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment
  @param shmflg shmat flags; see shmat(2)

  Determine whether the subject identified by the credential can map
  the System V shared memory segment associated with shmsegptr.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvshm_check_shmat_t(
	kauth_cred_t cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel,
	int shmflg
);
/**
  @brief Access control check for System V shared memory control operation
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment
  @param cmd Control operation to be performed; see shmctl(2)

  Determine whether the subject identified by the credential can perform
  the operation indicated by cmd on the System V shared memory segment
  shmsegptr.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvshm_check_shmctl_t(
	kauth_cred_t cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel,
	int cmd
);
/**
  @brief Access control check for unmapping System V shared memory
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment

  Determine whether the subject identified by the credential can unmap
  the System V shared memory segment associated with shmsegptr.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvshm_check_shmdt_t(
	kauth_cred_t cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel
);
/**
  @brief Access control check obtaining System V shared memory identifier
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment
  @param shmflg shmget flags; see shmget(2)

  Determine whether the subject identified by the credential can get
  the System V shared memory segment address.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_sysvshm_check_shmget_t(
	kauth_cred_t cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel,
	int shmflg
);
/**
  @brief Create a System V shared memory region label
  @param cred Subject credential
  @param shmsegptr The shared memory region being created
  @param shmlabel Label to associate with the new shared memory region

  Label a new System V shared memory region.  The label was previously
  initialized and associated with the shared memory region.  At this
  time, an appropriate initial label value should be assigned to the
  object and stored in shmlabel.
*/
typedef void mpo_sysvshm_label_associate_t(
	kauth_cred_t cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmlabel
);
/**
  @brief Destroy System V shared memory label
  @param label The label to be destroyed

  Destroy a System V shared memory region label.  Since the
  object is going out of scope, policy modules should free any
  internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_sysvshm_label_destroy_t(
	struct label *label
);
/**
  @brief Initialize System V Shared Memory region label
  @param label New label to initialize

  Initialize the label for a newly instantiated System V Shared Memory
  region.  Sleeping is permitted.
*/
typedef void mpo_sysvshm_label_init_t(
	struct label *label
);
/**
  @brief Clean up a System V Share Memory Region label
  @param shmlabel The label to be cleaned

  Clean up a System V Shared Memory Region label.  Darwin
  pre-allocates these objects at system boot time and re-uses them
  rather than allocating new ones.  Before the memory regions are
  returned to the "free pool", policies can cleanup or overwrite any
  information present in the label.
*/
typedef void mpo_sysvshm_label_recycle_t(
	struct label *shmlabel
);
/**
  @brief Access control check for getting a process's task name
  @param cred Subject credential
  @param p Object process

  Determine whether the subject identified by the credential can get
  the passed process's task name port.
  This call is used by the task_name_for_pid(2) API.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to hide visibility of the target.
*/
typedef int mpo_proc_check_get_task_name_t(
	kauth_cred_t cred,
	struct proc *p
);
/**
  @brief Access control check for getting a process's task port
  @param cred Subject credential
  @param p Object process

  Determine whether the subject identified by the credential can get
  the passed process's task control port.
  This call is used by the task_for_pid(2) API.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to hide visibility of the target.
*/
typedef int mpo_proc_check_get_task_t(
	kauth_cred_t cred,
	struct proc *p
);

/**
  @brief Access control check for exposing a process's task port
  @param cred Subject credential
  @param p Object process

  Determine whether the subject identified by the credential can expose
  the passed process's task control port.
  This call is used by the accessor APIs like processor_set_tasks() and
  processor_set_threads().

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to hide visibility of the target.
*/
typedef int mpo_proc_check_expose_task_t(
	kauth_cred_t cred,
	struct proc *p
);

/**
 @brief Check whether task's IPC may inherit across process exec
 @param p current process instance
 @param cur_vp vnode pointer to current instance
 @param cur_offset offset of binary of currently executing image
 @param img_vp vnode pointer to to be exec'ed image
 @param img_offset offset into file which is selected for execution
 @param scriptvp vnode pointer of script file if any.
 @return Return 0 if access is granted.
 	EPERM     if parent does not have any entitlements.
	EACCESS   if mismatch in entitlements
*/
typedef int mpo_proc_check_inherit_ipc_ports_t(
	struct proc *p,
	struct vnode *cur_vp,
	off_t cur_offset,
	struct vnode *img_vp,
	off_t img_offset,
	struct vnode *scriptvp
);

/**
 @brief Privilege check for a process to run invalid
 @param p Object process
 
 Determine whether the process may execute even though the system determined
 that it is untrusted (eg unidentified / modified code).
 
 @return Return 0 if access is granted, otherwise an appropriate value for
 errno should be returned.
 */
typedef int mpo_proc_check_run_cs_invalid_t(
	struct proc *p
);

/**
  @brief Perform MAC-related events when a thread returns to user space
  @param thread Mach (not BSD) thread that is returning

  This entry point permits policy modules to perform MAC-related
  events when a thread returns to user space, via a system call
  return or trap return.
*/
typedef void mpo_thread_userret_t(
	struct thread *thread
);

/**
  @brief Check vnode access
  @param cred Subject credential
  @param vp Object vnode
  @param label Label for vp
  @param acc_mode access(2) flags

  Determine how invocations of access(2) and related calls by the
  subject identified by the credential should return when performed
  on the passed vnode using the passed access flags. This should
  generally be implemented using the same semantics used in
  mpo_vnode_check_open.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_access_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	int acc_mode
);
/**
  @brief Access control check for changing working directory
  @param cred Subject credential
  @param dvp Object; vnode to chdir(2) into
  @param dlabel Policy label for dvp

  Determine whether the subject identified by the credential can change
  the process working directory to the passed vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_chdir_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel
);
/**
  @brief Access control check for changing root directory
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param cnp Component name for dvp

  Determine whether the subject identified by the credential should be
  allowed to chroot(2) into the specified directory (dvp).

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_vnode_check_chroot_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct componentname *cnp
);
/**
  @brief Access control check for creating clone
  @param cred Subject credential
  @param dvp Vnode of directory to create the clone in
  @param dlabel Policy label associated with dvp
  @param vp Vnode of the file to clone from
  @param label Policy label associated with vp
  @param cnp Component name for the clone being created

  Determine whether the subject identified by the credential should be
  allowed to create a clone of the vnode vp with the name specified by cnp.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_clone_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp
);
/**
  @brief Access control check for creating vnode
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label for dvp
  @param cnp Component name for dvp
  @param vap vnode attributes for vap

  Determine whether the subject identified by the credential can create
  a vnode with the passed parent directory, passed name information,
  and passed attribute information. This call may be made in a number of
  situations, including as a result of calls to open(2) with O_CREAT,
  mknod(2), mkfifo(2), and others.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_create_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct componentname *cnp,
	struct vnode_attr *vap
);
/**
  @brief Access control check for deleting extended attribute
  @param cred Subject credential
  @param vp Object vnode
  @param vlabel Label associated with vp
  @param name Extended attribute name

  Determine whether the subject identified by the credential can delete
  the extended attribute from the passed vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_deleteextattr_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	const char *name
);
/**
  @brief Access control check for exchanging file data
  @param cred Subject credential
  @param v1 vnode 1 to swap
  @param vl1 Policy label for v1
  @param v2 vnode 2 to swap
  @param vl2 Policy label for v2

  Determine whether the subject identified by the credential can swap the data
  in the two supplied vnodes.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_exchangedata_t(
	kauth_cred_t cred,
	struct vnode *v1,
	struct label *vl1,
	struct vnode *v2,
	struct label *vl2
);
/**
  @brief Access control check for executing the vnode
  @param cred Subject credential
  @param vp Object vnode to execute
  @param scriptvp Script being executed by interpreter, if any.
  @param vnodelabel Label corresponding to vp
  @param scriptlabel Script vnode label
  @param execlabel Userspace provided execution label
  @param cnp Component name for file being executed
  @param macpolicyattr MAC policy-specific spawn attribute data.
  @param macpolicyattrlen Length of policy-specific spawn attribute data.

  Determine whether the subject identified by the credential can execute
  the passed vnode. Determination of execute privilege is made separately
  from decisions about any process label transitioning event.

  The final label, execlabel, corresponds to a label supplied by a
  user space application through the use of the mac_execve system call.
  This label will be NULL if the user application uses the the vendor
  execve(2) call instead of the MAC Framework mac_execve() call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_exec_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct vnode *scriptvp,
	struct label *vnodelabel,
	struct label *scriptlabel,
	struct label *execlabel,	/* NULLOK */
	struct componentname *cnp,
	u_int *csflags,
	void *macpolicyattr,
	size_t macpolicyattrlen
);
/**
  @brief Access control check for fsgetpath
  @param cred Subject credential
  @param vp Vnode for which a path will be returned
  @param label Label associated with the vnode

  Determine whether the subject identified by the credential can get the path
  of the given vnode with fsgetpath.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_fsgetpath_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for retrieving file attributes
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct fileproc
  @param vp Object vnode
  @param vlabel Policy label for vp
  @param va Vnode attributes to retrieve

  Determine whether the subject identified by the credential can
  get information about the passed vnode.  The active_cred hold
  the credentials of the subject performing the operation, and
  file_cred holds the credentials of the subject that originally
  opened the file. This check happens during stat(), lstat(),
  fstat(), and getattrlist() syscalls.  See <sys/vnode.h> for
  definitions of the attributes.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.

  @note Policies may change the contents of va to alter the list of
  file attributes returned.
*/
typedef int mpo_vnode_check_getattr_t(
	kauth_cred_t active_cred,
	kauth_cred_t file_cred, /* NULLOK */
	struct vnode *vp,
	struct label *vlabel,
	struct vnode_attr *va
);
/**
  @brief Access control check for retrieving file attributes
  @param cred Subject credential
  @param vp Object vnode
  @param vlabel Policy label for vp
  @param alist List of attributes to retrieve

  Determine whether the subject identified by the credential can read
  various attributes of the specified vnode, or the filesystem or volume on
  which that vnode resides. See <sys/attr.h> for definitions of the
  attributes.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege. Access control covers all attributes requested
  with this call; the security policy is not permitted to change the set of
  attributes requested.
*/
typedef int mpo_vnode_check_getattrlist_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	struct attrlist *alist
);
/**
  @brief Access control check for retrieving an extended attribute
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param name Extended attribute name
  @param uio I/O structure pointer

  Determine whether the subject identified by the credential can retrieve
  the extended attribute from the passed vnode.  The uio parameter
  will be NULL when the getxattr(2) call has been made with a NULL data
  value; this is done to request the size of the data only.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_getextattr_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,		/* NULLOK */
	const char *name,
	struct uio *uio			/* NULLOK */
);
/**
  @brief Access control check for ioctl
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param cmd Device-dependent request code; see ioctl(2)

  Determine whether the subject identified by the credential can perform
  the ioctl operation indicated by com.

  @warning Since ioctl data is opaque from the standpoint of the MAC
  framework, and since ioctls can affect many aspects of system
  operation, policies must exercise extreme care when implementing
  access control checks.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_ioctl_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	unsigned int cmd
);
/**
  @brief Access control check for vnode kqfilter
  @param active_cred Subject credential
  @param kn Object knote
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can
  receive the knote on the passed vnode.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_vnode_check_kqfilter_t(
	kauth_cred_t active_cred,
	kauth_cred_t file_cred,		/* NULLOK */
	struct knote *kn,
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for relabel
  @param cred Subject credential
  @param vp Object vnode
  @param vnodelabel Existing policy label for vp
  @param newlabel Policy label update to later be applied to vp
  @see mpo_relable_vnode_t

  Determine whether the subject identified by the credential can relabel
  the passed vnode to the passed label update.  If all policies permit
  the label change, the actual relabel entry point (mpo_vnode_label_update)
  will follow.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_label_update_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vnodelabel,
	struct label *newlabel
);
/**
  @brief Access control check for creating link
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param vp Link destination vnode
  @param label Policy label associated with vp
  @param cnp Component name for the link being created

  Determine whether the subject identified by the credential should be
  allowed to create a link to the vnode vp with the name specified by cnp.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_link_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp
);
/**
  @brief Access control check for listing extended attributes
  @param cred Subject credential
  @param vp Object vnode
  @param vlabel Policy label associated with vp

  Determine whether the subject identified by the credential can retrieve
  a list of named extended attributes from a vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_listextattr_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Access control check for lookup
  @param cred Subject credential
  @param dvp Object vnode
  @param dlabel Policy label for dvp
  @param cnp Component name being looked up

  Determine whether the subject identified by the credential can perform
  a lookup in the passed directory vnode for the passed name (cnp).

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_lookup_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct componentname *cnp
);
/**
  @brief Access control check for open
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label associated with vp
  @param acc_mode open(2) access mode

  Determine whether the subject identified by the credential can perform
  an open operation on the passed vnode with the passed access mode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_open_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	int acc_mode
);
/**
  @brief Access control check for read
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct fileproc
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can perform
  a read operation on the passed vnode.  The active_cred hold the credentials
  of the subject performing the operation, and file_cred holds the
  credentials of the subject that originally opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_read_t(
	kauth_cred_t active_cred,	/* SUBJECT */
	kauth_cred_t file_cred,	/* NULLOK */
	struct vnode *vp,		/* OBJECT */
	struct label *label		/* LABEL */
);
/**
  @brief Access control check for read directory
  @param cred Subject credential
  @param dvp Object directory vnode
  @param dlabel Policy label for dvp

  Determine whether the subject identified by the credential can
  perform a readdir operation on the passed directory vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_readdir_t(
	kauth_cred_t cred,		/* SUBJECT */
	struct vnode *dvp,		/* OBJECT */
	struct label *dlabel		/* LABEL */
);
/**
  @brief Access control check for read link
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can perform
  a readlink operation on the passed symlink vnode.  This call can be made
  in a number of situations, including an explicit readlink call by the
  user process, or as a result of an implicit readlink during a name
  lookup by the process.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_readlink_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for rename
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param vp vnode to be renamed
  @param label Policy label associated with vp
  @param cnp Component name for vp
  @param tdvp Destination directory vnode
  @param tdlabel Policy label associated with tdvp
  @param tvp Overwritten vnode
  @param tlabel Policy label associated with tvp
  @param tcnp Destination component name

  Determine whether the subject identified by the credential should be allowed
  to rename the vnode vp to something else.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_rename_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp,
	struct vnode *tdvp,
	struct label *tdlabel,
	struct vnode *tvp,
	struct label *tlabel,
	struct componentname *tcnp
);
/**
  @brief Access control check for rename from
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param vp vnode to be renamed
  @param label Policy label associated with vp
  @param cnp Component name for vp
  @see mpo_vnode_check_rename_t
  @see mpo_vnode_check_rename_to_t

  Determine whether the subject identified by the credential should be
  allowed to rename the vnode vp to something else.

  Due to VFS locking constraints (to make sure proper vnode locks are
  held during this entry point), the vnode relabel checks had to be
  split into two parts: relabel_from and relabel to.

  This hook is deprecated, mpo_vnode_check_rename_t should be used instead.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_rename_from_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp
);
/**
  @brief Access control check for rename to
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param vp Overwritten vnode
  @param label Policy label associated with vp
  @param samedir Boolean; 1 if the source and destination directories are the same
  @param cnp Destination component name
  @see mpo_vnode_check_rename_t
  @see mpo_vnode_check_rename_from_t

  Determine whether the subject identified by the credential should be
  allowed to rename to the vnode vp, into the directory dvp, or to the
  name represented by cnp. If there is no existing file to overwrite,
  vp and label will be NULL.

  Due to VFS locking constraints (to make sure proper vnode locks are
  held during this entry point), the vnode relabel checks had to be
  split into two parts: relabel_from and relabel to.

  This hook is deprecated, mpo_vnode_check_rename_t should be used instead.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_rename_to_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,			/* NULLOK */
	struct label *label,			/* NULLOK */
	int samedir,
	struct componentname *cnp
);
/**
  @brief Access control check for revoke
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can revoke
  access to the passed vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_revoke_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for searchfs
  @param cred Subject credential
  @param vp Object vnode
  @param vlabel Policy label for vp
  @param alist List of attributes used as search criteria

  Determine whether the subject identified by the credential can search the
  vnode using the searchfs system call.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_searchfs_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	struct attrlist *alist
);
/**
  @brief Access control check for select
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param which The operation selected on: FREAD or FWRITE

  Determine whether the subject identified by the credential can select
  the vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
*/
typedef int mpo_vnode_check_select_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	int which
);
/**
  @brief Access control check for setting ACL
  @param cred Subject credential
  @param vp Object node
  @param label Policy label for vp
  @param acl ACL structure pointer

  Determine whether the subject identified by the credential can set an ACL
  on the specified vnode.  The ACL pointer will be NULL when removing an ACL.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_setacl_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	struct kauth_acl *acl
);
/**
  @brief Access control check for setting file attributes
  @param cred Subject credential
  @param vp Object vnode
  @param vlabel Policy label for vp
  @param alist List of attributes to set

  Determine whether the subject identified by the credential can set
  various attributes of the specified vnode, or the filesystem or volume on
  which that vnode resides. See <sys/attr.h> for definitions of the
  attributes.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege. Access control covers all attributes requested
  with this call.
*/
typedef int mpo_vnode_check_setattrlist_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	struct attrlist *alist
);
/**
  @brief Access control check for setting extended attribute
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param name Extended attribute name
  @param uio I/O structure pointer

  Determine whether the subject identified by the credential can set the
  extended attribute of passed name and passed namespace on the passed
  vnode. Policies implementing security labels backed into extended
  attributes may want to provide additional protections for those
  attributes. Additionally, policies should avoid making decisions based
  on the data referenced from uio, as there is a potential race condition
  between this check and the actual operation. The uio may also be NULL
  if a delete operation is being performed.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_setextattr_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	const char *name,
	struct uio *uio
);
/**
  @brief Access control check for setting flags
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param flags File flags; see chflags(2)

  Determine whether the subject identified by the credential can set
  the passed flags on the passed vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_setflags_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	u_long flags
);
/**
  @brief Access control check for setting mode
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param mode File mode; see chmod(2)

  Determine whether the subject identified by the credential can set
  the passed mode on the passed vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_setmode_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	mode_t mode
);
/**
  @brief Access control check for setting uid and gid
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param uid User ID
  @param gid Group ID

  Determine whether the subject identified by the credential can set
  the passed uid and passed gid as file uid and file gid on the passed
  vnode. The IDs may be set to (-1) to request no update.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_setowner_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	uid_t uid,
	gid_t gid
);
/**
  @brief Access control check for setting timestamps
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param atime Access time; see utimes(2)
  @param mtime Modification time; see utimes(2)

  Determine whether the subject identified by the credential can set
  the passed access timestamps on the passed vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_setutimes_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	struct timespec atime,
	struct timespec mtime
);
/**
  @brief Access control check after determining the code directory hash
  @param vp vnode vnode to combine into proc
  @param label label associated with the vnode
  @param cs_blob the code signature to check
  @param cs_flags update code signing flags if needed
  @param flags operational flag to mpo_vnode_check_signature
  @param fatal_failure_desc description of fatal failure
  @param fatal_failure_desc_len failure description len, failure is fatal if non-0

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.
 */
typedef int mpo_vnode_check_signature_t(
	struct vnode *vp,
	struct label *label,
	struct cs_blob *cs_blob,
	unsigned int *cs_flags,
	int flags,
	char **fatal_failure_desc, size_t *fatal_failure_desc_len
);
/**
  @brief Access control check for stat
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct fileproc
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can stat
  the passed vnode. See stat(2) for more information.  The active_cred
  hold the credentials of the subject performing the operation, and
  file_cred holds the credentials of the subject that originally
  opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_stat_t(
	struct ucred *active_cred,
	struct ucred *file_cred,	/* NULLOK */
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for truncate/ftruncate
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct fileproc
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can
  perform a truncate operation on the passed vnode.  The active_cred hold
  the credentials of the subject performing the operation, and
  file_cred holds the credentials of the subject that originally
  opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_truncate_t(
	kauth_cred_t active_cred,
	kauth_cred_t file_cred,	/* NULLOK */
	struct vnode *vp,
	struct label *label
);
/**
  @brief Access control check for binding UNIX domain socket
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label for dvp
  @param cnp Component name for dvp
  @param vap vnode attributes for vap

  Determine whether the subject identified by the credential can perform a
  bind operation on a UNIX domain socket with the passed parent directory,
  passed name information, and passed attribute information.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_uipc_bind_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct componentname *cnp,
	struct vnode_attr *vap
);
/**
  @brief Access control check for connecting UNIX domain socket
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label associated with vp
  @param so Socket

  Determine whether the subject identified by the credential can perform a
  connect operation on the passed UNIX domain socket vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_uipc_connect_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	socket_t so
);
/**
  @brief Access control check for deleting vnode
  @param cred Subject credential
  @param dvp Parent directory vnode
  @param dlabel Policy label for dvp
  @param vp Object vnode to delete
  @param label Policy label for vp
  @param cnp Component name for vp
  @see mpo_check_rename_to_t

  Determine whether the subject identified by the credential can delete
  a vnode from the passed parent directory and passed name information.
  This call may be made in a number of situations, including as a
  results of calls to unlink(2) and rmdir(2). Policies implementing
  this entry point should also implement mpo_check_rename_to to
  authorize deletion of objects as a result of being the target of a rename.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_unlink_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp
);
/**
  @brief Access control check for write
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct fileproc
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can
  perform a write operation on the passed vnode.  The active_cred hold
  the credentials of the subject performing the operation, and
  file_cred holds the credentials of the subject that originally
  opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EACCES for label mismatch or
  EPERM for lack of privilege.
*/
typedef int mpo_vnode_check_write_t(
	kauth_cred_t active_cred,
	kauth_cred_t file_cred,	/* NULLOK */
	struct vnode *vp,
	struct label *label
);
/**
  @brief Associate a vnode with a devfs entry
  @param mp Devfs mount point
  @param mntlabel Devfs mount point label
  @param de Devfs directory entry
  @param delabel Label associated with de
  @param vp vnode associated with de
  @param vlabel Label associated with vp

  Fill in the label (vlabel) for a newly created devfs vnode.  The
  label is typically derived from the label on the devfs directory
  entry or the label on the filesystem, supplied as parameters.
*/
typedef void mpo_vnode_label_associate_devfs_t(
	struct mount *mp,
	struct label *mntlabel,
	struct devnode *de,
	struct label *delabel,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Associate a label with a vnode
  @param mp File system mount point
  @param mntlabel File system mount point label
  @param vp Vnode to label
  @param vlabel Label associated with vp

  Attempt to retrieve label information for the vnode, vp, from the
  file system extended attribute store.  The label should be stored in
  the supplied vlabel parameter.  If a policy cannot retrieve an
  extended attribute, sometimes it is acceptible to fallback to using
  the mntlabel.

  If the policy requires vnodes to have a valid label elsewhere it
  MUST NOT return other than temporary errors, and must always provide
  a valid label of some sort.  Returning an error will cause vnode
  labeling to be retried at a later access.  Failure to handle policy
  centric errors internally (corrupt labels etc.) will result in
  inaccessible files.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_vnode_label_associate_extattr_t(
	struct mount *mp,
	struct label *mntlabel,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Associate a file label with a vnode
  @param cred User credential
  @param mp Fdesc mount point
  @param mntlabel Fdesc mount point label
  @param fg Fileglob structure
  @param label Policy label for fg
  @param vp Vnode to label
  @param vlabel Label associated with vp

  Associate label information for the vnode, vp, with the label of
  the open file descriptor described by fg.
  The label should be stored in the supplied vlabel parameter.
*/
typedef void mpo_vnode_label_associate_file_t(
	struct ucred *cred,
	struct mount *mp,
	struct label *mntlabel,
	struct fileglob *fg,
	struct label *label,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Associate a pipe label with a vnode
  @param cred User credential for the process that opened the pipe
  @param cpipe Pipe structure
  @param pipelabel Label associated with pipe
  @param vp Vnode to label
  @param vlabel Label associated with vp

  Associate label information for the vnode, vp, with the label of
  the pipe described by the pipe structure cpipe.
  The label should be stored in the supplied vlabel parameter.
*/
typedef void mpo_vnode_label_associate_pipe_t(
	struct ucred *cred,
	struct pipe *cpipe,
	struct label *pipelabel,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Associate a POSIX semaphore label with a vnode
  @param cred User credential for the process that create psem
  @param psem POSIX semaphore structure
  @param psemlabel Label associated with psem
  @param vp Vnode to label
  @param vlabel Label associated with vp

  Associate label information for the vnode, vp, with the label of
  the POSIX semaphore described by psem.
  The label should be stored in the supplied vlabel parameter.
*/
typedef void mpo_vnode_label_associate_posixsem_t(
	struct ucred *cred,
	struct pseminfo *psem,
	struct label *psemlabel,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Associate a POSIX shared memory label with a vnode
  @param cred User credential for the process that created pshm
  @param pshm POSIX shared memory structure
  @param pshmlabel Label associated with pshm
  @param vp Vnode to label
  @param vlabel Label associated with vp

  Associate label information for the vnode, vp, with the label of
  the POSIX shared memory region described by pshm.
  The label should be stored in the supplied vlabel parameter.
*/
typedef void mpo_vnode_label_associate_posixshm_t(
	struct ucred *cred,
	struct pshminfo *pshm,
	struct label *pshmlabel,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Associate a label with a vnode
  @param mp File system mount point
  @param mntlabel File system mount point label
  @param vp Vnode to label
  @param vlabel Label associated with vp

  On non-multilabel file systems, set the label for a vnode.  The
  label will most likely be based on the file system label.
*/
typedef void mpo_vnode_label_associate_singlelabel_t(
	struct mount *mp,
	struct label *mntlabel,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Associate a socket label with a vnode
  @param cred User credential for the process that opened the socket
  @param so Socket structure
  @param solabel Label associated with so
  @param vp Vnode to label
  @param vlabel Label associated with vp

  Associate label information for the vnode, vp, with the label of
  the open socket described by the socket structure so.
  The label should be stored in the supplied vlabel parameter.
*/
typedef void mpo_vnode_label_associate_socket_t(
	kauth_cred_t cred,
	socket_t so,
	struct label *solabel,
	struct vnode *vp,
	struct label *vlabel
);
/**
  @brief Copy a vnode label
  @param src Source vnode label
  @param dest Destination vnode label

  Copy the vnode label information from src to dest.  On Darwin, this
  is currently only necessary when executing interpreted scripts, but
  will later be used if vnode label externalization cannot be an
  atomic operation.
*/
typedef void mpo_vnode_label_copy_t(
	struct label *src,
	struct label *dest
);
/**
  @brief Destroy vnode label
  @param label The label to be destroyed

  Destroy a vnode label.  Since the object is going out of scope,
  policy modules should free any internal storage associated with the
  label so that it may be destroyed.
*/
typedef void mpo_vnode_label_destroy_t(
	struct label *label
);
/**
  @brief Externalize a vnode label for auditing
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a vnode suitable for
  inclusion in an audit record.  An externalized label consists of a text
  representation of the label contents that will be added to the audit record
  as part of a text token.  Policy-agnostic user space tools will display
  this externalized version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data.

*/
typedef int mpo_vnode_label_externalize_audit_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Externalize a vnode label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a vnode.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will display this externalized version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data.

*/
typedef int mpo_vnode_label_externalize_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);
/**
  @brief Initialize vnode label
  @param label New label to initialize

  Initialize label storage for use with a newly instantiated vnode, or
  for temporary storage associated with the copying in or out of a
  vnode label.  While it is necessary to allocate space for a
  kernel-resident vnode label, it is not yet necessary to link this vnode
  with persistent label storage facilities, such as extended attributes.
  Sleeping is permitted.
*/
typedef void mpo_vnode_label_init_t(
	struct label *label
);
/**
  @brief Internalize a vnode label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce a vnode label from an external representation.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data.
*/
typedef int mpo_vnode_label_internalize_t(
	struct label *label,
	char *element_name,
	char *element_data
);
/**
  @brief Clean up a vnode label
  @param label The label to be cleaned for re-use

  Clean up a vnode label.  Darwin (Tiger, 8.x) allocates vnodes on demand, but
  typically never frees them.  Before vnodes are placed back on free lists for
  re-use, policies can cleanup or overwrite any information present in the label.
*/
typedef void mpo_vnode_label_recycle_t(
	struct label *label
);
/**
  @brief Write a label to a extended attribute
  @param cred Subject credential
  @param vp The vnode for which the label is being stored
  @param vlabel Label associated with vp
  @param intlabel The new label to store

  Store a new label in the extended attribute corresponding to the
  supplied vnode.  The policy has already authorized the operation;
  this call must be implemented in order to perform the actual
  operation.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.

  @warning XXX After examining the extended attribute implementation on
  Apple's future release, this entry point may be changed.
*/
typedef int mpo_vnode_label_store_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	struct label *intlabel
);
/**
  @brief Update vnode label from extended attributes
  @param mp File system mount point
  @param mntlabel Mount point label
  @param vp Vnode to label
  @param vlabel Label associated with vp
  @param name Name of the xattr
  @see mpo_vnode_check_setextattr_t

  When an extended attribute is updated via the Vendor attribute management
  functions, the MAC vnode label might also require an update.
  Policies should first determine if 'name' matches their xattr label
  name.  If it does, the kernel is has either replaced or removed the
  named extended attribute that was previously associated with the
  vnode.  Normally labels should only be modified via MAC Framework label
  management calls, but sometimes the user space components will directly
  modify extended attributes.  For example, 'cp', 'tar', etc. manage
  extended attributes in userspace, not the kernel.

  This entry point is called after the label update has occurred, so
  it cannot return a failure.  However, the operation is preceded by
  the mpo_vnode_check_setextattr() access control check.

  If the vnode label needs to be updated the policy should return
  a non-zero value.  The vnode label will be marked for re-association
  by the framework.
*/
typedef int mpo_vnode_label_update_extattr_t(
	struct mount *mp,
	struct label *mntlabel,
	struct vnode *vp,
	struct label *vlabel,
	const char *name
);
/**
  @brief Update a vnode label
  @param cred Subject credential
  @param vp The vnode to relabel
  @param vnodelabel Existing vnode label
  @param label New label to replace existing label
  @see mpo_vnode_check_label_update_t

  The subject identified by the credential has previously requested
  and was authorized to relabel the vnode; this entry point allows
  policies to perform the actual relabel operation.  Policies should
  update vnodelabel using the label stored in the label parameter.
*/
typedef void mpo_vnode_label_update_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vnodelabel,
	struct label *label
);
/**
  @brief Find deatched signatures for a shared library
  @param p file trying to find the signature
  @param vp The vnode to relabel
  @param offset offset in the macho that the signature is requested for (for fat binaries)
  @param label Existing vnode label

*/
typedef int mpo_vnode_find_sigs_t(
	struct proc *p,
	struct vnode *vp,
	off_t offset,
	struct label *label
);
/**
  @brief Create a new vnode, backed by extended attributes
  @param cred User credential for the creating process
  @param mp File system mount point
  @param mntlabel File system mount point label
  @param dvp Parent directory vnode
  @param dlabel Parent directory vnode label
  @param vp Newly created vnode
  @param vlabel Label to associate with the new vnode
  @param cnp Component name for vp

  Write out the label for the newly created vnode, most likely storing
  the results in a file system extended attribute.  Most policies will
  derive the new vnode label using information from a combination
  of the subject (user) credential, the file system label, the parent
  directory label, and potentially the path name component.

  @return If the operation succeeds, store the new label in vlabel and
  return 0.  Otherwise, return an appropriate errno value.
*/
typedef int mpo_vnode_notify_create_t(
	kauth_cred_t cred,
	struct mount *mp,
	struct label *mntlabel,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *vlabel,
	struct componentname *cnp
);

/**
  @brief Inform MAC policies that a vnode has been opened
  @param cred User credential for the creating process
  @param vp vnode opened
  @param label Policy label for the vp
  @param acc_mode open(2) access mode used

  Inform Mac policies that a vnode have been successfully opened
  (passing all MAC polices and DAC).
*/
typedef void mpo_vnode_notify_open_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	int acc_mode
);

/**
  @brief Inform MAC policies that a vnode has been renamed
  @param cred User credential for the renaming process
  @param vp Vnode that's being renamed
  @param label Policy label for vp
  @param dvp Parent directory for the destination
  @param dlabel Policy label for dvp
  @param cnp Component name for the destination

  Inform MAC policies that a vnode has been renamed.
 */
typedef void mpo_vnode_notify_rename_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	struct vnode *dvp,
	struct label *dlabel,
	struct componentname *cnp
);

/**
  @brief Inform MAC policies that a vnode has been linked
  @param cred User credential for the renaming process
  @param dvp Parent directory for the destination
  @param dlabel Policy label for dvp
  @param vp Vnode that's being linked
  @param vlabel Policy label for vp
  @param cnp Component name for the destination

  Inform MAC policies that a vnode has been linked.
 */
typedef void mpo_vnode_notify_link_t(
	kauth_cred_t cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *vlabel,
	struct componentname *cnp
);

/**
  @brief Inform MAC policies that an extended attribute has been removed from a vnode
  @param cred Subject credential
  @param vp Object node
  @param label Policy label for vp
  @param name Extended attribute name

  Inform MAC policies that an extended attribute has been removed from a vnode.
*/
typedef void mpo_vnode_notify_deleteextattr_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	const char *name
);


/**
  @brief Inform MAC policies that an ACL has been set on a vnode
  @param cred Subject credential
  @param vp Object node
  @param label Policy label for vp
  @param acl ACL structure pointer

  Inform MAC policies that an ACL has been set on a vnode.
*/
typedef void mpo_vnode_notify_setacl_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	struct kauth_acl *acl
);

/**
  @brief Inform MAC policies that an attributes have been set on a vnode
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param alist List of attributes to set

  Inform MAC policies that an attributes have been set on a vnode.
*/
typedef void mpo_vnode_notify_setattrlist_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	struct attrlist *alist
);

/**
  @brief Inform MAC policies that an extended attribute has been set on a vnode
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param name Extended attribute name
  @param uio I/O structure pointer

  Inform MAC policies that an extended attribute has been set on a vnode.
*/
typedef void mpo_vnode_notify_setextattr_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	const char *name,
	struct uio *uio
);

/**
  @brief Inform MAC policies that flags have been set on a vnode
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param flags File flags; see chflags(2)

  Inform MAC policies that flags have been set on a vnode.
*/
typedef void mpo_vnode_notify_setflags_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	u_long flags
);

/**
  @brief Inform MAC policies that a new mode has been set on a vnode
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param mode File mode; see chmod(2)

  Inform MAC policies that a new mode has been set on a vnode.
*/
typedef void mpo_vnode_notify_setmode_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	mode_t mode
);

/**
  @brief Inform MAC policies that new uid/gid have been set on a vnode
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param uid User ID
  @param gid Group ID

  Inform MAC policies that new uid/gid have been set on a vnode.
*/
typedef void mpo_vnode_notify_setowner_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	uid_t uid,
	gid_t gid
);

/**
  @brief Inform MAC policies that new timestamps have been set on a vnode
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param atime Access time; see utimes(2)
  @param mtime Modification time; see utimes(2)

  Inform MAC policies that new timestamps have been set on a vnode.
*/
typedef void mpo_vnode_notify_setutimes_t(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	struct timespec atime,
	struct timespec mtime
);

/**
  @brief Inform MAC policies that a vnode has been truncated
  @param cred Subject credential
  @param file_cred Credential associated with the struct fileproc
  @param vp Object vnode
  @param label Policy label for vp

  Inform MAC policies that a vnode has been truncated.
*/
typedef void mpo_vnode_notify_truncate_t(
	kauth_cred_t cred,
	kauth_cred_t file_cred,
	struct vnode *vp,
	struct label *label
);


/**
  @brief Inform MAC policies that a pty slave has been granted
  @param p Responsible process
  @param tp tty data structure
  @param dev Major and minor numbers of device
  @param label Policy label for tp
  
  Inform MAC policies that a pty slave has been granted.
*/
typedef void mpo_pty_notify_grant_t(
	proc_t p,
	struct tty *tp,
	dev_t dev,
	struct label *label
);

/**
  @brief Inform MAC policies that a pty master has been closed
  @param p Responsible process
  @param tp tty data structure
  @param dev Major and minor numbers of device
  @param label Policy label for tp
  
  Inform MAC policies that a pty master has been closed.
*/
typedef void mpo_pty_notify_close_t(
	proc_t p,
	struct tty *tp,
	dev_t dev,
	struct label *label
);

/**
  @brief Access control check for kext loading
  @param cred Subject credential
  @param identifier Kext identifier

  Determine whether the subject identified by the credential can load the
  specified kext.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EPERM for lack of privilege.
*/
typedef int mpo_kext_check_load_t(
	kauth_cred_t cred,
	const char *identifier
);

/**
  @brief Access control check for kext unloading
  @param cred Subject credential
  @param identifier Kext identifier

  Determine whether the subject identified by the credential can unload the
  specified kext.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned. Suggested failure: EPERM for lack of privilege.
*/
typedef int mpo_kext_check_unload_t(
	kauth_cred_t cred,
	const char *identifier
);

/**
  @brief Access control check for querying information about loaded kexts
  @param cred Subject credential

  Determine whether the subject identified by the credential can query
  information about loaded kexts.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.  Suggested failure: EPERM for lack of privilege.
*/
typedef int mpo_kext_check_query_t(
	kauth_cred_t cred
);

/**
  @brief Access control check for getting NVRAM variables.
  @param cred Subject credential
  @param name NVRAM variable to get

  Determine whether the subject identifier by the credential can get the
  value of the named NVRAM variable.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.  Suggested failure: EPERM for lack of privilege.
*/
typedef int mpo_iokit_check_nvram_get_t(
	kauth_cred_t cred,
	const char *name
);

/**
  @brief Access control check for setting NVRAM variables.
  @param cred Subject credential
  @param name NVRAM variable to set
  @param value The new value for the NVRAM variable

  Determine whether the subject identifier by the credential can set the
  value of the named NVRAM variable.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.  Suggested failure: EPERM for lack of privilege.
*/
typedef int mpo_iokit_check_nvram_set_t(
	kauth_cred_t cred,
	const char *name,
	io_object_t value
);

/**
  @brief Access control check for deleting NVRAM variables.
  @param cred Subject credential
  @param name NVRAM variable to delete

  Determine whether the subject identifier by the credential can delete the
  named NVRAM variable.

  @return Return 0 if access is granted, otherwise an appropriate value for
  errno should be returned.  Suggested failure: EPERM for lack of privilege.
*/
typedef int mpo_iokit_check_nvram_delete_t(
	kauth_cred_t cred,
	const char *name
);

/*
 * Placeholder for future events that may need mac hooks.
 */
typedef void mpo_reserved_hook_t(void);

/*
 * Policy module operations.
 *
 * Please note that this should be kept in sync with the check assumptions
 * policy in bsd/kern/policy_check.c (policy_ops struct).
 */
#define MAC_POLICY_OPS_VERSION 47 /* inc when new reserved slots are taken */
struct mac_policy_ops {
	mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
	mpo_audit_check_preselect_t		*mpo_audit_check_preselect;

	mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
	mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
	mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
	mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;

	mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
	mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
	mpo_cred_check_visible_t		*mpo_cred_check_visible;
	mpo_cred_label_associate_fork_t		*mpo_cred_label_associate_fork;
	mpo_cred_label_associate_kernel_t	*mpo_cred_label_associate_kernel;
	mpo_cred_label_associate_t		*mpo_cred_label_associate;
	mpo_cred_label_associate_user_t		*mpo_cred_label_associate_user;
	mpo_cred_label_destroy_t		*mpo_cred_label_destroy;
	mpo_cred_label_externalize_audit_t	*mpo_cred_label_externalize_audit;
	mpo_cred_label_externalize_t		*mpo_cred_label_externalize;
	mpo_cred_label_init_t			*mpo_cred_label_init;
	mpo_cred_label_internalize_t		*mpo_cred_label_internalize;
	mpo_cred_label_update_execve_t		*mpo_cred_label_update_execve;
	mpo_cred_label_update_t			*mpo_cred_label_update;

	mpo_devfs_label_associate_device_t	*mpo_devfs_label_associate_device;
	mpo_devfs_label_associate_directory_t	*mpo_devfs_label_associate_directory;
	mpo_devfs_label_copy_t			*mpo_devfs_label_copy;
	mpo_devfs_label_destroy_t		*mpo_devfs_label_destroy;
	mpo_devfs_label_init_t			*mpo_devfs_label_init;
	mpo_devfs_label_update_t		*mpo_devfs_label_update;

	mpo_file_check_change_offset_t		*mpo_file_check_change_offset;
	mpo_file_check_create_t			*mpo_file_check_create;
	mpo_file_check_dup_t			*mpo_file_check_dup;
	mpo_file_check_fcntl_t			*mpo_file_check_fcntl;
	mpo_file_check_get_offset_t		*mpo_file_check_get_offset;
	mpo_file_check_get_t			*mpo_file_check_get;
	mpo_file_check_inherit_t		*mpo_file_check_inherit;
	mpo_file_check_ioctl_t			*mpo_file_check_ioctl;
	mpo_file_check_lock_t			*mpo_file_check_lock;
	mpo_file_check_mmap_downgrade_t		*mpo_file_check_mmap_downgrade;
	mpo_file_check_mmap_t			*mpo_file_check_mmap;
	mpo_file_check_receive_t		*mpo_file_check_receive;
	mpo_file_check_set_t			*mpo_file_check_set;
	mpo_file_label_init_t			*mpo_file_label_init;
	mpo_file_label_destroy_t		*mpo_file_label_destroy;
	mpo_file_label_associate_t		*mpo_file_label_associate;

	mpo_ifnet_check_label_update_t		*mpo_ifnet_check_label_update;
	mpo_ifnet_check_transmit_t		*mpo_ifnet_check_transmit;
	mpo_ifnet_label_associate_t		*mpo_ifnet_label_associate;
	mpo_ifnet_label_copy_t			*mpo_ifnet_label_copy;
	mpo_ifnet_label_destroy_t		*mpo_ifnet_label_destroy;
	mpo_ifnet_label_externalize_t		*mpo_ifnet_label_externalize;
	mpo_ifnet_label_init_t			*mpo_ifnet_label_init;
	mpo_ifnet_label_internalize_t		*mpo_ifnet_label_internalize;
	mpo_ifnet_label_update_t		*mpo_ifnet_label_update;
	mpo_ifnet_label_recycle_t		*mpo_ifnet_label_recycle;

	mpo_inpcb_check_deliver_t		*mpo_inpcb_check_deliver;
	mpo_inpcb_label_associate_t		*mpo_inpcb_label_associate;
	mpo_inpcb_label_destroy_t		*mpo_inpcb_label_destroy;
	mpo_inpcb_label_init_t			*mpo_inpcb_label_init;
	mpo_inpcb_label_recycle_t		*mpo_inpcb_label_recycle;
	mpo_inpcb_label_update_t		*mpo_inpcb_label_update;

	mpo_iokit_check_device_t		*mpo_iokit_check_device;

	mpo_ipq_label_associate_t		*mpo_ipq_label_associate;
	mpo_ipq_label_compare_t			*mpo_ipq_label_compare;
	mpo_ipq_label_destroy_t			*mpo_ipq_label_destroy;
	mpo_ipq_label_init_t			*mpo_ipq_label_init;
	mpo_ipq_label_update_t			*mpo_ipq_label_update;

	mpo_file_check_library_validation_t     *mpo_file_check_library_validation;
	mpo_vnode_notify_setacl_t               *mpo_vnode_notify_setacl;
	mpo_vnode_notify_setattrlist_t          *mpo_vnode_notify_setattrlist;
	mpo_vnode_notify_setextattr_t           *mpo_vnode_notify_setextattr;
	mpo_vnode_notify_setflags_t             *mpo_vnode_notify_setflags;
	mpo_vnode_notify_setmode_t              *mpo_vnode_notify_setmode;
	mpo_vnode_notify_setowner_t             *mpo_vnode_notify_setowner;
	mpo_vnode_notify_setutimes_t            *mpo_vnode_notify_setutimes;
	mpo_vnode_notify_truncate_t             *mpo_vnode_notify_truncate;

	mpo_mbuf_label_associate_bpfdesc_t	*mpo_mbuf_label_associate_bpfdesc;
	mpo_mbuf_label_associate_ifnet_t	*mpo_mbuf_label_associate_ifnet;
	mpo_mbuf_label_associate_inpcb_t	*mpo_mbuf_label_associate_inpcb;
	mpo_mbuf_label_associate_ipq_t		*mpo_mbuf_label_associate_ipq;
	mpo_mbuf_label_associate_linklayer_t	*mpo_mbuf_label_associate_linklayer;
	mpo_mbuf_label_associate_multicast_encap_t *mpo_mbuf_label_associate_multicast_encap;
	mpo_mbuf_label_associate_netlayer_t	*mpo_mbuf_label_associate_netlayer;
	mpo_mbuf_label_associate_socket_t	*mpo_mbuf_label_associate_socket;
	mpo_mbuf_label_copy_t			*mpo_mbuf_label_copy;
	mpo_mbuf_label_destroy_t		*mpo_mbuf_label_destroy;
	mpo_mbuf_label_init_t			*mpo_mbuf_label_init;

	mpo_mount_check_fsctl_t			*mpo_mount_check_fsctl;
	mpo_mount_check_getattr_t		*mpo_mount_check_getattr;
	mpo_mount_check_label_update_t		*mpo_mount_check_label_update;
	mpo_mount_check_mount_t			*mpo_mount_check_mount;
	mpo_mount_check_remount_t		*mpo_mount_check_remount;
	mpo_mount_check_setattr_t		*mpo_mount_check_setattr;
	mpo_mount_check_stat_t			*mpo_mount_check_stat;
	mpo_mount_check_umount_t		*mpo_mount_check_umount;
	mpo_mount_label_associate_t		*mpo_mount_label_associate;
	mpo_mount_label_destroy_t		*mpo_mount_label_destroy;
	mpo_mount_label_externalize_t		*mpo_mount_label_externalize;
	mpo_mount_label_init_t			*mpo_mount_label_init;
	mpo_mount_label_internalize_t		*mpo_mount_label_internalize;

	mpo_netinet_fragment_t			*mpo_netinet_fragment;
	mpo_netinet_icmp_reply_t		*mpo_netinet_icmp_reply;
	mpo_netinet_tcp_reply_t			*mpo_netinet_tcp_reply;

	mpo_pipe_check_ioctl_t			*mpo_pipe_check_ioctl;
	mpo_pipe_check_kqfilter_t		*mpo_pipe_check_kqfilter;
	mpo_pipe_check_label_update_t		*mpo_pipe_check_label_update;
	mpo_pipe_check_read_t			*mpo_pipe_check_read;
	mpo_pipe_check_select_t			*mpo_pipe_check_select;
	mpo_pipe_check_stat_t			*mpo_pipe_check_stat;
	mpo_pipe_check_write_t			*mpo_pipe_check_write;
	mpo_pipe_label_associate_t		*mpo_pipe_label_associate;
	mpo_pipe_label_copy_t			*mpo_pipe_label_copy;
	mpo_pipe_label_destroy_t		*mpo_pipe_label_destroy;
	mpo_pipe_label_externalize_t		*mpo_pipe_label_externalize;
	mpo_pipe_label_init_t			*mpo_pipe_label_init;
	mpo_pipe_label_internalize_t		*mpo_pipe_label_internalize;
	mpo_pipe_label_update_t			*mpo_pipe_label_update;

	mpo_policy_destroy_t			*mpo_policy_destroy;
	mpo_policy_init_t			*mpo_policy_init;
	mpo_policy_initbsd_t			*mpo_policy_initbsd;
	mpo_policy_syscall_t			*mpo_policy_syscall;

	mpo_system_check_sysctlbyname_t		*mpo_system_check_sysctlbyname;
	mpo_proc_check_inherit_ipc_ports_t	*mpo_proc_check_inherit_ipc_ports;
	mpo_vnode_check_rename_t		*mpo_vnode_check_rename;
	mpo_kext_check_query_t			*mpo_kext_check_query;
	mpo_iokit_check_nvram_get_t		*mpo_iokit_check_nvram_get;
	mpo_iokit_check_nvram_set_t		*mpo_iokit_check_nvram_set;
	mpo_iokit_check_nvram_delete_t		*mpo_iokit_check_nvram_delete;
	mpo_proc_check_expose_task_t		*mpo_proc_check_expose_task;
	mpo_proc_check_set_host_special_port_t	*mpo_proc_check_set_host_special_port;
	mpo_proc_check_set_host_exception_port_t *mpo_proc_check_set_host_exception_port;
	mpo_exc_action_check_exception_send_t	*mpo_exc_action_check_exception_send;
	mpo_exc_action_label_associate_t	*mpo_exc_action_label_associate;
	mpo_exc_action_label_copy_t		*mpo_exc_action_label_copy;
	mpo_exc_action_label_destroy_t		*mpo_exc_action_label_destroy;
	mpo_exc_action_label_init_t		*mpo_exc_action_label_init;
	mpo_exc_action_label_update_t		*mpo_exc_action_label_update;

	mpo_reserved_hook_t			*mpo_reserved1;
	mpo_reserved_hook_t			*mpo_reserved2;
	mpo_reserved_hook_t			*mpo_reserved3;
	mpo_reserved_hook_t			*mpo_reserved4;
	mpo_reserved_hook_t			*mpo_reserved5;
	mpo_reserved_hook_t			*mpo_reserved6;

	mpo_posixsem_check_create_t		*mpo_posixsem_check_create;
	mpo_posixsem_check_open_t		*mpo_posixsem_check_open;
	mpo_posixsem_check_post_t		*mpo_posixsem_check_post;
	mpo_posixsem_check_unlink_t		*mpo_posixsem_check_unlink;
	mpo_posixsem_check_wait_t		*mpo_posixsem_check_wait;
	mpo_posixsem_label_associate_t		*mpo_posixsem_label_associate;
	mpo_posixsem_label_destroy_t		*mpo_posixsem_label_destroy;
	mpo_posixsem_label_init_t		*mpo_posixsem_label_init;
	mpo_posixshm_check_create_t		*mpo_posixshm_check_create;
	mpo_posixshm_check_mmap_t		*mpo_posixshm_check_mmap;
	mpo_posixshm_check_open_t		*mpo_posixshm_check_open;
	mpo_posixshm_check_stat_t		*mpo_posixshm_check_stat;
	mpo_posixshm_check_truncate_t		*mpo_posixshm_check_truncate;
	mpo_posixshm_check_unlink_t		*mpo_posixshm_check_unlink;
	mpo_posixshm_label_associate_t		*mpo_posixshm_label_associate;
	mpo_posixshm_label_destroy_t		*mpo_posixshm_label_destroy;
	mpo_posixshm_label_init_t		*mpo_posixshm_label_init;

	mpo_proc_check_debug_t			*mpo_proc_check_debug;
	mpo_proc_check_fork_t			*mpo_proc_check_fork;
	mpo_proc_check_get_task_name_t		*mpo_proc_check_get_task_name;
	mpo_proc_check_get_task_t		*mpo_proc_check_get_task;
	mpo_proc_check_getaudit_t		*mpo_proc_check_getaudit;
	mpo_proc_check_getauid_t		*mpo_proc_check_getauid;
	mpo_proc_check_getlcid_t		*mpo_proc_check_getlcid;
	mpo_proc_check_mprotect_t		*mpo_proc_check_mprotect;
	mpo_proc_check_sched_t			*mpo_proc_check_sched;
	mpo_proc_check_setaudit_t		*mpo_proc_check_setaudit;
	mpo_proc_check_setauid_t		*mpo_proc_check_setauid;
	mpo_proc_check_setlcid_t		*mpo_proc_check_setlcid;
	mpo_proc_check_signal_t			*mpo_proc_check_signal;
	mpo_proc_check_wait_t			*mpo_proc_check_wait;
	mpo_proc_label_destroy_t		*mpo_proc_label_destroy;
	mpo_proc_label_init_t			*mpo_proc_label_init;

	mpo_socket_check_accept_t		*mpo_socket_check_accept;
	mpo_socket_check_accepted_t		*mpo_socket_check_accepted;
	mpo_socket_check_bind_t			*mpo_socket_check_bind;
	mpo_socket_check_connect_t		*mpo_socket_check_connect;
	mpo_socket_check_create_t		*mpo_socket_check_create;
	mpo_socket_check_deliver_t		*mpo_socket_check_deliver;
	mpo_socket_check_kqfilter_t		*mpo_socket_check_kqfilter;
	mpo_socket_check_label_update_t		*mpo_socket_check_label_update;
	mpo_socket_check_listen_t		*mpo_socket_check_listen;
	mpo_socket_check_receive_t		*mpo_socket_check_receive;
	mpo_socket_check_received_t		*mpo_socket_check_received;
	mpo_socket_check_select_t		*mpo_socket_check_select;
	mpo_socket_check_send_t			*mpo_socket_check_send;
	mpo_socket_check_stat_t			*mpo_socket_check_stat;
	mpo_socket_check_setsockopt_t		*mpo_socket_check_setsockopt;
	mpo_socket_check_getsockopt_t		*mpo_socket_check_getsockopt;
	mpo_socket_label_associate_accept_t	*mpo_socket_label_associate_accept;
	mpo_socket_label_associate_t		*mpo_socket_label_associate;
	mpo_socket_label_copy_t			*mpo_socket_label_copy;
	mpo_socket_label_destroy_t		*mpo_socket_label_destroy;
	mpo_socket_label_externalize_t		*mpo_socket_label_externalize;
	mpo_socket_label_init_t			*mpo_socket_label_init;
	mpo_socket_label_internalize_t		*mpo_socket_label_internalize;
	mpo_socket_label_update_t		*mpo_socket_label_update;

	mpo_socketpeer_label_associate_mbuf_t	*mpo_socketpeer_label_associate_mbuf;
	mpo_socketpeer_label_associate_socket_t	*mpo_socketpeer_label_associate_socket;
	mpo_socketpeer_label_destroy_t		*mpo_socketpeer_label_destroy;
	mpo_socketpeer_label_externalize_t	*mpo_socketpeer_label_externalize;
	mpo_socketpeer_label_init_t		*mpo_socketpeer_label_init;

	mpo_system_check_acct_t			*mpo_system_check_acct;
	mpo_system_check_audit_t		*mpo_system_check_audit;
	mpo_system_check_auditctl_t		*mpo_system_check_auditctl;
	mpo_system_check_auditon_t		*mpo_system_check_auditon;
	mpo_system_check_host_priv_t		*mpo_system_check_host_priv;
	mpo_system_check_nfsd_t			*mpo_system_check_nfsd;
	mpo_system_check_reboot_t		*mpo_system_check_reboot;
	mpo_system_check_settime_t		*mpo_system_check_settime;
	mpo_system_check_swapoff_t		*mpo_system_check_swapoff;
	mpo_system_check_swapon_t		*mpo_system_check_swapon;
	mpo_reserved_hook_t			*mpo_reserved7;

	mpo_sysvmsg_label_associate_t		*mpo_sysvmsg_label_associate;
	mpo_sysvmsg_label_destroy_t		*mpo_sysvmsg_label_destroy;
	mpo_sysvmsg_label_init_t		*mpo_sysvmsg_label_init;
	mpo_sysvmsg_label_recycle_t		*mpo_sysvmsg_label_recycle;
	mpo_sysvmsq_check_enqueue_t		*mpo_sysvmsq_check_enqueue;
	mpo_sysvmsq_check_msgrcv_t		*mpo_sysvmsq_check_msgrcv;
	mpo_sysvmsq_check_msgrmid_t		*mpo_sysvmsq_check_msgrmid;
	mpo_sysvmsq_check_msqctl_t		*mpo_sysvmsq_check_msqctl;
	mpo_sysvmsq_check_msqget_t		*mpo_sysvmsq_check_msqget;
	mpo_sysvmsq_check_msqrcv_t		*mpo_sysvmsq_check_msqrcv;
	mpo_sysvmsq_check_msqsnd_t		*mpo_sysvmsq_check_msqsnd;
	mpo_sysvmsq_label_associate_t		*mpo_sysvmsq_label_associate;
	mpo_sysvmsq_label_destroy_t		*mpo_sysvmsq_label_destroy;
	mpo_sysvmsq_label_init_t		*mpo_sysvmsq_label_init;
	mpo_sysvmsq_label_recycle_t		*mpo_sysvmsq_label_recycle;
	mpo_sysvsem_check_semctl_t		*mpo_sysvsem_check_semctl;
	mpo_sysvsem_check_semget_t		*mpo_sysvsem_check_semget;
	mpo_sysvsem_check_semop_t		*mpo_sysvsem_check_semop;
	mpo_sysvsem_label_associate_t		*mpo_sysvsem_label_associate;
	mpo_sysvsem_label_destroy_t		*mpo_sysvsem_label_destroy;
	mpo_sysvsem_label_init_t		*mpo_sysvsem_label_init;
	mpo_sysvsem_label_recycle_t		*mpo_sysvsem_label_recycle;
	mpo_sysvshm_check_shmat_t		*mpo_sysvshm_check_shmat;
	mpo_sysvshm_check_shmctl_t		*mpo_sysvshm_check_shmctl;
	mpo_sysvshm_check_shmdt_t		*mpo_sysvshm_check_shmdt;
	mpo_sysvshm_check_shmget_t		*mpo_sysvshm_check_shmget;
	mpo_sysvshm_label_associate_t		*mpo_sysvshm_label_associate;
	mpo_sysvshm_label_destroy_t		*mpo_sysvshm_label_destroy;
	mpo_sysvshm_label_init_t		*mpo_sysvshm_label_init;
	mpo_sysvshm_label_recycle_t		*mpo_sysvshm_label_recycle;

	mpo_reserved_hook_t			*mpo_reserved8;
	mpo_mount_check_snapshot_revert_t	*mpo_mount_check_snapshot_revert;
	mpo_vnode_check_getattr_t		*mpo_vnode_check_getattr;
	mpo_mount_check_snapshot_create_t	*mpo_mount_check_snapshot_create;
	mpo_mount_check_snapshot_delete_t	*mpo_mount_check_snapshot_delete;
	mpo_vnode_check_clone_t			*mpo_vnode_check_clone;
	mpo_proc_check_get_cs_info_t		*mpo_proc_check_get_cs_info;
	mpo_proc_check_set_cs_info_t		*mpo_proc_check_set_cs_info;

	mpo_iokit_check_hid_control_t		*mpo_iokit_check_hid_control;

	mpo_vnode_check_access_t		*mpo_vnode_check_access;
	mpo_vnode_check_chdir_t			*mpo_vnode_check_chdir;
	mpo_vnode_check_chroot_t		*mpo_vnode_check_chroot;
	mpo_vnode_check_create_t		*mpo_vnode_check_create;
	mpo_vnode_check_deleteextattr_t		*mpo_vnode_check_deleteextattr;
	mpo_vnode_check_exchangedata_t		*mpo_vnode_check_exchangedata;
	mpo_vnode_check_exec_t			*mpo_vnode_check_exec;
	mpo_vnode_check_getattrlist_t		*mpo_vnode_check_getattrlist;
	mpo_vnode_check_getextattr_t		*mpo_vnode_check_getextattr;
	mpo_vnode_check_ioctl_t			*mpo_vnode_check_ioctl;
	mpo_vnode_check_kqfilter_t		*mpo_vnode_check_kqfilter;
	mpo_vnode_check_label_update_t		*mpo_vnode_check_label_update;
	mpo_vnode_check_link_t			*mpo_vnode_check_link;
	mpo_vnode_check_listextattr_t		*mpo_vnode_check_listextattr;
	mpo_vnode_check_lookup_t		*mpo_vnode_check_lookup;
	mpo_vnode_check_open_t			*mpo_vnode_check_open;
	mpo_vnode_check_read_t			*mpo_vnode_check_read;
	mpo_vnode_check_readdir_t		*mpo_vnode_check_readdir;
	mpo_vnode_check_readlink_t		*mpo_vnode_check_readlink;
	mpo_vnode_check_rename_from_t		*mpo_vnode_check_rename_from;
	mpo_vnode_check_rename_to_t		*mpo_vnode_check_rename_to;
	mpo_vnode_check_revoke_t		*mpo_vnode_check_revoke;
	mpo_vnode_check_select_t		*mpo_vnode_check_select;
	mpo_vnode_check_setattrlist_t		*mpo_vnode_check_setattrlist;
	mpo_vnode_check_setextattr_t		*mpo_vnode_check_setextattr;
	mpo_vnode_check_setflags_t		*mpo_vnode_check_setflags;
	mpo_vnode_check_setmode_t		*mpo_vnode_check_setmode;
	mpo_vnode_check_setowner_t		*mpo_vnode_check_setowner;
	mpo_vnode_check_setutimes_t		*mpo_vnode_check_setutimes;
	mpo_vnode_check_stat_t			*mpo_vnode_check_stat;
	mpo_vnode_check_truncate_t		*mpo_vnode_check_truncate;
	mpo_vnode_check_unlink_t		*mpo_vnode_check_unlink;
	mpo_vnode_check_write_t			*mpo_vnode_check_write;
	mpo_vnode_label_associate_devfs_t	*mpo_vnode_label_associate_devfs;
	mpo_vnode_label_associate_extattr_t	*mpo_vnode_label_associate_extattr;
	mpo_vnode_label_associate_file_t	*mpo_vnode_label_associate_file;
	mpo_vnode_label_associate_pipe_t	*mpo_vnode_label_associate_pipe;
	mpo_vnode_label_associate_posixsem_t	*mpo_vnode_label_associate_posixsem;
	mpo_vnode_label_associate_posixshm_t	*mpo_vnode_label_associate_posixshm;
	mpo_vnode_label_associate_singlelabel_t	*mpo_vnode_label_associate_singlelabel;
	mpo_vnode_label_associate_socket_t	*mpo_vnode_label_associate_socket;
	mpo_vnode_label_copy_t			*mpo_vnode_label_copy;
	mpo_vnode_label_destroy_t		*mpo_vnode_label_destroy;
	mpo_vnode_label_externalize_audit_t	*mpo_vnode_label_externalize_audit;
	mpo_vnode_label_externalize_t		*mpo_vnode_label_externalize;
	mpo_vnode_label_init_t			*mpo_vnode_label_init;
	mpo_vnode_label_internalize_t		*mpo_vnode_label_internalize;
	mpo_vnode_label_recycle_t		*mpo_vnode_label_recycle;
	mpo_vnode_label_store_t			*mpo_vnode_label_store;
	mpo_vnode_label_update_extattr_t	*mpo_vnode_label_update_extattr;
	mpo_vnode_label_update_t		*mpo_vnode_label_update;
	mpo_vnode_notify_create_t		*mpo_vnode_notify_create;
	mpo_vnode_check_signature_t		*mpo_vnode_check_signature;
	mpo_vnode_check_uipc_bind_t		*mpo_vnode_check_uipc_bind;
	mpo_vnode_check_uipc_connect_t		*mpo_vnode_check_uipc_connect;

	mpo_proc_check_run_cs_invalid_t		*mpo_proc_check_run_cs_invalid;
	mpo_proc_check_suspend_resume_t		*mpo_proc_check_suspend_resume;

	mpo_thread_userret_t			*mpo_thread_userret;

	mpo_iokit_check_set_properties_t	*mpo_iokit_check_set_properties;

	mpo_system_check_chud_t			*mpo_system_check_chud;

	mpo_vnode_check_searchfs_t		*mpo_vnode_check_searchfs;

	mpo_priv_check_t			*mpo_priv_check;
	mpo_priv_grant_t			*mpo_priv_grant;

	mpo_proc_check_map_anon_t		*mpo_proc_check_map_anon;

	mpo_vnode_check_fsgetpath_t		*mpo_vnode_check_fsgetpath;

	mpo_iokit_check_open_t			*mpo_iokit_check_open;

 	mpo_proc_check_ledger_t			*mpo_proc_check_ledger;

	mpo_vnode_notify_rename_t		*mpo_vnode_notify_rename;

	mpo_vnode_check_setacl_t		*mpo_vnode_check_setacl;

	mpo_vnode_notify_deleteextattr_t        *mpo_vnode_notify_deleteextattr;

	mpo_system_check_kas_info_t		*mpo_system_check_kas_info;

	mpo_proc_check_cpumon_t			*mpo_proc_check_cpumon;

	mpo_vnode_notify_open_t			*mpo_vnode_notify_open;

	mpo_system_check_info_t			*mpo_system_check_info;

	mpo_pty_notify_grant_t 			*mpo_pty_notify_grant;
	mpo_pty_notify_close_t			*mpo_pty_notify_close;

	mpo_vnode_find_sigs_t			*mpo_vnode_find_sigs;

	mpo_kext_check_load_t			*mpo_kext_check_load;
	mpo_kext_check_unload_t			*mpo_kext_check_unload;

	mpo_proc_check_proc_info_t		*mpo_proc_check_proc_info;
	mpo_vnode_notify_link_t			*mpo_vnode_notify_link;
	mpo_iokit_check_filter_properties_t	*mpo_iokit_check_filter_properties;
	mpo_iokit_check_get_property_t		*mpo_iokit_check_get_property;
};

/**
   @brief MAC policy handle type

   The MAC handle is used to uniquely identify a loaded policy within
   the MAC Framework.

   A variable of this type is set by mac_policy_register().
 */
typedef unsigned int mac_policy_handle_t;

#define mpc_t	struct mac_policy_conf *

/**
  @brief Mac policy configuration

  This structure specifies the configuration information for a
  MAC policy module.  A policy module developer must supply
  a short unique policy name, a more descriptive full name, a list of label
  namespaces and count, a pointer to the registered enty point operations,
  any load time flags, and optionally, a pointer to a label slot identifier.

  The Framework will update the runtime flags (mpc_runtime_flags) to
  indicate that the module has been registered.

  If the label slot identifier (mpc_field_off) is NULL, the Framework
  will not provide label storage for the policy.  Otherwise, the
  Framework will store the label location (slot) in this field.

  The mpc_list field is used by the Framework and should not be
  modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
struct mac_policy_conf {
	const char		*mpc_name;		/** policy name */
	const char		*mpc_fullname;		/** full name */
	char const * const *mpc_labelnames;	/** managed label namespaces */
	unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
	struct mac_policy_ops	*mpc_ops;		/** operation vector */
	int			 mpc_loadtime_flags;	/** load time flags */
	int			*mpc_field_off;		/** label slot */
	int			 mpc_runtime_flags;	/** run time flags */
	mpc_t			 mpc_list;		/** List reference */
	void			*mpc_data;		/** module data */
};

/**
   @brief MAC policy module registration routine

   This function is called to register a policy with the
   MAC framework.  A policy module will typically call this from the
   Darwin KEXT registration routine.
 */
int	mac_policy_register(struct mac_policy_conf *mpc,
    mac_policy_handle_t *handlep, void *xd);

/**
   @brief MAC policy module de-registration routine

   This function is called to de-register a policy with theD
   MAC framework.  A policy module will typically call this from the
   Darwin KEXT de-registration routine.
 */
int	mac_policy_unregister(mac_policy_handle_t handle);

/*
 * Framework entry points for the policies to add audit data.
 */
int	mac_audit_text(char *text, mac_policy_handle_t handle);

/*
 * Calls to assist with use of Apple XATTRs within policy modules.
 */
int	mac_vnop_setxattr(struct vnode *, const char *, char *, size_t);
int	mac_vnop_getxattr(struct vnode *, const char *, char *, size_t,
			  size_t *);
int	mac_vnop_removexattr(struct vnode *, const char *);

/**
   @brief Set an extended attribute on a vnode-based fileglob.
   @param fg fileglob representing file to attach the extended attribute
   @param name extended attribute name
   @param buf buffer of data to use as the extended attribute value
   @param len size of buffer

   Sets the value of an extended attribute on a file.

   Caller must hold an iocount on the vnode represented by the fileglob.
*/
int	mac_file_setxattr(struct fileglob *fg, const char *name, char *buf, size_t len);

/**
	@brief Get an extended attribute from a vnode-based fileglob.
	@param fg fileglob representing file to read the extended attribute
	@param name extended attribute name
	@param buf buffer of data to hold the extended attribute value
	@param len size of buffer
	@param attrlen size of full extended attribute value

	Gets the value of an extended attribute on a file.

	Caller must hold an iocount on the vnode represented by the fileglob.
*/
int	mac_file_getxattr(struct fileglob *fg, const char *name, char *buf, size_t len,
			  size_t *attrlen);

/**
	@brief Remove an extended attribute from a vnode-based fileglob.
	@param fg fileglob representing file to remove the extended attribute
	@param name extended attribute name

	Removes the named extended attribute from the file.

	Caller must hold an iocount on the vnode represented by the fileglob.
*/
int	mac_file_removexattr(struct fileglob *fg, const char *name);


/*
 * Arbitrary limit on how much data will be logged by the audit
 * entry points above.
 */
#define	MAC_AUDIT_DATA_LIMIT	1024

/*
 * Values returned by mac_audit_{pre,post}select. To combine the responses
 * of the security policies into a single decision,
 * mac_audit_{pre,post}select() choose the greatest value returned.
 */
#define	MAC_AUDIT_DEFAULT	0	/* use system behavior */
#define	MAC_AUDIT_NO		1	/* force not auditing this event */
#define	MAC_AUDIT_YES		2	/* force auditing this event */

//  \defgroup mpc_loadtime_flags Flags for the mpc_loadtime_flags field

/**
  @name Flags for the mpc_loadtime_flags field
  @see mac_policy_conf

  This is the complete list of flags that are supported by the
  mpc_loadtime_flags field of the mac_policy_conf structure.  These
  flags specify the load time behavior of MAC Framework policy
  modules.
*/

/*@{*/

/**
  @brief Flag to indicate registration preference

  This flag indicates that the policy module must be loaded and
  initialized early in the boot process. If the flag is specified,
  attempts to register the module following boot will be rejected. The
  flag may be used by policies that require pervasive labeling of all
  system objects, and cannot handle objects that have not been
  properly initialized by the policy.
 */
#define	MPC_LOADTIME_FLAG_NOTLATE	0x00000001

/**
  @brief Flag to indicate unload preference

  This flag indicates that the policy module may be unloaded. If this
  flag is not set, then the policy framework will reject requests to
  unload the module. This flag might be used by modules that allocate
  label state and are unable to free that state at runtime, or for
  modules that simply do not want to permit unload operations.
*/
#define	MPC_LOADTIME_FLAG_UNLOADOK	0x00000002

/**
  @brief Unsupported

  XXX This flag is not yet supported.
*/
#define	MPC_LOADTIME_FLAG_LABELMBUFS	0x00000004

/**
  @brief Flag to indicate a base policy

  This flag indicates that the policy module is a base policy. Only
  one module can declare itself as base, otherwise the boot process
  will be halted.
 */
#define	MPC_LOADTIME_BASE_POLICY	0x00000008

/*@}*/

/**
  @brief Policy registration flag
  @see mac_policy_conf

  This flag indicates that the policy module has been successfully
  registered with the TrustedBSD MAC Framework.  The Framework will
  set this flag in the mpc_runtime_flags field of the policy's
  mac_policy_conf structure after registering the policy.
 */
#define	MPC_RUNTIME_FLAG_REGISTERED	0x00000001

/*
 * Depends on POLICY_VER
 */

#ifndef POLICY_VER
#define	POLICY_VER	1.0
#endif

#define	MAC_POLICY_SET(handle, mpops, mpname, mpfullname, lnames, lcount, slot, lflags, rflags) \
	static struct mac_policy_conf mpname##_mac_policy_conf = {	\
		.mpc_name		= #mpname,			\
		.mpc_fullname		= mpfullname,			\
		.mpc_labelnames		= lnames,			\
		.mpc_labelname_count	= lcount,			\
		.mpc_ops		= mpops,			\
		.mpc_loadtime_flags	= lflags,			\
		.mpc_field_off		= slot,				\
		.mpc_runtime_flags	= rflags			\
	};								\
									\
	static kern_return_t						\
	kmod_start(kmod_info_t *ki, void *xd)				\
	{								\
		return mac_policy_register(&mpname##_mac_policy_conf,	\
		    &handle, xd);					\
	}								\
									\
	static kern_return_t						\
	kmod_stop(kmod_info_t *ki, void *xd)				\
	{								\
		return mac_policy_unregister(handle);			\
	}								\
									\
	extern kern_return_t _start(kmod_info_t *ki, void *data);	\
	extern kern_return_t _stop(kmod_info_t *ki, void *data);	\
									\
	KMOD_EXPLICIT_DECL(security.mpname, POLICY_VER, _start, _stop)	\
	kmod_start_func_t *_realmain = kmod_start;			\
	kmod_stop_func_t *_antimain = kmod_stop;			\
	int _kext_apple_cc = __APPLE_CC__


#define	LABEL_TO_SLOT(l, s)	(l)->l_perpolicy[s]

/*
 * Policy interface to map a struct label pointer to per-policy data.
 * Typically, policies wrap this in their own accessor macro that casts an
 * intptr_t to a policy-specific data type.
 */
intptr_t        mac_label_get(struct label *l, int slot);
void            mac_label_set(struct label *l, int slot, intptr_t v);

#define	mac_get_mpc(h)		(mac_policy_list.entries[h].mpc)

/**
  @name Flags for MAC allocator interfaces

  These flags are passed to the Darwin kernel allocator routines to
  indicate whether the allocation is permitted to block or not.
  Caution should be taken; some operations are not permitted to sleep,
  and some types of locks cannot be held when sleeping.
 */

/*@{*/

/**
    @brief Allocation operations may block

    If memory is not immediately available, the allocation routine
    will block (typically sleeping) until memory is available.

    @warning Inappropriate use of this flag may cause kernel panics.
 */
#define MAC_WAITOK  0

/**
    @brief Allocation operations may not block

    Rather than blocking, the allocator may return an error if memory
    is not immediately available.  This type of allocation will not
    sleep, preserving locking semantics.
 */
#define MAC_NOWAIT  1

/*@}*/

#endif /* !_SECURITY_MAC_POLICY_H_ */
