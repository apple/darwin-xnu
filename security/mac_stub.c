/*
 * Copyright (c) 2006-2007 Apple Inc. All rights reserved.
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

#include <mac.h>

#if !CONFIG_MACF
/*
 * XXX stubs until we fix <rdar://problem/4607887>
 */
int mac_check_ipc_method(void)
{
	return 0;
}
int mac_check_port_copy_send(void)
{
	return 0;
}
int mac_check_port_hold_receive(void)
{
	return 0;
}
int mac_check_port_hold_send(void)
{
	return 0;
}
int mac_check_port_make_send(void)
{
	return 0;
}
int mac_check_port_move_receive(void)
{
	return 0;
}
int mac_check_port_relabel(void)
{
	return 0;
}
int mac_check_port_send(void)
{
	return 0;
}
int mac_check_service_access(void)
{
	return 0;
}
int mac_copy_cred_to_task(void)
{
	return 0;
}
int mac_copy_port_label(void)
{
	return 0;
}
int mac_create_kernel_port(void)
{
	return 0;
}
int mac_create_kernel_task(void)
{
	return 0;
}
int mac_create_port(void)
{
	return 0;
}
int mac_create_task(void)
{
	return 0;
}
int mac_destroy_port_label(void)
{
	return 0;
}
int mac_destroy_task_label(void)
{
	return 0;
}
int mac_externalize_port_label(void)
{
	return 0;
}
int mac_externalize_task_label(void)
{
	return 0;
}
int mac_init(void)
{
	return 0;
}
int mac_init_mach(void)
{
	return 0;
}
int mac_init_port_label(void)
{
	return 0;
}
int mac_init_task_label(void)
{
	return 0;
}
int mac_internalize_port_label(void)
{
	return 0;
}
int mac_request_object_label(void)
{
	return 0;
}
int mac_update_port_from_cred_label(void)
{
	return 0;
}
int mac_update_port_kobject(void)
{
	return 0;
}
int mac_associate_vnode_devfs(void)
{
	return 0;
}
int mac_associate_vnode_extattr(void)
{
	return 0;
}
int mac_associate_vnode_singlelabel(void)
{
	return 0;
}
int mac_check_mount_getattr(void)
{
	return 0;
}
int mac_check_mount_setattr(void)
{
	return 0;
}
int mac_check_pipe_ioctl(void)
{
	return 0;
}
int mac_check_pipe_kqfilter(void)
{
	return 0;
}
int mac_check_pipe_read(void)
{
	return 0;
}
int mac_check_pipe_select(void)
{
	return 0;
}
int mac_check_pipe_stat(void)
{
	return 0;
}
int mac_check_pipe_write(void)
{
	return 0;
}
int mac_check_posix_sem_create(void)
{
	return 0;
}
int mac_check_posix_sem_open(void)
{
	return 0;
}
int mac_check_posix_sem_post(void)
{
	return 0;
}
int mac_check_posix_sem_unlink(void)
{
	return 0;
}
int mac_check_posix_sem_wait(void)
{
	return 0;
}
int mac_check_posix_shm_create(void)
{
	return 0;
}
int mac_check_posix_shm_mmap(void)
{
	return 0;
}
int mac_check_posix_shm_open(void)
{
	return 0;
}
int mac_check_posix_shm_stat(void)
{
	return 0;
}
int mac_check_posix_shm_truncate(void)
{
	return 0;
}
int mac_check_posix_shm_unlink(void)
{
	return 0;
}
int mac_check_proc_getlcid(void)
{
	return 0;
}
int mac_check_proc_fork(void)
{
	return 0;
}
int mac_check_proc_sched(void)
{
	return 0;
}
int mac_check_proc_setlcid(void)
{
	return 0;
}
int mac_check_proc_signal(void)
{
	return 0;
}
int mac_check_socket_received(void)
{
	return 0;
}
int mac_check_proc_wait(void)
{
	return 0;
}
int mac_check_system_acct(void)
{
	return 0;
}
int mac_check_system_nfsd(void)
{
	return 0;
}
int mac_check_system_reboot(void)
{
	return 0;
}
int mac_check_system_settime(void)
{
	return 0;
}
int mac_check_system_swapoff(void)
{
	return 0;
}
int mac_check_system_swapon(void)
{
	return 0;
}
int mac_check_system_sysctl(void)
{
	return 0;
}
int mac_check_vnode_access(void)
{
	return 0;
}
int mac_check_vnode_chdir(void)
{
	return 0;
}
int mac_check_vnode_chroot(void)
{
	return 0;
}
int mac_check_vnode_create(void)
{
	return 0;
}
int mac_check_vnode_delete(void)
{
	return 0;
}
int mac_check_vnode_deleteextattr(void)
{
	return 0;
}
int mac_check_vnode_exchangedata(void)
{
	return 0;
}
int mac_check_vnode_exec(void)
{
	return 0;
}
int mac_check_vnode_getattrlist(void)
{
	return 0;
}
int mac_check_vnode_getextattr(void)
{
	return 0;
}
int mac_check_vnode_kqfilter(void)
{
	return 0;
}
int mac_check_vnode_link(void)
{
	return 0;
}
int mac_check_vnode_listextattr(void)
{
	return 0;
}
int mac_check_vnode_lookup(void)
{
	return 0;
}
int mac_check_vnode_mmap(void)
{
	return 0;
}
int mac_check_vnode_open(void)
{
	return 0;
}
int mac_check_vnode_read(void)
{
	return 0;
}
int mac_check_vnode_readdir(void)
{
	return 0;
}
int mac_check_vnode_readlink(void)
{
	return 0;
}
int mac_check_vnode_rename_from(void)
{
	return 0;
}
int mac_check_vnode_rename_to(void)
{
	return 0;
}
int mac_check_vnode_revoke(void)
{
	return 0;
}
int mac_check_vnode_select(void)
{
	return 0;
}
int mac_check_vnode_setattrlist(void)
{
	return 0;
}
int mac_check_vnode_setextattr(void)
{
	return 0;
}
int mac_check_vnode_setflags(void)
{
	return 0;
}
int mac_check_vnode_setmode(void)
{
	return 0;
}
int mac_check_vnode_setowner(void)
{
	return 0;
}
int mac_check_vnode_setutimes(void)
{
	return 0;
}
int mac_check_vnode_stat(void)
{
	return 0;
}
int mac_check_vnode_write(void)
{
	return 0;
}
int mac_cleanup_vnode(void)
{
	return 0;
}
int mac_copy_devfs_label(void)
{
	return 0;
}
int mac_copy_vnode_label(void)
{
	return 0;
}
int mac_create_cred(void)
{
	return 0;
}
int mac_create_devfs_device(void)
{
	return 0;
}
int mac_create_devfs_directory(void)
{
	return 0;
}
int mac_create_mount(void)
{
	return 0;
}
int mac_create_pipe(void)
{
	return 0;
}
int mac_create_posix_sem(void)
{
	return 0;
}
int mac_create_posix_shm(void)
{
	return 0;
}
int mac_create_proc0(void)
{
	return 0;
}
int mac_create_proc1(void)
{
	return 0;
}
int mac_create_vnode_extattr(void)
{
	return 0;
}
int mac_cred_label_alloc(void)
{
	return 0;
}
int mac_cred_label_free(void)
{
	return 0;
}
int mac_destroy_cred(void)
{
	return 0;
}
int mac_destroy_devfsdirent(void)
{
	return 0;
}
int mac_destroy_mount(void)
{
	return 0;
}
int mac_destroy_pipe(void)
{
	return 0;
}
int mac_destroy_posix_sem(void)
{
	return 0;
}
int mac_destroy_posix_shm(void)
{
	return 0;
}
int mac_destroy_proc(void)
{
	return 0;
}
int mac_execve_enter(void)
{
	return 0;
}
int mac_execve_transition(void)
{
	return 0;
}
int mac_execve_will_transition(void)
{
	return 0;
}
int mac_init_bsd(void)
{
	return 0;
}
int mac_init_cred(void)
{
	return 0;
}
int mac_init_devfsdirent(void)
{
	return 0;
}
int mac_init_mount(void)
{
	return 0;
}
int mac_init_pipe(void)
{
	return 0;
}
int mac_init_posix_sem(void)
{
	return 0;
}
int mac_init_posix_shm(void)
{
	return 0;
}
int mac_init_proc(void)
{
	return 0;
}
int mac_init_vnode(void)
{
	return 0;
}
int mac_lctx_label_alloc(void)
{
	return 0;
}
int mac_lctx_label_free(void)
{
	return 0;
}
int mac_proc_create_lctx(void)
{
	return 0;
}
int mac_proc_join_lctx(void)
{
	return 0;
}
int mac_proc_leave_lctx(void)
{
	return 0;
}
int mac_relabel_cred(void)
{
	return 0;
}
int mac_relabel_vnode(void)
{
	return 0;
}
int mac_update_devfsdirent(void)
{
	return 0;
}
int mac_update_vnode_extattr(void)
{
	return 0;
}
int mac_vnode_label_alloc(void)
{
	return 0;
}
int mac_vnode_label_free(void)
{
	return 0;
}
int vop_stdsetlabel_ea(void)
{
	return 0;
}
int kau_will_audit(void)
{
	return 0;
}
int mac_kalloc(void)
{
	return 0;
}
int mac_kalloc_noblock(void)
{
	return 0;
}
int mac_kfree(void)
{
	return 0;
}
int mac_mbuf_alloc(void)
{
	return 0;
}
int mac_mbuf_free(void)
{
	return 0;
}
int mac_unwire(void)
{
	return 0;
}
int mac_wire(void)
{
	return 0;
}
int sysctl__security_mac_children(void)
{
	return 0;
}
int mac_check_socket_accept(void)
{
	return 0;
}
int mac_check_socket_accepted(void)
{
	return 0;
}
int mac_check_socket_bind(void)
{
	return 0;
}
int mac_check_socket_connect(void)
{
	return 0;
}
int mac_check_socket_create(void)
{
	return 0;
}
int mac_check_socket_getsockopt(void)
{
	return 0;
}
int mac_check_socket_listen(void)
{
	return 0;
}
int mac_check_socket_receive(void)
{
	return 0;
}
int mac_check_socket_send(void)
{
	return 0;
}
int mac_check_socket_setsockopt(void)
{
	return 0;
}
int mac_fork_proc(void)
{
	return 0;
}
int mac_set_enforce_proc(void)
{
	return 0;
}
#endif /* CONFIG_MACF */
