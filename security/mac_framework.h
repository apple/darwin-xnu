/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * $FreeBSD: src/sys/sys/mac.h,v 1.40 2003/04/18 19:57:37 rwatson Exp $
 *
 */
/*
 * Kernel interface for Mandatory Access Control -- how kernel services
 * interact with the TrustedBSD MAC Framework.
 */

#ifndef _SECURITY_MAC_FRAMEWORK_H_
#define	_SECURITY_MAC_FRAMEWORK_H_

#ifndef KERNEL
#error "no user-serviceable parts inside"
#endif

#ifndef PRIVATE
#warning "MAC policy is not KPI, see Technical Q&A QA1574, this header will be removed in next version"
#endif

struct attrlist;
struct auditinfo;
struct bpf_d;
struct componentname;
struct devnode;
struct flock;
struct fdescnode;
struct fileglob;
struct fileproc;
struct ifnet;
struct ifreq;
struct image_params;
struct inpcb;
struct ipq;
struct knote;
struct lctx;
struct m_tag;
struct mac;
struct mac_module_data;
struct mbuf;
struct msg;
struct msqid_kernel;
struct mount;
struct pipe;
struct proc;
struct pseminfo;
struct pshminfo;
struct semid_kernel;
struct shmid_kernel;
struct sockaddr;
struct sockopt;
struct socket;
struct task;
struct thread;
struct timespec;
struct tty;
struct ucred;
struct uio;
struct uthread;
struct vfs_attr;
struct vfs_context;
struct vnode;
struct vnode_attr;
struct vop_setlabel_args;

#if CONFIG_MACF

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

/*@ macros */
#define	VNODE_LABEL_CREATE	1

/*@ === */
int	mac_audit_check_postselect(kauth_cred_t cred, unsigned short syscode,
	    void *args, int error, int retval, int mac_forced);
int	mac_audit_check_preselect(kauth_cred_t cred, unsigned short syscode,
	    void *args);
int	mac_bpfdesc_check_receive(struct bpf_d *bpf_d, struct ifnet *ifp);
void	mac_bpfdesc_label_destroy(struct bpf_d *bpf_d);
void	mac_bpfdesc_label_init(struct bpf_d *bpf_d);
void	mac_bpfdesc_label_associate(kauth_cred_t cred, struct bpf_d *bpf_d);
int	mac_cred_check_label_update(kauth_cred_t cred,
	    struct label *newlabel);
int	mac_cred_check_label_update_execve(vfs_context_t ctx,
	    struct vnode *vp, off_t offset, struct vnode *scriptvp,
	    struct label *scriptvnodelabel, struct label *execlabel,
	    proc_t proc, void *macextensions);
int	mac_cred_check_visible(kauth_cred_t u1, kauth_cred_t u2);
struct label	*mac_cred_label_alloc(void);
void	mac_cred_label_associate(kauth_cred_t cred_parent,
	    kauth_cred_t cred_child);
void	mac_cred_label_associate_fork(kauth_cred_t cred, proc_t child);
void	mac_cred_label_associate_kernel(kauth_cred_t cred);
void	mac_cred_label_associate_user(kauth_cred_t cred);
void	mac_cred_label_destroy(kauth_cred_t cred);
int	mac_cred_label_externalize_audit(proc_t p, struct mac *mac);
void	mac_cred_label_free(struct label *label);
void	mac_cred_label_init(kauth_cred_t cred);
int	mac_cred_label_compare(struct label *a, struct label *b);
void	mac_cred_label_update(kauth_cred_t cred, struct label *newlabel);
void	mac_cred_label_update_execve(vfs_context_t ctx, kauth_cred_t newcred,
	    struct vnode *vp, off_t offset, struct vnode *scriptvp,
	    struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags,
	    void *macextensions, int *disjoint, int *labelupdateerror);
void	mac_devfs_label_associate_device(dev_t dev, struct devnode *de,
	    const char *fullpath);
void	mac_devfs_label_associate_directory(const char *dirname, int dirnamelen,
	    struct devnode *de, const char *fullpath);
void	mac_devfs_label_copy(struct label *, struct label *label);
void	mac_devfs_label_destroy(struct devnode *de);
void	mac_devfs_label_init(struct devnode *de);
void	mac_devfs_label_update(struct mount *mp, struct devnode *de,
	    struct vnode *vp);
int	mac_execve_enter(user_addr_t mac_p, struct image_params *imgp);
int	mac_file_check_change_offset(kauth_cred_t cred, struct fileglob *fg);
int	mac_file_check_create(kauth_cred_t cred);
int	mac_file_check_dup(kauth_cred_t cred, struct fileglob *fg, int newfd);
int	mac_file_check_fcntl(kauth_cred_t cred, struct fileglob *fg, int cmd,
	    user_long_t arg);
int	mac_file_check_get(kauth_cred_t cred, struct fileglob *fg,
	    char *elements, int len);
int	mac_file_check_get_offset(kauth_cred_t cred, struct fileglob *fg);
int	mac_file_check_inherit(kauth_cred_t cred, struct fileglob *fg);
int	mac_file_check_ioctl(kauth_cred_t cred, struct fileglob *fg,
	    unsigned int cmd);
int	mac_file_check_lock(kauth_cred_t cred, struct fileglob *fg, int op,
	    struct flock *fl);
int	mac_file_check_mmap(kauth_cred_t cred, struct fileglob *fg,
	    int prot, int flags, int *maxprot);
void	mac_file_check_mmap_downgrade(kauth_cred_t cred, struct fileglob *fg,
	    int *prot);
int	mac_file_check_receive(kauth_cred_t cred, struct fileglob *fg);
int	mac_file_check_set(kauth_cred_t cred, struct fileglob *fg,
	    char *bufp, int buflen);
void	mac_file_label_associate(kauth_cred_t cred, struct fileglob *fg);
void	mac_file_label_destroy(struct fileglob *fg);
void	mac_file_label_init(struct fileglob *fg);
int	mac_ifnet_check_transmit(struct ifnet *ifp, struct mbuf *mbuf,
	    int family, int type);
void	mac_ifnet_label_associate(struct ifnet *ifp);
void	mac_ifnet_label_destroy(struct ifnet *ifp);
int	mac_ifnet_label_get(kauth_cred_t cred, struct ifreq *ifr,
	    struct ifnet *ifp);
void	mac_ifnet_label_init(struct ifnet *ifp);
void	mac_ifnet_label_recycle(struct ifnet *ifp);
int	mac_ifnet_label_set(kauth_cred_t cred, struct ifreq *ifr,
	    struct ifnet *ifp);
int	mac_inpcb_check_deliver(struct inpcb *inp, struct mbuf *mbuf,
	    int family, int type);
void	mac_inpcb_label_associate(struct socket *so, struct inpcb *inp);
void	mac_inpcb_label_destroy(struct inpcb *inp);
int	mac_inpcb_label_init(struct inpcb *inp, int flag);
void	mac_inpcb_label_recycle(struct inpcb *inp);
void	mac_inpcb_label_update(struct socket *so);
int	mac_iokit_check_device(char *devtype, struct mac_module_data *mdata);
int	mac_iokit_check_open(kauth_cred_t cred, io_object_t user_client, unsigned int user_client_type);
int	mac_iokit_check_set_properties(kauth_cred_t cred, io_object_t registry_entry, io_object_t properties);
int	mac_iokit_check_filter_properties(kauth_cred_t cred, io_object_t registry_entry);
int	mac_iokit_check_get_property(kauth_cred_t cred, io_object_t registry_entry, const char *name);
int	mac_iokit_check_hid_control(kauth_cred_t cred);
void	mac_ipq_label_associate(struct mbuf *fragment, struct ipq *ipq);
int	mac_ipq_label_compare(struct mbuf *fragment, struct ipq *ipq);
void	mac_ipq_label_destroy(struct ipq *ipq);
int	mac_ipq_label_init(struct ipq *ipq, int flag);
void	mac_ipq_label_update(struct mbuf *fragment, struct ipq *ipq);
struct label	*mac_lctx_label_alloc(void);
void    mac_lctx_label_free(struct label *label);
void	mac_lctx_label_update(struct lctx *l, struct label *newlabel);
int	mac_lctx_check_label_update(struct lctx *l, struct label *newlabel);
void	mac_lctx_notify_create(proc_t proc, struct lctx *l);
void	mac_lctx_notify_join(proc_t proc, struct lctx *l);
void	mac_lctx_notify_leave(proc_t proc, struct lctx *l);
void	mac_mbuf_label_associate_bpfdesc(struct bpf_d *bpf_d, struct mbuf *m);
void	mac_mbuf_label_associate_ifnet(struct ifnet *ifp, struct mbuf *m);
void	mac_mbuf_label_associate_inpcb(struct inpcb *inp, struct mbuf *m);
void	mac_mbuf_label_associate_ipq(struct ipq *ipq, struct mbuf *mbuf);
void	mac_mbuf_label_associate_linklayer(struct ifnet *ifp, struct mbuf *m);
void	mac_mbuf_label_associate_multicast_encap(struct mbuf *oldmbuf,
	    struct ifnet *ifp, struct mbuf *newmbuf);
void	mac_mbuf_label_associate_netlayer(struct mbuf *oldmbuf,
	    struct mbuf *newmbuf);
void	mac_mbuf_label_associate_socket(struct socket *so, struct mbuf *m);
void	mac_mbuf_label_copy(struct mbuf *m_from, struct mbuf *m_to);
void	mac_mbuf_label_destroy(struct mbuf *m);
int	mac_mbuf_label_init(struct mbuf *m, int flag);
void	mac_mbuf_tag_copy(struct m_tag *m, struct m_tag *mtag);
void	mac_mbuf_tag_destroy(struct m_tag *mtag);
int	mac_mbuf_tag_init(struct m_tag *, int how);
int	mac_mount_check_fsctl(vfs_context_t ctx, struct mount *mp,
	    unsigned int cmd);
int	mac_mount_check_getattr(vfs_context_t ctx, struct mount *mp,
	    struct vfs_attr *vfa);
int	mac_mount_check_label_update(vfs_context_t ctx, struct mount *mp);
int	mac_mount_check_mount(vfs_context_t ctx, struct vnode *vp,
	    struct componentname *cnp, const char *vfc_name);
int	mac_mount_check_remount(vfs_context_t ctx, struct mount *mp);
int	mac_mount_check_setattr(vfs_context_t ctx, struct mount *mp,
	    struct vfs_attr *vfa);
int	mac_mount_check_stat(vfs_context_t ctx, struct mount *mp);
int	mac_mount_check_umount(vfs_context_t ctx, struct mount *mp);
void	mac_mount_label_associate(vfs_context_t ctx, struct mount *mp);
void	mac_mount_label_destroy(struct mount *mp);
int	mac_mount_label_externalize(struct label *label, char *elements,
	    char *outbuf, size_t outbuflen);
int	mac_mount_label_get(struct mount *mp, user_addr_t mac_p);
void	mac_mount_label_init(struct mount *);
int	mac_mount_label_internalize(struct label *, char *string);
void	mac_netinet_fragment(struct mbuf *datagram, struct mbuf *fragment);
void	mac_netinet_icmp_reply(struct mbuf *m);
void	mac_netinet_tcp_reply(struct mbuf *m);
int	mac_pipe_check_ioctl(kauth_cred_t cred, struct pipe *cpipe,
	    unsigned int cmd);
int	mac_pipe_check_kqfilter(kauth_cred_t cred, struct knote *kn,
	    struct pipe *cpipe);
int	mac_pipe_check_read(kauth_cred_t cred, struct pipe *cpipe);
int	mac_pipe_check_select(kauth_cred_t cred, struct pipe *cpipe,
	    int which);
int	mac_pipe_check_stat(kauth_cred_t cred, struct pipe *cpipe);
int	mac_pipe_check_write(kauth_cred_t cred, struct pipe *cpipe);
struct label	*mac_pipe_label_alloc(void);
void	mac_pipe_label_associate(kauth_cred_t cred, struct pipe *cpipe);
void	mac_pipe_label_copy(struct label *src, struct label *dest);
void	mac_pipe_label_destroy(struct pipe *cpipe);
void	mac_pipe_label_free(struct label *label);
void	mac_pipe_label_init(struct pipe *cpipe);
int	mac_pipe_label_update(kauth_cred_t cred, struct pipe *cpipe,
	    struct label *label);
void    mac_policy_initbsd(void);
int	mac_posixsem_check_create(kauth_cred_t cred, const char *name);
int	mac_posixsem_check_open(kauth_cred_t cred, struct pseminfo *psem);
int	mac_posixsem_check_post(kauth_cred_t cred, struct pseminfo *psem);
int	mac_posixsem_check_unlink(kauth_cred_t cred, struct pseminfo *psem,
	    const char *name);
int	mac_posixsem_check_wait(kauth_cred_t cred, struct pseminfo *psem);
void	mac_posixsem_vnode_label_associate(kauth_cred_t cred,
	    struct pseminfo *psem, struct label *plabel,
	    vnode_t vp, struct label *vlabel);
void	mac_posixsem_label_associate(kauth_cred_t cred,
	    struct pseminfo *psem, const char *name);
void	mac_posixsem_label_destroy(struct pseminfo *psem);
void	mac_posixsem_label_init(struct pseminfo *psem);
int	mac_posixshm_check_create(kauth_cred_t cred, const char *name);
int	mac_posixshm_check_mmap(kauth_cred_t cred, struct pshminfo *pshm,
	    int prot, int flags);
int	mac_posixshm_check_open(kauth_cred_t cred, struct pshminfo *pshm,
	    int fflags);
int	mac_posixshm_check_stat(kauth_cred_t cred, struct pshminfo *pshm);
int	mac_posixshm_check_truncate(kauth_cred_t cred, struct pshminfo *pshm,
	    off_t s);
int	mac_posixshm_check_unlink(kauth_cred_t cred, struct pshminfo *pshm,
	    const char *name);
void	mac_posixshm_vnode_label_associate(kauth_cred_t cred,
	    struct pshminfo *pshm, struct label *plabel,
	    vnode_t vp, struct label *vlabel);
void	mac_posixshm_label_associate(kauth_cred_t cred,
	    struct pshminfo *pshm, const char *name);
void	mac_posixshm_label_destroy(struct pshminfo *pshm);
void	mac_posixshm_label_init(struct pshminfo *pshm);
int	mac_priv_check(kauth_cred_t cred, int priv);
int	mac_priv_grant(kauth_cred_t cred, int priv);
int	mac_proc_check_debug(proc_t proc1, proc_t proc2);
int	mac_proc_check_cpumon(proc_t curp);
int	mac_proc_check_proc_info(proc_t curp, proc_t target, int callnum, int flavor);
int	mac_proc_check_fork(proc_t proc);
int	mac_proc_check_suspend_resume(proc_t proc, int sr);
int	mac_proc_check_get_task_name(kauth_cred_t cred, struct proc *p);
int	mac_proc_check_get_task(kauth_cred_t cred, struct proc *p);
int	mac_proc_check_inherit_ipc_ports(struct proc *p, struct vnode *cur_vp, off_t cur_offset, struct vnode *img_vp, off_t img_offset, struct vnode *scriptvp);
int	mac_proc_check_getaudit(proc_t proc);
int	mac_proc_check_getauid(proc_t proc);
int     mac_proc_check_getlcid(proc_t proc1, proc_t proc2,
	    pid_t pid);
int     mac_proc_check_ledger(proc_t curp, proc_t target, int op);
int	mac_proc_check_map_anon(proc_t proc, user_addr_t u_addr,
	    user_size_t u_size, int prot, int flags, int *maxprot);
int	mac_proc_check_mprotect(proc_t proc,
	    user_addr_t addr, user_size_t size, int prot);
int	mac_proc_check_run_cs_invalid(proc_t proc);
int	mac_proc_check_sched(proc_t proc, proc_t proc2);
int	mac_proc_check_setaudit(proc_t proc, struct auditinfo_addr *ai);
int	mac_proc_check_setauid(proc_t proc, uid_t auid);
int     mac_proc_check_setlcid(proc_t proc1, proc_t proc2,
	    pid_t pid1, pid_t pid2);
int	mac_proc_check_signal(proc_t proc1, proc_t proc2,
	    int signum);
int	mac_proc_check_wait(proc_t proc1, proc_t proc2);
void	mac_proc_set_enforce(proc_t p, int enforce_flags);
int	mac_setsockopt_label(kauth_cred_t cred, struct socket *so,
	    struct mac *extmac);
int     mac_socket_check_accept(kauth_cred_t cred, struct socket *so);
int     mac_socket_check_accepted(kauth_cred_t cred, struct socket *so);
int	mac_socket_check_bind(kauth_cred_t cred, struct socket *so,
	    struct sockaddr *addr);
int	mac_socket_check_connect(kauth_cred_t cred, struct socket *so,
	    struct sockaddr *addr);
int	mac_socket_check_create(kauth_cred_t cred, int domain,
	    int type, int protocol);
int	mac_socket_check_deliver(struct socket *so, struct mbuf *m);
int	mac_socket_check_kqfilter(kauth_cred_t cred, struct knote *kn,
	    struct socket *so);
int	mac_socket_check_listen(kauth_cred_t cred, struct socket *so);
int	mac_socket_check_receive(kauth_cred_t cred, struct socket *so);
int	mac_socket_check_received(kauth_cred_t cred, struct socket *so, 
	    struct sockaddr *saddr);
int     mac_socket_check_select(kauth_cred_t cred, struct socket *so,
	    int which);
int	mac_socket_check_send(kauth_cred_t cred, struct socket *so,
	    struct sockaddr *addr);
int	mac_socket_check_getsockopt(kauth_cred_t cred, struct socket *so,
	    struct sockopt *sopt);
int	mac_socket_check_setsockopt(kauth_cred_t cred, struct socket *so,
	    struct sockopt *sopt);
int	mac_socket_check_stat(kauth_cred_t cred, struct socket *so);
void	mac_socket_label_associate(kauth_cred_t cred, struct socket *so);
void	mac_socket_label_associate_accept(struct socket *oldsocket,
	    struct socket *newsocket);
void	mac_socket_label_copy(struct label *from, struct label *to);
void	mac_socket_label_destroy(struct socket *);
int	mac_socket_label_get(kauth_cred_t cred, struct socket *so,
	    struct mac *extmac);
int	mac_socket_label_init(struct socket *, int waitok);
void	mac_socketpeer_label_associate_mbuf(struct mbuf *m, struct socket *so);
void	mac_socketpeer_label_associate_socket(struct socket *peersocket,
	    struct socket *socket_to_modify);
int	mac_socketpeer_label_get(kauth_cred_t cred, struct socket *so,
	    struct mac *extmac);
int	mac_system_check_acct(kauth_cred_t cred, struct vnode *vp);
int	mac_system_check_audit(kauth_cred_t cred, void *record, int length);
int	mac_system_check_auditctl(kauth_cred_t cred, struct vnode *vp);
int	mac_system_check_auditon(kauth_cred_t cred, int cmd);
int	mac_system_check_chud(kauth_cred_t cred);
int	mac_system_check_host_priv(kauth_cred_t cred);
int	mac_system_check_info(kauth_cred_t, const char *info_type);
int	mac_system_check_nfsd(kauth_cred_t cred);
int	mac_system_check_reboot(kauth_cred_t cred, int howto);
int	mac_system_check_settime(kauth_cred_t cred);
int	mac_system_check_swapoff(kauth_cred_t cred, struct vnode *vp);
int	mac_system_check_swapon(kauth_cred_t cred, struct vnode *vp);
int	mac_system_check_sysctlbyname(kauth_cred_t cred, const char *namestring, int *name,
				      u_int namelen, user_addr_t oldctl, size_t oldlen,
				      user_addr_t newctl, size_t newlen);
int	mac_system_check_kas_info(kauth_cred_t cred, int selector);
void	mac_sysvmsg_label_associate(kauth_cred_t cred,
	    struct msqid_kernel *msqptr, struct msg *msgptr);
void	mac_sysvmsg_label_init(struct msg *msgptr);
void	mac_sysvmsg_label_recycle(struct msg *msgptr);
int	mac_sysvmsq_check_enqueue(kauth_cred_t cred, struct msg *msgptr,
	    struct msqid_kernel *msqptr);
int	mac_sysvmsq_check_msgrcv(kauth_cred_t cred, struct msg *msgptr);
int	mac_sysvmsq_check_msgrmid(kauth_cred_t cred, struct msg *msgptr);
int	mac_sysvmsq_check_msqctl(kauth_cred_t cred,
	    struct msqid_kernel *msqptr, int cmd);
int	mac_sysvmsq_check_msqget(kauth_cred_t cred,
	    struct msqid_kernel *msqptr);
int	mac_sysvmsq_check_msqrcv(kauth_cred_t cred,
	    struct msqid_kernel *msqptr);
int	mac_sysvmsq_check_msqsnd(kauth_cred_t cred,
	    struct msqid_kernel *msqptr);
void	mac_sysvmsq_label_associate(kauth_cred_t cred,
	    struct msqid_kernel *msqptr);
void 	mac_sysvmsq_label_init(struct msqid_kernel *msqptr);
void 	mac_sysvmsq_label_recycle(struct msqid_kernel *msqptr);
int	mac_sysvsem_check_semctl(kauth_cred_t cred,
	    struct semid_kernel *semakptr, int cmd);
int	mac_sysvsem_check_semget(kauth_cred_t cred,
	    struct semid_kernel *semakptr);
int	mac_sysvsem_check_semop(kauth_cred_t cred,
	    struct semid_kernel *semakptr, size_t accesstype);
void	mac_sysvsem_label_associate(kauth_cred_t cred,
	    struct semid_kernel *semakptr);
void	mac_sysvsem_label_destroy(struct semid_kernel *semakptr);
void	mac_sysvsem_label_init(struct semid_kernel *semakptr);
void	mac_sysvsem_label_recycle(struct semid_kernel *semakptr);
int	mac_sysvshm_check_shmat(kauth_cred_t cred,
	    struct shmid_kernel *shmsegptr, int shmflg);
int	mac_sysvshm_check_shmctl(kauth_cred_t cred,
	    struct shmid_kernel *shmsegptr, int cmd);
int	mac_sysvshm_check_shmdt(kauth_cred_t cred,
	    struct shmid_kernel *shmsegptr);
int	mac_sysvshm_check_shmget(kauth_cred_t cred,
	    struct shmid_kernel *shmsegptr, int shmflg);
void	mac_sysvshm_label_associate(kauth_cred_t cred,
	    struct shmid_kernel *shmsegptr);
void	mac_sysvshm_label_destroy(struct shmid_kernel *shmsegptr);
void	mac_sysvshm_label_init(struct shmid_kernel* shmsegptr);
void	mac_sysvshm_label_recycle(struct shmid_kernel *shmsegptr);
struct label * mac_thread_label_alloc(void);
void	mac_thread_label_destroy(struct uthread *uthread);
void	mac_thread_label_free(struct label *label);
void	mac_thread_label_init(struct uthread *uthread);
int	mac_vnode_check_access(vfs_context_t ctx, struct vnode *vp,
	    int acc_mode);
int	mac_vnode_check_chdir(vfs_context_t ctx, struct vnode *dvp);
int	mac_vnode_check_chroot(vfs_context_t ctx, struct vnode *dvp,
	    struct componentname *cnp);
int	mac_vnode_check_create(vfs_context_t ctx, struct vnode *dvp,
	    struct componentname *cnp, struct vnode_attr *vap);
int	mac_vnode_check_deleteextattr(vfs_context_t ctx, struct vnode *vp,
	    const char *name);
int	mac_vnode_check_exchangedata(vfs_context_t ctx, struct vnode *v1,
	    struct vnode *v2);
int	mac_vnode_check_exec(vfs_context_t ctx, struct vnode *vp,
	    struct image_params *imgp);
int	mac_vnode_check_fsgetpath(vfs_context_t ctx, struct vnode *vp);
int	mac_vnode_check_signature(struct vnode *vp, off_t macho_offset,
	    unsigned char *sha1, const void * signature, size_t size, 
	    int flags, int *is_platform_binary);
int     mac_vnode_check_getattrlist(vfs_context_t ctx, struct vnode *vp,
	    struct attrlist *alist);
int	mac_vnode_check_getextattr(vfs_context_t ctx, struct vnode *vp,
	    const char *name, struct uio *uio);
int	mac_vnode_check_ioctl(vfs_context_t ctx, struct vnode *vp,
	    unsigned int cmd);
int	mac_vnode_check_kqfilter(vfs_context_t ctx,
	    kauth_cred_t file_cred, struct knote *kn, struct vnode *vp);
int	mac_vnode_check_label_update(vfs_context_t ctx, struct vnode *vp,
	    struct label *newlabel);
int	mac_vnode_check_link(vfs_context_t ctx, struct vnode *dvp,
	    struct vnode *vp, struct componentname *cnp);
int	mac_vnode_check_listextattr(vfs_context_t ctx, struct vnode *vp);
int	mac_vnode_check_lookup(vfs_context_t ctx, struct vnode *dvp,
	    struct componentname *cnp);
int	mac_vnode_check_open(vfs_context_t ctx, struct vnode *vp,
	    int acc_mode);
int	mac_vnode_check_read(vfs_context_t ctx,
	    kauth_cred_t file_cred, struct vnode *vp);
int	mac_vnode_check_readdir(vfs_context_t ctx, struct vnode *vp);
int	mac_vnode_check_readlink(vfs_context_t ctx, struct vnode *vp);
int	mac_vnode_check_rename(vfs_context_t ctx, struct vnode *dvp,
	    struct vnode *vp, struct componentname *cnp, struct vnode *tdvp,
	    struct vnode *tvp, struct componentname *tcnp);
int	mac_vnode_check_revoke(vfs_context_t ctx, struct vnode *vp);
int	mac_vnode_check_searchfs(vfs_context_t ctx, struct vnode *vp,
	    struct attrlist *alist);
int     mac_vnode_check_select(vfs_context_t ctx, struct vnode *vp,
	    int which);
int     mac_vnode_check_setattrlist(vfs_context_t ctxd, struct vnode *vp,
	    struct attrlist *alist);
int	mac_vnode_check_setextattr(vfs_context_t ctx, struct vnode *vp,
	    const char *name, struct uio *uio);
int	mac_vnode_check_setflags(vfs_context_t ctx, struct vnode *vp,
	    u_long flags);
int	mac_vnode_check_setmode(vfs_context_t ctx, struct vnode *vp,
	    mode_t mode);
int	mac_vnode_check_setowner(vfs_context_t ctx, struct vnode *vp,
	    uid_t uid, gid_t gid);
int	mac_vnode_check_setutimes(vfs_context_t ctx, struct vnode *vp,
	    struct timespec atime, struct timespec mtime);
int	mac_vnode_check_stat(vfs_context_t ctx,
	    kauth_cred_t file_cred, struct vnode *vp);
int	mac_vnode_check_truncate(vfs_context_t ctx,
	    kauth_cred_t file_cred, struct vnode *vp);
int	mac_vnode_check_uipc_bind(vfs_context_t ctx, struct vnode *dvp,
	    struct componentname *cnp, struct vnode_attr *vap);
int	mac_vnode_check_uipc_connect(vfs_context_t ctx, struct vnode *vp);
int	mac_vnode_check_unlink(vfs_context_t ctx, struct vnode *dvp,
	    struct vnode *vp, struct componentname *cnp);
int	mac_vnode_check_write(vfs_context_t ctx,
	    kauth_cred_t file_cred, struct vnode *vp);
struct label	*mac_vnode_label_alloc(void);
int	mac_vnode_label_associate(struct mount *mp, struct vnode *vp,
	    vfs_context_t ctx);
void	mac_vnode_label_associate_devfs(struct mount *mp, struct devnode *de,
	    struct vnode *vp);
int	mac_vnode_label_associate_extattr(struct mount *mp, struct vnode *vp);
int	mac_vnode_label_associate_fdesc(struct mount *mp, struct fdescnode *fnp,
	    struct vnode *vp, vfs_context_t ctx);
void	mac_vnode_label_associate_singlelabel(struct mount *mp,
	    struct vnode *vp);
void	mac_vnode_label_copy(struct label *l1, struct label *l2);
void	mac_vnode_label_destroy(struct vnode *vp);
int	mac_vnode_label_externalize_audit(struct vnode *vp, struct mac *mac);
void	mac_vnode_label_free(struct label *label);
void	mac_vnode_label_init(struct vnode *vp);
int	mac_vnode_label_init_needed(struct vnode *vp);
void	mac_vnode_label_recycle(struct vnode *vp);
void	mac_vnode_label_update(vfs_context_t ctx, struct vnode *vp,
	    struct label *newlabel);
void	mac_vnode_label_update_extattr(struct mount *mp, struct vnode *vp,
	    const char *name);
int	mac_vnode_notify_create(vfs_context_t ctx, struct mount *mp,
	    struct vnode *dvp, struct vnode *vp, struct componentname *cnp);
void	mac_vnode_notify_rename(vfs_context_t ctx, struct vnode *vp,
	    struct vnode *dvp, struct componentname *cnp);
void	mac_vnode_notify_open(vfs_context_t ctx, struct vnode *vp, int acc_flags);
void	mac_vnode_notify_link(vfs_context_t ctx, struct vnode *vp,
			      struct vnode *dvp, struct componentname *cnp);
int	mac_vnode_find_sigs(struct proc *p, struct vnode *vp, off_t offsetInMacho);
int	vnode_label(struct mount *mp, struct vnode *dvp, struct vnode *vp,
	    struct componentname *cnp, int flags, vfs_context_t ctx);
void	vnode_relabel(struct vnode *vp);
void	mac_pty_notify_grant(proc_t p, struct tty *tp, dev_t dev, struct label *label);
void	mac_pty_notify_close(proc_t p, struct tty *tp, dev_t dev, struct label *label);
int	mac_kext_check_load(kauth_cred_t cred, const char *identifier);
int	mac_kext_check_unload(kauth_cred_t cred, const char *identifier);

void psem_label_associate(struct fileproc *fp, struct vnode *vp, struct vfs_context *ctx);
void pshm_label_associate(struct fileproc *fp, struct vnode *vp, struct vfs_context *ctx);

#if CONFIG_MACF_NET
struct label *mac_bpfdesc_label_get(struct bpf_d *d);
void mac_bpfdesc_label_set(struct bpf_d *d, struct label *label);
#endif

#endif	/* CONFIG_MACF */

#endif /* !_SECURITY_MAC_FRAMEWORK_H_ */
