#include <sys/param.h>
#include <sys/systm.h>		/* XXX printf() */

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/vnode.h>
#include <security/mac.h>
#include <security/mac_policy.h>

#include <libkern/OSDebug.h>	/* OSBPrintBacktrace */


/* forward declaration; see bsd_init.c */
errno_t check_policy_init(int);
int get_thread_lock_count(thread_t th);         /* forced forward */

/*
 * Policy flags used when the policy is enabled
 *
 * Note:	CHECK_POLICY_CHECK is probably not very useful unless you
 *		are kernel debugging and set a breakpoint.
 */
#define	CHECK_POLICY_CHECK	0x00000001	/* Check on calls */
#define	CHECK_POLICY_FAIL	0x00000002	/* EPERM on fails */
#define	CHECK_POLICY_BACKTRACE	0x00000004	/* Show call stack on fails */
#define	CHECK_POLICY_PANIC	0x00000008	/* Panic on fails */
#define	CHECK_POLICY_PERIODIC	0x00000010	/* Show fails periodically */

static int policy_flags = 0;


#define CHECK_SET_INT_HOOK(x)	.mpo_##x = (mpo_##x##_t *)common_int_hook,
#define CHECK_SET_VOID_HOOK(x)	.mpo_##x = (mpo_##x##_t *)common_void_hook,


/*
 * Init; currently, we only print our arrival notice.
 */
static void
hook_policy_init(struct mac_policy_conf *mpc)
{
	printf("Policy '%s' = '%s' ready\n", mpc->mpc_name, mpc->mpc_fullname);
}

static void
hook_policy_initbsd(struct mac_policy_conf *mpc)
{
	/* called with policy_grab_exclusive mutex held; exempt */
	printf("hook_policy_initbsd: %s\n", mpc->mpc_name);
}


/* Implementation */
#define	CLASS_PERIOD_LIMIT	10000
#define	CLASS_PERIOD_MULT	20

static int policy_check_event = 1;
static int policy_check_period = 1;
static int policy_check_next = CLASS_PERIOD_MULT;


static int
common_int_hook(void)
{
	int	i;
	int	rv = 0;

	if ((i = get_thread_lock_count(current_thread())) != 0) {
		/*
		 * fail the MACF check if we hold a lock; this assumes a
		 * a non-void (authorization) MACF hook.
		 */
		if (policy_flags & CHECK_POLICY_FAIL)
			rv = EPERM;

		/*
		 * display a backtrace if we hold a lock and we are not
		 * going to panic
		 */
		if ((policy_flags & (CHECK_POLICY_BACKTRACE | CHECK_POLICY_PANIC)) == CHECK_POLICY_BACKTRACE) {
			if (policy_flags & CHECK_POLICY_PERIODIC) {
			    /* at exponentially increasing intervals */
			    if (!(policy_check_event % policy_check_period)) {
				if (policy_check_event <= policy_check_next || policy_check_period == CLASS_PERIOD_LIMIT) {
					/*
					 * According to Derek, we could
					 * technically get a symbolicated name
					 * here, if we refactered some code
					 * and set the "keepsyms=1" boot
					 * argument...
					 */
					OSReportWithBacktrace("calling MACF hook with mutex count %d (event %d) ", i, policy_check_event);
				}
			    } else {
				if (policy_check_period < CLASS_PERIOD_LIMIT) {
					policy_check_next *= CLASS_PERIOD_MULT;
					policy_check_period *= CLASS_PERIOD_MULT;
				}
			    }
			} else {
				/* always */
				OSReportWithBacktrace("calling MACF hook with mutex count %d (event %d) ", i, policy_check_event);
			}
		}

		/* Panic */
		if (policy_flags & CHECK_POLICY_PANIC)
			panic("calling MACF hook with mutex count %d\n", i);

		/* count for non-fatal tracing */
		policy_check_event++;
	}

	return rv;
}

static void
common_void_hook(void)
{
	(void)common_int_hook();

	return;
}


/*
 * Policy hooks; one per possible hook
 */
static struct mac_policy_ops policy_ops = {

	/* separate init */
	.mpo_policy_init = hook_policy_init,
	.mpo_policy_initbsd = hook_policy_initbsd,

	/* operations which return int */
	CHECK_SET_INT_HOOK(audit_check_postselect)
	CHECK_SET_INT_HOOK(audit_check_preselect)
	CHECK_SET_INT_HOOK(bpfdesc_check_receive)
	CHECK_SET_INT_HOOK(cred_check_label_update_execve)
	CHECK_SET_INT_HOOK(cred_check_label_update)
	CHECK_SET_INT_HOOK(cred_check_visible)
	CHECK_SET_INT_HOOK(cred_label_externalize_audit)
	CHECK_SET_INT_HOOK(cred_label_externalize)
	CHECK_SET_INT_HOOK(cred_label_internalize)
	CHECK_SET_INT_HOOK(file_check_change_offset)
	CHECK_SET_INT_HOOK(file_check_create)
	CHECK_SET_INT_HOOK(file_check_dup)
	CHECK_SET_INT_HOOK(file_check_fcntl)
	CHECK_SET_INT_HOOK(file_check_get)
	CHECK_SET_INT_HOOK(file_check_get_offset)
	CHECK_SET_INT_HOOK(file_check_inherit)
	CHECK_SET_INT_HOOK(file_check_ioctl)
	CHECK_SET_INT_HOOK(file_check_lock)
	CHECK_SET_INT_HOOK(file_check_mmap)
	CHECK_SET_INT_HOOK(file_check_receive)
	CHECK_SET_INT_HOOK(file_check_set)
	CHECK_SET_INT_HOOK(ifnet_check_label_update)
	CHECK_SET_INT_HOOK(ifnet_check_transmit)
	CHECK_SET_INT_HOOK(ifnet_label_externalize)
	CHECK_SET_INT_HOOK(ifnet_label_internalize)
	CHECK_SET_INT_HOOK(inpcb_check_deliver)
	CHECK_SET_INT_HOOK(inpcb_label_init)
	CHECK_SET_INT_HOOK(iokit_check_device)
	CHECK_SET_INT_HOOK(iokit_check_open)
	CHECK_SET_INT_HOOK(iokit_check_set_properties)
	CHECK_SET_INT_HOOK(iokit_check_hid_control)
	CHECK_SET_INT_HOOK(ipq_label_compare)
	CHECK_SET_INT_HOOK(ipq_label_init)
	CHECK_SET_INT_HOOK(lctx_check_label_update)
	CHECK_SET_INT_HOOK(lctx_label_externalize)
	CHECK_SET_INT_HOOK(lctx_label_internalize)
	CHECK_SET_INT_HOOK(mbuf_label_init)
	CHECK_SET_INT_HOOK(mount_check_fsctl)
	CHECK_SET_INT_HOOK(mount_check_getattr)
	CHECK_SET_INT_HOOK(mount_check_label_update)
	CHECK_SET_INT_HOOK(mount_check_mount)
	CHECK_SET_INT_HOOK(mount_check_remount)
	CHECK_SET_INT_HOOK(mount_check_setattr)
	CHECK_SET_INT_HOOK(mount_check_stat)
	CHECK_SET_INT_HOOK(mount_check_umount)
	CHECK_SET_INT_HOOK(mount_label_externalize)
	CHECK_SET_INT_HOOK(mount_label_internalize)
	CHECK_SET_INT_HOOK(pipe_check_ioctl)
	CHECK_SET_INT_HOOK(pipe_check_kqfilter)
	CHECK_SET_INT_HOOK(pipe_check_label_update)
	CHECK_SET_INT_HOOK(pipe_check_read)
	CHECK_SET_INT_HOOK(pipe_check_select)
	CHECK_SET_INT_HOOK(pipe_check_stat)
	CHECK_SET_INT_HOOK(pipe_check_write)
	CHECK_SET_INT_HOOK(pipe_label_externalize)
	CHECK_SET_INT_HOOK(pipe_label_internalize)
	CHECK_SET_INT_HOOK(policy_syscall)
	CHECK_SET_INT_HOOK(port_check_copy_send)
	CHECK_SET_INT_HOOK(port_check_hold_receive)
	CHECK_SET_INT_HOOK(port_check_hold_send_once)
	CHECK_SET_INT_HOOK(port_check_hold_send)
	CHECK_SET_INT_HOOK(port_check_label_update)
	CHECK_SET_INT_HOOK(port_check_make_send_once)
	CHECK_SET_INT_HOOK(port_check_make_send)
	CHECK_SET_INT_HOOK(port_check_method)
	CHECK_SET_INT_HOOK(port_check_move_receive)
	CHECK_SET_INT_HOOK(port_check_move_send_once)
	CHECK_SET_INT_HOOK(port_check_move_send)
	CHECK_SET_INT_HOOK(port_check_receive)
	CHECK_SET_INT_HOOK(port_check_send)
	CHECK_SET_INT_HOOK(port_check_service)
	CHECK_SET_INT_HOOK(port_label_compute)
	CHECK_SET_INT_HOOK(posixsem_check_create)
	CHECK_SET_INT_HOOK(posixsem_check_open)
	CHECK_SET_INT_HOOK(posixsem_check_post)
	CHECK_SET_INT_HOOK(posixsem_check_unlink)
	CHECK_SET_INT_HOOK(posixsem_check_wait)
	CHECK_SET_INT_HOOK(posixshm_check_create)
	CHECK_SET_INT_HOOK(posixshm_check_mmap)
	CHECK_SET_INT_HOOK(posixshm_check_open)
	CHECK_SET_INT_HOOK(posixshm_check_stat)
	CHECK_SET_INT_HOOK(posixshm_check_truncate)
	CHECK_SET_INT_HOOK(posixshm_check_unlink)
	CHECK_SET_INT_HOOK(priv_check)
	/* relative ordinal location of "priv_grant" */
	CHECK_SET_INT_HOOK(proc_check_debug)
	CHECK_SET_INT_HOOK(proc_check_fork)
	CHECK_SET_INT_HOOK(proc_check_getaudit)
	CHECK_SET_INT_HOOK(proc_check_getauid)
	CHECK_SET_INT_HOOK(proc_check_getlcid)
	CHECK_SET_INT_HOOK(proc_check_ledger)
	CHECK_SET_INT_HOOK(proc_check_map_anon)
	CHECK_SET_INT_HOOK(proc_check_mprotect)
	CHECK_SET_INT_HOOK(proc_check_sched)
	CHECK_SET_INT_HOOK(proc_check_setaudit)
	CHECK_SET_INT_HOOK(proc_check_setauid)
	CHECK_SET_INT_HOOK(proc_check_setlcid)
	CHECK_SET_INT_HOOK(proc_check_signal)
	CHECK_SET_INT_HOOK(proc_check_suspend_resume)
	CHECK_SET_INT_HOOK(proc_check_wait)
	CHECK_SET_INT_HOOK(socket_check_accept)
	CHECK_SET_INT_HOOK(socket_check_accepted)
	CHECK_SET_INT_HOOK(socket_check_bind)
	CHECK_SET_INT_HOOK(socket_check_connect)
	CHECK_SET_INT_HOOK(socket_check_create)
	CHECK_SET_INT_HOOK(socket_check_deliver)
	CHECK_SET_INT_HOOK(socket_check_kqfilter)
	CHECK_SET_INT_HOOK(socket_check_label_update)
	CHECK_SET_INT_HOOK(socket_check_listen)
	CHECK_SET_INT_HOOK(socket_check_receive)
	CHECK_SET_INT_HOOK(socket_check_received)
	CHECK_SET_INT_HOOK(socket_check_select)
	CHECK_SET_INT_HOOK(socket_check_send)
	CHECK_SET_INT_HOOK(socket_check_stat)
	CHECK_SET_INT_HOOK(socket_check_setsockopt)
	CHECK_SET_INT_HOOK(socket_check_getsockopt)
	CHECK_SET_INT_HOOK(socket_label_externalize)
	CHECK_SET_INT_HOOK(socket_label_init)
	CHECK_SET_INT_HOOK(socket_label_internalize)
	CHECK_SET_INT_HOOK(socketpeer_label_externalize)
	CHECK_SET_INT_HOOK(socketpeer_label_init)
	CHECK_SET_INT_HOOK(system_check_acct)
	CHECK_SET_INT_HOOK(system_check_audit)
	CHECK_SET_INT_HOOK(system_check_auditctl)
	CHECK_SET_INT_HOOK(system_check_auditon)
	CHECK_SET_INT_HOOK(system_check_chud)
	CHECK_SET_INT_HOOK(system_check_host_priv)
	CHECK_SET_INT_HOOK(system_check_nfsd)
	CHECK_SET_INT_HOOK(system_check_reboot)
	CHECK_SET_INT_HOOK(system_check_settime)
	CHECK_SET_INT_HOOK(system_check_swapoff)
	CHECK_SET_INT_HOOK(system_check_swapon)
	CHECK_SET_INT_HOOK(system_check_sysctl)
	CHECK_SET_INT_HOOK(system_check_kas_info)
	CHECK_SET_INT_HOOK(sysvmsq_check_enqueue)
	CHECK_SET_INT_HOOK(sysvmsq_check_msgrcv)
	CHECK_SET_INT_HOOK(sysvmsq_check_msgrmid)
	CHECK_SET_INT_HOOK(sysvmsq_check_msqctl)
	CHECK_SET_INT_HOOK(sysvmsq_check_msqget)
	CHECK_SET_INT_HOOK(sysvmsq_check_msqrcv)
	CHECK_SET_INT_HOOK(sysvmsq_check_msqsnd)
	CHECK_SET_INT_HOOK(sysvsem_check_semctl)
	CHECK_SET_INT_HOOK(sysvsem_check_semget)
	CHECK_SET_INT_HOOK(sysvsem_check_semop)
	CHECK_SET_INT_HOOK(sysvshm_check_shmat)
	CHECK_SET_INT_HOOK(sysvshm_check_shmctl)
	CHECK_SET_INT_HOOK(sysvshm_check_shmdt)
	CHECK_SET_INT_HOOK(sysvshm_check_shmget)
	CHECK_SET_INT_HOOK(proc_check_get_task_name)
	CHECK_SET_INT_HOOK(proc_check_get_task)
	CHECK_SET_INT_HOOK(task_label_externalize)
	CHECK_SET_INT_HOOK(task_label_internalize)
	CHECK_SET_INT_HOOK(vnode_check_access)
	CHECK_SET_INT_HOOK(vnode_check_chdir)
	CHECK_SET_INT_HOOK(vnode_check_chroot)
	CHECK_SET_INT_HOOK(vnode_check_create)
	CHECK_SET_INT_HOOK(vnode_check_deleteextattr)
	CHECK_SET_INT_HOOK(vnode_check_exchangedata)
	CHECK_SET_INT_HOOK(vnode_check_exec)
	CHECK_SET_INT_HOOK(vnode_check_fsgetpath)
	CHECK_SET_INT_HOOK(vnode_check_signature)
	CHECK_SET_INT_HOOK(vnode_check_getattrlist)
	CHECK_SET_INT_HOOK(vnode_check_getextattr)
	CHECK_SET_INT_HOOK(vnode_check_ioctl)
	CHECK_SET_INT_HOOK(vnode_check_kqfilter)
	CHECK_SET_INT_HOOK(vnode_check_label_update)
	CHECK_SET_INT_HOOK(vnode_check_link)
	CHECK_SET_INT_HOOK(vnode_check_listextattr)
	CHECK_SET_INT_HOOK(vnode_check_lookup)
	CHECK_SET_INT_HOOK(vnode_check_open)
	CHECK_SET_INT_HOOK(vnode_check_read)
	CHECK_SET_INT_HOOK(vnode_check_readdir)
	CHECK_SET_INT_HOOK(vnode_check_readlink)
	CHECK_SET_INT_HOOK(vnode_check_rename_from)
	CHECK_SET_INT_HOOK(vnode_check_rename_to)
	CHECK_SET_INT_HOOK(vnode_check_revoke)
	CHECK_SET_INT_HOOK(vnode_check_searchfs)
	CHECK_SET_INT_HOOK(vnode_check_select)
	CHECK_SET_INT_HOOK(vnode_check_setattrlist)
	CHECK_SET_INT_HOOK(vnode_check_setextattr)
	CHECK_SET_INT_HOOK(vnode_check_setflags)
	CHECK_SET_INT_HOOK(vnode_check_setmode)
	CHECK_SET_INT_HOOK(vnode_check_setowner)
	CHECK_SET_INT_HOOK(vnode_check_setutimes)
	CHECK_SET_INT_HOOK(vnode_check_stat)
	CHECK_SET_INT_HOOK(vnode_check_truncate)
	CHECK_SET_INT_HOOK(vnode_check_uipc_bind)
	CHECK_SET_INT_HOOK(vnode_check_uipc_connect)
	CHECK_SET_INT_HOOK(vnode_check_unlink)
	CHECK_SET_INT_HOOK(vnode_check_write)
	CHECK_SET_INT_HOOK(vnode_label_associate_extattr)
	CHECK_SET_INT_HOOK(vnode_label_externalize_audit)
	CHECK_SET_INT_HOOK(vnode_label_externalize)
	CHECK_SET_INT_HOOK(vnode_label_internalize)
	CHECK_SET_INT_HOOK(vnode_label_store)
	CHECK_SET_INT_HOOK(vnode_label_update_extattr)
	CHECK_SET_INT_HOOK(vnode_notify_create)

	/* operations which return void */
	CHECK_SET_VOID_HOOK(bpfdesc_label_init)
	CHECK_SET_VOID_HOOK(bpfdesc_label_destroy)
	CHECK_SET_VOID_HOOK(bpfdesc_label_associate)
	CHECK_SET_VOID_HOOK(cred_label_associate_fork)
	CHECK_SET_VOID_HOOK(cred_label_associate_kernel)
	CHECK_SET_VOID_HOOK(cred_label_associate)
	CHECK_SET_VOID_HOOK(cred_label_associate_user)
	CHECK_SET_VOID_HOOK(cred_label_destroy)
	CHECK_SET_VOID_HOOK(cred_label_init)
	CHECK_SET_VOID_HOOK(cred_label_update_execve)
	CHECK_SET_VOID_HOOK(cred_label_update)
	CHECK_SET_VOID_HOOK(devfs_label_associate_device)
	CHECK_SET_VOID_HOOK(devfs_label_associate_directory)
	CHECK_SET_VOID_HOOK(devfs_label_copy)
	CHECK_SET_VOID_HOOK(devfs_label_destroy)
	CHECK_SET_VOID_HOOK(devfs_label_init)
	CHECK_SET_VOID_HOOK(devfs_label_update)
	CHECK_SET_VOID_HOOK(file_check_mmap_downgrade)
	CHECK_SET_VOID_HOOK(file_label_associate)
	CHECK_SET_VOID_HOOK(file_label_destroy)
	CHECK_SET_VOID_HOOK(file_label_init)
	CHECK_SET_VOID_HOOK(ifnet_label_associate)
	CHECK_SET_VOID_HOOK(ifnet_label_copy)
	CHECK_SET_VOID_HOOK(ifnet_label_destroy)
	CHECK_SET_VOID_HOOK(ifnet_label_init)
	CHECK_SET_VOID_HOOK(ifnet_label_recycle)
	CHECK_SET_VOID_HOOK(ifnet_label_update)
	CHECK_SET_VOID_HOOK(inpcb_label_associate)
	CHECK_SET_VOID_HOOK(inpcb_label_destroy)
	CHECK_SET_VOID_HOOK(inpcb_label_recycle)
	CHECK_SET_VOID_HOOK(inpcb_label_update)
	CHECK_SET_VOID_HOOK(ipq_label_associate)
	CHECK_SET_VOID_HOOK(ipq_label_destroy)
	CHECK_SET_VOID_HOOK(ipq_label_update)
	CHECK_SET_VOID_HOOK(lctx_label_destroy)
	CHECK_SET_VOID_HOOK(lctx_label_init)
	CHECK_SET_VOID_HOOK(lctx_label_update)
	CHECK_SET_VOID_HOOK(lctx_notify_create)
	CHECK_SET_VOID_HOOK(lctx_notify_join)
	CHECK_SET_VOID_HOOK(lctx_notify_leave)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_bpfdesc)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_ifnet)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_inpcb)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_ipq)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_linklayer)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_multicast_encap)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_netlayer)
	CHECK_SET_VOID_HOOK(mbuf_label_associate_socket)
	CHECK_SET_VOID_HOOK(mbuf_label_copy)
	CHECK_SET_VOID_HOOK(mbuf_label_destroy)
	CHECK_SET_VOID_HOOK(mount_label_associate)
	CHECK_SET_VOID_HOOK(mount_label_destroy)
	CHECK_SET_VOID_HOOK(mount_label_init)
	CHECK_SET_VOID_HOOK(netinet_fragment)
	CHECK_SET_VOID_HOOK(netinet_icmp_reply)
	CHECK_SET_VOID_HOOK(netinet_tcp_reply)
	CHECK_SET_VOID_HOOK(pipe_label_associate)
	CHECK_SET_VOID_HOOK(pipe_label_copy)
	CHECK_SET_VOID_HOOK(pipe_label_destroy)
	CHECK_SET_VOID_HOOK(pipe_label_init)
	CHECK_SET_VOID_HOOK(pipe_label_update)
	CHECK_SET_VOID_HOOK(policy_destroy)
	/* relative ordinal location of "policy_init" */
	/* relative ordinal location of "policy_initbsd" */
	CHECK_SET_VOID_HOOK(port_label_associate_kernel)
	CHECK_SET_VOID_HOOK(port_label_associate)
	CHECK_SET_VOID_HOOK(port_label_copy)
	CHECK_SET_VOID_HOOK(port_label_destroy)
	CHECK_SET_VOID_HOOK(port_label_init)
	CHECK_SET_VOID_HOOK(port_label_update_cred)
	CHECK_SET_VOID_HOOK(port_label_update_kobject)
	CHECK_SET_VOID_HOOK(posixsem_label_associate)
	CHECK_SET_VOID_HOOK(posixsem_label_destroy)
	CHECK_SET_VOID_HOOK(posixsem_label_init)
	CHECK_SET_VOID_HOOK(posixshm_label_associate)
	CHECK_SET_VOID_HOOK(posixshm_label_destroy)
	CHECK_SET_VOID_HOOK(posixshm_label_init)
	CHECK_SET_VOID_HOOK(proc_label_destroy)
	CHECK_SET_VOID_HOOK(proc_label_init)
	CHECK_SET_VOID_HOOK(socket_label_associate_accept)
	CHECK_SET_VOID_HOOK(socket_label_associate)
	CHECK_SET_VOID_HOOK(socket_label_copy)
	CHECK_SET_VOID_HOOK(socket_label_destroy)
	CHECK_SET_VOID_HOOK(socket_label_update)
	CHECK_SET_VOID_HOOK(socketpeer_label_associate_mbuf)
	CHECK_SET_VOID_HOOK(socketpeer_label_associate_socket)
	CHECK_SET_VOID_HOOK(socketpeer_label_destroy)
	CHECK_SET_VOID_HOOK(sysvmsg_label_associate)
	CHECK_SET_VOID_HOOK(sysvmsg_label_destroy)
	CHECK_SET_VOID_HOOK(sysvmsg_label_init)
	CHECK_SET_VOID_HOOK(sysvmsg_label_recycle)
	CHECK_SET_VOID_HOOK(sysvmsq_label_associate)
	CHECK_SET_VOID_HOOK(sysvmsq_label_destroy)
	CHECK_SET_VOID_HOOK(sysvmsq_label_init)
	CHECK_SET_VOID_HOOK(sysvmsq_label_recycle)
	CHECK_SET_VOID_HOOK(sysvsem_label_associate)
	CHECK_SET_VOID_HOOK(sysvsem_label_destroy)
	CHECK_SET_VOID_HOOK(sysvsem_label_init)
	CHECK_SET_VOID_HOOK(sysvsem_label_recycle)
	CHECK_SET_VOID_HOOK(sysvshm_label_associate)
	CHECK_SET_VOID_HOOK(sysvshm_label_destroy)
	CHECK_SET_VOID_HOOK(sysvshm_label_init)
	CHECK_SET_VOID_HOOK(sysvshm_label_recycle)
	CHECK_SET_VOID_HOOK(task_label_associate_kernel)
	CHECK_SET_VOID_HOOK(task_label_associate)
	CHECK_SET_VOID_HOOK(task_label_copy)
	CHECK_SET_VOID_HOOK(task_label_destroy)
	CHECK_SET_VOID_HOOK(task_label_init)
	CHECK_SET_VOID_HOOK(task_label_update)
	CHECK_SET_VOID_HOOK(vnode_label_associate_devfs)
	CHECK_SET_VOID_HOOK(vnode_label_associate_file)
	CHECK_SET_VOID_HOOK(thread_userret)
	CHECK_SET_VOID_HOOK(vnode_label_associate_posixsem)
	CHECK_SET_VOID_HOOK(vnode_label_associate_posixshm)
	CHECK_SET_VOID_HOOK(vnode_label_associate_singlelabel)
	CHECK_SET_VOID_HOOK(vnode_label_associate_socket)
	CHECK_SET_VOID_HOOK(vnode_label_copy)
	CHECK_SET_VOID_HOOK(vnode_label_destroy)
	CHECK_SET_VOID_HOOK(vnode_label_init)
	CHECK_SET_VOID_HOOK(vnode_label_recycle)
	CHECK_SET_VOID_HOOK(vnode_label_update)
	CHECK_SET_VOID_HOOK(vnode_notify_rename)
	CHECK_SET_VOID_HOOK(thread_label_init)
	CHECK_SET_VOID_HOOK(thread_label_destroy)
	.mpo_reserved18 = common_void_hook,
	CHECK_SET_VOID_HOOK(vnode_notify_open)
	.mpo_reserved20 = common_void_hook,
	.mpo_reserved21 = common_void_hook,
	.mpo_reserved22 = common_void_hook,
	.mpo_reserved23 = common_void_hook,
	.mpo_reserved24 = common_void_hook,
	.mpo_reserved25 = common_void_hook,
	.mpo_reserved26 = common_void_hook,
	.mpo_reserved27 = common_void_hook,
	.mpo_reserved28 = common_void_hook,
	.mpo_reserved29 = common_void_hook,
};

/*
 * Policy definition
 */
static struct mac_policy_conf policy_conf = {
	.mpc_name               = "CHECK",
	.mpc_fullname           = "Check Assumptions Policy",
	.mpc_field_off          = NULL,		/* no label slot */
	.mpc_labelnames         = NULL,		/* no policy label names */
	.mpc_labelname_count    = 0,		/* count of label names is 0 */
	.mpc_ops                = &policy_ops,	/* policy operations */
	.mpc_loadtime_flags     = 0,
	.mpc_runtime_flags      = 0,
};

static mac_policy_handle_t policy_handle;

/*
 * Init routine; for a loadable policy, this would be called during the KEXT
 * initialization; we're going to call this from bsd_init() if the boot
 * argument for checking is present.
 */
errno_t
check_policy_init(int flags)
{
	/* Only instantiate the module if we have been asked to do checking */
	if (!flags)
		return 0;

	policy_flags = flags;

	return mac_policy_register(&policy_conf, &policy_handle, NULL);
}
