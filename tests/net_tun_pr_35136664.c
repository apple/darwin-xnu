#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <net/if_utun.h>
#include <net/if_ipsec.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.net"),
    T_META_RUN_CONCURRENTLY(true));

T_DECL(PR_35136664_utun,
    "This bind a utun and close it without connecting")
{
	int tunsock;
	struct ctl_info kernctl_info;
	struct sockaddr_ctl kernctl_addr;

	T_ASSERT_POSIX_SUCCESS(tunsock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	memset(&kernctl_info, 0, sizeof(kernctl_info));
	strlcpy(kernctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(kernctl_info.ctl_name));
	T_ASSERT_POSIX_ZERO(ioctl(tunsock, CTLIOCGINFO, &kernctl_info), NULL);

	memset(&kernctl_addr, 0, sizeof(kernctl_addr));
	kernctl_addr.sc_len = sizeof(kernctl_addr);
	kernctl_addr.sc_family = AF_SYSTEM;
	kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
	kernctl_addr.sc_id = kernctl_info.ctl_id;
	kernctl_addr.sc_unit = 0;

	T_ASSERT_POSIX_ZERO(bind(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	T_ASSERT_POSIX_ZERO(close(tunsock), NULL);
}

T_DECL(PR_35136664_ipsec,
    "This bind a ipsec and close it without connecting")
{
	int tunsock;
	struct ctl_info kernctl_info;
	struct sockaddr_ctl kernctl_addr;

	T_ASSERT_POSIX_SUCCESS(tunsock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	memset(&kernctl_info, 0, sizeof(kernctl_info));
	strlcpy(kernctl_info.ctl_name, IPSEC_CONTROL_NAME, sizeof(kernctl_info.ctl_name));
	T_ASSERT_POSIX_ZERO(ioctl(tunsock, CTLIOCGINFO, &kernctl_info), NULL);

	memset(&kernctl_addr, 0, sizeof(kernctl_addr));
	kernctl_addr.sc_len = sizeof(kernctl_addr);
	kernctl_addr.sc_family = AF_SYSTEM;
	kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
	kernctl_addr.sc_id = kernctl_info.ctl_id;
	kernctl_addr.sc_unit = 0;

	T_ASSERT_POSIX_ZERO(bind(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	T_ASSERT_POSIX_ZERO(close(tunsock), NULL);
}
