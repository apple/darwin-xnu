#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <bsm/audit.h>
#include <bsm/audit_session.h>
#include <err.h>
#include <sysexits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(invalid_setaudit_57414044,
    "Verify that auditing a setaudit_addr syscall which has an invalid "
    "at_type field does not panic",
    T_META_CHECK_LEAKS(false))
{
	T_SETUPBEGIN;

	int cond, ret = auditon(A_GETCOND, &cond, sizeof(cond));
	if (ret == -1 && errno == ENOSYS) {
		T_SKIP("no kernel support for auditing; can't test");
	}
	T_ASSERT_POSIX_SUCCESS(ret, "auditon A_GETCOND");
	if (cond != AUC_AUDITING) {
		T_SKIP("auditing is not enabled; can't test");
	}

	/* set up auditing to audit `setaudit_addr` */
	auditpinfo_addr_t pinfo_addr = {.ap_pid = getpid()};
	T_ASSERT_POSIX_SUCCESS(auditon(A_GETPINFO_ADDR, &pinfo_addr, sizeof(pinfo_addr)), NULL);
	auditpinfo_t pinfo = {.ap_pid = getpid(), .ap_mask = pinfo_addr.ap_mask};
	pinfo.ap_mask.am_failure |= 0x800; /* man 5 audit_class */
	T_ASSERT_POSIX_SUCCESS(auditon(A_SETPMASK, &pinfo, sizeof(pinfo)), NULL);

	T_SETUPEND;

	struct auditinfo_addr a;
	memset(&a, 0, sizeof(a));
	a.ai_termid.at_type = 999;
	T_ASSERT_POSIX_FAILURE(setaudit_addr(&a, sizeof(a)), EINVAL,
	    "setaudit_addr should fail due to invalid at_type");
}
