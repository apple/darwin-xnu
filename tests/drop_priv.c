#include <darwintest.h>

#include <TargetConditionals.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>

#if !TARGET_OS_OSX
#include <pwd.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#endif

#if TARGET_OS_OSX
#define INVOKER_UID "SUDO_UID"
#define INVOKER_GID "SUDO_GID"
#define ID_MAX (unsigned long)UINT_MAX
static unsigned
_get_sudo_invoker(const char *var)
{
	char *value_str = getenv(var);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(value_str,
	    "Not running under sudo, getenv(\"%s\") failed", var);
	T_QUIET; T_ASSERT_NE_CHAR(*value_str, '\0',
	    "getenv(\"%s\") returned an empty string", var);

	char *endp;
	unsigned long value = strtoul(value_str, &endp, 10);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_EQ_CHAR(*endp, '\0',
	    "strtoul(\"%s\") not called on a valid number", value_str);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NE_ULONG(value, ULONG_MAX,
	    "strtoul(\"%s\") overflow", value_str);

	T_QUIET; T_ASSERT_NE_ULONG(value, 0ul, "%s invalid", var);
	T_QUIET; T_ASSERT_LT_ULONG(value, ID_MAX, "%s invalid", var);
	return (unsigned)value;
}
#endif /* TARGET_OS_OSX */

void
drop_priv(void);
void
drop_priv(void)
{
#if TARGET_OS_OSX
	uid_t lower_uid = _get_sudo_invoker(INVOKER_UID);
	gid_t lower_gid = _get_sudo_invoker(INVOKER_GID);
#else
	struct passwd *pw = getpwnam("mobile");
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(pw, "getpwnam(\"mobile\")");
	uid_t lower_uid = pw->pw_uid;
	gid_t lower_gid = pw->pw_gid;
#endif
	T_ASSERT_POSIX_SUCCESS(setgid(lower_gid), "Change group to %u", lower_gid);
	T_ASSERT_POSIX_SUCCESS(setuid(lower_uid), "Change user to %u", lower_uid);
}
