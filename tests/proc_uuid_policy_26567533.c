#include <darwintest.h>
#include <uuid/uuid.h>
#include <System/sys/proc_uuid_policy.h>
#include <stdint.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define NUM_PROC_UUID_POLICY_FLAGS 4

T_DECL(proc_uuid_policy_26567533, "Tests passing a NULL uuid in (uap->uuid).", T_META_LTEPHASE(LTE_POSTINIT))
{
	int i, ret;
	uuid_t null_uuid;
	memset(null_uuid, 0, sizeof(uuid_t));

	uint32_t policy_flags[] = {
		PROC_UUID_POLICY_FLAGS_NONE,
		PROC_UUID_NO_CELLULAR,
		PROC_UUID_NECP_APP_POLICY,
		PROC_UUID_ALT_DYLD_POLICY
	};

	for (i = 0; i < NUM_PROC_UUID_POLICY_FLAGS; i++) {
		T_LOG("Testing policy add with flag value 0x%x", policy_flags[i]);

		/* Since UUID is null, this call should fail with errno = EINVAL. */
		ret = proc_uuid_policy(PROC_UUID_POLICY_OPERATION_ADD, null_uuid, sizeof(uuid_t), policy_flags[i]);

		T_ASSERT_TRUE(ret == -1, "proc_uuid_policy returned %d", ret);
		T_WITH_ERRNO;
		T_ASSERT_TRUE(errno = EINVAL, "errno is %d", errno);
	}

	for (i = 0; i < NUM_PROC_UUID_POLICY_FLAGS; i++) {
		T_LOG("Testing policy remove with flag value 0x%x", policy_flags[i]);

		/* Since UUID is null, this call should fail with errno = EINVAL. */
		ret = proc_uuid_policy(PROC_UUID_POLICY_OPERATION_REMOVE, null_uuid, sizeof(uuid_t), policy_flags[i]);

		T_ASSERT_TRUE(ret == -1, "proc_uuid_policy returned %d", ret);
		T_WITH_ERRNO;
		T_ASSERT_TRUE(errno = EINVAL, "errno is %d", errno);
	}
}
