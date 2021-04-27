#include <errno.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <darwintest.h>

#include "drop_priv.h"
#include "test_utils.h"

#if ENTITLED
#define SET_TREATMENT_ID set_treatment_id_entitled
#define SET_TREATMENT_ID_DESCR "Can set treatment id with entitlement"
#else /* ENTITLED */
#define SET_TREATMENT_ID set_treatment_id_unentitled
#define SET_TREATMENT_ID_DESCR "Can't set treatment id without entitlement"
#endif /* ENTITLED */

T_DECL(SET_TREATMENT_ID, "Verifies that EXPERIMENT sysctls can only be set with the entitlement", T_META_ASROOT(false))
{
#define TEST_STR "testing"
#define IDENTIFIER_LENGTH 36

	int ret;
	errno_t err;
	char val[IDENTIFIER_LENGTH + 1] = {0};
	size_t len = sizeof(val);
	char new_val[IDENTIFIER_LENGTH + 1] = {0};

	if (!is_development_kernel()) {
		T_SKIP("skipping test on release kernel");
	}

	strlcpy(new_val, TEST_STR, sizeof(new_val));
	drop_priv();

	ret = sysctlbyname("kern.trial_treatment_id", val, &len, new_val, strlen(new_val));
	err = errno;
#if ENTITLED
	len = sizeof(val);
	memset(new_val, 0, sizeof(new_val));
	T_ASSERT_POSIX_SUCCESS(ret, "set kern.trial_treatment_id");
	/* Cleanup. Set it back to the empty string. */
	ret = sysctlbyname("kern.trial_treatment_id", val, &len, new_val, 1);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "reset kern.trial_treatment_id");
#else
	T_ASSERT_POSIX_FAILURE(ret, EPERM, "set kern.trial_treatment_id");
#endif /* ENTITLED */
}

#if ENTITLED
/* Check min and max value limits on numeric factors */
T_DECL(experiment_factor_numeric_limits,
    "Can only set factors within the legal range.",
    T_META_ASROOT(false))
{
#define kMinVal 5 /* The min value allowed for the testing factor. */
#define kMaxVal 10 /* The max value allowed for the testing factor. */
	errno_t err;
	int ret;
	unsigned int current_val;
	size_t len = sizeof(current_val);
	unsigned int new_val;

	drop_priv();
	new_val = kMinVal - 1;
	ret = sysctlbyname("kern.testing_experiment_factor", &current_val, &len, &new_val, sizeof(new_val));
	err = errno;
	T_ASSERT_POSIX_FAILURE(ret, EINVAL, "set kern.testing_experiment_factor below range.");

	new_val = kMaxVal + 1;
	ret = sysctlbyname("kern.testing_experiment_factor", &current_val, &len, &new_val, sizeof(new_val));
	err = errno;
	T_ASSERT_POSIX_FAILURE(ret, EINVAL, "set kern.testing_experiment_factor above range.");

	new_val = kMaxVal;
	ret = sysctlbyname("kern.testing_experiment_factor", &current_val, &len, &new_val, sizeof(new_val));
	T_ASSERT_POSIX_SUCCESS(ret, "set kern.testing_experiment_factor at top of range.");

	new_val = kMinVal;
	ret = sysctlbyname("kern.testing_experiment_factor", &current_val, &len, &new_val, sizeof(new_val));
	T_ASSERT_POSIX_SUCCESS(ret, "set kern.testing_experiment_factor at bottom of range.");
}
#endif /* ENTITLED */
