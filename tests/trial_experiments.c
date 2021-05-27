#include <errno.h>
#include <stdlib.h>
#include <libgen.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <xlocale.h>

#include <darwintest.h>
#include <darwintest_utils.h>

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

static uint64_t original_libmalloc_experiment_value = 0;

static void
reset_libmalloc_experiment()
{
	int ret = sysctlbyname("kern.libmalloc_experiments", NULL, NULL, &original_libmalloc_experiment_value, sizeof(original_libmalloc_experiment_value));
	T_ASSERT_POSIX_SUCCESS(ret, "reset kern.libmalloc_experiments");
}

static void
set_libmalloc_experiment(uint64_t val)
{
	T_LOG("Setting kern.libmalloc_experiments to %llu", val);
	size_t len = sizeof(original_libmalloc_experiment_value);
	int ret = sysctlbyname("kern.libmalloc_experiments", &original_libmalloc_experiment_value, &len, &val, sizeof(val));
	T_ASSERT_POSIX_SUCCESS(ret, "set kern.libmalloc_experiments");
	T_ATEND(reset_libmalloc_experiment);
}

#define PRINT_APPLE_ARRAY_TOOL "tools/print_apple_array"
/*
 * Spawns a new binary and returns the contents of its apple array
 * (after libsystem initialization).
 */
static char **
get_apple_array(size_t *num_array_entries)
{
	int ret;
	char stdout_path[MAXPATHLEN] = "apple_array.txt";
	dt_resultfile(stdout_path, MAXPATHLEN);
	int exit_status = 0, signum = 0;
	char binary_path[MAXPATHLEN], binary_dir[MAXPATHLEN];
	char *char_ret;
	const static size_t kMaxNumArguments = 256;
	size_t linecap = 0;
	ssize_t linelen = 0;
	char **apple_array;
	char **line = NULL;
	size_t num_lines = 0;
	FILE *stdout_f = NULL;
	uint32_t name_size = MAXPATHLEN;

	ret = _NSGetExecutablePath(binary_path, &name_size);
	T_QUIET; T_ASSERT_EQ(ret, 0, "_NSGetExecutablePath");
	char_ret = dirname_r(binary_path, binary_dir);
	T_QUIET; T_ASSERT_TRUE(char_ret != NULL, "dirname_r");
	snprintf(binary_path, MAXPATHLEN, "%s/%s", binary_dir, PRINT_APPLE_ARRAY_TOOL);

	char *launch_tool_args[] = {
		binary_path,
		NULL
	};
	pid_t child_pid;
	ret = dt_launch_tool(&child_pid, launch_tool_args, false, stdout_path, NULL);
	T_WITH_ERRNO; T_ASSERT_EQ(ret, 0, "dt_launch_tool: %s", binary_path);

	ret = dt_waitpid(child_pid, &exit_status, &signum, 60 * 5);
	T_ASSERT_EQ(ret, 1, "dt_waitpid");
	T_QUIET; T_ASSERT_EQ(exit_status, 0, "dt_waitpid: exit_status");
	T_QUIET; T_ASSERT_EQ(signum, 0, "dt_waitpid: signum");

	stdout_f = fopen(stdout_path, "r");
	T_WITH_ERRNO; T_ASSERT_NOTNULL(stdout_f, "open(%s)", stdout_path);
	apple_array = calloc(kMaxNumArguments, sizeof(char *));
	T_QUIET; T_ASSERT_NOTNULL(apple_array, "calloc: %lu\n", sizeof(char *) * kMaxNumArguments);
	while (num_lines < kMaxNumArguments) {
		line = &(apple_array[num_lines++]);
		linecap = 0;
		linelen = getline(line, &linecap, stdout_f);
		if (linelen == -1) {
			break;
		}
	}
	*num_array_entries = num_lines - 1;

	ret = fclose(stdout_f);
	T_ASSERT_POSIX_SUCCESS(ret, "fclose(%s)", stdout_path);

	return apple_array;
}

#define LIBMALLOC_EXPERIMENT_FACTORS_KEY "MallocExperiment="

/*
 * Get the value of the MallocExperiment key in the apple array.
 * Returns true iff the key is present.
 */
static bool
get_libmalloc_experiment_factors(char **apple_array, size_t num_array_entries, uint64_t *factors)
{
	bool found = false;
	for (size_t i = 0; i < num_array_entries; i++) {
		char *str = apple_array[i];
		if (strstr(str, LIBMALLOC_EXPERIMENT_FACTORS_KEY)) {
			found = true;
			if (factors != NULL) {
				str = strchr(str, '=');
				T_ASSERT_NOTNULL(str, "skip over =");
				++str;
				*factors = strtoull_l(str, NULL, 16, NULL);
			}
			break;
		}
	}
	return found;
}

T_DECL(libmalloc_experiment,
    "libmalloc experiment flags show up in apple array if we're doing an experiment",
    T_META_ASROOT(false))
{
	uint64_t new_val, apple_array_val = 0;
	size_t num_array_entries = 0;
	char **apple_array;
	bool found = false;

	drop_priv();
	new_val = (1ULL << 63) - 1;
	set_libmalloc_experiment(new_val);

	apple_array = get_apple_array(&num_array_entries);
	found = get_libmalloc_experiment_factors(apple_array, num_array_entries, &apple_array_val);
	T_ASSERT_TRUE(found, "Found " LIBMALLOC_EXPERIMENT_FACTORS_KEY " in apple array");
	T_ASSERT_EQ(apple_array_val, new_val, "Experiment value matches");
	free(apple_array);
}

T_DECL(libmalloc_experiment_not_in_array,
    "libmalloc experiment flags do not show up in apple array if we're not doing an experiment",
    T_META_ASROOT(false))
{
	size_t num_array_entries = 0;
	char **apple_array;
	bool found = false;

	drop_priv();
	set_libmalloc_experiment(0);

	apple_array = get_apple_array(&num_array_entries);
	found = get_libmalloc_experiment_factors(apple_array, num_array_entries, NULL);
	T_ASSERT_TRUE(!found, "Did not find " LIBMALLOC_EXPERIMENT_FACTORS_KEY " in apple array");
	free(apple_array);
}
#endif /* ENTITLED */
