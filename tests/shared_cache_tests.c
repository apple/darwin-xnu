#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_priv.h>
#include <TargetConditionals.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.shared_cache"));

// Give the test up to two minutes because in the failure case we want to invoke update_dyld_shared_cache, which
// might take a bit to do.
T_DECL(present, "tests that the device is running with a shared cache", T_META_ASROOT(true), T_META_TIMEOUT(120))
{
	size_t shared_cache_len = 0;
	const void *cache_header = _dyld_get_shared_cache_range(&shared_cache_len);

#if TARGET_OS_OSX
	T_SKIP("shared cache testing support incomplete (57267667)");
#endif /* TARGET_OS_OSX */

	if ((cache_header == NULL) || (shared_cache_len == 0)) {
#if TARGET_OS_OSX
		char *tmp_dir = (char *) dt_tmpdir();
		T_QUIET; T_ASSERT_NOTNULL(tmp_dir, "darwintest created tmp dir");
		// Try to invoke update_dyld_shared_cache to gather information on why we're not running with a shared cache
		char *shared_cache_update_cmd[] = { "/usr/bin/update_dyld_shared_cache", "-debug", "-cache_dir", tmp_dir, NULL };
		pid_t child1 = dt_launch_tool_pipe(shared_cache_update_cmd, false, NULL, ^bool (char *data, __unused size_t data_size, __unused dt_pipe_data_handler_context_t *context) {
			T_LOG("%s", data);
			return false;
		}, ^bool (__unused char *data, __unused size_t data_size, __unused dt_pipe_data_handler_context_t *context) {
			T_LOG("%s", data);
			return false;
		}, BUFFER_PATTERN_LINE, NULL);

		int status = 0;
		dt_waitpid(child1, &status, NULL, 0);

		T_LOG("waitpid for %d returned with status %d", child1, WEXITSTATUS(status));
#endif // TARGET_OS_OSX
		T_ASSERT_NOTNULL(cache_header, "shared cache present");
		T_ASSERT_GT((int) shared_cache_len, 0, "shared cache has non-zero length");
	}

	T_PASS("shared cache appears to be present and valid");
}
