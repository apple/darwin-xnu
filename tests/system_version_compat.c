#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <stdio.h>
#include <TargetConditionals.h>
#include <unistd.h>
#include <xpc/private.h>

#define SYSTEM_VERSION_COMPAT_PLIST_PATH "/System/Library/CoreServices/SystemVersionCompat.plist"
#define IOS_SYSTEM_VERSION_PLIST_PATH "/System/Library/CoreServices/iOSSystemVersion.plist"

#define SYSTEM_VERSION_PLIST_FILENAME "SystemVersion.plist"
#define SYSTEM_VERSION_PLIST_PATH ("/System/Library/CoreServices/" SYSTEM_VERSION_PLIST_FILENAME)

#define PRODUCT_VERSION_KEY "ProductVersion"
#define IOS_SUPPORT_VERSION_KEY "iOSSupportVersion"

#define PRODUCT_VERSION_SYSCTL "kern.osproductversion"
#define PRODUCT_VERSION_COMPAT_SYSCTL "kern.osproductversioncompat"

T_GLOBAL_META(T_META_CHECK_LEAKS(false));

#if TARGET_OS_OSX
static void
check_system_version_compat_plist_exists(void)
{
	struct stat buf;

	int ret = stat(SYSTEM_VERSION_COMPAT_PLIST_PATH, &buf);
	int error = errno;
	if (ret != 0) {
		if (error == ENOENT) {
			T_SKIP("no SystemVersionCompat.plist on this system in %s, skipping test...",
			    SYSTEM_VERSION_COMPAT_PLIST_PATH);
		} else {
			T_ASSERT_FAIL("failed to find SystemVersionCompat.plist at " IOS_SYSTEM_VERSION_PLIST_PATH "with error: %s",
			    strerror(error));
		}
	}
}

static void
check_ios_version_plist_exists(void)
{
	struct stat buf;

	int ret = stat(IOS_SYSTEM_VERSION_PLIST_PATH, &buf);
	int error = errno;
	if (ret != 0) {
		if (errno == ENOENT) {
			T_SKIP("no iOSSystemVersion.plist on this system in %s, skipping test...",
			    IOS_SYSTEM_VERSION_PLIST_PATH);
		} else {
			T_ASSERT_FAIL("failed to find iOSSystemVersion.plist at " IOS_SYSTEM_VERSION_PLIST_PATH "with error: %s",
			    strerror(error));
		}
	}
}

static void
read_plist_version_info(char **version_plist_vers, char **compat_version_plist_vers, bool expect_shim)
{
	char opened_path[MAXPATHLEN] = { '\0' };

	int version_plist_fd = open(SYSTEM_VERSION_PLIST_PATH, O_RDONLY);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(version_plist_fd, 0, "opened %s", SYSTEM_VERSION_PLIST_PATH);

	// Resolve the full path of the file we've opened, verify it was either shimmed or not (as expected)
	int ret = fcntl(version_plist_fd, F_GETPATH, opened_path);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_NE(ret, -1, "F_GETPATH on opened SystemVersion.plist");
	if (ret != -1) {
		size_t opened_path_strlen = strlen(opened_path);
		if (expect_shim) {
			T_QUIET; T_EXPECT_GE(opened_path_strlen, strlen(SYSTEM_VERSION_COMPAT_PLIST_PATH), "opened path string length");
			T_EXPECT_EQ_STR(SYSTEM_VERSION_COMPAT_PLIST_PATH, (const char *)&opened_path[(opened_path_strlen - strlen(SYSTEM_VERSION_COMPAT_PLIST_PATH))],
			    "opened file path shimmed (Mac OS)");
		} else {
			T_QUIET; T_EXPECT_GE(opened_path_strlen, strlen(SYSTEM_VERSION_PLIST_PATH), "opened path string length");
			T_EXPECT_EQ_STR(SYSTEM_VERSION_PLIST_PATH, (const char *)&opened_path[(opened_path_strlen - strlen(SYSTEM_VERSION_PLIST_PATH))],
			    "opened file path not shimmed");
		}
	}

	// Read and parse the plists
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
	xpc_create_from_plist_descriptor(version_plist_fd, queue, ^(xpc_object_t object) {
		if (object == NULL) {
		        T_ASSERT_FAIL("Failed to parse dictionary from %s", SYSTEM_VERSION_PLIST_PATH);
		}
		if (xpc_get_type(object) != XPC_TYPE_DICTIONARY) {
		        T_ASSERT_FAIL("%s does not contain dictionary plist", SYSTEM_VERSION_PLIST_PATH);
		}

		const char *plist_version = xpc_dictionary_get_string(object, PRODUCT_VERSION_KEY);
		if (plist_version) {
		        T_LOG("Found %s for %s from %s", plist_version, PRODUCT_VERSION_KEY, SYSTEM_VERSION_PLIST_PATH);
		        *version_plist_vers = strdup(plist_version);
		}
		dispatch_semaphore_signal(sema);
	});
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

	close(version_plist_fd);
	version_plist_fd = -1;

	int compat_version_plist_fd = open(SYSTEM_VERSION_COMPAT_PLIST_PATH, O_RDONLY);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(compat_version_plist_fd, 0, "opened %s", SYSTEM_VERSION_COMPAT_PLIST_PATH);

	xpc_create_from_plist_descriptor(compat_version_plist_fd, queue, ^(xpc_object_t object) {
		if (object == NULL) {
		        T_ASSERT_FAIL("Failed to parse dictionary from %s", SYSTEM_VERSION_COMPAT_PLIST_PATH);
		}
		if (xpc_get_type(object) != XPC_TYPE_DICTIONARY) {
		        T_ASSERT_FAIL("%s does not contain dictionary plist", SYSTEM_VERSION_COMPAT_PLIST_PATH);
		}

		const char *plist_version = xpc_dictionary_get_string(object, PRODUCT_VERSION_KEY);
		if (plist_version) {
		        T_LOG("Found %s for %s from %s", plist_version, PRODUCT_VERSION_KEY, SYSTEM_VERSION_COMPAT_PLIST_PATH);
		        *compat_version_plist_vers = strdup(plist_version);
		}
		dispatch_semaphore_signal(sema);
	});
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

	close(compat_version_plist_fd);
	compat_version_plist_fd = -1;

	return;
}

static void
read_sysctl_version_info(char **vers, char **compat_vers)
{
	char version[16] = { '\0' }, compat_version[16] = { '\0' };
	size_t version_len = sizeof(version), compat_version_len = sizeof(compat_version);

	T_QUIET; T_ASSERT_POSIX_ZERO(sysctlbyname(PRODUCT_VERSION_SYSCTL, version, &version_len, NULL, 0), "read %s", PRODUCT_VERSION_SYSCTL);
	T_LOG("Foundd %s from %s", version, PRODUCT_VERSION_SYSCTL);

	T_QUIET; T_ASSERT_POSIX_ZERO(sysctlbyname(PRODUCT_VERSION_COMPAT_SYSCTL, compat_version, &compat_version_len, NULL, 0),
	    "read %s", PRODUCT_VERSION_COMPAT_SYSCTL);
	T_LOG("Found %s from %s", compat_version, PRODUCT_VERSION_COMPAT_SYSCTL);

	*vers = strdup(version);
	*compat_vers = strdup(compat_version);

	return;
}
#endif // TARGET_OS_OSX

T_DECL(test_system_version_compat_disabled,
    "Tests reading system product information without system version compat enabled")
{
#if TARGET_OS_OSX
	check_system_version_compat_plist_exists();
	char *plist_vers = NULL, *plist_compat_vers = NULL;
	char *sysctl_vers = NULL, *sysctl_compat_vers = NULL;

	// Read plist version data
	read_plist_version_info(&plist_vers, &plist_compat_vers, false);

	// Read sysctl version data
	read_sysctl_version_info(&sysctl_vers, &sysctl_compat_vers);

	// Verify the normal data matches
	T_EXPECT_EQ_STR(plist_vers, sysctl_vers, "%s %s matches %s value", SYSTEM_VERSION_PLIST_PATH,
	    PRODUCT_VERSION_KEY, PRODUCT_VERSION_SYSCTL);

	// Verify that the compatibility data matches
	T_EXPECT_EQ_STR(plist_compat_vers, sysctl_compat_vers, "%s %s matches %s value", SYSTEM_VERSION_COMPAT_PLIST_PATH,
	    PRODUCT_VERSION_KEY, PRODUCT_VERSION_COMPAT_SYSCTL);


	free(plist_vers);
	free(plist_compat_vers);
	free(sysctl_vers);
	free(sysctl_compat_vers);

	T_PASS("verified version information without system version compat");
#else // TARGET_OS_OSX
	T_SKIP("system version compat only supported on macOS");
#endif // TARGET_OS_OSX
}

T_DECL(test_system_version_compat_enabled,
    "Tests reading system product information with system version compat enabled",
    T_META_ENVVAR("SYSTEM_VERSION_COMPAT=1"))
{
#if TARGET_OS_OSX
	check_system_version_compat_plist_exists();
	char *plist_vers = NULL, *plist_compat_vers = NULL;
	char *sysctl_vers = NULL, *sysctl_compat_vers = NULL;

	// Read plist version data
	read_plist_version_info(&plist_vers, &plist_compat_vers, true);

	// Read sysctl version data
	read_sysctl_version_info(&sysctl_vers, &sysctl_compat_vers);

	// The version information should match from all sources with the shim enabled

	// Verify the normal data matches
	T_EXPECT_EQ_STR(plist_vers, sysctl_vers, "%s %s matches %s value", SYSTEM_VERSION_PLIST_PATH,
	    PRODUCT_VERSION_KEY, PRODUCT_VERSION_SYSCTL);

	// Verify that the compatibility data matches
	T_EXPECT_EQ_STR(plist_compat_vers, sysctl_compat_vers, "%s %s matches %s value", SYSTEM_VERSION_COMPAT_PLIST_PATH,
	    PRODUCT_VERSION_KEY, PRODUCT_VERSION_COMPAT_SYSCTL);

	// Verify the normal data matches the compatibility data
	T_EXPECT_EQ_STR(plist_vers, plist_compat_vers, "%s matches in both %s and %s", PRODUCT_VERSION_KEY,
	    SYSTEM_VERSION_PLIST_PATH, SYSTEM_VERSION_COMPAT_PLIST_PATH);

	free(plist_vers);
	free(plist_compat_vers);
	free(sysctl_vers);
	free(sysctl_compat_vers);

	T_PASS("verified version information with Mac OS X shim enabled");
#else // TARGET_OS_OSX
	T_SKIP("system version compat only supported on macOS");
#endif // TARGET_OS_OSX
}

T_DECL(test_system_version_compat_enabled_ios,
    "Tests reading system product information with the iOS system version compat shim enabled",
    T_META_ENVVAR("SYSTEM_VERSION_COMPAT=2"))
{
#if TARGET_OS_OSX
	char opened_path[MAXPATHLEN] = { '\0' };

	check_ios_version_plist_exists();

	// Read out the ProductVersion from SystemVersion.plist and ensure that it contains the same value as the
	// iOSSupportVersion key

	__block char *read_plist_vers = NULL, *read_ios_support_version = NULL;

	int version_plist_fd = open(SYSTEM_VERSION_PLIST_PATH, O_RDONLY);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_GT(version_plist_fd, 0, "opened %s", SYSTEM_VERSION_PLIST_PATH);

	// Resolve the full path of the file we've opened, verify it was shimmed as expected
	int ret = fcntl(version_plist_fd, F_GETPATH, opened_path);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_NE(ret, -1, "F_GETPATH on opened SystemVersion.plist");
	if (ret != -1) {
		size_t opened_path_strlen = strlen(opened_path);
		T_QUIET; T_EXPECT_GE(opened_path_strlen, strlen(IOS_SYSTEM_VERSION_PLIST_PATH), "opened path string length");
		T_EXPECT_EQ_STR(IOS_SYSTEM_VERSION_PLIST_PATH, (const char *)&opened_path[(opened_path_strlen - strlen(IOS_SYSTEM_VERSION_PLIST_PATH))],
		    "opened file path shimmed (iOS)");
	}

	// Read and parse the attributes from the SystemVersion plist
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
	xpc_create_from_plist_descriptor(version_plist_fd, queue, ^(xpc_object_t object) {
		if (object == NULL) {
		        T_ASSERT_FAIL("Failed to parse dictionary from %s", SYSTEM_VERSION_PLIST_PATH);
		}
		if (xpc_get_type(object) != XPC_TYPE_DICTIONARY) {
		        T_ASSERT_FAIL("%s does not contain dictionary plist", SYSTEM_VERSION_PLIST_PATH);
		}

		const char *plist_version = xpc_dictionary_get_string(object, PRODUCT_VERSION_KEY);
		if (plist_version) {
		        T_LOG("Found %s for %s from %s", plist_version, PRODUCT_VERSION_KEY, SYSTEM_VERSION_PLIST_PATH);
		        read_plist_vers = strdup(plist_version);
		}

		const char *ios_support_version = xpc_dictionary_get_string(object, IOS_SUPPORT_VERSION_KEY);
		if (ios_support_version) {
		        T_LOG("Found %s for %s from %s", ios_support_version, IOS_SUPPORT_VERSION_KEY, SYSTEM_VERSION_PLIST_PATH);
		        read_ios_support_version = strdup(ios_support_version);
		}

		dispatch_semaphore_signal(sema);
	});
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

	close(version_plist_fd);
	version_plist_fd = -1;

	// Verify the data matches
	T_EXPECT_EQ_STR(read_plist_vers, read_ios_support_version, "%s %s matches %s value", SYSTEM_VERSION_PLIST_PATH,
	    PRODUCT_VERSION_KEY, IOS_SUPPORT_VERSION_KEY);

	T_PASS("verified version information with iOS shim enabled");

#else // TARGET_OS_OSX
	T_SKIP("iOS system version shim only supported on macOS");
#endif // TARGET_OS_OSX
}
