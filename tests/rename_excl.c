#include <darwintest.h>
#include <darwintest_utils.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs"),
	T_META_CHECK_LEAKS(false)
	);

#define TEST_DIR         "rename_dir"
#define TEST_FILE1       TEST_DIR "/file1"
#define TEST_FILE1_UC    TEST_DIR "/FILE1"
#define TEST_FILE2       TEST_DIR "/file2"
#define TEST_FILE3_HL    TEST_DIR "/file3"

static void
cleanup(void)
{
	(void) remove(TEST_FILE1);
	(void) remove(TEST_FILE1_UC);
	(void) remove(TEST_FILE2);
	(void) remove(TEST_FILE3_HL);
	(void) rmdir(TEST_DIR);
}

/*
 * This unit-test validates the behavior of renamex_np() with RENAME_EXCL flag.
 * On either a case-insensitve/case-sensitive volume:
 * 1. rename from source to existing target should succeed when the change is
 *    only case-variant (for e.g rename_dir/file1 -> rename_dir/FILE1)
 * 2. rename from source to existing target should fail with EEXIST
 * 3. rename from source to existing target which is a hardlink of the source
 *    should fail with EEXIST
 *
 * On case-insensitive volume:
 * 1. rename from source to itself should succeed
 *    (rename_dir/file1 -> rename_dir/file1)
 *
 * On case-sensitive volume:
 * 1. rename from source to itself should fail with EEXIST
 *    (rename_dir/file1 -> rename_dir/file1)
 */

T_DECL(rename_excl_with_case_variant,
    "test renamex_np() with RENAME_EXCL flag for files with case variants")
{
	const char *tmpdir = dt_tmpdir();
	long case_sensitive_vol;
	int err, saved_errno;
	int fd;

	T_SETUPBEGIN;

	atexit(cleanup);

	T_ASSERT_POSIX_ZERO(chdir(tmpdir),
	    "Setup: changing to tmpdir: %s", tmpdir);

	T_ASSERT_POSIX_SUCCESS(mkdir(TEST_DIR, 0777),
	    "Setup: creating test dir: %s", TEST_DIR);

	T_WITH_ERRNO;
	fd = open(TEST_FILE1, O_CREAT | O_RDWR, 0666);
	T_ASSERT_TRUE(fd != -1, "Creating test file1: %s", TEST_FILE1);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing test file1: %s",
	    TEST_FILE1);

	T_WITH_ERRNO;
	fd = open(TEST_FILE2, O_CREAT | O_RDWR, 0666);
	T_ASSERT_TRUE(fd != -1, "Creating test file2: %s", TEST_FILE2);

	T_ASSERT_POSIX_SUCCESS(close(fd), "Closing test file2: %s",
	    TEST_FILE2);

	T_ASSERT_POSIX_SUCCESS(link(TEST_FILE1, TEST_FILE3_HL),
	    "Creating hardlink for %s from source: %s",
	    TEST_FILE3_HL, TEST_FILE1);

	case_sensitive_vol = pathconf(TEST_DIR, _PC_CASE_SENSITIVE);
	T_ASSERT_TRUE(case_sensitive_vol != -1,
	    "Checking if target volume is case-sensitive, is_case_sensitive: %ld",
	    case_sensitive_vol);

	T_SETUPEND;

	err = renamex_np(TEST_FILE1, TEST_FILE2, RENAME_EXCL);
	saved_errno = errno;
	T_ASSERT_TRUE((err == -1 && saved_errno == EEXIST),
	    "Renaming with RENAME_EXCL from source: %s to target: %s",
	    TEST_FILE1, TEST_FILE2);

	err = renamex_np(TEST_FILE1, TEST_FILE3_HL, RENAME_EXCL);
	saved_errno = errno;
	T_ASSERT_TRUE((err == -1 && saved_errno == EEXIST),
	    "Renaming with RENAME_EXCL from source: %s to hardlink target: %s",
	    TEST_FILE1, TEST_FILE3_HL);

	if (case_sensitive_vol) {
		err = renamex_np(TEST_FILE1, TEST_FILE1, RENAME_EXCL);
		saved_errno = errno;
		T_ASSERT_TRUE((err == -1 && saved_errno == EEXIST),
		    "Renaming with RENAME_EXCL from source: %s to target: %s",
		    TEST_FILE1, TEST_FILE1);
	} else {
		T_ASSERT_POSIX_SUCCESS(renamex_np(TEST_FILE1, TEST_FILE1, RENAME_EXCL),
		    "Renaming with RENAME_EXCL from source: %s to target: %s",
		    TEST_FILE1, TEST_FILE1);
	}

	T_ASSERT_POSIX_SUCCESS(renamex_np(TEST_FILE1, TEST_FILE1_UC, RENAME_EXCL),
	    "Renaming with RENAME_EXCL from source: %s to target: %s",
	    TEST_FILE1, TEST_FILE1_UC);
}
