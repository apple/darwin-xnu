/*
 * cd $XNU/tests
 * xcrun -sdk macosx.internal/iphoneos.internal make proc_rlimit LDFLAGS="-ldarwintest"
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <darwintest.h>

/* Defined in <sys/resource.h> but not visible to user space */
#define RLIMIT_NLIMITS 9

/* Defined in <sys/resource.h> and visible to user space */
static const char *RESOURCE_STRING[] = {
	"RLIMIT_CPU",     /* #define RLIMIT_CPU      0 */
	"RLIMIT_FSIZE",   /* #define RLIMIT_FSIZE    1 */
	"RLIMIT_DATA",    /* #define RLIMIT_DATA     2 */
	"RLIMIT_STACK",   /* #define RLIMIT_STACK    3 */
	"RLIMIT_CORE",    /* #define RLIMIT_CORE     4 */
	"RLIMIT_AS/RSS",  /* #define RLIMIT_AS       5 */
	/* #define RLIMIT_RSS      RLIMIT_AS */
	"RLIMIT_MEMLOCK", /* #define RLIMIT_MEMLOCK  6 */
	"RLIMIT_NPROC",   /* #define RLIMIT_NPROC    7 */
	"RLIMIT_NOFILE"   /* #define RLIMIT_NOFILE   8 */
};

/* Change limit values by this arbitrary amount */
#define LIMIT_DIFF 64

/* Limit type */
#define SOFT_LIMIT 0
#define HARD_LIMIT 1

/* Action on changing limit values */
#define LOWER 0
#define RAISE 1

static struct rlimit orig_rlimit[RLIMIT_NLIMITS];

/* Maximum number of open files allowed by normal user */
static rlim_t maxfilesperproc;
static size_t maxfilesperproc_size = sizeof(maxfilesperproc);

/* Maximum number of open files allowed by super user */
static rlim_t maxfiles;
static size_t maxfiles_size = sizeof(maxfiles);

/* Maximum number of simultaneous processes allowed by normal user */
static rlim_t maxprocperuid;
static size_t maxprocperuid_size = sizeof(maxprocperuid);

/* Maximum number of simultaneous processes allowed by super user */
static rlim_t maxproc;
static size_t maxproc_size = sizeof(maxproc);

static bool superuser = FALSE;

static int
get_initial_rlimits(void)
{
	int err = -1;
	int i;

	for (i = 0; i < RLIMIT_NLIMITS; i++) {
		err = getrlimit(i, &orig_rlimit[i]);
		T_QUIET; T_EXPECT_EQ(0, err, "getrlimit(%15s, soft: 0x%16llx, hard 0x%16llx) %s", RESOURCE_STRING[i], orig_rlimit[i].rlim_cur, orig_rlimit[i].rlim_max, err == 0 ? "" : strerror(errno));
	}
	return err;
}

static void
print_rlimits(bool initial_limits)
{
	int err;
	int i;

	for (i = 0; i < RLIMIT_NLIMITS; i++) {
		struct rlimit lim;

		if (initial_limits) {
			lim = orig_rlimit[i];
		} else {
			err = getrlimit(i, &lim);
			T_QUIET; T_EXPECT_EQ(0, err, "getrlimit(%15s, soft: 0x%16llx, hard 0x%16llx) %s", RESOURCE_STRING[i], lim.rlim_cur, lim.rlim_max, err == 0 ? "" : strerror(errno));
		}
		T_LOG("%35s soft: 0x%16llx hard 0x%16llx", RESOURCE_STRING[i], lim.rlim_cur, lim.rlim_max);
	}
}

/*
 * Change "limit_type" of all of the process's "rlimit" by amount
 *
 * limit_type: SOFT_LIMIT/HARD_LIMIT
 * amount:     rlim_t
 * action:     RAISE/LOWER
 */
static void
change_rlimits(int limit_type, rlim_t amount, int action)
{
	int err = -1;
	int i;

	for (i = 0; i < RLIMIT_NLIMITS; i++) {
		struct rlimit newlim;     // for setrlimit
		struct rlimit verifylim;  // for getrlimit
		bool expect_failure = FALSE;
		int expect_errno = 0;

		/* Get the current limit values */
		err = getrlimit(i, &newlim);
		T_EXPECT_EQ(0, err, "getrlimit(%15s, soft: 0x%16llx, hard 0x%16llx) %s", RESOURCE_STRING[i], newlim.rlim_cur, newlim.rlim_max, err == 0 ? "" : strerror(errno));

		/* Changing soft limit */
		if (limit_type == SOFT_LIMIT) {
			if (action == RAISE) {
				/* Raising soft limits to exceed hard limits is not allowed and we expect to see failure on setrlimit call later */
				if (newlim.rlim_cur + amount > newlim.rlim_max) {
					expect_failure = TRUE;
					expect_errno = EINVAL;
				}
				newlim.rlim_cur += amount;
			} else if (action == LOWER) {
				if (newlim.rlim_cur == 0) {
					/* Soft limit might be 0 already, if so skip lowering it */
				} else {
					newlim.rlim_cur -= amount;
				}
			} else {
				T_FAIL("Unknown action on soft limit: %d", action);
			}
		}
		/* Changing hard limit */
		else if (limit_type == HARD_LIMIT) {
			if (action == RAISE) {
				newlim.rlim_max += amount;

				/* Raising hard limits is not allowed for normal user and we expect to see failure on setrlimit call later */
				expect_failure = TRUE;
				expect_errno = EPERM;
			} else if (action == LOWER) {
				if (newlim.rlim_max == 0) {
					/* Hard limit might be 0 already, if so skip lowering it (e.g., RLIMIT_CORE on iOS) */
				} else {
					newlim.rlim_max -= amount;
				}
				/* Soft limit might need to be changed as well since soft cannot be greater than hard  */
				if (newlim.rlim_cur > newlim.rlim_max) {
					newlim.rlim_cur = newlim.rlim_max;
				}
			} else {
				T_FAIL("Unknown action on hard limit: %d", action);
			}
		}
		/* Changing unknown limit type */
		else {
			T_FAIL("Unknown limit type: %d", limit_type);
		}

		/* Request the kernel to change limit values */
		err = setrlimit(i, &newlim);

		if (expect_failure) {
			/* We expect the setrlimit call to fail */
			T_EXPECT_EQ(-1, err, "setrlimit(%15s, soft: 0x%16llx, hard 0x%16llx) failed as expected: %s", RESOURCE_STRING[i], newlim.rlim_cur, newlim.rlim_max, strerror(errno));
			T_EXPECT_EQ(expect_errno, errno, "Expect errno %d, errno returned %d", expect_errno, errno);
			continue;
		} else {
			T_EXPECT_EQ(0, err, "setrlimit(%15s, soft: 0x%16llx, hard 0x%16llx) %s", RESOURCE_STRING[i], newlim.rlim_cur, newlim.rlim_max, err == 0 ? "" : strerror(errno));
		}

		/* Verify the kernel correctly changed the limit values */
		err = getrlimit(i, &verifylim);
		T_EXPECT_EQ(0, err, "getrlimit(%15s, soft: 0x%16llx, hard 0x%16llx) %s", RESOURCE_STRING[i], verifylim.rlim_cur, verifylim.rlim_max, err == 0 ? "" : strerror(errno));

		/* The kernel forces the hard limit of RLIMIT_NOFILE to be at most maxfileperproc for normal user when changing the hard limit with setrlimit */
		if (i == RLIMIT_NOFILE && limit_type == HARD_LIMIT && newlim.rlim_max > maxfilesperproc) {
			if (newlim.rlim_cur != verifylim.rlim_cur ||
			    maxfilesperproc != verifylim.rlim_max) {
				T_FAIL("Mismatch limit values %s despite a successful setrlimit call (setrlimit'd soft 0x%16llx hard 0x%16llx but getrlimit'd soft 0x%16llx hard 0x%16llx)",
				    RESOURCE_STRING[i], newlim.rlim_cur, newlim.rlim_max, verifylim.rlim_cur, verifylim.rlim_max);
			}
		}
		/* The kernel forces the hard limit of RLIMIT_NPROC to be at most maxproc for normal user when changing either soft/hard limit with setrlimit */
		else if (i == RLIMIT_NPROC && newlim.rlim_max > maxprocperuid) {
			if (newlim.rlim_cur != verifylim.rlim_cur ||
			    maxprocperuid != verifylim.rlim_max) {
				T_FAIL("Mismatch limit values %s despite a successful setrlimit call (setrlimit'd soft 0x%16llx hard 0x%16llx but getrlimit'd soft 0x%16llx hard 0x%16llx)",
				    RESOURCE_STRING[i], newlim.rlim_cur, newlim.rlim_max, verifylim.rlim_cur, verifylim.rlim_max);
			}
		} else {
			if (newlim.rlim_cur != verifylim.rlim_cur ||
			    newlim.rlim_max != verifylim.rlim_max) {
				T_FAIL("Mismatch limit values %s despite a successful setrlimit call (setrlimit'd soft 0x%16llx hard 0x%16llx but getrlimit'd soft 0x%16llx hard 0x%16llx)",
				    RESOURCE_STRING[i], newlim.rlim_cur, newlim.rlim_max, verifylim.rlim_cur, verifylim.rlim_max);
			}
		}
	}
}

T_DECL(proc_rlimit,
    "Test basic functionalities of the getrlimit and setrlimit")
{
	int err;
	struct rlimit lim;

	T_SETUPBEGIN;

	if (geteuid() == 0) {
		superuser = TRUE;
		T_SKIP("This test should not be run as super user.");
	}

	/* Use sysctl to query the real limits of RLIMIT_NOFILE/RLIMIT_NPROC for normal user on Apple's systems */
	err = sysctlbyname("kern.maxfilesperproc", &maxfilesperproc, &maxfilesperproc_size, NULL, 0);
	T_EXPECT_EQ_INT(0, err, "maxfilesperproc: %llu", maxfilesperproc);

	err = sysctlbyname("kern.maxprocperuid", &maxprocperuid, &maxprocperuid_size, NULL, 0);
	T_EXPECT_EQ_INT(0, err, "maxprocperuid: %llu", maxprocperuid);

	/* Use sysctl to query the real limits of RLIMIT_NOFILE/RLIMIT_NPROC for super user on Apple's systems (placeholder for adding super user tests) */
	err = sysctlbyname("kern.maxfiles", &maxfiles, &maxfiles_size, NULL, 0);
	T_EXPECT_EQ_INT(0, err, "maxfiles: %llu", maxfiles);

	err = sysctlbyname("kern.maxproc", &maxproc, &maxproc_size, NULL, 0);
	T_EXPECT_EQ_INT(0, err, "maxproc: %llu", maxproc);

	/* Issue getrlimit syscall to retrieve the initial resource limit values before calling setrlimit */
	err = get_initial_rlimits();
	T_EXPECT_EQ(0, err, "Obtained initial resource values.");

	/* Print out resource limit values to stdout for less-painful triage in case needed */
	T_LOG("Resource limits before the test:");
	print_rlimits(TRUE);

	T_SETUPEND;

	/* Lower soft limits by arbitrary amount */
	T_LOG("---------Lowering soft limits by 0x%x---------:\n", LIMIT_DIFF);
	change_rlimits(SOFT_LIMIT, LIMIT_DIFF, LOWER);

	/* Raise soft limits back to the orginal values */
	T_LOG("---------Raising soft limits by 0x%x---------:\n", LIMIT_DIFF);
	change_rlimits(SOFT_LIMIT, LIMIT_DIFF, RAISE);

	/* Lower hard limits */
	T_LOG("---------Lowering hard limits by 0x%x---------:", LIMIT_DIFF);
	change_rlimits(HARD_LIMIT, LIMIT_DIFF, LOWER);

	/* Raise soft limits to exceed hard limits (setrlimit should fail, but the darwintest should pass) */
	T_LOG("---------Attempting to raised soft limits by 0x%x to exceed hard limits---------:", LIMIT_DIFF);
	change_rlimits(SOFT_LIMIT, LIMIT_DIFF, RAISE);

	/* Raise hard limits (setrlimit should fail, but the darwintest should pass) */
	T_LOG("---------Attempting to raise hard limits by 0x%x---------:", LIMIT_DIFF);
	change_rlimits(HARD_LIMIT, LIMIT_DIFF, RAISE);

	/* Get and set a non-existing resource limit */
	T_LOG("---------Accessing a non-existing resource---------:");
	err = getrlimit(RLIMIT_NLIMITS + 1, &lim);
	T_EXPECT_EQ(-1, err, "Expect getrlimit to fail when accessing a non-existing resource: %s\n", strerror(errno));
	T_EXPECT_EQ(EINVAL, errno, "Expect errno %d, errno returned %d", EINVAL, errno);

	err = setrlimit(RLIMIT_NLIMITS + 1, &lim);
	T_EXPECT_EQ(-1, err, "Expect setrlimit to fail when accessing a non-existing resource: %s\n", strerror(errno));
	T_EXPECT_EQ(EINVAL, errno, "Expect errno %d, errno returned %d", EINVAL, errno);

	T_LOG("Resource limits after the test:");
	print_rlimits(FALSE);
}
