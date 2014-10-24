#include <asl.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libproc.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/shared_region.h>
#include <mach/task_info.h>
#include <mach/vm_map.h>
#include <mach/vm_page_size.h>	/* Needed for vm_region info */

#include <sys/event.h>
#include <sys/ipc.h>
#include <sys/kern_memorystatus.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <xpc/xpc.h>
#include <xpc/private.h>

#include <CoreFoundation/CoreFoundation.h>

#include <Security/Security.h>
#include <ServiceManagement/ServiceManagement.h>
#include <ServiceManagement/SMErrors.h>

#include <Kernel/kern/ledger.h>

#include <sys/spawn_internal.h>
#include <spawn_private.h>

#define CR_JOB "com.apple.ReportCrash.Jetsam"
#define CR_JOB_PLIST_PATH "/System/Library/LaunchDaemons/com.apple.ReportCrash.Jetsam.plist"

#define ERR_BUF_LEN 1024

#ifndef VM_PAGE_SIZE
#define VM_PAGE_SIZE 4096
#endif

#define TASK_LIMIT_MB 75
#define HWM_LIMIT_MB 8

/*
 * Blob of data that is not easily compressed.
 * Guaranteed during setup to be at least
 * RANDOM_DATA_SIZE in length.
 */

#define RANDOM_DATA_SIZE 4096
char	random_data[] = "ffd8ffe000104a46494600010101002400240000ffe100744578696600004d4d002a000000080004011a0005000000010000003e011b0005000000010000004601280003000000010002000087690004000000010000004e00000000000000240000000100000024000000010002a002000400000001000003c0a003000400000001000001ff00000000ffdb00430002020202020102020202020202030306040303030307050504060807080808070808090a0d0b09090c0a08080b0f0b0c0d0e0e0e0e090b10110f0e110d0e0e0effdb004301020202030303060404060e0908090e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0effc000110801ff03c003012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00f9e74fbd37baa2db99e6506391f28371f9519ba67fd9fcabd46cbc1315de8d6776752d7419e049084b152a37283c1dfc8e6bc02db4af18d9df79c9e1bd59a40ae9b65b1761f32953c63ae09c7a1c57656fe24f8896da7c16c9e0bb3748a358d5a4d04b31006324f73c75a00935f7fec9f165ee98b7372e2ddc05795763f2a0f20138ebeb590bac3e70d2b6e1fed1ac6d4ecbc65aa6b973a85c7867528a6998168edec1a38c1c01c2f61c550fec1f16ff00d0bdade4f5ff00447ff0a00eaffb5dbfe7abfe668fed76ff009eaff99ae57fb07c5bff0042f6b7ff00808ffe147f60f8b7fe85ed6fff00011ffc2803aafed76ff9eaff0099a3fb5dbfe7abfe66b95fec1f16ff00d0bdadff00e023ff00851fd83e2dff00a17b5bff00c047ff000a00eabfb5dbfe7abfe668fed76ff9eaff0099ae57fb07c5bff42f6b7ff808ff00e147f60f8b7fe85ed6ff00f011ff00c2803aafed76ff009eaff99a3fb5dbfe7abfe66b95fec1f16ffd0bdadffe023ff851fd83e2dffa17b5bffc047ff0a00eabfb5dbfe7abfe668fed76ff009eaff99ae57fb07c5bff0042f6b7ff00808ffe147f60f8b7fe85ed6fff00011ffc2803aafed76ff9eaff0099a3fb5dbfe7abfe66b95fec1f16ff00d0bdadff00e023ff00851fd83e2dff00a17b5bff00c047ff000a00eabfb5dbfe7abfe668fed76ff9eaff0099ae57fb07c5bff42f6b7ff808ff00e147f60f8b7fe85ed6ff00f011ff00c2803aafed76ff009eaff99a3fb5dbfe7abfe66b95fec1f16ffd0bdadffe023ff851fd83e2dffa17b5bffc047ff0a00eabfb5dbfe7abfe668fed76ff009eaff99ae57fb07c5bff0042f6b7ff00808ffe147f60f8b7fe85ed6fff00011ffc2803aafed76ff9eaff0099a3fb5dbfe7abfe66b95fec1f16ff00d0bdadff00e023ff00851fd83e2dff00a17b5bff00c047ff000a00eabfb5dbfe7abfe668fed76ff9eaff0099ae57fb07c5bff42f6b7ff808ff00e147f60f8b7fe85ed6ff00f011ff00c2803aafed76ff009eaff99a3fb5dbfe7abfe66b95fec1f16ffd0bdadffe023ff851fd83e2dffa17b5bffc047ff0a00eabfb5dbfe7abfe668fed76ff009eaff99ae57fb07c5bff0042f6b7ff00808ffe147f60f8b7fe85ed6fff00011ffc2803aafed76ff9eaff0099a3fb5dbfe7abfe66b95fec1f16ff00d0bdadff00e023ff00851fd83e2dff00a17b5bff00c047ff000a00eabfb5dbfe7abfe668fed76ff9eaff0099ae57fb07c5bff42f6b7ff808ff00e147f60f8b7fe85ed6ff00f011ff00c2803aafed76ff009eaff99a3fb5dbfe7abfe66b95fec1f16ffd0bdadffe023ff851fd83e2dffa17b5bffc047ff0a00eabfb5dbfe7abfe668fed76ff009eaff99ae57fb07c5bff0042f6b7ff00808ffe147f60f8b7fe85ed6fff00011ffc2803aafed76ff9eaff0099a3fb5dbfe7abfe66b95fec1f16ff00d0bdadff00e023ff00851fd83e2dff00a17b5bff00c047ff000a00eabfb5dbfe7abfe668fed76ff9eaff0099ae57fb07c5bff42f6b7ff808ff00e147f60f8b7fe85ed6ff00f011ff00c2803aafed76ff009eaff99a3fb5dbfe7abfe66b95fec1f16ffd0bdadffe023ff851fd83e2dffa17b5bffc047ff0a00eabfb5dbfe7abfe668fed76ff009eaff99ae57fb07c5bff0042f6b7ff00808ffe147f60f8b7fe85ed6fff00011ffc2803aafed76ff9eaff0099a3fb5dbfe7abfe66b95fec1f16ff00d0bdadff00e023ff00851fd83e2dff00a17b5bff00c047ff000a00eabfb5dbfe7abfe668fed76ff9eaff0099ae57fb07c5bff42f6b7ff808ff00e147f60f8b7fe85ed6ff00f011ff00c2803aafed76ff009eaff99a3fb5dbfe7abfe66b95fec1f";

/* 
 * TODO: import header (currently vm_pageout.h) without pulling in extraneous definitions;
 * see <rdar://problem/13374916>.
 */
#ifndef VM_PAGER_FREEZER_DEFAULT
#define VM_PAGER_FREEZER_DEFAULT 0x8	/* Freezer backed by default pager.*/
#endif

/*
 * Special note to ourselves: the jetsam cause to look out for is *either*
 * a high watermark kill, *or* a per-process kill.
 */
#define CAUSE_HIWAT_OR_PERPROC -1

typedef enum jetsam_test {
    kSimpleJetsamTest = 1,
    kCustomTaskLimitTest,
    kPressureJetsamTestFG,
    kPressureJetsamTestBG,
    kHighwaterJetsamTest,
    kVnodeJetsamTest,
    kBackgroundJetsamTest
} jetsam_test_t;

typedef enum idle_exit_test {
    kDeferTimeoutCleanTest = 1,
    kDeferTimeoutDirtyTest,
    kCancelTimeoutCleanTest,
    kCancelTimeoutDirtyTest
} idle_exit_test_t;

typedef struct shared_mem_t {
    pthread_mutex_t mutex;
    pthread_cond_t cv;
    boolean_t completed;
    boolean_t pressure_event_fired;
    boolean_t child_failed;
} shared_mem_t;

shared_mem_t *g_shared = NULL;
unsigned long g_physmem = 0;
int g_compressor_mode=0;
int g_ledger_count = -1, g_footprint_index = -1;
int64_t g_per_process_limit = -1;

/*
 * g_exit_status:
 *	Holds the PASS/FAIL status of the memorystatus
 *	test run as a whole.
 *	e.g: If one subtest reports failure, the entire
 *	     test run reports failure.
 *
 *	PASS:  returns 0   (default)
 *	FAIL:  returns -1
 *
 *	The only time the g_exit_status changes state
 *	is when printTestResult() reports a FAIL status.
 */
int g_exit_status = 0;


extern int ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3);
static boolean_t check_properties(pid_t pid, int32_t requested_priority, int32_t requested_limit_mb, uint64_t requested_user_data, const char *test);

/* Utilities. */

static void
printTestHeader(pid_t testPid, const char *testName, ...)
{
    va_list va;
    printf("========================================\n");
    printf("[TEST] ");
    va_start(va, testName);
    vprintf(testName, va);
    va_end(va);
    printf("\n");
    printf("[PID]  %d\n", testPid);
    printf("========================================\n");
    printf("[BEGIN]\n");
    fflush(stdout);
}

static void
printTestResult(const char *testName, boolean_t didPass, const char *msg, ...)
{
    if (msg != NULL) {
    	va_list va;
    	printf("\t\t");
    	va_start(va, msg);
    	vprintf(msg, va);
    	va_end(va);
    	printf("\n");
    }
    if (didPass) {
        printf("[PASS]\t%s\n\n", testName);
    } else {
        printf("[FAIL]\t%s\n\n", testName);

	/* Any single failure, fails full test run */
	g_exit_status = -1;
    }
    fflush(stdout);
}

static int
_get_munch_interval(int given_interval)
{
    int res;
    int new_interval=0;
    char *slow_device;
    char model_name_buf[1025];
    size_t mnb_size = 1024;
    res = sysctlbyname("hw.model", model_name_buf, &mnb_size, NULL, 0);

    if (res) {
        perror("\t\tsysctlbyname(hw.model...)");
    }
    else {
        /* see if we're a slow device (N90, K66, J33) */
        slow_device = strstr(model_name_buf, "N90");
        if (slow_device == NULL) {
            slow_device = strstr(model_name_buf, "K66");
        }
        if (slow_device == NULL) {
            slow_device = strstr(model_name_buf, "J33");
        }

        if (slow_device != NULL) {
            printf("\t\tRunning on a slow device...\n");
        }
        
        if (given_interval == 0) {
            if (slow_device != NULL) {
                new_interval = 500 * 1000; /* want sleep time in microseconds */
            }
	    else {
		new_interval = 100 * 1000;/* want sleep time in microseconds */
	    }
        }
        else {
            new_interval = given_interval * USEC_PER_SEC;
        }
    }

    return new_interval;
}

static CFDictionaryRef create_dictionary_from_plist(const char *path) {
    void *bytes = NULL;
    CFDataRef data = NULL;
    CFDictionaryRef options = NULL;
    size_t bufLen;
    int fd = open(path, O_RDONLY, 0);
    if (fd == -1) {
        goto exit;
    }
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        goto exit;
    }

    bufLen = (size_t)sb.st_size;
    bytes = malloc(bufLen);
    if (bytes == NULL) {
        goto exit;
    }

    if (read(fd, bytes, bufLen) != bufLen) {
        goto exit;
    }

    data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (const UInt8 *) bytes, bufLen, kCFAllocatorNull);
    if (data == NULL) {
        goto exit;
    }

    options = (CFDictionaryRef) CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, NULL);
    if (options == NULL) {
        goto exit;
    }

exit:
    if (data != NULL) {
        CFRelease(data);
    }
    if (bytes != NULL) {
        free(bytes);
    }
    if (fd != -1) {
        close(fd);
    }
    
    return options;
}


/*
 * cleanup_and_exit():
 *    The parent process can call this routine to exit or abort
 *    the test run at any time.
 *
 *    The child process on the other hand should not call this routine.
 *    Be mindful about how re-enabling the crashreporter can affect tests
 *    further down the line.
 */
static void cleanup_and_exit(int status) {
    
    /* Exit. Pretty literal. */
    exit(status);
}

/*
 * child_ready():
 *     After a child process takes care of its inital setup, it
 *     synchronizes back to the parent using this call.
 *
 *     If the child process experiences a failure during its
 *     intial setup, it should abort using a standard exit
 *     routine, leaving crashreporter cleanup to the parent.
 *
 *     The child should never call cleanup_and_exit().
 *     That's for the parent only.
 */
static void child_ready() {
    pthread_mutex_lock(&g_shared->mutex);
    pthread_cond_signal(&g_shared->cv);
    pthread_mutex_unlock(&g_shared->mutex);
}

static pid_t init_and_fork() {
    int pid;

    g_shared->completed = 0;
    g_shared->pressure_event_fired = 0;
    
    pthread_mutex_lock(&g_shared->mutex);

    pid = fork();
    if (pid == 0) {
        return 0;
    } else if (pid == -1) {
        printTestResult(__func__, false, "Fork error!");
        cleanup_and_exit(-1);        
    }
    
    /* Wait for child's signal */
    pthread_cond_wait(&g_shared->cv, &g_shared->mutex);
    pthread_mutex_unlock(&g_shared->mutex);    
    return (pid_t)pid;
}

static memorystatus_priority_entry_t *get_priority_list(int *size) {
    memorystatus_priority_entry_t *list = NULL;
    
    assert(size);
    
    *size = memorystatus_control(MEMORYSTATUS_CMD_GET_PRIORITY_LIST, 0, 0, NULL, 0);
    if (*size <= 0) {
        printf("\t\tCan't get list size: %d!\n", *size);
        goto exit;
    }

    list = (memorystatus_priority_entry_t*)malloc(*size);
    if (!list) {
        printf("\t\tCan't allocate list!\n");
        goto exit;
    }

    *size = memorystatus_control(MEMORYSTATUS_CMD_GET_PRIORITY_LIST, 0, 0, list, *size);
    if (*size <= 0) {
        printf("\t\tCan't retrieve list!\n");
        goto exit;
    }
    
exit:
    return list;
}

/* Tests */


static boolean_t get_ledger_info(pid_t pid, int64_t *balance_mb, int64_t *limit_mb) {
    struct ledger_entry_info *lei;
    uint64_t count;
    boolean_t res = false;
        
    lei = (struct ledger_entry_info *)malloc((size_t)(g_ledger_count * sizeof (*lei)));
    if (lei) {
        void *arg;
            
        arg = (void *)(long)pid;
        count = g_ledger_count;
        
        if ((ledger(LEDGER_ENTRY_INFO, arg, (caddr_t)lei, (caddr_t)&count) >= 0) && (g_footprint_index < count)) {
            if (balance_mb) {
                *balance_mb = lei[g_footprint_index].lei_balance;
            }
            if (limit_mb) {
                *limit_mb = lei[g_footprint_index].lei_limit;
            }
            res = true;
        }
        
        free(lei);
    }
        
    return res;
}

static boolean_t get_priority_props(pid_t pid, int32_t *priority, int32_t *limit_mb, uint64_t *user_data) {
    int size;
    memorystatus_priority_entry_t *entries = NULL;
    int i;
    boolean_t res = false;

    entries = get_priority_list(&size);
    if (!entries) {
        goto exit;
    }

    /* Locate */
    for (i = 0; i < size/sizeof(memorystatus_priority_entry_t); i++ ){
        if (entries[i].pid == pid) {
            int64_t limit;
                   
            *priority = entries[i].priority;
            *user_data = entries[i].user_data;
#if 1
            *limit_mb = entries[i].limit;
            res = true;
#else
            res = get_ledger_info(entries[i].pid, NULL, &limit);
            if (false == res) {
                    printf("Failed to get highwater!\n");
            }
            /* The limit is retrieved in bytes, but set in MB, so rescale */
            *limit_mb = (int32_t)(limit/(1024 * 1024));
#endif 
            goto exit;
        }
    }

    printf("\t\tCan't find pid: %d!\n", pid);

exit:
    if (entries)
	free(entries);

    return res;  
}

static boolean_t check_properties(pid_t pid, int32_t requested_priority, int32_t requested_limit_mb, uint64_t requested_user_data, const char *test) {
    const char *PROP_GET_ERROR_STRING = "failed to get properties";
    const char *PROP_CHECK_ERROR_STRING = "property mismatch";
    
    int32_t actual_priority, actual_hiwat;
    uint64_t actual_user_data;
    
    if (!get_priority_props(pid, &actual_priority, &actual_hiwat, &actual_user_data)) {
        printf("\t\t%s test failed: %s\n", test, PROP_GET_ERROR_STRING);
        return false;
    }
    
    /* -1 really means the default per-process limit, which varies per device */
    if (requested_limit_mb <= 0) {
        requested_limit_mb = (int32_t)g_per_process_limit;
    }
    
    if (actual_priority != requested_priority || actual_hiwat != requested_limit_mb || actual_user_data != requested_user_data) {
        printf("\t\t%s test failed: %s\n", test, PROP_CHECK_ERROR_STRING);
        printf("priority is %d, should be %d\n", actual_priority, requested_priority);
        printf("hiwat is %d, should be %d\n", actual_hiwat, requested_limit_mb);
        printf("user data is 0x%llx, should be 0x%llx\n", actual_user_data, requested_user_data);
        return false;
    }
    
    printf("\t\t%s test ok...\n", test);
    
    return true;
}


static void start_list_validation_test() {
    int size;
    memorystatus_priority_entry_t *entries = NULL;
    int i;
    boolean_t valid = false;
    
    printTestHeader(getpid(), "List validation test");
    
    entries = get_priority_list(&size);
    if (!entries) {
        printf("Can't get entries!\n");
        goto exit;
    }

    /* Validate */
    for (i = 0; i < size/sizeof(memorystatus_priority_entry_t); i++ ) {
        int dirty_ret;
        uint32_t dirty_flags;
        
        /* Make sure launchd isn't in the list - <rdar://problem/13168754> */
        if (entries[i].pid <= 1) {
            printf("\t\tBad process (%d) in list!\n", entries[i].pid);
            goto exit;
        }
        
        /* Sanity check idle exit state */
        dirty_ret = proc_get_dirty(entries[i].pid, &dirty_flags);
        if (dirty_ret != 0) {
            dirty_flags = 0;
        }
        
        if (dirty_flags & PROC_DIRTY_ALLOWS_IDLE_EXIT) {
            /* Check that the process isn't at idle priority when dirty */
            if ((entries[i].priority == JETSAM_PRIORITY_IDLE) && (dirty_flags & PROC_DIRTY_IS_DIRTY)) {
                printf("\t\tProcess %d at idle priority when dirty (priority %d, flags 0x%x)!\n", entries[i].pid, entries[i].priority, dirty_flags);
                goto exit;
            }
            /* Check that the process is at idle (or deferred) priority when clean. */
            if ((entries[i].priority > JETSAM_PRIORITY_IDLE_DEFERRED) && !(dirty_flags & PROC_DIRTY_IS_DIRTY)) {
                printf("\t\tProcess %d not at non-idle priority when clean(priority %d, flags 0x%x)\n", entries[i].pid, entries[i].priority, dirty_flags);
                goto exit;
            }
        }        
    }

    valid = true;

exit:
    if (entries)
	free(entries);
    
    printTestResult("List validation test", valid, NULL);
}

/* Random individual tests */
static void start_general_sanity_test() {
    int ret, size;
    int i;
    boolean_t valid = false;

    /*
     * The sanity test checks for permission failures
     * against P_MEMSTAT_INTERNAL processes.
     * Currently only launchd (pid==1) qualifies.
    */
    
    printTestHeader(getpid(), "Sanity test");
    

    /* Ensure that launchd's transaction state is fixed */
    ret = proc_track_dirty(1, PROC_DIRTY_TRACK | PROC_DIRTY_ALLOW_IDLE_EXIT | PROC_DIRTY_DEFER);
    if (ret != EPERM) {
        printf("\t\tNo EPERM tracking launchd (%d/%d)!\n", ret, errno);
        goto exit;           
    } else {
        printf("\t\tlaunchd track test OK!\n");    
    }
    
    ret = proc_set_dirty(1, true);
    if (ret != EPERM) {
        printf("\t\tNo EPERM setting launchd dirty state (%d/%d)!\n", ret, errno);
        goto exit;           
    } else {
        printf("\t\tlaunchd dirty test OK!\n");    
    }


    valid = true;

exit:
    printTestResult("Sanity test", valid, NULL);
}

static void idle_exit_deferral_test(idle_exit_test_t test) {
    int secs = DEFERRED_IDLE_EXIT_TIME_SECS;

    child_ready();

    if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#1 - pre xpc_track_activity()")) {
        goto exit;
    }
    
    proc_track_dirty(getpid(), PROC_DIRTY_TRACK | PROC_DIRTY_ALLOW_IDLE_EXIT | PROC_DIRTY_DEFER);
    
    if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE_DEFERRED, -1, 0x0, "#2 - post xpc_track_activity()")) {
        goto exit;
    }

    /* Toggle */
    proc_set_dirty(getpid(), true);
    proc_set_dirty(getpid(), false);
    proc_set_dirty(getpid(), true);
    proc_set_dirty(getpid(), false);

    switch (test) {
    case kDeferTimeoutCleanTest:
        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE_DEFERRED, -1, 0x0, "#3 - post toggle")) {
            goto exit;
        }
        
        /* Approximate transition check */
        sleep(secs - 1);
        
        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE_DEFERRED, -1, 0x0, "#4 - pre timeout")) {
            goto exit;
        }

        sleep(2);

        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE, -1, 0x0, "#5 - post timeout")) {
            goto exit;
        }

        proc_set_dirty(getpid(), true);

        if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#6 - post dirty")) {
            goto exit;
        }

        proc_set_dirty(getpid(), false);

        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE, -1, 0x0, "#7 - post clean")) {
            goto exit;
        }

        break;
    case kDeferTimeoutDirtyTest:
        proc_set_dirty(getpid(), true);
        
        if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#3 - post dirty")) {
            goto exit;
        }
        
        /* Approximate transition check */
        sleep(secs - 1);
        
        if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#4 - pre timeout")) {
            goto exit;
        }

        sleep(2);

        if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#5 - post timeout")) {
            goto exit;
        }

        proc_set_dirty(getpid(), false);

        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE, -1, 0x0, "#6 - post clean")) {
            goto exit;
        }

        break;
    case kCancelTimeoutDirtyTest:
        proc_set_dirty(getpid(), true);
        
        if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#3 - post toggle")) {
           goto exit;
        }
        
        proc_clear_dirty(getpid(), PROC_DIRTY_DEFER);

        if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#4 - post deferral cancellation")) {
           goto exit;
        }

        proc_set_dirty(getpid(), false);

        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE, -1, 0x0, "#5 - post toggle")) {
           goto exit;
        }
        
        break;
    case kCancelTimeoutCleanTest:
        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE_DEFERRED, -1, 0x0, "#3 - post toggle")) {
            goto exit;
        }
        
        proc_clear_dirty(getpid(), PROC_DIRTY_DEFER);
  
        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE, -1, 0x0, "#4 - post deferral cancellation")) {
            goto exit;
        }
      
        proc_set_dirty(getpid(), true);

        if (!check_properties(getpid(), JETSAM_PRIORITY_DEFAULT, -1, 0x0, "#5 - post dirty")) {
           goto exit;
        }
        
        proc_set_dirty(getpid(), false);

        if (!check_properties(getpid(), JETSAM_PRIORITY_IDLE, -1, 0x0, "#6 - post clean")) {
           goto exit;
        }
        
        break;
    }

    g_shared->completed = 1;
    exit(0);
        
exit:
    printTestResult(__func__, false, "Something bad happened...");
    exit(-1);
}

static void start_idle_exit_defer_test(idle_exit_test_t test) {
    pid_t pid;
    int status;
	
    /* Reset */
    memset(g_shared, 0, sizeof(shared_mem_t));
    
    pid = init_and_fork();
    if (pid == 0) {
        idle_exit_deferral_test(test);
    }
    else {
        printTestHeader(pid, "Idle exit deferral test: %d", test);
    }

    /* Wait for exit */
    waitpid(pid, &status, 0);
    /* Idle exit not reported on embedded */
    // wait_for_exit_event(pid, kMemorystatusKilledIdleExit);

    printTestResult("Idle exit deferral test", g_shared->completed, NULL);
}

static void ledger_init(void) {
    const char *physFootprintName = "phys_footprint";
    struct ledger_info li;
    int64_t template_cnt;
    struct ledger_template_info *templateInfo;
    void *arg;
    int i;
        
    /* Grab ledger entries */
    arg = (void *)(long)getpid();
    if (ledger(LEDGER_INFO, arg, (caddr_t)&li, NULL) < 0) {
            exit(-1);
    }
    
    g_ledger_count = template_cnt = li.li_entries; 

    templateInfo = malloc(template_cnt * sizeof (struct ledger_template_info));
    if (templateInfo == NULL) {
            exit (-1);
    }
    
    if (!(ledger(LEDGER_TEMPLATE_INFO, (caddr_t)templateInfo, (caddr_t)&template_cnt, NULL) < 0)) {
            for (i = 0; i < template_cnt; i++) {
                    if (!strncmp(templateInfo[i].lti_name, physFootprintName, strlen(physFootprintName))) {
                            g_footprint_index = i;
                            break;
                    }
            }
    }
    
    free(templateInfo);
}

static void run_tests(const char *path) {
    /* Embedded-only */
#pragma unused(path)
    
    /* Generic */
    start_general_sanity_test();
    start_list_validation_test();
    start_idle_exit_defer_test(kDeferTimeoutCleanTest);
    start_idle_exit_defer_test(kDeferTimeoutDirtyTest);
    start_idle_exit_defer_test(kCancelTimeoutCleanTest);
    start_idle_exit_defer_test(kCancelTimeoutDirtyTest);
}


int main(int argc, char **argv)
{
    pthread_mutexattr_t attr;
    pthread_condattr_t cattr;
    size_t size;

    /* Must be run as root for priority retrieval */
    if (getuid() != 0) {
        fprintf(stderr, "%s must be run as root.\n", getprogname());
        exit(EXIT_FAILURE);
    }
    

    /* Memory */
    size = sizeof(g_physmem);
    if (sysctlbyname("hw.physmem", &g_physmem, &size, NULL, 0) != 0 || !g_physmem) {
        printTestResult(__func__, false, "Failed to retrieve system memory");
        cleanup_and_exit(-1);
    }

    /* VM Compressor Mode */
    size = sizeof(g_compressor_mode);
    if (sysctlbyname("vm.compressor_mode", &g_compressor_mode, &size, NULL, 0) != 0) {
	printTestResult(__func__, false, "Failed to retrieve compressor config");
	cleanup_and_exit(-1);
    }

    /* Ledger; default limit applies to this process, so grab it here */
    ledger_init();
    if ((-1 == g_ledger_count) || (-1 == g_footprint_index) || (false == get_ledger_info(getpid(), NULL, &g_per_process_limit))) {
        printTestResult("setup", false, "Unable to init ledger!\n");
        cleanup_and_exit(-1);            
    }
    
    if (g_per_process_limit == LEDGER_LIMIT_INFINITY) {
        g_per_process_limit = 0;
    } else {
        /* Rescale to MB */
        g_per_process_limit /= (1024 * 1024);
    }
    
    /* Shared memory */
    g_shared = mmap(NULL, sizeof(shared_mem_t), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, 0, 0);
    if (!g_shared) {
        printTestResult(__func__, false, "Failed mmap");
        cleanup_and_exit(-1);
    }

    /* Guarantee size of random_data buffer */
    if (sizeof(random_data) < RANDOM_DATA_SIZE) {
	printTestResult(__func__, false, "Failed to guarantee random_data buffer size [expected %d, actual %d]",
	  RANDOM_DATA_SIZE, sizeof(random_data));
	cleanup_and_exit(-1);
    }

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED );

    pthread_condattr_init(&cattr);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);

    if (pthread_mutex_init(&g_shared->mutex, &attr) || pthread_cond_init(&g_shared->cv, &cattr)) {
        printTestResult("setup", false, "Unable to init condition variable!");
        cleanup_and_exit(-1);
    }

    run_tests(argv[0]);

    /* Teardown */
    pthread_mutex_destroy(&g_shared->mutex);
    pthread_cond_destroy(&g_shared->cv);

    pthread_mutexattr_destroy(&attr);
    pthread_condattr_destroy(&cattr);


    return (g_exit_status);   /* exit status 0 on success, -1 on failure */
}
