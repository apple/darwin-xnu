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
} shared_mem_t;

shared_mem_t *g_shared = NULL;
unsigned long g_physmem = 0;
int g_ledger_count = -1, g_footprint_index = -1;
int64_t g_per_process_limit = -1;

#if TARGET_OS_EMBEDDED
static boolean_t set_priority(pid_t pid, int32_t priority, uint64_t user_data);
#endif

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
    }
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

    options = (CFDictionaryRef) CFPropertyListCreateFromXMLData(kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL);
    if (options == NULL) {
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

#if TARGET_OS_EMBEDDED

static void disable_crashreporter(void) {
    if (!SMJobRemove(kSMDomainSystemLaunchd, CFSTR(CR_JOB), NULL, true, NULL)) {
        printf ("\t\tCould not unload %s\n", CR_JOB);
    }
}

static void enable_crashreporter(void) {
    CFDictionaryRef job_dict;
    
    job_dict = create_dictionary_from_plist(CR_JOB_PLIST_PATH);
    if (!job_dict) {
        printf("\t\tCould not create dictionary from %s\n", CR_JOB_PLIST_PATH);
    }
     
    if (!SMJobSubmit(kSMDomainSystemLaunchd, job_dict, NULL, NULL)) {
        printf ("\t\tCould not submit %s\n", CR_JOB);
    }
    
    CFRelease(job_dict);
}

static boolean_t verify_snapshot(pid_t pid, int32_t priority, uint32_t kill_cause, uint64_t user_data, bool expecting_snapshot) {
    int size;
    memorystatus_jetsam_snapshot_t *snapshot = NULL;
    int i;
    boolean_t res = false;

    if (kill_cause == CAUSE_HIWAT_OR_PERPROC) {
        kill_cause = kMemorystatusKilledHiwat|kMemorystatusKilledVMPageShortage;
    }

    size = memorystatus_control(MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT, 0, 0, NULL, 0);
    if (size <= 0) {
        if (expecting_snapshot) {
            printf("\t\tCan't get snapshot size: %d!\n", size);
        }
        goto exit;
    }

    snapshot = (memorystatus_jetsam_snapshot_t*)malloc(size);
    if (!snapshot) {
        printf("\t\tCan't allocate snapshot!\n");
        goto exit;
    }

    size = memorystatus_control(MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT, 0, 0, snapshot, size);
    if (size <= 0) {
        printf("\t\tCan't retrieve snapshot (%d)!\n", size);
        goto exit;
    } 

    if (((size - sizeof(memorystatus_jetsam_snapshot_t)) / sizeof(memorystatus_jetsam_snapshot_entry_t)) != snapshot->entry_count) {
        printf("\t\tMalformed snapshot: %d! Expected %ld + %zd x %ld = %ld\n", size, 
            sizeof(memorystatus_jetsam_snapshot_t), snapshot->entry_count, sizeof(memorystatus_jetsam_snapshot_entry_t), 
            sizeof(memorystatus_jetsam_snapshot_t) + (snapshot->entry_count * sizeof(memorystatus_jetsam_snapshot_entry_t)));
        goto exit;    
    }
    
    if (pid == -1) {
        /* Just flushing the buffer */
        res = true;
        goto exit;
    }

    /* Locate */
    for (i = 0; i < snapshot->entry_count; i++) {
        if (snapshot->entries[i].pid == pid) {
            res = 0;
            if ((priority == snapshot->entries[i].priority) && ((kill_cause | snapshot->entries[i].killed) == kill_cause) && (user_data == snapshot->entries[i].user_data)) {
                res = true;
            } else {
                printf("\t\tMismatched snapshot properties for pid %d (expected/actual): priority %d/%d : kill cause 0x%x/0x%x : user data 0x%llx/0x%llx\n",
                    pid, priority, snapshot->entries[i].priority, kill_cause, snapshot->entries[i].killed, user_data, snapshot->entries[i].user_data);
            }            
            goto exit;
        }
    }   
    
exit:
    free(snapshot);

    return res;
}

#endif /* TARGET_OS_EMBEDDED */

static void cleanup_and_exit(int status) {
#if TARGET_OS_EMBEDDED
    /* Cleanup */
    enable_crashreporter();
#endif
    
    /* Exit. Pretty literal. */
    exit(status);
}

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
        printTestResult(__func__, false, "Fork error!\n");
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

#if TARGET_OS_EMBEDDED

/* Spawn tests */

static void spawn_test() {
    int page_delta = 32768; /* 128MB */
    char *mem;
    unsigned long total = 0;
    
    /* Spin */
    while (1) {
        /* Priority will be shifted during this time... */
        sleep(1);
        
        /* ...then process will be backgrounded and hopefully killed by the memory limit */
        while(1) {
            int i;
            mem = malloc(page_delta * VM_PAGE_SIZE);
            if (!mem) {
                fprintf(stderr, "Failed to allocate memory!\n");
                while (1) {
                    sleep(1);
                }
            }

            total += page_delta;
            memset(mem, 0xFF, page_delta * VM_PAGE_SIZE);
            
            set_priority(getpid(), JETSAM_PRIORITY_BACKGROUND, 0);
            
            while(1) {
                sleep(1);
            }
        }
    }
}

#endif

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
        requested_limit_mb = g_per_process_limit;
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

#if TARGET_OS_EMBEDDED

static void spin() {    
    child_ready();
    
    /* Spin */
    while (1) {
        sleep(10);
    }
}

/* Priority tests */

static boolean_t set_priority(pid_t pid, int32_t priority, uint64_t user_data) {
    int ret;
    memorystatus_priority_properties_t props;

    props.priority = priority;
    props.user_data = (uint32_t)user_data;

    return memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, pid, 0, &props, sizeof(props));
}

static boolean_t set_memlimit(pid_t pid, int32_t limit_mb) {
    return memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, pid, limit_mb, NULL, 0);
}

static boolean_t set_priority_properties(pid_t pid, int32_t priority, int32_t limit_mb, uint64_t user_data, const char *stage, boolean_t show_error) {
    int ret;
    
    ret = set_priority(pid, priority, user_data);
    if (ret == 0) {
        ret = set_memlimit(pid, limit_mb);
    }

    if (ret) {
        if (show_error) {
            printf("\t\t%s stage: failed to set properties!\n", stage);
        }
        
        return false;
    }

    return true;
}

static void start_priority_test() {
    const char *DEFAULT_TEST_STR = "Default";
    const char *INVALID_NEGATIVE_TEST_STR = "Invalid (Negative)";
    const char *INVALID_POSITIVE_TEST_STR = "Invalid (Positive)";
    const char *IDLE_ALIAS_TEST_STR = "Idle Alias";
    const char *DEFERRED_TEST_STR = "Deferred";
    const char *SUSPENDED_TEST_STR = "Suspended";
    const char *FOREGROUND_TEST_STR = "Foreground";
    const char *HIGHPRI_TEST_STR = "Highpri";
    
    pid_t pid;
    int status;
    int success = false;

    pid = init_and_fork();
    if (pid == 0) {
        spin();
    } else {
        printTestHeader(pid, "Priority test");
    }

    /* Check the default properties */
    if (!check_properties(pid, JETSAM_PRIORITY_DEFAULT, -1, 0, DEFAULT_TEST_STR)) {
        goto exit;
    }
    
    /* Check that setting a negative value (other than -1) leaves properties unchanged */
    if (set_priority_properties(pid, -100, 0xABABABAB, 0, INVALID_NEGATIVE_TEST_STR, false) || !check_properties(pid, JETSAM_PRIORITY_DEFAULT, -1, 0, INVALID_NEGATIVE_TEST_STR)) {
        goto exit;
    }
    
    /* Check that setting an out-of-range positive value leaves properties unchanged */
    if (set_priority_properties(pid, 100, 0xCBCBCBCB, 0, INVALID_POSITIVE_TEST_STR, false) || !check_properties(pid, JETSAM_PRIORITY_DEFAULT, -1, 0, INVALID_POSITIVE_TEST_STR)) {
        goto exit;
    }
    
    /* Idle-deferred - this should be adjusted down to idle */
    if (!set_priority_properties(pid, JETSAM_PRIORITY_IDLE_DEFERRED, 0, 0xBEEF, DEFERRED_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_IDLE, 0, 0xBEEF, DEFERRED_TEST_STR)) {
        goto exit;
    }
    
    /* Suspended */
    if (!set_priority_properties(pid, JETSAM_PRIORITY_IDLE, 0, 0xCAFE, SUSPENDED_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_IDLE, 0, 0xCAFE, SUSPENDED_TEST_STR)) {
        goto exit;
    }
    
    /* Foreground */
    if (!set_priority_properties(pid, JETSAM_PRIORITY_FOREGROUND, 50, 0xBEEFF00D, FOREGROUND_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_FOREGROUND, 50, 0xBEEFF00D, FOREGROUND_TEST_STR)) {
        goto exit;
    }
    
    /* Hipri */
    if (!set_priority_properties(pid, JETSAM_PRIORITY_DEFAULT - 1, 0, 0x01234567, HIGHPRI_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_DEFAULT - 1, 0, 0x01234567, HIGHPRI_TEST_STR)) {
        goto exit;
    }

    /* Foreground again (to test that the limit is restored) */
    if (!set_priority_properties(pid, JETSAM_PRIORITY_FOREGROUND, 50, 0xBEEFF00D, FOREGROUND_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_FOREGROUND, 50, 0xBEEFF00D, FOREGROUND_TEST_STR)) {
        goto exit;
    }
    
    /* Set foreground priority again; this would have caught <rdar://problem/13056007> */
    if (!set_priority_properties(pid, JETSAM_PRIORITY_FOREGROUND, 50, 0xFEEDF00D, FOREGROUND_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_FOREGROUND, 50, 0xFEEDF00D, FOREGROUND_TEST_STR)) {
        goto exit;
    }

    /* Set foreground priority again but pass a large memory limit; this would have caught <rdar://problem/13116445> */
    if (!set_priority_properties(pid, JETSAM_PRIORITY_FOREGROUND, 4096, 0xBEEFF00D, FOREGROUND_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_FOREGROUND, 4096, 0xBEEFF00D, FOREGROUND_TEST_STR)) {
        goto exit;
    }
    
    /* Check that -1 aliases to JETSAM_PRIORITY_DEFAULT */
    if (!set_priority_properties(pid, -1, 0, 0xFADEF00D, IDLE_ALIAS_TEST_STR, true) || !check_properties(pid, JETSAM_PRIORITY_DEFAULT, 0, 0xFADEF00D, IDLE_ALIAS_TEST_STR)) {
        goto exit;
    }

    success = true;
    
exit:
    
    /* Done here... */
    kill(pid, SIGKILL);
    
    /* Wait for exit */
    waitpid(pid, &status, 0);

    printTestResult("Priority test", success, NULL);
}

/* Reordering */

static boolean_t check_reorder_priorities(pid_t pid1, pid_t pid2, int priority) {
    int size;
    memorystatus_priority_entry_t *entries = NULL;
    int i;
    boolean_t res = false;

    entries = get_priority_list(&size);
    if (!entries) {
        goto exit;
    }

    /* Check relative priorities */
    for (i = 0; i < size/sizeof(memorystatus_priority_entry_t); i++ ){
        if (entries[i].pid == pid1) {
            /* First process. The priority should match... */
            if (entries[i].priority != priority) {
               goto exit;                
            }
            
            /* There should be one more daemon to follow... */
            if ((i + 1) >= size) {
               goto exit;                 
            }
            
            /* The next process should be pid2 */
            if (entries[i + 1].pid != pid2) {
               goto exit;                
            }
            
            /* The priority should also match... */
            if (entries[i + 1].priority != priority) {
               goto exit;                
            }
            
            break;
        }
    }
    
    res = true;
    
exit:

    return res;
}

static void start_fs_priority_test() {
    const char *REORDER_TEST_STR = "Reorder";
    const int test_priority = JETSAM_PRIORITY_FOREGROUND_SUPPORT;
    
    pid_t pid1, pid2;
    int status;
    int success = false;

    pid1 = init_and_fork();
    if (pid1 == 0) {
        spin();
    }
   
    pid2 = init_and_fork();
    if (pid2 == 0) {
        spin();
    }     
        
    printTestHeader(pid1, "Reorder test");

    /* pid2 should follow pid1 in the bucket */
    if (!set_priority_properties(pid1, test_priority, 0, 0, REORDER_TEST_STR, true) || !set_priority_properties(pid2, test_priority, 0, 0, REORDER_TEST_STR, true)) {
         printf("Cannot set priorities - #1!\n");
         goto exit;
     }
     
     /* Check relative priorities */
     if (!check_reorder_priorities(pid1, pid2, test_priority)) {
         printf("Bad pid1 -> pid2 priorities - #2!\n");
         goto exit;
     }
     
    /* pid 1 should move to the back... */
    if (!set_priority_properties(pid1, test_priority, 0, 0, REORDER_TEST_STR, true)) {
         printf("Cannot set priorities - #3!\n");
         goto exit;
     }
     
     /* ...so validate */
     if (!check_reorder_priorities(pid2, pid1, test_priority)) {
         printf("Bad pid2 -> pid1 priorities - #4!\n");
         goto exit;         
     }
     
    /* Again, pid 2 should move to the back... */
    if (!set_priority_properties(pid2, test_priority, 0, 0, REORDER_TEST_STR, true)) {
         printf("Cannot set priorities - #5!\n");
         goto exit;
     }
     
     /* ...so validate for the last time */
     if (!check_reorder_priorities(pid1, pid2, test_priority)) {
         printf("Bad pid1 -> pid2 priorities - #6!\n");
         goto exit;         
     }

    success = true;
    
exit:
    
    /* Done here... */
    kill(pid1, SIGKILL);
    kill(pid2, SIGKILL);
    
    /* Wait for exit */
    waitpid(pid1, &status, 0);
    waitpid(pid2, &status, 0);

    printTestResult("Reorder test", success, NULL);
}

/* Jetsam tests */

/* 
 
 ASL message format:
 
 Message is ReadUID 0
 Message is ReadGID 80
 Message is ASLMessageID 703
 Message is Level 7
 Message is Time 1333155901
 Message is Sender kernel
 Message is Facility kern
 
 */

static void vnode_test(int page_delta, int interval, int verbose, int32_t priority, uint64_t user_data) {
    memorystatus_priority_properties_t props;
    
    props.priority = priority;
    props.user_data = user_data;
    
    if (memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, getpid(), 0, &props, sizeof(props))) {
        /*printf("\t\tFailed to set jetsam priority!\n");*/
        printTestResult(__func__, false, "Failed to set jetsam priority!");
        cleanup_and_exit(-1);
    }

    /* Initialized... */
    child_ready();
    
    /* ...so start stealing vnodes */
    while(1) {
        sleep(1);
    }
}

static void *wait_for_pressure_event(void *s) {
    int kq;
    int res;
    struct kevent event, mevent;
    char errMsg[ERR_BUF_LEN + 1];
    
    kq = kqueue();
    
    EV_SET(&mevent, 0, EVFILT_VM, EV_ADD, NOTE_VM_PRESSURE, 0, 0);

    res = kevent(kq, &mevent, 1, NULL, 0, NULL);
    if (res != 0) {
        /*printf("\t\tKevent registration failed - returning: %d!\n", res);*/
        snprintf(errMsg, ERR_BUF_LEN, "Kevent registration failed - returning: %d!",res);
        printTestResult(__func__, false, errMsg);
        cleanup_and_exit(-1);
    }

    while (1) {
        memset(&event, 0, sizeof(struct kevent));
        res = kevent(kq, NULL, 0, &event, 1, NULL);
        g_shared->pressure_event_fired = 1;
    }
}

static void wait_for_exit_event(int pid, uint32_t kill_cause) {
    int kq;
    int res;
    uint32_t expected_flag, received_flag;
    struct kevent event, mevent;
    char errMsg[ERR_BUF_LEN + 1];
    
    switch (kill_cause) {
        case kMemorystatusKilledVnodes:             expected_flag = NOTE_EXIT_MEMORY_VNODE; break;
        case kMemorystatusKilledVMPageShortage:     expected_flag = NOTE_EXIT_MEMORY_VMPAGESHORTAGE; break;
        case kMemorystatusKilledVMThrashing:        expected_flag = NOTE_EXIT_MEMORY_VMTHRASHING; break;
        case kMemorystatusKilledHiwat:              expected_flag = NOTE_EXIT_MEMORY_HIWAT; break;
        case kMemorystatusKilledPerProcessLimit:    expected_flag = NOTE_EXIT_MEMORY_PID; break;
        case kMemorystatusKilledIdleExit:           expected_flag = NOTE_EXIT_MEMORY_IDLE; break;
        case CAUSE_HIWAT_OR_PERPROC:                expected_flag = NOTE_EXIT_MEMORY_HIWAT|NOTE_EXIT_MEMORY_PID; break;
    }

    kq = kqueue();

    EV_SET(&mevent, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT | NOTE_EXIT_DETAIL, 0, 0);

    res = kevent(kq, &mevent, 1, NULL, 0, NULL);
    if (res != 0) {
        snprintf(errMsg,ERR_BUF_LEN,"Exit kevent registration failed - returning: %d!",res);
        printTestResult(__func__, false, errMsg);
        cleanup_and_exit(-1);
    }

    res = kevent(kq, NULL, 0, &event, 1, NULL);

    /* Check if appropriate flags are set */
    if (!event.fflags & NOTE_EXIT_MEMORY) {
        printTestResult(__func__, false, "Exit event fflags do not contain NOTE_EXIT_MEMORY\n");
        cleanup_and_exit(-1);
    }

    received_flag = event.data & NOTE_EXIT_MEMORY_DETAIL_MASK;
    if ((received_flag | expected_flag) != expected_flag) {
        printTestResult(__func__, false, "Exit event data does not contain the expected jetsam flag for cause %x.\n"
				    "\t\t(expected %x, got %x)", kill_cause, expected_flag, received_flag);
        cleanup_and_exit(-1);
    }
}

static void munch_test(int page_delta, int interval, int verbose, int32_t priority, int32_t highwater, uint64_t user_data) {
    const char *MUNCH_TEST_STR = "Munch";
    char *mem;
    unsigned long total = 0;
    pthread_t pe_thread;
    int res;

    /* Start thread to watch for pressure messages */
    res = pthread_create(&pe_thread, NULL, wait_for_pressure_event, (void*)g_shared);
    if (res) {
        printTestResult(__func__, false, "Error creating pressure event thread!\n");
        cleanup_and_exit(-1);
    }

    if (set_priority_properties(getpid(), priority, highwater, user_data, MUNCH_TEST_STR, false) == false) {
        printTestResult(__func__, false, "Failed to set jetsam priority!");
        cleanup_and_exit(-1);
    }

    if (!page_delta) {
        page_delta = 4096;
    }

    sleep(1);

    /* Initialized... */
    child_ready();

    /* ...so start munch */
    while(1) {
        int i;
        mem = malloc(page_delta * VM_PAGE_SIZE);
        if (!mem) {
            fprintf(stderr, "Failed to allocate memory!\n");
            while (1) {
                sleep(1);
            }
        }

        total += page_delta;
        memset(mem, 0xFF, page_delta * VM_PAGE_SIZE);

        if (verbose) {
            printf("\t\t%lu pages dirtied...\n", total);
        }

        sleep(interval);
    }
}

static bool is_pressure_test(test) {
    return ((test == kPressureJetsamTestFG) || (test == kPressureJetsamTestBG));
}

static bool verify_exit(pid_t pid, uint32_t kill_cause, time_t start_time, uint32_t test_pri, uint64_t test_user_data, jetsam_test_t test, bool expecting_snapshot) {
    const char *msg_key = "Message";
    const char *time_key = "Time";
    aslmsg query;
    aslresponse response;
    aslmsg message;
    char pid_buffer[16];
    const char *val;
    int got_jetsam = 0;
    bool got_snapshot = 0;
    bool success;
    
    /* Wait for exit */
    wait_for_exit_event(pid, kill_cause);

    /* Let the messages filter through to the log - arbitrary */
    sleep(3);

    query = asl_new(ASL_TYPE_QUERY);
    asl_set_query(query, ASL_KEY_SENDER, "kernel", ASL_QUERY_OP_EQUAL);
    asl_set_query(query, ASL_KEY_MSG, "memorystatus", ASL_QUERY_OP_EQUAL|ASL_QUERY_OP_SUBSTRING);
    snprintf(pid_buffer, sizeof(pid_buffer) - 1, "%d", pid);
    asl_set_query(query, ASL_KEY_MSG, pid_buffer, ASL_QUERY_OP_EQUAL|ASL_QUERY_OP_SUBSTRING);
    response = asl_search(NULL, query);
    asl_free(query);

    while (NULL != (message = aslresponse_next(response)))
    {
        val = asl_get(message, time_key);
        if (val) {
            uint32_t msg_time = atoi(val);
            if (msg_time > start_time) {
                val = asl_get(message, msg_key);
                if (val) {
                    printf("\t\tFound: %s\n", val);
                    got_jetsam = 1;
                }
            }
        }
    }

    if (got_jetsam) {
        got_snapshot = verify_snapshot(pid, test_pri, kill_cause, test_user_data, expecting_snapshot);
    } else {
        printf("\t\tCouldn't find jetsam message in log!\n");
    }

    aslresponse_free(response);

    success = got_jetsam && (expecting_snapshot == got_snapshot) && (!(is_pressure_test(test)) || (is_pressure_test(test) && g_shared->pressure_event_fired));
    printTestResult("munch_test", success, "(test: %d, got_jetsam: %d, got_snapshot: %d, fired: %d)", test, got_jetsam, got_snapshot, g_shared->pressure_event_fired);
    
    return success;
}

static void start_jetsam_test(jetsam_test_t test, const char *description) {
    const char *msg_key = "Message";
    const char *time_key = "Time";
    const char *val;
    aslmsg query;
    aslresponse response;
    aslmsg message;
    time_t start_time;
    pid_t pid;
    char pid_buffer[16];
    int status;
    int got_jetsam = 0;
    int got_snapshot = 0;
    uint32_t test_pri = 0;
    uint64_t test_user_data = 0;
    uint32_t kill_cause;
    int success;
    boolean_t expecting_snapshot = TRUE;
    boolean_t big_mem = (g_physmem > 512 * 1024 * 1024);

    if (big_mem) {
        /*
         * On big memory machines (1GB+), there is a per-task memory limit.
         * A munch test could fail because of this, if they manage to cross it;
         * *or* because the high watermark was crossed, and the system was under
         * enough mem pressure to go looking for a high watermark victim to kill.
         */
        kill_cause = CAUSE_HIWAT_OR_PERPROC;
    } else if (test == kHighwaterJetsamTest) {
        /*
         * On systems without the per-task memory limit, we shouldn't see any
         * such kills; so that leaves high watermark kills as the only legitimate
         *  reason to kill a munch test that has a high watermark set.
         */
        kill_cause = kMemorystatusKilledHiwat;
    } else {
        /*
         * If this is a standard munch test and we're on a machine without the
         * per-task memory limit, the only reason for kill should be that we need
         * memory.
         */
        kill_cause = kMemorystatusKilledVMPageShortage;
    }

    start_time = time(NULL);

    switch (test) {
        case kPressureJetsamTestFG:
            test_pri = JETSAM_PRIORITY_FOREGROUND; /* Test that FG processes get pressure events  */
            test_user_data = 0xDEADBEEF;
            break;
        case kPressureJetsamTestBG:
            test_pri = JETSAM_PRIORITY_UI_SUPPORT; /* Test that BG processes get pressure events */
            test_user_data = 0xFADEBEEF;
            break;
        case kSimpleJetsamTest:
            /* 
             * On 1GB devices, we should see a snapshot as the per-process limit is hit.
             * On 512MB devices, we should see a normal jetsam, and no snapshot.
             */
            expecting_snapshot = big_mem ? TRUE : FALSE;
            test_pri = JETSAM_PRIORITY_IDLE; /* Suspended */
            test_user_data = 0xFACEF00D;
            break;
        default:
            test_pri = JETSAM_PRIORITY_IDLE; /* Suspended */
            test_user_data = 0xCAFEF00D;
            break;
    }

    pid = init_and_fork();

    if (pid == 0) {
        switch (test) {
            case kVnodeJetsamTest:
                vnode_test(0, 0, 0, test_pri, test_user_data);
                break;
            case kHighwaterJetsamTest:
                munch_test(0, 0, 0, test_pri, 8, test_user_data);
                break;
            default:
                munch_test(0, 0, 0, test_pri, -1, test_user_data);
                break;
        }
    }
    else {
        printTestHeader(pid, "%s test", description);
    }

    verify_exit(pid, kill_cause, start_time, test_pri, test_user_data, test, expecting_snapshot);
}

static void start_jetsam_test_background(const char *path) {
    const char *argv[] = {
        path,
        "-s",
        NULL
    };
    
    const uint32_t memlimit = 100; /* 100 MB */
    
    time_t start_time;
    pid_t pid = 1;
    int status;
    uint32_t test_pri = 0;
    posix_spawnattr_t spattr;
    int32_t pf_balance;
    bool success;

    start_time = time(NULL);

    pid = 1;
    status = 1;
    
    posix_spawnattr_init(&spattr);
    posix_spawnattr_setjetsam(&spattr, (POSIX_SPAWN_JETSAM_USE_EFFECTIVE_PRIORITY | POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND), JETSAM_PRIORITY_UI_SUPPORT, 100);

    if (posix_spawn(&pid, path, NULL, &spattr, (char *const *)argv, NULL) < 0) {
        printf("posix_spawn() failed!\n");
        goto exit;
    }
    
    printTestHeader(pid, "Background memory limit test");
    
    /* Starts in background */
    if (!check_properties(pid, JETSAM_PRIORITY_UI_SUPPORT, memlimit, 0x0, "jetsam_test_background - #1 BG")) {
        goto exit;
    }
    
    /* Set to foreground - priority and memlimit should change */
    set_priority(pid, JETSAM_PRIORITY_FOREGROUND, 0);
    if (!check_properties(pid, JETSAM_PRIORITY_FOREGROUND, 0, 0x0, "jetsam_test_background - #2 FG")) {
        goto exit;
    }
    
    /* ...and back */
    set_priority(pid, JETSAM_PRIORITY_BACKGROUND, 0);
    if (!check_properties(pid, JETSAM_PRIORITY_BACKGROUND, memlimit, 0x0, "jetsam_test_background - #3 BG")) {
        goto exit;
    }
   
    /* ...and again */
    set_priority(pid, JETSAM_PRIORITY_FOREGROUND, 0);
    if (!check_properties(pid, JETSAM_PRIORITY_FOREGROUND, 0, 0x0, "jetsam_test_background - #4 FG")) {
        goto exit;
    }

#if 1
    /*
     * For now, this is all we can do. Limitations of the ledger mean that this process is credited with
     * the dirty pages, *not* the child. At least the memory limit is reported to have shifted dynamically
     * by this point. Kill the child and continue.
     */
     kill(pid, SIGKILL);
#else
    /* Let the process dirty 128MB of memory, then background itself */
    verify_exit(pid, kMemorystatusKilledPerProcessLimit, start_time, test_pri, 0, kBackgroundJetsamTest);
#endif

    success = true;
    
exit:
    if (pid != -1) {
        kill(pid, SIGKILL);
    }
    
    /* Wait for exit */
    waitpid(pid, &status, 0);

    printTestResult("Background test", success, NULL);
}

/* Freeze tests */

/* Cribbed from 'top'... */
static int
in_shared_region(mach_vm_address_t addr, cpu_type_t type) {
    mach_vm_address_t base = 0, size = 0;

    switch(type) {
        case CPU_TYPE_ARM:
            base = SHARED_REGION_BASE_ARM;
            size = SHARED_REGION_SIZE_ARM;
            break;

        case CPU_TYPE_X86_64:
            base = SHARED_REGION_BASE_X86_64;
            size = SHARED_REGION_SIZE_X86_64;
            break;

        case CPU_TYPE_I386:
            base = SHARED_REGION_BASE_I386;
            size = SHARED_REGION_SIZE_I386;
            break;

        case CPU_TYPE_POWERPC:
            base = SHARED_REGION_BASE_PPC;
            size = SHARED_REGION_SIZE_PPC;
            break;

        case CPU_TYPE_POWERPC64:
            base = SHARED_REGION_BASE_PPC64;
            size = SHARED_REGION_SIZE_PPC64;
            break;

        default: {
            int t = type;

            fprintf(stderr, "unknown CPU type: 0x%x\n", t);
            abort();
            }
            break;
    }

    return(addr >= base && addr < (base + size));
}

static unsigned long long get_rprvt(mach_port_t task, pid_t pid) {
    kern_return_t kr;

    mach_vm_size_t rprvt = 0;
    mach_vm_size_t empty = 0;
    mach_vm_size_t fw_private = 0;
    mach_vm_size_t pagesize = VM_PAGE_SIZE;
    mach_vm_size_t regs = 0;

    mach_vm_address_t addr;
    mach_vm_size_t size;

    int split = 0;

    for (addr = 0; ; addr += size) {
        vm_region_top_info_data_t info;
        mach_msg_type_number_t count = VM_REGION_TOP_INFO_COUNT;
        mach_port_t object_name;

        kr = mach_vm_region(task, &addr, &size, VM_REGION_TOP_INFO, (vm_region_info_t)&info, &count, &object_name);
        if (kr != KERN_SUCCESS) break;

        if (in_shared_region(addr, CPU_TYPE_ARM)) {
            // Private Shared
            fw_private += info.private_pages_resident * pagesize;

            /*
             * Check if this process has the globally shared
             * text and data regions mapped in.  If so, set
             * split to TRUE and avoid checking
             * again.
             */
            if (split == FALSE && info.share_mode == SM_EMPTY) {
                vm_region_basic_info_data_64_t	b_info;
                mach_vm_address_t b_addr = addr;
                mach_vm_size_t b_size = size;
                count = VM_REGION_BASIC_INFO_COUNT_64;

                kr = mach_vm_region(task, &b_addr, &b_size, VM_REGION_BASIC_INFO, (vm_region_info_t)&b_info, &count, &object_name);
                if (kr != KERN_SUCCESS) break;

                if (b_info.reserved) {
                    split = TRUE;
                }
            }

            /*
             * Short circuit the loop if this isn't a shared
             * private region, since that's the only region
             * type we care about within the current address
             * range.
             */
            if (info.share_mode != SM_PRIVATE) {
                continue;
            }
        }

        regs++;

        /*
         * Update counters according to the region type.
         */

        if (info.share_mode == SM_COW && info.ref_count == 1) {
            // Treat single reference SM_COW as SM_PRIVATE
            info.share_mode = SM_PRIVATE;
        }

        switch (info.share_mode) {
            case SM_LARGE_PAGE:
                // Treat SM_LARGE_PAGE the same as SM_PRIVATE
                // since they are not shareable and are wired.
            case SM_PRIVATE:
                rprvt += info.private_pages_resident * pagesize;
                rprvt += info.shared_pages_resident * pagesize;
                break;

            case SM_EMPTY:
                empty += size;
                break;

            case SM_COW:
            case SM_SHARED:
                if (pid == 0) {
                    // Treat kernel_task specially
                    if (info.share_mode == SM_COW) {
                        rprvt += info.private_pages_resident * pagesize;
                    }
                    break;
                }

                if (info.share_mode == SM_COW) {
                    rprvt += info.private_pages_resident * pagesize;
                }
                break;

            default:
                assert(0);
                break;
        }
    }

    return rprvt;
}

static void freeze_test() {
    const unsigned long DIRTY_ALLOC = 16 * 1024 * 1024;
    unsigned long *ptr;
    task_port_t task = mach_task_self();

    child_ready();

    /* Needs to be vm_allocate() here; otherwise the compiler will optimize memset away */
    vm_allocate(task, (vm_address_t *)&ptr, DIRTY_ALLOC, TRUE);
    if (ptr) {
        int i;
    	int pid = getpid();
    	unsigned long long baseline_rprvt, half_rprvt, rprvt;

    	/* Get baseline */
    	baseline_rprvt = get_rprvt(task, pid);

    	/* Dirty half */
    	memset(ptr, 0xAB, DIRTY_ALLOC / 2);

    	/* Check RPRVT */
    	half_rprvt = get_rprvt(task, pid);
    	printf("\t\trprvt is %llu\n", half_rprvt);
	
    	if (half_rprvt != (baseline_rprvt + (DIRTY_ALLOC / 2)))
    	{
            printTestResult(__func__, false, "Failed to dirty memory");
            cleanup_and_exit(-1);
    	}

    	/* Freeze */
    	sysctlbyname("kern.memorystatus_freeze", NULL, 0, &pid, sizeof(pid));

    	sleep(2);

    	/* Check RPRVT */
    	rprvt = get_rprvt(task, pid);
    	printf("\t\trprvt is %llu\n", rprvt);

    	if ((rprvt > (half_rprvt - (DIRTY_ALLOC / 2))) || (rprvt > (64 * 1024)) /* Sanity */)
    	{
            printTestResult(__func__, false, "Failed to freeze memory");
            cleanup_and_exit(-1);
    	}

        /* Thaw */
        sysctlbyname("kern.memorystatus_thaw", NULL, 0, &pid, sizeof(pid));

        sleep(2);

        /* Check RPRVT */
        rprvt = get_rprvt(task, pid);
        printf("\t\trprvt is %llu\n", rprvt);

    	if (rprvt < (baseline_rprvt + (DIRTY_ALLOC / 2)))
    	{
            printTestResult(__func__, false, "Failed to thaw memory");
            cleanup_and_exit(-1);
    	}

    	/* Dirty the rest */
    	memset(ptr + (DIRTY_ALLOC / (2 * sizeof(unsigned long))), 0xBC, DIRTY_ALLOC / 2);

    	/* Check RPRVT */
    	rprvt = get_rprvt(task, pid);
    	printf("\t\trprvt is %llu\n", rprvt);

    	if (rprvt < (baseline_rprvt + DIRTY_ALLOC))
    	{
            printTestResult(__func__, false, "Failed to dirty memory");
            cleanup_and_exit(-1);
    	}

        g_shared->completed = 1;
        cleanup_and_exit(0);
    }

    printTestResult(__func__, false, "Something bad happened...");
    cleanup_and_exit(-1);
}

static void start_freeze_test() {
    pid_t pid;
    int status;
    int mode;
    size_t size;
	
    /* Check to see if the test is applicable */
    size = sizeof(mode);
    if (sysctlbyname("vm.compressor_mode", &mode, &size, NULL, 0) != 0) {
        printTestHeader(getpid(), "Freeze test");
        printTestResult(__func__, false, "Failed to retrieve compressor config");
        cleanup_and_exit(-1);
    }
    
    if (mode != VM_PAGER_FREEZER_DEFAULT) {
        printTestHeader(getpid(), "Freeze test");
        printTestResult(__func__, true, "Freeze disabled; skipping test");
        return;
    }
	
    /* Reset */
    memset(g_shared, 0, sizeof(shared_mem_t));
    
    pid = init_and_fork();
    if (pid == 0) {
        freeze_test();
    } else {
        printTestHeader(pid, "Freeze test");
    }

    /* Wait for exit */
    waitpid(pid, &status, 0);

    printTestResult("Freeze test", g_shared->completed, NULL);
}

#endif

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
    free(entries);
    
    printTestResult("List validation test", valid, NULL);
}

/* Random individual tests */
static void start_general_sanity_test() {
    int ret, size;
    memorystatus_priority_entry_t *entries = NULL;
    int i;
    boolean_t valid = false;
    
    printTestHeader(getpid(), "Sanity test");
    
    /* Should not be able to set the priority of launchd... */
    ret = set_priority(1, JETSAM_PRIORITY_FOREGROUND, 0);
    if (ret != -1 || errno != EPERM) {
        printf("\t\tAble to set priority of launchd (%d/%d)!\n", ret, errno);
        goto exit;           
    } else {
        printf("\t\tlaunchd priority test OK!\n");    
    }
    
    /* ...nor the memory limit... */
    ret = set_memlimit(1, 100);
    if (ret != -1 || errno != EPERM) {
        printf("\t\tNo EPERM setting launchd memlimit (%d/%d)!\n", ret, errno);
        goto exit;           
    } else {
        printf("\t\tlaunchd memlimit test OK!\n");    
    }
    
    /* ...nor tinker with transactions */
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
    free(entries);
    
    printTestResult("Idle exit test", valid, NULL);
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
        
        proc_track_dirty(getpid(), PROC_DIRTY_TRACK | PROC_DIRTY_ALLOW_IDLE_EXIT);

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
        
        proc_track_dirty(getpid(), PROC_DIRTY_TRACK | PROC_DIRTY_ALLOW_IDLE_EXIT);
  
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
    cleanup_and_exit(0);
        
exit:
    printTestResult(__func__, false, "Something bad happened...");
    cleanup_and_exit(-1);
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
        printTestHeader(pid, "Idle exit deferral test");
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
#if TARGET_OS_EMBEDDED
    start_jetsam_test(kSimpleJetsamTest, "Simple munch");
    start_jetsam_test(kHighwaterJetsamTest, "Highwater munch");
    start_jetsam_test(kPressureJetsamTestBG, "Background pressure munch");
    start_jetsam_test(kPressureJetsamTestFG, "Foreground Pressure munch");
    start_jetsam_test_background(path);
    start_freeze_test();
    start_priority_test();
    start_fs_priority_test();
#else
#pragma unused(path)
#endif
    
    /* Generic */
    start_general_sanity_test();
    start_list_validation_test();
    start_idle_exit_defer_test(kDeferTimeoutCleanTest);
    start_idle_exit_defer_test(kDeferTimeoutDirtyTest);
    start_idle_exit_defer_test(kCancelTimeoutCleanTest);
    start_idle_exit_defer_test(kCancelTimeoutDirtyTest);
}

#if TARGET_OS_EMBEDDED

static void
sigterm(int sig)
{
    /* Reload crash reporter job */
    enable_crashreporter();
    
    /* Reset signal handlers and re-raise signal */
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    
    kill(getpid(), sig);
}

#endif

int main(int argc, char **argv)
{
    pthread_mutexattr_t attr;
    pthread_condattr_t cattr;
    size_t size;
#if TARGET_OS_EMBEDDED
    struct sigaction sa;
#endif

    /* Must be run as root for priority retrieval */
    if (getuid() != 0) {
        fprintf(stderr, "%s must be run as root.\n", getprogname());
        exit(EXIT_FAILURE);
    }
    
#if TARGET_OS_EMBEDDED
    /* Spawn test */    
    if ((argc == 2) && !strcmp(argv[1], "-s")) {
        spawn_test();
    }

    sa.sa_flags = 0;
    sa.sa_handler = sigterm;
    sigemptyset(&sa.sa_mask);
	
	/* Ensure we can reinstate CrashReporter on exit */
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /* Unload */
    disable_crashreporter();

    /* Flush the jetsam snapshot */
    verify_snapshot(-1, 0, 0, 0, FALSE);
#endif

    /* Memory */
    size = sizeof(g_physmem);
    if (sysctlbyname("hw.physmem", &g_physmem, &size, NULL, 0) != 0 || !g_physmem) {
        printTestResult(__func__, false, "Failed to retrieve system memory");
        cleanup_and_exit(-1);
    }

    /* Ledger; default limit applies to this process, so grab it here */
    ledger_init();
    if ((-1 == g_ledger_count) || (-1 == g_footprint_index) || (false == get_ledger_info(getpid(), NULL, &g_per_process_limit))) {
        printTestResult("setup", false, "Unable to init ledger!\n");
        cleanup_and_exit(-1);            
    }
    
    /* Rescale to MB */
    g_per_process_limit /= (1024 * 1024);
    
    /* Shared memory */
    g_shared = mmap(NULL, sizeof(shared_mem_t), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, 0, 0);
    if (!g_shared) {
        printTestResult(__func__, false, "Failed mmap");
        cleanup_and_exit(-1);
    }

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED );

    pthread_condattr_init(&cattr);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);

    if (pthread_mutex_init(&g_shared->mutex, &attr) || pthread_cond_init(&g_shared->cv, &cattr)) {
        printTestResult("setup", false, "Unable to init condition variable!\n");
        cleanup_and_exit(-1);
    }

    run_tests(argv[0]);

    /* Teardown */
    pthread_mutex_destroy(&g_shared->mutex);
    pthread_cond_destroy(&g_shared->cv);

    pthread_mutexattr_destroy(&attr);
    pthread_condattr_destroy(&cattr);

#if TARGET_OS_EMBEDDED
    /* Reload crash reporter */
    enable_crashreporter();
#endif

    return 0;
}
