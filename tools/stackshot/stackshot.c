
#include <stdio.h>
#include <dispatch/dispatch.h>
#include <sysexits.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <mach/mach_time.h>
#include <sys/stackshot.h>
#include <sys/types.h>
#include <kern/debug.h>
#include <unistd.h>
#include <assert.h>

#include <kern/kcdata.h>

#define	STACKSHOT_TAILSPIN (0x80000)

uint64_t
stackshot_get_mach_absolute_time(void *buffer, uint32_t size)
{
    kcdata_iter_t iter = kcdata_iter_find_type(kcdata_iter(buffer, size), KCDATA_TYPE_MACH_ABSOLUTE_TIME);
    if (!kcdata_iter_valid(iter) || kcdata_iter_size(iter) < sizeof(uint64_t)) {
        fprintf(stderr, "bad kcdata\n");
        exit(1);
    }
    return *(uint64_t *)kcdata_iter_payload(iter);
}

static void usage(char **argv)
{
	fprintf (stderr, "usage: %s [-d] [-t] >file\n", argv[0]);
    fprintf (stderr, "    -d      : take delta stackshot\n");
    fprintf (stderr, "    -b      : get bootprofile\n");
    fprintf (stderr, "    -t      : enable tailspin mode\n");
    fprintf (stderr, "    -s      : fork a sleep process\n");
    fprintf (stderr, "    -L      : disable loadinfo\n");
    fprintf (stderr, "    -k      : active kernel threads only\n");
    fprintf (stderr, "    -I      : disable io statistics\n");
    fprintf (stderr, "    -p PID  : target a pid\n");
	exit(1);
}

void forksleep() {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        execlp("sleep", "sleep", "30", NULL);
        perror("execlp");
        exit(1);
    }
}


int main(int argc, char **argv) {

    uint32_t iostats = 0;
    uint32_t active_kernel_threads_only = 0;
    uint32_t tailspin = 0;
    uint32_t bootprofile = 0;
    uint32_t loadinfo = STACKSHOT_SAVE_LOADINFO | STACKSHOT_SAVE_KEXT_LOADINFO;
    boolean_t delta = FALSE;
    boolean_t sleep = FALSE;
    pid_t pid = -1;
    int c;

    while ((c = getopt(argc, argv, "IkbLdtsp:")) != EOF) {
        switch(c) {
        case 'I':
            iostats |= STACKSHOT_NO_IO_STATS;
            break;
        case 'k':
            active_kernel_threads_only |= STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY;
            loadinfo &= ~STACKSHOT_SAVE_LOADINFO;
            break;
        case 'b':
            bootprofile |= STACKSHOT_GET_BOOT_PROFILE;
            break;
        case 'L':
            loadinfo = 0;
            break;
        case 't':
            tailspin |= STACKSHOT_TAILSPIN;
            break;
        case 'd':
            delta = TRUE;
            break;
        case 's':
            sleep = TRUE;
            break;
        case 'p':
            pid = atoi(optarg);
            break;
        case '?':
        case 'h':
        default:
            usage(argv);
            break;
        }
    }

    if (optind < argc)
    {
        usage(argv);
    }

    void * config = stackshot_config_create();
    if (!config) {
        perror("stackshot_config_create");
        return 1;
    }
    uint32_t flags =  loadinfo | STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_GET_DQ | STACKSHOT_KCDATA_FORMAT |
        tailspin | bootprofile | active_kernel_threads_only | iostats;

    int err = stackshot_config_set_flags(config, flags);
    if (err != 0) {
        perror("stackshot_config_set_flags");
        return 1;
    }

    if (pid != -1) {
        int err = stackshot_config_set_pid(config, pid);
        if (err != 0) {
            perror("stackshot_config_set_flags");
            return 1;
        }
    }

    err = stackshot_capture_with_config(config);
    if (err != 0) {
        perror("stackshot_capture_with_config");
        return 1;
    }

    void *buf = stackshot_config_get_stackshot_buffer(config);
    if (!buf) {
        perror("stackshot_config_get_stackshot_buffer");
        return 1;
    }

    uint32_t size = stackshot_config_get_stackshot_size(config);

    if (delta) {
        // output the original somewhere?

        uint64_t time = stackshot_get_mach_absolute_time(buf, size);

        err = stackshot_config_dealloc_buffer(config);
        assert(!err);

        flags |= STACKSHOT_COLLECT_DELTA_SNAPSHOT;
        int err = stackshot_config_set_flags(config, flags);
        if (err != 0) {
            perror("stackshot_config_set_flags");
            return 1;
        }

        err = stackshot_config_set_delta_timestamp(config, time);
        if (err != 0) {
            perror("stackshot_config_delta_timestamp");
            return 1;
        }

        if (sleep) {
            forksleep();
        }
        usleep(10000);

        err = stackshot_capture_with_config(config);
        if (err != 0) {
            perror("stackshot_capture_with_config");
            return 1;
        }

        buf = stackshot_config_get_stackshot_buffer(config);
        if (!buf) {
            perror("stackshot_config_get_stackshot_buffer");
            return 1;
        }

        size = stackshot_config_get_stackshot_size(config);

    }

    fwrite(buf, size, 1, stdout);
}
