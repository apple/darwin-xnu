#define PRIVATE
#include <darwintest.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/spawn_internal.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sys/reason.h>
#include <sysexits.h>
#include <unistd.h>
#include <signal.h>
#include <libproc.h>
#undef PRIVATE

#include <mach-o/dyld.h>
#include <mach-o/dyld_priv.h>
#include <dlfcn.h>

#define SHARED_CACHE_HELPER "get_shared_cache_address"
#define DO_RUSAGE_CHECK "check_rusage_flag"
#define DO_DUMMY "dummy"
#define ADDRESS_OUTPUT_SIZE     12L

#ifndef _POSIX_SPAWN_RESLIDE
#define _POSIX_SPAWN_RESLIDE    0x0800
#endif

#ifndef OS_REASON_FLAG_SHAREDREGION_FAULT
#define OS_REASON_FLAG_SHAREDREGION_FAULT       0x400
#endif

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));


T_DECL(reslide_sharedcache, "crash induced reslide of the shared cache",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*shared_cache_reslide_test.*"),
    T_META_ASROOT(true))
{
	T_SKIP("shared cache reslide is currently only supported on arm64e iPhones");
}
