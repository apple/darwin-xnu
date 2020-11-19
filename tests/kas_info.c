/* Copyright (c) 2020 Apple Computer, Inc.  All rights reserved. */

#include <CoreSymbolication/CoreSymbolication.h>
#include <CoreSymbolication/CoreSymbolicationPrivate.h>
#include <darwintest.h>
#include <dispatch/dispatch.h>

#include <mach-o/loader.h>

#include <sys/kas_info.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <fcntl.h>

#include <stdint.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.kas_info"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true));

static bool
slide_enabled(void)
{
	int slide_enabled, err;
	size_t size = sizeof(slide_enabled);
	err = sysctlbyname("kern.slide", &slide_enabled, &size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(err, "sysctl(\"kern.slide\");");
	return slide_enabled != 0;
}

static uint64_t
kernel_slide(void)
{
	uint64_t slide;
	size_t size = sizeof(slide);
	int err = kas_info(KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR, &slide, &size);
	if (err && errno == ENOTSUP) {
		T_SKIP("Running on kernel without kas_info");
	}

	T_ASSERT_POSIX_SUCCESS(errno, "kas_info KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR");
	T_ASSERT_EQ(size, sizeof(slide), "returned size is valid");

	return slide;
}

T_DECL(kernel_text_slide,
    "ensures that kas_info can return the kernel text slide")
{
	if (!slide_enabled()) {
		T_SKIP("KASLR is not enabled");
		__builtin_unreachable();
	}

	uint64_t slide = kernel_slide();

	T_ASSERT_GT_ULLONG(slide, 0ULL, "kernel slide is non-zero");
}

T_DECL(kernel_text_slide_invalid,
    "ensures that kas_info handles invalid input to KERNEL_TEXT_SLIDE_SELECTOR")
{
	uint64_t slide;
	size_t size = 0;
	int err;

	err = kas_info(KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR, &slide, NULL);
	if (errno == ENOTSUP) {
		T_SKIP("Running on kernel without kas_info");
	}
	T_ASSERT_POSIX_FAILURE(err, EFAULT, "kas_info with NULL size");

	size = sizeof(uint64_t);
	err = kas_info(KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR, NULL, &size);
	T_ASSERT_POSIX_FAILURE(err, EFAULT, "kas_info with NULL slide");

	size = sizeof(uint32_t);
	err = kas_info(KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR, &slide, &size);
	T_ASSERT_POSIX_FAILURE(err, EINVAL, "kas_info with invalid size");
}

static char const*
kernel_path(void)
{
	static CSSymbolicatorRef symbolicator;
	static char const* path;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		uint32_t flags = kCSSymbolicatorDefaultCreateFlags;
		symbolicator = CSSymbolicatorCreateWithMachKernelFlagsAndNotification(flags, NULL);
		T_QUIET; T_ASSERT_TRUE(!CSIsNull(symbolicator), "CSSymbolicatorCreateWithMachKernelFlagsAndNotification");
		path = CSSymbolOwnerGetPath(CSSymbolicatorGetAOutSymbolOwner(symbolicator));
		if (!path) {
		        path = CSSymbolOwnerGetPath(CSSymbolicatorGetSymbolOwner(symbolicator));
		}
		T_QUIET; T_ASSERT_NOTNULL(path, "CSSymbolOwnerGetPath/CSSymbolicatorGetSymbolOwner");
	});
	return path;
}

static void
disk_kernel_segments(uint64_t **segs_out, size_t *nsegs_out)
{
	char const* path = kernel_path();
	int fd = open(path, O_RDONLY);
	int err;
	struct stat sb;
	size_t nsegs = 0;
	uint64_t *segs = NULL;
	void *data;

	T_LOG("Kernel file is %s", path);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "open kernel file");

	err = fstat(fd, &sb);
	T_ASSERT_POSIX_SUCCESS(err, "fstat kernel file");

	data = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	T_ASSERT_NE(data, MAP_FAILED, "mmap kernel file");

	/*
	 * TODO: If we bring back FAT kernel binaries
	 * this will need to be fixed to handle them properly
	 */
	uint32_t magic = *(uint32_t*)data;
	struct load_command *cmd = NULL;

	switch (magic) {
	case MH_MAGIC: OS_FALLTHROUGH;
	case MH_CIGAM: {
		struct mach_header *mh = (struct mach_header *)data;
		cmd = (struct load_command *)(&(mh[1]));
		nsegs = mh->ncmds;
	}
	break;
	case MH_MAGIC_64: OS_FALLTHROUGH;
	case MH_CIGAM_64: {
		struct mach_header_64 *mh = (struct mach_header_64 *)data;
		cmd = (struct load_command *)(&(mh[1]));
		nsegs = mh->ncmds;
	}
	break;
	default:
		T_FAIL("kernel file is not a Mach-O file, magic is %x", magic);
	}

	/* Adjust for the LC_UUID && LC_BUILD_VERSION commands in front of
	 * load commands for dSYMs
	 */
	while (cmd->cmd != LC_SEGMENT && cmd->cmd != LC_SEGMENT_64) {
		cmd = (struct load_command *) ((uintptr_t) cmd + cmd->cmdsize);
		nsegs--;
	}

	segs = calloc(nsegs, sizeof(*segs));
	T_ASSERT_NOTNULL(segs, "calloc disk segment array");

	for (uint8_t i = 0; i < nsegs; i++) {
		if (cmd->cmd == LC_SEGMENT) {
			struct segment_command *sg = (struct segment_command *) cmd;
			if (sg->vmsize > 0) {
				segs[i] = sg->vmaddr;
			}
		} else if (cmd->cmd == LC_SEGMENT_64) {
			struct segment_command_64 *sg = (struct segment_command_64 *) cmd;
			if (sg->vmsize > 0) {
				segs[i] = sg->vmaddr;
			}
		}
		cmd = (struct load_command *) ((uintptr_t) cmd + cmd->cmdsize);
	}

	*segs_out = segs;
	*nsegs_out = nsegs;

	err = munmap(data, (size_t)sb.st_size);

	err = close(fd);
	T_ASSERT_POSIX_SUCCESS(err, "close kernel fd");
}

static bool
is_fileset_kc(void)
{
	char uuid[1024];
	int err;
	size_t size = sizeof(uuid);
	err = sysctlbyname("kern.filesetuuid", uuid, &size, NULL, 0);
	return err == 0;
}

#define KAS_INFO_KERNEL_SEGMENT_LOCATION_SELECTOR 1

T_DECL(kernel_segment_location,
    "ensures that KAS_INFO_KERNEL_SEGMENT_LOCATION returns correct segment locations")
{
	int err;

	if (!slide_enabled()) {
		T_SKIP("KASLR is not enabled");
		__builtin_unreachable();
	}

	uint64_t *disk_segs;
	size_t disk_nsegs;
	disk_kernel_segments(&disk_segs, &disk_nsegs);

	size_t size = 0;

	err = kas_info(KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR, NULL, &size);
	if (errno == ENOTSUP) {
		T_SKIP("KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR not supported");
	}
	T_ASSERT_POSIX_SUCCESS(err, "kas_info KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR for size");

	uint64_t mem_nsegs = size / sizeof(uint64_t);
	uint64_t *mem_segs = calloc(mem_nsegs, sizeof(*disk_segs));

	err = kas_info(KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR, mem_segs, &size);
	if (errno == ENOTSUP) {
		T_SKIP("KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR not supported");
	}

	T_ASSERT_POSIX_SUCCESS(err, "kas_info KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR for data");

	T_LOG("Kernel has %zu segments on disk, %zu in memory:", disk_nsegs, mem_nsegs);
	for (size_t i = 0; i < disk_nsegs; i++) {
		T_LOG("%zu %llx %llx", i, disk_segs[i], mem_segs[i]);
	}

	/*
	 * If the kernel is not a fileset, verify that all
	 * the segments in memory are the segment on disk
	 * + the kaslr slide
	 */
	if (!is_fileset_kc()) {
		T_LOG("Kernelcache is not a fileset kernelcache");

		uint64_t slide = kernel_slide();
		for (size_t i = 0; i < disk_nsegs; i++) {
			if (disk_segs[i] == 0 || mem_segs[i] == 0) {
				continue;
			}
			T_ASSERT_EQ(disk_segs[i] + slide, mem_segs[i], "segment %zu is slid", i);
		}
	}

	free(disk_segs);
	free(mem_segs);
}
