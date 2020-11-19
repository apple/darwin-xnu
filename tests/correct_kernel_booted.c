// Copyright (c) 2020 Apple, Inc.  All rights reserved.

#include <darwintest.h>
#include <dirent.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>
#include <unistd.h>
#include <uuid/uuid.h>

static bool
get_macho_uuid(const char *cwd, const char *path, uuid_t uuid)
{
	bool found = false;
	void *mapped = MAP_FAILED;
	size_t mapped_len = 0;

	T_SETUPBEGIN;

	// Skip irregular files (directories, devices, etc.).
	struct stat stbuf = {};
	int ret = stat(path, &stbuf);
	if (ret < 0 && errno == ENOENT) {
		goto out;
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "should stat %s%s", cwd, path);
	if ((stbuf.st_mode & S_IFREG) == 0) {
		goto out;
	}
	if (stbuf.st_size < (off_t)sizeof(struct mach_header)) {
		goto out;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0 && (errno == EPERM || errno == EACCES || errno == ENOENT)) {
		goto out;
	}
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fd, "should open file at %s%s", cwd, path);

	mapped = mmap(NULL, (size_t)stbuf.st_size, PROT_READ, MAP_PRIVATE,
	    fd, 0);
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NE(mapped, MAP_FAILED, "should map Mach-O binary at %s%s",
	    cwd, path);
	(void)close(fd);

	// Mach-O parsing boilerplate.
	uint32_t magic = *(uint32_t *)mapped;
	bool should_swap = false;
	bool b32 = false;
	// XXX This does not handle fat binaries.
	switch (magic) {
	case MH_CIGAM:
		should_swap = true;
		OS_FALLTHROUGH;
	case MH_MAGIC:
		b32 = true;
		break;
	case MH_CIGAM_64:
		should_swap = true;
		break;
	case MH_MAGIC_64:
		break;
	default:
		goto out;
	}
	const struct load_command *lcmd = NULL;
	unsigned int ncmds = 0;
	if (b32) {
		const struct mach_header *hdr = mapped;
		ncmds = hdr->ncmds;
		lcmd = (const void *)((const char *)mapped + sizeof(*hdr));
	} else {
		const struct mach_header_64 *hdr = mapped;
		ncmds = hdr->ncmds;
		lcmd = (const void *)((const char *)mapped + sizeof(*hdr));
	}
	ncmds = should_swap ? OSSwapInt32(ncmds) : ncmds;

	// Scan through load commands to find LC_UUID.
	for (unsigned int i = 0; i < ncmds; i++) {
		if ((should_swap ? OSSwapInt32(lcmd->cmd) : lcmd->cmd) == LC_UUID) {
			const struct uuid_command *uuid_cmd = (const void *)lcmd;
			uuid_copy(uuid, uuid_cmd->uuid);
			found = true;
			break;
		}

		uint32_t cmdsize = should_swap ? OSSwapInt32(lcmd->cmdsize) :
		    lcmd->cmdsize;
		lcmd = (const void *)((const char *)lcmd + cmdsize);
	}

	if (!found) {
		T_LOG("could not find LC_UUID in Mach-O at %s%s", cwd, path);
	}

out:
	T_SETUPEND;

	if (mapped != MAP_FAILED) {
		munmap(mapped, mapped_len);
	}
	return found;
}

T_DECL(correct_kernel_booted,
    "Make sure the kernel on disk matches the running kernel, by UUID.",
    T_META_RUN_CONCURRENTLY(true))
{
	T_SETUPBEGIN;

	uuid_t kern_uuid;
	uuid_string_t kern_uuid_str;
	size_t kern_uuid_size = sizeof(kern_uuid_str);
	int ret = sysctlbyname("kern.uuid", &kern_uuid_str, &kern_uuid_size, NULL,
	    0);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "should get running kernel UUID");
	T_LOG("%s: running kernel", kern_uuid_str);

	ret = uuid_parse(kern_uuid_str, kern_uuid);
	T_QUIET; T_ASSERT_EQ(ret, 0, "should parse kernel UUID into bytes");

#if TARGET_OS_OSX
	const char *kernels_path = "/System/Library/Kernels/";
#else // TARGET_OS_OSX
	const char *kernels_path = "/";
#endif // !TARGET_OS_OSX
	T_LOG("searching for kernels at %s", kernels_path);

	ret = chdir(kernels_path);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "should change directory to %s",
	    kernels_path);

	DIR *kernels_dir = opendir(kernels_path);
	T_QUIET; T_ASSERT_NOTNULL(kernels_dir, "should open directory at %s",
	    kernels_path);

	T_SETUPEND;

	bool found = false;
	struct dirent *entry = NULL;
	while ((entry = readdir(kernels_dir)) != NULL) {
		uuid_t bin_uuid;
		bool ok = get_macho_uuid(kernels_path, entry->d_name, bin_uuid);
		if (ok) {
			uuid_string_t bin_uuid_str;
			uuid_unparse(bin_uuid, bin_uuid_str);
			T_LOG("%s: from %s%s", bin_uuid_str, kernels_path, entry->d_name);
			if (uuid_compare(bin_uuid, kern_uuid) == 0) {
				found = true;
				T_PASS("UUID from %s%s matches kernel UUID", kernels_path,
				    entry->d_name);
			}
		}
	}
	if (!found) {
		T_FAIL("failed to find kernel binary with UUID of the running kernel, "
		    "wrong kernel is booted");
	}
}
