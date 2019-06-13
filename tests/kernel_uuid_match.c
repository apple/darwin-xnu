#include <darwintest.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>
#include <glob.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/swap.h>
#include <libkern/OSByteOrder.h>

#define MAX_LEN 1024

#if TARGET_OS_MAC && !TARGET_OS_EMBEDDED
	//running on macOS
	#define KERNEL_SEARCH_DIR "/System/Library/Kernels/*"
#else
	//running on a different OS (e.g. iOS, watchOS, etc.)
	#define KERNEL_SEARCH_DIR "/*"
#endif

#define SWAP32(v)		v = OSSwapInt32(v)


/* opens and maps the file at [path] in memory,
 * sets the length in [len] and returns a pointer
 * to the beginning of the memory region or NULL
 * if unable to open and map the file
 */
static void *open_file(char *path, size_t *len) {
	int fd;
	if ((fd = open(path, O_RDONLY)) < 0) {
		return NULL;
	}
	*len = (size_t)lseek(fd, (off_t)0, SEEK_END);
	void *p = mmap(NULL, *len, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		return NULL;
	}
	return p;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
static void __swap_mach_header(struct mach_header *header) {
	SWAP32(header->magic);
	SWAP32(header->cputype);
	SWAP32(header->cpusubtype);
	SWAP32(header->filetype);
	SWAP32(header->ncmds);
	SWAP32(header->sizeofcmds);
	SWAP32(header->flags);
}

static void __swap_mach_header_64(struct mach_header_64 *header) {
	SWAP32(header->magic);
	SWAP32(header->cputype);
	SWAP32(header->cpusubtype);
	SWAP32(header->filetype);
	SWAP32(header->ncmds);
	SWAP32(header->sizeofcmds);
	SWAP32(header->flags);
}
#pragma clang diagnostic pop

/* parses the uuid from the file at [path] and sets the uuid in [uuid]
 * returns true if successfully parses the file, returns false otherwise
 * (e.g. the file is not a Mach-O binary)
 */
static bool parse_binary_uuid(char *path, uuid_t uuid) {
	size_t len = 0;
	bool should_swap = false;
	unsigned int ncmds = 0;
	struct load_command *lc = NULL;
	bool ret = false;

	struct mach_header *h = open_file(path, &len);
	if (!h) {
		return false;
	}
	if (h->magic == MH_MAGIC || h->magic == MH_CIGAM) {
		//32-bit header
		struct mach_header *header = h;
		if (header->magic == MH_CIGAM) {
			__swap_mach_header(header);
			should_swap = true;
		}
		ncmds = header->ncmds;
		//the first load command is after the header
		lc = (struct load_command *)(header + 1);
	} else if (h->magic == MH_MAGIC_64 || h->magic == MH_CIGAM_64) {
		//64-bit header
		struct mach_header_64 *header = (struct mach_header_64 *)h;
		if (header->magic == MH_CIGAM_64) {
			__swap_mach_header_64(header);
			should_swap = true;
		}
		ncmds = header->ncmds;
		lc = (struct load_command *)(header + 1);
	} else {
		//this is not a Mach-O binary, or it is a FAT binary
		munmap(h, len);
		return false;
	}
	for (unsigned int i = 0; i < ncmds; i++) {
		uint32_t cmd = lc->cmd;
		uint32_t cmdsize = lc->cmdsize;
		if (should_swap) {
			SWAP32(cmd);
			SWAP32(cmdsize);
		}
		if (cmd == LC_UUID) {
			struct uuid_command *uuid_cmd =
					(struct uuid_command *)lc;
			uuid_copy(uuid, uuid_cmd->uuid);
			uuid_string_t tuuid_str;
			uuid_unparse(uuid, tuuid_str);
			T_LOG("Trying test UUID %s", tuuid_str);
			ret = true;
			break;
		}
		lc = (struct load_command *)((uintptr_t)lc + cmdsize);
	}
	munmap(h, len);
	return ret;
}

/* uses the sysctl command line tool to get the uuid
 * of the currently running kernel
 */
static void get_system_kernel_uuid(uuid_t kuuid) {
	char kuuid_line[MAX_LEN];
	memset(kuuid_line, 0, sizeof(kuuid_line));
	size_t len = sizeof(kuuid_line);
	int ret = sysctlbyname("kern.uuid", kuuid_line, &len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.uuid");

	T_ASSERT_TRUE(uuid_parse(kuuid_line, kuuid) == 0,
			"Parse running kernel uuid");
}

/* compares [kuuid] to the uuid in each of the kernel binaries on OS's
 * other than macOS (there can be multiple kernel binaries if the mastering
 * process doesn't remove all of the irrelevant binaries)
 */
static void find_and_compare_test_uuids(char *search_path, uuid_t kuuid) {
	glob_t g;
	int ret = glob(search_path, 0, NULL, &g);
	T_WITH_ERRNO; T_ASSERT_EQ(ret, 0, "glob %s", search_path);

	bool pass = false;
	for (int i = 0; i < g.gl_matchc; i++) {
		char *path = g.gl_pathv[i];

		//check that [path] is the path for a file (not a directory, device, etc.)
		struct stat s;
		int ret = stat(path, &s);
		T_ASSERT_POSIX_SUCCESS(ret, "stat %s", path);
		if ((s.st_mode & S_IFREG) == 0) {
			continue;
		}

		T_LOG("Reading file at path: %s", path);
		uuid_t tuuid;
		if (parse_binary_uuid(path, tuuid) &&
				uuid_compare(kuuid, tuuid) == 0) {
			pass = true;
			break;
		}
	}
	globfree(&g);
	T_EXPECT_TRUE(pass, "The sources match");
}

T_DECL(uuid_match, "Compare the running kernel UUID to kernel binaries.")
{
	uuid_t kuuid;
	uuid_clear(kuuid);
	get_system_kernel_uuid(kuuid);
	uuid_string_t kuuid_str;
	uuid_unparse(kuuid, kuuid_str);
	T_LOG("Got running kernel UUID %s", kuuid_str);
	find_and_compare_test_uuids(KERNEL_SEARCH_DIR, kuuid);
}
