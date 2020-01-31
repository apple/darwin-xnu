/*
 * This tests the Mac OS X Superpage API introduced in 10.7
 *
 * Note that most of these calls go through the mach_vm_allocate() interface,
 * but the actually supported and documented interface is the mmap() one
 * (see mmap(2)).
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define SUPERPAGE_SIZE (2*1024*1024)
#define SUPERPAGE_MASK (-SUPERPAGE_SIZE)

#ifdef __LP64__
#define FIXED_ADDRESS1 (0x100000000ULL+500*1024*1024) /* at 4 GB + 500 MB virtual */
#define FIXED_ADDRESS2 (0x100000000ULL+502*1024*1024 + 4*1024) /* at 4 GB + 502 MB + 4 KB virtual */
#else
#define FIXED_ADDRESS1 (500*1024*1024) /* at 500 MB virtual */
#define FIXED_ADDRESS2 (502*1024*1024 + 4*1024) /* at 502 MB + 4 KB virtual */
#endif

char error[100];

jmp_buf resume;
void
test_signal_handler(int signo)
{
	longjmp(resume, signo);
}

char *signame[32] = {
	[SIGBUS] "SIGBUS",
	[SIGSEGV] "SIGSEGV"
};

typedef struct {
	char *description;
	boolean_t (*fn)();
} test_t;

boolean_t
check_kr(int kr, char *fn)
{
	if (kr) {
		sprintf(error, "%s() returned %d", fn, kr);
		return FALSE;
	}
	return TRUE;
}

boolean_t
check_addr0(mach_vm_address_t addr, char *fn)
{
	if (!addr) {
		sprintf(error, "%s() returned address 0", fn);
		return FALSE;
	}
	return TRUE;
}

boolean_t
check_addr(mach_vm_address_t addr1, mach_vm_address_t addr2, char *fn)
{
	if (addr1 != addr2) {
		sprintf(error, "%s() returned address %llx instead of %llx", fn, addr1, addr2);
		return FALSE;
	}
	return TRUE;
}

boolean_t
check_align(mach_vm_address_t addr)
{
	if (addr & !SUPERPAGE_MASK) {
		sprintf(error, "address not aligned properly: 0x%llx", addr);
		return FALSE;
	}
	return TRUE;
}

boolean_t
check_r(mach_vm_address_t addr, mach_vm_size_t size, int *res)
{
	volatile char *data = (char*)(uintptr_t)addr;
	int i, sig, test;

	if ((sig = setjmp(resume)) != 0) {
		sprintf(error, "%s when reading", signame[sig]);
		return FALSE;
	}
	test = 0;
	for (i = 0; i < size; i++) {
		test += (data)[i];
	}

	if (res) {
		*res = test;
	}

	return TRUE;
}

/* check that no subpage of the superpage is readable */
boolean_t
check_nr(mach_vm_address_t addr, mach_vm_size_t size, int *res)
{
	int i;
	boolean_t ret;
	for (i = 0; i < size / PAGE_SIZE; i++) {
		if ((ret = check_r(addr + i * PAGE_SIZE, PAGE_SIZE, res))) {
			sprintf(error, "page still readable");
			return FALSE;
		}
	}
	return TRUE;
}

boolean_t
check_w(mach_vm_address_t addr, mach_vm_size_t size)
{
	char *data = (char*)(uintptr_t)addr;
	int i, sig;

	if ((sig = setjmp(resume)) != 0) {
		sprintf(error, "%s when writing", signame[sig]);
		return FALSE;
	}

	for (i = 0; i < size; i++) {
		(data)[i] = i & 0xFF;
	}

	return TRUE;
}

boolean_t
check_nw(mach_vm_address_t addr, mach_vm_size_t size)
{
	int i;
	boolean_t ret;

	for (i = 0; i < size / PAGE_SIZE; i++) {
		if ((ret = check_w(addr + i * PAGE_SIZE, PAGE_SIZE))) {
			sprintf(error, "page still writable");
			return FALSE;
		}
	}
	return TRUE;
}

boolean_t
check_rw(mach_vm_address_t addr, mach_vm_size_t size)
{
	int ret;
	int res;
	if (!(ret = check_w(addr, size))) {
		return ret;
	}
	if (!(ret = check_r(addr, size, &res))) {
		return ret;
	}
	if ((size == SUPERPAGE_SIZE) && (res != 0xfff00000)) {
		sprintf(error, "checksum error");
		return FALSE;
	}

	return TRUE;
}

mach_vm_address_t global_addr = 0;
mach_vm_size_t  global_size = 0;

/*
 * If we allocate a 2 MB superpage read-write without specifying an address,
 * - the call should succeed
 * - not return 0
 * - return a 2 MB aligned address
 * - the memory should be readable and writable
 */
boolean_t
test_allocate()
{
	int kr, ret;

	global_addr = 0;
	global_size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &global_addr, global_size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_addr0(global_addr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_align(global_addr))) {
		return ret;
	}
	if (!(ret = check_rw(global_addr, global_size))) {
		return ret;
	}

	return TRUE;
}

/*
 * If we deallocate a superpage,
 * - the call should succeed
 * - make the memory inaccessible
 */
boolean_t
test_deallocate()
{
	mach_vm_size_t  size = SUPERPAGE_SIZE;
	int kr, ret;

	if (!global_addr) {
		sprintf(error, "skipped deallocation");
		return FALSE;
	}
	kr = mach_vm_deallocate(mach_task_self(), global_addr, global_size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}
	if (!(ret = check_nr(global_addr, size, NULL))) {
		return ret;
	}
	return TRUE;
}

/*
 * If we allocate a superpage of any size read-write without specifying an address
 * - the call should succeed
 * - not return 0
 * - the memory should be readable and writable
 * If we deallocate it,
 * - the call should succeed
 * - make the memory inaccessible
 */
boolean_t
test_allocate_size_any()
{
	int kr;
	int ret;
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = 2 * PAGE_SIZE; /* will be rounded up to some superpage size */

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_ANY);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_addr0(addr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_rw(addr, size))) {
		return ret;
	}
	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}
	if (!(ret = check_nr(addr, size, NULL))) {
		return ret;
	}
	return TRUE;
}

/*
 * If we allocate a 2 MB superpage read-write at a 2 MB aligned address,
 * - the call should succeed
 * - return the address we wished for
 * - the memory should be readable and writable
 * If we deallocate it,
 * - the call should succeed
 * - make the memory inaccessible
 */
boolean_t
test_allocatefixed()
{
	int kr;
	int ret;
	mach_vm_address_t addr = FIXED_ADDRESS1;
	mach_vm_size_t  size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_addr(addr, FIXED_ADDRESS1, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_rw(addr, size))) {
		return ret;
	}
	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}
	if (!(ret = check_nr(addr, size, NULL))) {
		return ret;
	}
	return TRUE;
}

/*
 * If we allocate a 2 MB superpage read-write at an unaligned address,
 * - the call should fail
 */
boolean_t
test_allocateunalignedfixed()
{
	int kr;
	int ret;
	mach_vm_address_t addr = FIXED_ADDRESS2;
	mach_vm_size_t  size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_SUPERPAGE_SIZE_2MB);
	/* is supposed to fail */
	if ((ret = check_kr(kr, "mach_vm_allocate"))) {
		sprintf(error, "mach_vm_allocate() should have failed");
		return FALSE;
	}
	return TRUE;
}

/*
 * If we allocate an amount of memory not divisible by 2 MB as a 2 MB superpage
 * - the call should fail
 */
boolean_t
test_allocateoddsize()
{
	int kr;
	int ret;
	mach_vm_address_t addr = FIXED_ADDRESS1;
	mach_vm_size_t  size = PAGE_SIZE; /* != 2 MB */

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_SUPERPAGE_SIZE_2MB);
	/* is supposed to fail */
	if ((ret = check_kr(kr, "mach_vm_allocate"))) {
		sprintf(error, "mach_vm_allocate() should have failed");
		return FALSE;
	}
	return TRUE;
}

/*
 * If we deallocate a sub-page of a superpage,
 * - the call should succeed
 * - make the complete memory inaccessible
 */
boolean_t
test_deallocatesubpage()
{
	int kr;
	int ret;
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}
	kr = mach_vm_deallocate(mach_task_self(), addr + PAGE_SIZE, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}
	if (!(ret = check_nr(addr, size, NULL))) {
		return ret;
	}
	return TRUE;
}

/*
 * If we try to allocate memory occupied by superpages as normal pages
 * - the call should fail
 */
boolean_t
test_reallocate()
{
	mach_vm_address_t addr = 0, addr2;
	mach_vm_size_t  size = SUPERPAGE_SIZE;
	int kr, ret;
	int i;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}

	/* attempt to allocate every sub-page of superpage */
	for (i = 0; i < SUPERPAGE_SIZE / PAGE_SIZE; i++) {
		addr2 = addr + i * PAGE_SIZE;
		size = PAGE_SIZE;
		kr = mach_vm_allocate(mach_task_self(), &addr2, size, 0);
		if ((ret = check_kr(kr, "mach_vm_allocate"))) {
			sprintf(error, "could allocate already allocated space, page %d", i);
			mach_vm_deallocate(mach_task_self(), addr, size);
			return FALSE;
		}
	}
	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}
	return TRUE;
}

/*
 * If we try to wire superpages
 * - the call should succeed
 * - the memory should remain readable and writable
 */
boolean_t
test_wire()
{
	int kr;
	int ret;
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}

	kr = mach_vm_wire(mach_host_self(), mach_task_self(), addr, size, VM_PROT_WRITE | VM_PROT_READ);

	if (!geteuid()) { /* may fail as user */
		if (!(ret = check_kr(kr, "mach_vm_wire"))) {
			return ret;
		}
	}

	if (!(ret = check_rw(addr, size))) {
		return ret;
	}

	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}

	return TRUE;
}

/*
 * If we try to wire superpages
 * - the call should fail
 * - the memory should remain readable and writable
 * Currently, superpages are always wired.
 */
boolean_t
test_unwire()
{
	int kr;
	int ret;
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}

	kr = mach_vm_wire(mach_host_self(), mach_task_self(), addr, size, VM_PROT_NONE);
	if ((ret = check_kr(kr, "mach_vm_wire"))) {
		sprintf(error, "could unwire");
		return FALSE;
	}

	if (!(ret = check_rw(addr, size))) {
		return ret;
	}

	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}

	return TRUE;
}

/*
 * If we try to write-protect superpages
 * - the call should succeed
 * - the memory should remain readable
 * - the memory should not be writable
 */
boolean_t
test_readonly()
{
	int kr;
	int ret;
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}

	mach_vm_protect(mach_task_self(), addr, size, 0, VM_PROT_READ);
	if (!(ret = check_kr(kr, "mach_vm_protect"))) {
		return ret;
	}

	if (!(ret = check_r(addr, size, NULL))) {
		return ret;
	}
	if (!(ret = check_nw(addr, size))) {
		return ret;
	}

	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}

	return TRUE;
}

/*
 * If we try to write-protect a sub-page of a superpage
 * - the call should succeed
 * - the complete memory should remain readable
 * - the complete memory should not be writable
 */
boolean_t
test_readonlysubpage()
{
	int kr;
	int ret;
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}

	mach_vm_protect(mach_task_self(), addr + PAGE_SIZE, PAGE_SIZE, 0, VM_PROT_READ);
	if (!(ret = check_kr(kr, "mach_vm_protect"))) {
		return ret;
	}

	if (!(ret = check_r(addr, size, NULL))) {
		return ret;
	}
	if (!(ret = check_nw(addr, size))) {
		return ret;
	}

	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}

	return TRUE;
}

/*
 * If we fork with active superpages
 * - the parent should still be able to access the superpages
 * - the child should not be able to access the superpages
 */
boolean_t
test_fork()
{
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;
	int kr, ret;
	pid_t pid;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}

	fflush(stdout);
	if ((pid = fork())) { /* parent */
		if (!(ret = check_rw(addr, size))) {
			return ret;
		}
		waitpid(pid, &ret, 0);
		if (!ret) {
			sprintf(error, "child could access superpage");
			return ret;
		}
	} else { /* child */
		if (!(ret = check_nr(addr, size, NULL))) {
			exit(ret);
		}
		exit(TRUE);
	}

	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}
	return TRUE;
}

/*
 * Doing file I/O with superpages
 * - should succeed
 * - should behave the same as with base pages (i.e. no bad data)
 */
#define FILENAME "/System/Library/Kernels/kernel"
boolean_t
test_fileio()
{
	mach_vm_address_t addr1 = 0;
	mach_vm_address_t addr2 = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;
	int kr, ret;
	int fd;
	unsigned int bytes;

	/* allocate one superpage */
	kr = mach_vm_allocate(mach_task_self(), &addr1, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate (1)"))) {
		return ret;
	}

	/* allocate base pages (superpage-sized) */
	kr = mach_vm_allocate(mach_task_self(), &addr2, size, VM_FLAGS_ANYWHERE);
	if (!(ret = check_kr(kr, "mach_vm_allocate (2)"))) {
		return ret;
	}

	if ((fd = open(FILENAME, O_RDONLY)) < 0) {
		sprintf(error, "couldn't open %s", FILENAME);
		return FALSE;
	}
	fcntl(fd, F_NOCACHE, 1);
	/* read kernel into superpage */
	if ((bytes = read(fd, (void*)(uintptr_t)addr1, SUPERPAGE_SIZE)) < SUPERPAGE_SIZE) {
		sprintf(error, "short read (1)");
		return FALSE;
	}
	lseek(fd, 0, SEEK_SET);
	/* read kernel into base pages */
	if ((bytes = read(fd, (void*)(uintptr_t)addr2, SUPERPAGE_SIZE)) < SUPERPAGE_SIZE) {
		sprintf(error, "short read (2)");
		return FALSE;
	}
	close(fd);

	/* compare */
	if (memcmp((void*)(uintptr_t)addr1, (void*)(uintptr_t)addr2, bytes)) {
		sprintf(error, "read data corrupt");
		return FALSE;
	}

	kr = mach_vm_deallocate(mach_task_self(), addr1, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate (1)"))) {
		return ret;
	}
	kr = mach_vm_deallocate(mach_task_self(), addr2, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate (2)"))) {
		return ret;
	}
	return TRUE;
}

/*
 * The mmap() interface should work just as well!
 */
boolean_t
test_mmap()
{
	int kr, ret;
	uintptr_t addr = 0;
	int size = SUPERPAGE_SIZE;

	addr = (uintptr_t)mmap((void*)addr, size, PROT_READ, MAP_ANON | MAP_PRIVATE, VM_FLAGS_SUPERPAGE_SIZE_2MB, 0);
	if (addr == (uintptr_t)MAP_FAILED) {
		sprintf(error, "mmap()");
		return FALSE;
	}
	if (!(ret = check_addr0(addr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_align(addr))) {
		return ret;
	}
	if (!(ret = check_r(addr, SUPERPAGE_SIZE, NULL))) {
		return ret;
	}
	if (!(ret = check_nw(addr, SUPERPAGE_SIZE))) {
		return ret;
	}
	kr = munmap((void*)addr, size);
	if (!(ret = check_kr(kr, "munmap"))) {
		return ret;
	}
	if (!(ret = check_nr(addr, size, NULL))) {
		return ret;
	}

	return TRUE;
}

/*
 * Tests one allocation/deallocaton cycle; used in a loop this tests for leaks
 */
boolean_t
test_alloc_dealloc()
{
	mach_vm_address_t addr = 0;
	mach_vm_size_t  size = SUPERPAGE_SIZE;
	int kr, ret;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | VM_FLAGS_SUPERPAGE_SIZE_2MB);
	if (!(ret = check_kr(kr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_addr0(addr, "mach_vm_allocate"))) {
		return ret;
	}
	if (!(ret = check_align(addr))) {
		return ret;
	}
	if (!(ret = check_rw(addr, size))) {
		return ret;
	}
	kr = mach_vm_deallocate(mach_task_self(), addr, size);
	if (!(ret = check_kr(kr, "mach_vm_deallocate"))) {
		return ret;
	}
	return TRUE;
}

test_t test[] = {
	{ "allocate one page anywhere", test_allocate },
	{ "deallocate a page", test_deallocate },
	{ "allocate a SIZE_ANY page anywhere", test_allocate_size_any },
	{ "allocate one page at a fixed address", test_allocatefixed },
	{ "allocate one page at an unaligned fixed address", test_allocateunalignedfixed },
	{ "deallocate sub-page", test_deallocatesubpage },
	{ "allocate already allocated subpage", test_reallocate },
	{ "wire a page", test_wire },
	{ "unwire a page", test_unwire },
	{ "make page readonly", test_readonly },
	{ "make sub-page readonly", test_readonlysubpage },
	{ "file I/O", test_fileio },
	{ "mmap()", test_mmap },
	{ "fork", test_fork },
};
#define TESTS ((int)(sizeof(test)/sizeof(*test)))

boolean_t
testit(int i)
{
	boolean_t ret;

	error[0] = 0;
	printf("Test #%d \"%s\"...", i + 1, test[i].description);
	ret = test[i].fn();
	if (ret) {
		printf("OK\n");
	} else {
		printf("FAILED!");
		if (error[0]) {
			printf(" (%s)\n", error);
		} else {
			printf("\n");
		}
	}
}

int
main(int argc, char **argv)
{
	int i;
	uint64_t time1, time2;

	int mode = 0;
	if (argc > 1) {
		if (!strcmp(argv[1], "-h")) {
			printf("Usage: %s <mode>\n", argv[0]);
			printf("\tmode = 0:  test all cases\n");
			printf("\tmode = -1: allocate/deallocate until failure\n");
			printf("\tmode > 0:  run test <tmode>\n");
			exit(0);
		}
		mode = atoi(argv[1]);
	}

	/* install SIGBUS handler */
	struct sigaction my_sigaction;
	my_sigaction.sa_handler = test_signal_handler;
	my_sigaction.sa_flags = SA_RESTART;
	my_sigaction.sa_mask = 0;
	sigaction( SIGBUS, &my_sigaction, NULL );
	sigaction( SIGSEGV, &my_sigaction, NULL );

	if (mode > 0) {           /* one specific test */
		testit(mode - 1);
	}

	if (mode == 0) {  /* test all cases */
		printf("Running %d tests:\n", TESTS);
		for (i = 0; i < TESTS; i++) {
			testit(i);
		}
	}
	if (mode == -1) { /* alloc/dealloc */
		boolean_t ret;
		do {
			ret = test_alloc_dealloc(TRUE);
			printf(".");
			fflush(stdout);
		} while (ret);
		if (error[0]) {
			printf(" (%s)\n", error);
		}
	}
	return 0;
}
