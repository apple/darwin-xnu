#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <darwintest.h>


/*
 * macOS only test. Try to map 2 different MAP_JIT regions. 2nd should fail.
 */
T_DECL(restrict_jit, "macOS restricted JIT entitlement test")
{
#if TARGET_OS_OSX
	void *addr1;
	void *addr2;
	size_t size = 64 * 1024;


	addr1 = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
	T_ASSERT_NE_PTR(addr1, MAP_FAILED, "First map MAP_JIT");

	addr2 = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
	if (addr2 == MAP_FAILED) {
		T_PASS("Only one MAP_JIT was allowed");
	} else {
		T_FAIL("Second MAP_JIT was allowed");
	}

#else
	T_SKIP("Not macOS");
#endif
}
