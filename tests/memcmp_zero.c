#include <darwintest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <mach/machine/vm_param.h>

static inline unsigned char *
get_guarded_page(void)
{
	unsigned char *p = mmap(NULL, 3 * PAGE_SIZE, PROT_NONE, MAP_SHARED | MAP_ANON, 0, 0);
	p += PAGE_SIZE;
	mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE);
	return p;
}

static inline void
free_guarded_page(unsigned char *p)
{
	munmap(p - PAGE_SIZE, 3 * PAGE_SIZE);
}

/* memcmp_zero_ptr_aligned() checks string s of n bytes contains all zeros.
 * Address and size of the string s must be pointer-aligned.
 * Return 0 if true, 1 otherwise. Also return 0 if n is 0.
 */
extern int
memcmp_zero_ptr_aligned(const void *s, size_t n);

T_DECL(memcmp_zero, "memcmp_zero")
{
	// the assembly version is for the kernel and doesn't support arm64_32
#if defined(__arm64__) && __LP64__
	unsigned char *buffer = get_guarded_page();
	unsigned char *right = buffer + PAGE_SIZE - 512;
	const int ptr_size = sizeof(buffer);

	for (size_t i = 0; i < 256; i += ptr_size) {
		for (size_t j = i; j < 256; ++j) {
			for (size_t k = 0; k < 256; ++k) {
				if (k < i) {
					buffer[k] = (unsigned char)rand();
				} else if (k < j) {
					buffer[k] = '\0';
				} else if (k == j) {
					do {
						buffer[k] = (unsigned char)rand();
					} while (!buffer[k]);
				} else {
					buffer[k] = '\0';
				}
			}
			for (size_t m = 0; m < 128; m += ptr_size) {
				int result = memcmp_zero_ptr_aligned(&buffer[i], m);
				int ref = j - i < m ? 1 : 0;
				T_QUIET; T_ASSERT_EQ(result, ref, "expected %d, saw %d\n"
				    "memcmp_zero_ptr_aligned(buf[%zd], %zd)\n",
				    ref, result, i, m);
			}


			for (size_t k = 0; k < 256; ++k) {
				if (k < i) {
					right[k] = (unsigned char)rand();
				} else if (k < j) {
					right[k] = '\0';
				} else if (k == j) {
					do {
						right[k] = (unsigned char)rand();
					} while (!right[k]);
				} else {
					right[k] = '\0';
				}
			}
			for (size_t m = 0; m < 256; m += ptr_size) {
				int result = memcmp_zero_ptr_aligned(&right[i], m);
				int ref = j - i < m ? 1 : 0;
				T_QUIET; T_ASSERT_EQ(result, ref, "expected %d, saw %d\n"
				    "memcmp_zero_ptr_aligned(buf[%zd], %zd)\n",
				    ref, result, i, m);
			}
		}
	}

	T_PASS("success");

	free_guarded_page(buffer);
#else
	T_SKIP("no optimized version to test");
#endif
}
