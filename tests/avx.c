#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <immintrin.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <i386/cpu_capabilities.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.intel"),
	T_META_CHECK_LEAKS(false)
	);

#define NORMAL_RUN_TIME  (10)
#define LONG_RUN_TIME    (10*60)
#define TIMEOUT_OVERHEAD (10)

volatile boolean_t checking = true;
char vec_str_buf[8196];
char karray_str_buf[1024];

/*
 * ymm defines/globals/prototypes
 */
#define STOP_COOKIE_256 0x01234567
#if defined(__x86_64__)
#define YMM_MAX                 16
#define X86_AVX_STATE_T         x86_avx_state64_t
#define X86_AVX_STATE_COUNT     x86_AVX_STATE64_COUNT
#define X86_AVX_STATE_FLAVOR    x86_AVX_STATE64
#define MCONTEXT_SIZE_256       sizeof(struct __darwin_mcontext_avx64)
#else
#define YMM_MAX                 8
#define X86_AVX_STATE_T         x86_avx_state32_t
#define X86_AVX_STATE_COUNT     x86_AVX_STATE32_COUNT
#define X86_AVX_STATE_FLAVOR    x86_AVX_STATE32
#define MCONTEXT_SIZE_256       sizeof(struct __darwin_mcontext_avx32)
#endif
#define VECTOR256 __m256
#define VEC256ALIGN __attribute ((aligned(32)))
static inline void populate_ymm(void);
static inline void check_ymm(void);
VECTOR256       vec256array0[YMM_MAX] VEC256ALIGN;
VECTOR256       vec256array1[YMM_MAX] VEC256ALIGN;
VECTOR256       vec256array2[YMM_MAX] VEC256ALIGN;
VECTOR256       vec256array3[YMM_MAX] VEC256ALIGN;

/*
 * zmm defines/globals/prototypes
 */
#define STOP_COOKIE_512 0x0123456789abcdefULL
#if defined(__x86_64__)
#define ZMM_MAX                 32
#define X86_AVX512_STATE_T      x86_avx512_state64_t
#define X86_AVX512_STATE_COUNT  x86_AVX512_STATE64_COUNT
#define X86_AVX512_STATE_FLAVOR x86_AVX512_STATE64
#define MCONTEXT_SIZE_512       sizeof(struct __darwin_mcontext_avx512_64)
#else
#define ZMM_MAX                 8
#define X86_AVX512_STATE_T      x86_avx512_state32_t
#define X86_AVX512_STATE_COUNT  x86_AVX512_STATE32_COUNT
#define X86_AVX512_STATE_FLAVOR x86_AVX512_STATE32
#define MCONTEXT_SIZE_512       sizeof(struct __darwin_mcontext_avx512_32)
#endif
#define VECTOR512 __m512
#define VEC512ALIGN __attribute ((aligned(64)))
#define OPMASK uint64_t
#define KARRAY_MAX              8
static inline void populate_zmm(void);
static inline void populate_opmask(void);
static inline void check_zmm(void);
VECTOR512       vec512array0[ZMM_MAX] VEC512ALIGN;
VECTOR512       vec512array1[ZMM_MAX] VEC512ALIGN;
VECTOR512       vec512array2[ZMM_MAX] VEC512ALIGN;
VECTOR512       vec512array3[ZMM_MAX] VEC512ALIGN;
OPMASK karray0[8];
OPMASK karray1[8];
OPMASK karray2[8];
OPMASK karray3[8];

kern_return_t _thread_get_state_avx(thread_t thread, int flavor, thread_state_t state,
    mach_msg_type_number_t *state_count);
kern_return_t _thread_get_state_avx512(thread_t thread, int flavor, thread_state_t state,
    mach_msg_type_number_t *state_count);

/*
 * Common functions
 */

int
memcmp_unoptimized(const void *s1, const void *s2, size_t n)
{
	if (n != 0) {
		const unsigned char *p1 = s1, *p2 = s2;
		do {
			if (*p1++ != *p2++) {
				return *--p1 - *--p2;
			}
		} while (--n != 0);
	}
	return 0;
}

void
start_timer(int seconds, void (*handler)(int, siginfo_t *, void *))
{
	struct sigaction sigalrm_action = {
		.sa_sigaction = handler,
		.sa_flags = SA_RESTART,
		.sa_mask = 0
	};
	struct itimerval timer = {
		.it_value.tv_sec = seconds,
		.it_value.tv_usec = 0,
		.it_interval.tv_sec = 0,
		.it_interval.tv_usec = 0
	};
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NE(sigaction(SIGALRM, &sigalrm_action, NULL), -1, NULL);
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NE(setitimer(ITIMER_REAL, &timer, NULL), -1, NULL);
}

void
require_avx(void)
{
	if ((_get_cpu_capabilities() & kHasAVX1_0) != kHasAVX1_0) {
		T_SKIP("AVX not supported on this system");
	}
}

void
require_avx512(void)
{
	if ((_get_cpu_capabilities() & kHasAVX512F) != kHasAVX512F) {
		T_SKIP("AVX-512 not supported on this system");
	}
}

/*
 * ymm functions
 */

static inline void
store_ymm(VECTOR256 *vec256array)
{
	int i = 0;
	__asm__ volatile ("vmovaps  %%ymm0, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm1, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm2, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm3, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm4, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm5, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm6, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm7, %0" :"=m" (vec256array[i]));
#if defined(__x86_64__)
	i++; __asm__ volatile ("vmovaps  %%ymm8, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm9, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm10, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm11, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm12, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm13, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm14, %0" :"=m" (vec256array[i]));
	i++; __asm__ volatile ("vmovaps  %%ymm15, %0" :"=m" (vec256array[i]));
#endif
}

static inline void
restore_ymm(VECTOR256 *vec256array)
{
	VECTOR256 *p = vec256array;

	__asm__ volatile ("vmovaps  %0, %%ymm0" :: "m" (*(__m256i*)p) : "ymm0"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm1" :: "m" (*(__m256i*)p) : "ymm1"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm2" :: "m" (*(__m256i*)p) : "ymm2"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm3" :: "m" (*(__m256i*)p) : "ymm3"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm4" :: "m" (*(__m256i*)p) : "ymm4"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm5" :: "m" (*(__m256i*)p) : "ymm5"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm6" :: "m" (*(__m256i*)p) : "ymm6"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm7" :: "m" (*(__m256i*)p) : "ymm7");

#if defined(__x86_64__)
	++p; __asm__ volatile ("vmovaps  %0, %%ymm8" :: "m" (*(__m256i*)p) : "ymm8"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm9" :: "m" (*(__m256i*)p) : "ymm9"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm10" :: "m" (*(__m256i*)p) : "ymm10"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm11" :: "m" (*(__m256i*)p) : "ymm11"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm12" :: "m" (*(__m256i*)p) : "ymm12"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm13" :: "m" (*(__m256i*)p) : "ymm13"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm14" :: "m" (*(__m256i*)p) : "ymm14"); p++;
	__asm__ volatile ("vmovaps  %0, %%ymm15" :: "m" (*(__m256i*)p) : "ymm15");
#endif
}

static inline void
populate_ymm(void)
{
	int j;
	uint32_t p[8] VEC256ALIGN;

	for (j = 0; j < (int) (sizeof(p) / sizeof(p[0])); j++) {
		p[j] = getpid();
	}

	p[0] = 0x22222222;
	p[7] = 0x77777777;
	__asm__ volatile ("vmovaps  %0, %%ymm0" :: "m" (*(__m256i*)p) : "ymm0");
	__asm__ volatile ("vmovaps  %0, %%ymm1" :: "m" (*(__m256i*)p) : "ymm1");
	__asm__ volatile ("vmovaps  %0, %%ymm2" :: "m" (*(__m256i*)p) : "ymm2");
	__asm__ volatile ("vmovaps  %0, %%ymm3" :: "m" (*(__m256i*)p) : "ymm3");

	p[0] = 0x44444444;
	p[7] = 0xEEEEEEEE;
	__asm__ volatile ("vmovaps  %0, %%ymm4" :: "m" (*(__m256i*)p) : "ymm4");
	__asm__ volatile ("vmovaps  %0, %%ymm5" :: "m" (*(__m256i*)p) : "ymm5");
	__asm__ volatile ("vmovaps  %0, %%ymm6" :: "m" (*(__m256i*)p) : "ymm6");
	__asm__ volatile ("vmovaps  %0, %%ymm7" :: "m" (*(__m256i*)p) : "ymm7");

#if defined(__x86_64__)
	p[0] = 0x88888888;
	p[7] = 0xAAAAAAAA;
	__asm__ volatile ("vmovaps  %0, %%ymm8" :: "m" (*(__m256i*)p) : "ymm8");
	__asm__ volatile ("vmovaps  %0, %%ymm9" :: "m" (*(__m256i*)p) : "ymm9");
	__asm__ volatile ("vmovaps  %0, %%ymm10" :: "m" (*(__m256i*)p) : "ymm10");
	__asm__ volatile ("vmovaps  %0, %%ymm11" :: "m" (*(__m256i*)p) : "ymm11");

	p[0] = 0xBBBBBBBB;
	p[7] = 0xCCCCCCCC;
	__asm__ volatile ("vmovaps  %0, %%ymm12" :: "m" (*(__m256i*)p) : "ymm12");
	__asm__ volatile ("vmovaps  %0, %%ymm13" :: "m" (*(__m256i*)p) : "ymm13");
	__asm__ volatile ("vmovaps  %0, %%ymm14" :: "m" (*(__m256i*)p) : "ymm14");
	__asm__ volatile ("vmovaps  %0, %%ymm15" :: "m" (*(__m256i*)p) : "ymm15");
#endif

	store_ymm(vec256array0);
}

void
vec256_to_string(VECTOR256 *vec, char *buf)
{
	unsigned int vec_idx = 0;
	unsigned int buf_idx = 0;
	int ret = 0;

	for (vec_idx = 0; vec_idx < YMM_MAX; vec_idx++) {
		uint64_t a[4];
		bcopy(&vec[vec_idx], &a[0], sizeof(a));
		ret = sprintf(
			buf + buf_idx,
			"0x%016llx:%016llx:%016llx:%016llx\n",
			a[0], a[1], a[2], a[3]
			);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sprintf()");
		buf_idx += ret;
	}
}

void
assert_ymm_eq(void *a, void *b, int c)
{
	if (memcmp_unoptimized(a, b, c)) {
		vec256_to_string(a, vec_str_buf);
		T_LOG("Compare failed, vector A:\n%s", vec_str_buf);
		vec256_to_string(b, vec_str_buf);
		T_LOG("Compare failed, vector B:\n%s", vec_str_buf);
		T_ASSERT_FAIL("vectors not equal");
	}
}

void
check_ymm(void)
{
	uint32_t *p = (uint32_t *) &vec256array1[7];
	store_ymm(vec256array1);
	if (p[0] == STOP_COOKIE_256) {
		return;
	}
	assert_ymm_eq(vec256array0, vec256array1, sizeof(vec256array0));
}

static void
copy_ymm_state_to_vector(X86_AVX_STATE_T *sp, VECTOR256 *vp)
{
	int     i;
	struct  __darwin_xmm_reg *xmm  = &sp->__fpu_xmm0;
	struct  __darwin_xmm_reg *ymmh = &sp->__fpu_ymmh0;

	for (i = 0; i < YMM_MAX; i++) {
		bcopy(&xmm[i], &vp[i], sizeof(*xmm));
		bcopy(&ymmh[i], (void *) ((uint64_t)&vp[i] + sizeof(*ymmh)), sizeof(*ymmh));
	}
}

static void
ymm_sigalrm_handler(int signum __unused, siginfo_t *info __unused, void *ctx)
{
	ucontext_t *contextp = (ucontext_t *) ctx;
	mcontext_t mcontext = contextp->uc_mcontext;
	X86_AVX_STATE_T *avx_state = (X86_AVX_STATE_T *) &mcontext->__fs;
	uint32_t *xp = (uint32_t *) &avx_state->__fpu_xmm7;
	uint32_t *yp = (uint32_t *) &avx_state->__fpu_ymmh7;

	T_LOG("Got SIGALRM");

	/* Check for AVX state */
	T_QUIET;
	T_ASSERT_GE(contextp->uc_mcsize, MCONTEXT_SIZE_256, "check context size");

	/* Check that the state in the context is what's set and expected */
	copy_ymm_state_to_vector(avx_state, vec256array3);
	assert_ymm_eq(vec256array3, vec256array0, sizeof(vec256array1));

	/* Change the context and break the main loop */
	xp[0] = STOP_COOKIE_256;
	yp[0] = STOP_COOKIE_256;
	checking = FALSE;
}

kern_return_t
_thread_get_state_avx(
	thread_t                thread,
	int                     flavor,
	thread_state_t          state,          /* pointer to OUT array */
	mach_msg_type_number_t  *state_count)   /*IN/OUT*/
{
	kern_return_t rv;
	VECTOR256 ymms[YMM_MAX];

	/*
	 * We must save and restore the YMMs across thread_get_state() because
	 * code in thread_get_state changes at least one xmm register AFTER the
	 * thread_get_state has saved the state in userspace.  While it's still
	 * possible for something to muck with %xmms BEFORE making the mach
	 * system call (and rendering this save/restore useless), that does not
	 * currently occur, and since we depend on the avx state saved in the
	 * thread_get_state to be the same as that manually copied from YMMs after
	 * thread_get_state returns, we have to go through these machinations.
	 */
	store_ymm(ymms);

	rv = thread_get_state(thread, flavor, state, state_count);

	restore_ymm(ymms);

	return rv;
}

void
ymm_integrity(int time)
{
	mach_msg_type_number_t avx_count = X86_AVX_STATE_COUNT;
	kern_return_t kret;
	X86_AVX_STATE_T avx_state, avx_state2;
	mach_port_t ts = mach_thread_self();

	bzero(&avx_state, sizeof(avx_state));
	bzero(&avx_state2, sizeof(avx_state));

	kret = _thread_get_state_avx(
		ts, X86_AVX_STATE_FLAVOR, (thread_state_t)&avx_state, &avx_count
		);

	store_ymm(vec256array2);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "thread_get_state()");
	vec256_to_string(vec256array2, vec_str_buf);
	T_LOG("Initial state:\n%s", vec_str_buf);

	copy_ymm_state_to_vector(&avx_state, vec256array1);
	assert_ymm_eq(vec256array2, vec256array1, sizeof(vec256array1));

	populate_ymm();

	kret = _thread_get_state_avx(
		ts, X86_AVX_STATE_FLAVOR, (thread_state_t)&avx_state2, &avx_count
		);

	store_ymm(vec256array2);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "thread_get_state()");
	vec256_to_string(vec256array2, vec_str_buf);
	T_LOG("Populated state:\n%s", vec_str_buf);

	copy_ymm_state_to_vector(&avx_state2, vec256array1);
	assert_ymm_eq(vec256array2, vec256array1, sizeof(vec256array0));

	T_LOG("Running for %ds…", time);
	start_timer(time, ymm_sigalrm_handler);

	/* re-populate because printing mucks up XMMs */
	populate_ymm();

	/* Check state until timer fires */
	while (checking) {
		check_ymm();
	}

	/* Check that the sig handler changed out AVX state */
	store_ymm(vec256array1);

	uint32_t *p = (uint32_t *) &vec256array1[7];
	if (p[0] != STOP_COOKIE_256 ||
	    p[4] != STOP_COOKIE_256) {
		vec256_to_string(vec256array1, vec_str_buf);
		T_ASSERT_FAIL("sigreturn failed to stick");
		T_LOG("State:\n%s", vec_str_buf);
	}

	T_LOG("Ran for %ds", time);
	T_PASS("No ymm register corruption occurred");
}

/*
 * zmm functions
 */

static inline void
store_opmask(OPMASK k[])
{
	__asm__ volatile ("kmovq %%k0, %0" :"=m" (k[0]));
	__asm__ volatile ("kmovq %%k1, %0" :"=m" (k[1]));
	__asm__ volatile ("kmovq %%k2, %0" :"=m" (k[2]));
	__asm__ volatile ("kmovq %%k3, %0" :"=m" (k[3]));
	__asm__ volatile ("kmovq %%k4, %0" :"=m" (k[4]));
	__asm__ volatile ("kmovq %%k5, %0" :"=m" (k[5]));
	__asm__ volatile ("kmovq %%k6, %0" :"=m" (k[6]));
	__asm__ volatile ("kmovq %%k7, %0" :"=m" (k[7]));
}

static inline void
store_zmm(VECTOR512 *vecarray)
{
	int i = 0;
	__asm__ volatile ("vmovaps  %%zmm0, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm1, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm2, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm3, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm4, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm5, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm6, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm7, %0" :"=m" (vecarray[i]));
#if defined(__x86_64__)
	i++; __asm__ volatile ("vmovaps  %%zmm8, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm9, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm10, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm11, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm12, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm13, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm14, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm15, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm16, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm17, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm18, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm19, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm20, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm21, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm22, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm23, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm24, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm25, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm26, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm27, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm28, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm29, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm30, %0" :"=m" (vecarray[i]));
	i++; __asm__ volatile ("vmovaps  %%zmm31, %0" :"=m" (vecarray[i]));
#endif
}

static inline void
restore_zmm(VECTOR512 *vecarray)
{
	VECTOR512 *p = vecarray;

	__asm__ volatile ("vmovaps  %0, %%zmm0" :: "m" (*(__m512i*)p) : "zmm0"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm1" :: "m" (*(__m512i*)p) : "zmm1"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm2" :: "m" (*(__m512i*)p) : "zmm2"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm3" :: "m" (*(__m512i*)p) : "zmm3"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm4" :: "m" (*(__m512i*)p) : "zmm4"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm5" :: "m" (*(__m512i*)p) : "zmm5"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm6" :: "m" (*(__m512i*)p) : "zmm6"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm7" :: "m" (*(__m512i*)p) : "zmm7");

#if defined(__x86_64__)
	++p; __asm__ volatile ("vmovaps  %0, %%zmm8" :: "m" (*(__m512i*)p) : "zmm8"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm9" :: "m" (*(__m512i*)p) : "zmm9"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm10" :: "m" (*(__m512i*)p) : "zmm10"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm11" :: "m" (*(__m512i*)p) : "zmm11"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm12" :: "m" (*(__m512i*)p) : "zmm12"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm13" :: "m" (*(__m512i*)p) : "zmm13"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm14" :: "m" (*(__m512i*)p) : "zmm14"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm15" :: "m" (*(__m512i*)p) : "zmm15"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm16" :: "m" (*(__m512i*)p) : "zmm16"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm17" :: "m" (*(__m512i*)p) : "zmm17"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm18" :: "m" (*(__m512i*)p) : "zmm18"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm19" :: "m" (*(__m512i*)p) : "zmm19"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm20" :: "m" (*(__m512i*)p) : "zmm20"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm21" :: "m" (*(__m512i*)p) : "zmm21"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm22" :: "m" (*(__m512i*)p) : "zmm22"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm23" :: "m" (*(__m512i*)p) : "zmm23"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm24" :: "m" (*(__m512i*)p) : "zmm24"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm25" :: "m" (*(__m512i*)p) : "zmm25"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm26" :: "m" (*(__m512i*)p) : "zmm26"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm27" :: "m" (*(__m512i*)p) : "zmm27"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm28" :: "m" (*(__m512i*)p) : "zmm28"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm29" :: "m" (*(__m512i*)p) : "zmm29"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm30" :: "m" (*(__m512i*)p) : "zmm30"); p++;
	__asm__ volatile ("vmovaps  %0, %%zmm31" :: "m" (*(__m512i*)p) : "zmm31");
#endif
}

static inline void
populate_opmask(void)
{
	uint64_t k[8];

	for (int j = 0; j < 8; j++) {
		k[j] = ((uint64_t) getpid() << 32) + (0x11111111 * j);
	}

	__asm__ volatile ("kmovq %0, %%k0" : :"m" (k[0]));
	__asm__ volatile ("kmovq %0, %%k1" : :"m" (k[1]));
	__asm__ volatile ("kmovq %0, %%k2" : :"m" (k[2]));
	__asm__ volatile ("kmovq %0, %%k3" : :"m" (k[3]));
	__asm__ volatile ("kmovq %0, %%k4" : :"m" (k[4]));
	__asm__ volatile ("kmovq %0, %%k5" : :"m" (k[5]));
	__asm__ volatile ("kmovq %0, %%k6" : :"m" (k[6]));
	__asm__ volatile ("kmovq %0, %%k7" : :"m" (k[7]));

	store_opmask(karray0);
}

kern_return_t
_thread_get_state_avx512(
	thread_t                thread,
	int                     flavor,
	thread_state_t          state,          /* pointer to OUT array */
	mach_msg_type_number_t  *state_count)   /*IN/OUT*/
{
	kern_return_t rv;
	VECTOR512 zmms[ZMM_MAX];

	/*
	 * We must save and restore the ZMMs across thread_get_state() because
	 * code in thread_get_state changes at least one xmm register AFTER the
	 * thread_get_state has saved the state in userspace.  While it's still
	 * possible for something to muck with %XMMs BEFORE making the mach
	 * system call (and rendering this save/restore useless), that does not
	 * currently occur, and since we depend on the avx512 state saved in the
	 * thread_get_state to be the same as that manually copied from ZMMs after
	 * thread_get_state returns, we have to go through these machinations.
	 */
	store_zmm(zmms);

	rv = thread_get_state(thread, flavor, state, state_count);

	restore_zmm(zmms);

	return rv;
}

static inline void
populate_zmm(void)
{
	int j;
	uint64_t p[8] VEC512ALIGN;

	for (j = 0; j < (int) (sizeof(p) / sizeof(p[0])); j++) {
		p[j] = ((uint64_t) getpid() << 32) + getpid();
	}

	p[0] = 0x0000000000000000ULL;
	p[2] = 0x4444444444444444ULL;
	p[4] = 0x8888888888888888ULL;
	p[7] = 0xCCCCCCCCCCCCCCCCULL;
	__asm__ volatile ("vmovaps  %0, %%zmm0" :: "m" (*(__m256i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm1" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm2" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm3" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm4" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm5" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm6" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm7" :: "m" (*(__m512i*)p));

#if defined(__x86_64__)
	p[0] = 0x1111111111111111ULL;
	p[2] = 0x5555555555555555ULL;
	p[4] = 0x9999999999999999ULL;
	p[7] = 0xDDDDDDDDDDDDDDDDULL;
	__asm__ volatile ("vmovaps  %0, %%zmm8" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm9" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm10" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm11" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm12" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm13" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm14" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm15" :: "m" (*(__m512i*)p));

	p[0] = 0x2222222222222222ULL;
	p[2] = 0x6666666666666666ULL;
	p[4] = 0xAAAAAAAAAAAAAAAAULL;
	p[7] = 0xEEEEEEEEEEEEEEEEULL;
	__asm__ volatile ("vmovaps  %0, %%zmm16" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm17" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm18" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm19" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm20" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm21" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm22" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm23" :: "m" (*(__m512i*)p));

	p[0] = 0x3333333333333333ULL;
	p[2] = 0x7777777777777777ULL;
	p[4] = 0xBBBBBBBBBBBBBBBBULL;
	p[7] = 0xFFFFFFFFFFFFFFFFULL;
	__asm__ volatile ("vmovaps  %0, %%zmm24" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm25" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm26" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm27" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm28" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm29" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm30" :: "m" (*(__m512i*)p));
	__asm__ volatile ("vmovaps  %0, %%zmm31" :: "m" (*(__m512i*)p));
#endif

	store_zmm(vec512array0);
}

void
vec512_to_string(VECTOR512 *vec, char *buf)
{
	unsigned int vec_idx = 0;
	unsigned int buf_idx = 0;
	int ret = 0;

	for (vec_idx = 0; vec_idx < ZMM_MAX; vec_idx++) {
		uint64_t a[8];
		bcopy(&vec[vec_idx], &a[0], sizeof(a));
		ret = sprintf(
			buf + buf_idx,
			"0x%016llx:%016llx:%016llx:%016llx:"
			"%016llx:%016llx:%016llx:%016llx%s",
			a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
			vec_idx < ZMM_MAX - 1 ? "\n" : ""
			);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sprintf()");
		buf_idx += ret;
	}
}

void
opmask_to_string(OPMASK *karray, char *buf)
{
	unsigned int karray_idx = 0;
	unsigned int buf_idx = 0;
	int ret = 0;

	for (karray_idx = 0; karray_idx < KARRAY_MAX; karray_idx++) {
		ret = sprintf(
			buf + buf_idx,
			"k%d: 0x%016llx%s",
			karray_idx, karray[karray_idx],
			karray_idx < KARRAY_MAX ? "\n" : ""
			);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sprintf()");
		buf_idx += ret;
	}
}

static void
assert_zmm_eq(void *a, void *b, int c)
{
	if (memcmp_unoptimized(a, b, c)) {
		vec512_to_string(a, vec_str_buf);
		T_LOG("Compare failed, vector A:\n%s", vec_str_buf);
		vec512_to_string(b, vec_str_buf);
		T_LOG("Compare failed, vector B:\n%s", vec_str_buf);
		T_ASSERT_FAIL("Vectors not equal");
	}
}

static void
assert_opmask_eq(OPMASK *a, OPMASK *b)
{
	for (int i = 0; i < KARRAY_MAX; i++) {
		if (a[i] != b[i]) {
			opmask_to_string(a, karray_str_buf);
			T_LOG("Compare failed, opmask A:\n%s", karray_str_buf);
			opmask_to_string(b, karray_str_buf);
			T_LOG("Compare failed, opmask B:\n%s", karray_str_buf);
			T_ASSERT_FAIL("opmasks not equal");
		}
	}
}

void
check_zmm(void)
{
	uint64_t *p = (uint64_t *) &vec512array1[7];
	store_opmask(karray1);
	store_zmm(vec512array1);
	if (p[0] == STOP_COOKIE_512) {
		return;
	}

	assert_zmm_eq(vec512array0, vec512array1, sizeof(vec512array0));
	assert_opmask_eq(karray0, karray1);
}

static void
copy_state_to_opmask(X86_AVX512_STATE_T *sp, OPMASK *op)
{
	OPMASK *k = (OPMASK *) &sp->__fpu_k0;
	for (int i = 0; i < KARRAY_MAX; i++) {
		bcopy(&k[i], &op[i], sizeof(*op));
	}
}

static void
copy_zmm_state_to_vector(X86_AVX512_STATE_T *sp, VECTOR512 *vp)
{
	int     i;
	struct  __darwin_xmm_reg *xmm  = &sp->__fpu_xmm0;
	struct  __darwin_xmm_reg *ymmh = &sp->__fpu_ymmh0;
	struct  __darwin_ymm_reg *zmmh = &sp->__fpu_zmmh0;
#if defined(__x86_64__)
	struct  __darwin_zmm_reg *zmm  = &sp->__fpu_zmm16;

	for (i = 0; i < ZMM_MAX / 2; i++) {
		bcopy(&xmm[i], &vp[i], sizeof(*xmm));
		bcopy(&ymmh[i], (void *) ((uint64_t)&vp[i] + sizeof(*ymmh)), sizeof(*ymmh));
		bcopy(&zmmh[i], (void *) ((uint64_t)&vp[i] + sizeof(*zmmh)), sizeof(*zmmh));
		bcopy(&zmm[i], &vp[(ZMM_MAX / 2) + i], sizeof(*zmm));
	}
#else
	for (i = 0; i < ZMM_MAX; i++) {
		bcopy(&xmm[i], &vp[i], sizeof(*xmm));
		bcopy(&ymmh[i], (void *) ((uint64_t)&vp[i] + sizeof(*ymmh)), sizeof(*ymmh));
		bcopy(&zmmh[i], (void *) ((uint64_t)&vp[i] + sizeof(*zmmh)), sizeof(*zmmh));
	}
#endif
}

static void
zmm_sigalrm_handler(int signum __unused, siginfo_t *info __unused, void *ctx)
{
	ucontext_t *contextp = (ucontext_t *) ctx;
	mcontext_t mcontext = contextp->uc_mcontext;
	X86_AVX512_STATE_T *avx_state = (X86_AVX512_STATE_T *) &mcontext->__fs;
	uint64_t *xp = (uint64_t *) &avx_state->__fpu_xmm7;
	uint64_t *yp = (uint64_t *) &avx_state->__fpu_ymmh7;
	uint64_t *zp = (uint64_t *) &avx_state->__fpu_zmmh7;
	uint64_t *kp = (uint64_t *) &avx_state->__fpu_k0;

	/* Check for AVX512 state */
	T_QUIET;
	T_ASSERT_GE(contextp->uc_mcsize, MCONTEXT_SIZE_512, "check context size");

	/* Check that the state in the context is what's set and expected */
	copy_zmm_state_to_vector(avx_state, vec512array3);
	assert_zmm_eq(vec512array3, vec512array0, sizeof(vec512array1));
	copy_state_to_opmask(avx_state, karray3);
	assert_opmask_eq(karray3, karray0);

	/* Change the context and break the main loop */
	xp[0] = STOP_COOKIE_512;
	yp[0] = STOP_COOKIE_512;
	zp[0] = STOP_COOKIE_512;
	kp[7] = STOP_COOKIE_512;
	checking = FALSE;
}

void
zmm_integrity(int time)
{
	mach_msg_type_number_t avx_count = X86_AVX512_STATE_COUNT;
	kern_return_t kret;
	X86_AVX512_STATE_T avx_state, avx_state2;
	mach_port_t ts = mach_thread_self();

	bzero(&avx_state, sizeof(avx_state));
	bzero(&avx_state2, sizeof(avx_state));

	store_zmm(vec512array2);
	store_opmask(karray2);

	kret = _thread_get_state_avx512(
		ts, X86_AVX512_STATE_FLAVOR, (thread_state_t)&avx_state, &avx_count
		);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "thread_get_state()");
	vec512_to_string(vec512array2, vec_str_buf);
	opmask_to_string(karray2, karray_str_buf);
	T_LOG("Initial state:\n%s\n%s", vec_str_buf, karray_str_buf);

	copy_zmm_state_to_vector(&avx_state, vec512array1);
	assert_zmm_eq(vec512array2, vec512array1, sizeof(vec512array1));
	copy_state_to_opmask(&avx_state, karray1);
	assert_opmask_eq(karray2, karray1);

	populate_zmm();
	populate_opmask();

	kret = _thread_get_state_avx512(
		ts, X86_AVX512_STATE_FLAVOR, (thread_state_t)&avx_state2, &avx_count
		);

	store_zmm(vec512array2);
	store_opmask(karray2);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "thread_get_state()");
	vec512_to_string(vec512array2, vec_str_buf);
	opmask_to_string(karray2, karray_str_buf);
	T_LOG("Populated state:\n%s\n%s", vec_str_buf, karray_str_buf);

	copy_zmm_state_to_vector(&avx_state2, vec512array1);
	assert_zmm_eq(vec512array2, vec512array1, sizeof(vec512array1));
	copy_state_to_opmask(&avx_state2, karray1);
	assert_opmask_eq(karray2, karray1);

	T_LOG("Running for %ds…", time);
	start_timer(time, zmm_sigalrm_handler);

	/* re-populate because printing mucks up XMMs */
	populate_zmm();
	populate_opmask();

	/* Check state until timer fires */
	while (checking) {
		check_zmm();
	}

	/* Check that the sig handler changed our AVX state */
	store_zmm(vec512array1);
	store_opmask(karray1);

	uint64_t *p = (uint64_t *) &vec512array1[7];
	if (p[0] != STOP_COOKIE_512 ||
	    p[2] != STOP_COOKIE_512 ||
	    p[4] != STOP_COOKIE_512 ||
	    karray1[7] != STOP_COOKIE_512) {
		vec512_to_string(vec512array1, vec_str_buf);
		opmask_to_string(karray1, karray_str_buf);
		T_ASSERT_FAIL("sigreturn failed to stick");
		T_LOG("State:\n%s\n%s", vec_str_buf, karray_str_buf);
	}

	T_LOG("Ran for %ds", time);
	T_PASS("No zmm register corruption occurred");
}

/*
 * Main test declarations
 */
T_DECL(ymm_integrity,
    "Quick soak test to verify that AVX "
    "register state is maintained correctly",
    T_META_TIMEOUT(NORMAL_RUN_TIME + TIMEOUT_OVERHEAD)) {
	require_avx();
	ymm_integrity(NORMAL_RUN_TIME);
}

T_DECL(ymm_integrity_stress,
    "Extended soak test to verify that AVX "
    "register state is maintained correctly",
    T_META_TIMEOUT(LONG_RUN_TIME + TIMEOUT_OVERHEAD),
    T_META_ENABLED(false)) {
	require_avx();
	ymm_integrity(LONG_RUN_TIME);
}

T_DECL(zmm_integrity,
    "Quick soak test to verify that AVX-512 "
    "register state is maintained correctly",
    T_META_TIMEOUT(LONG_RUN_TIME + TIMEOUT_OVERHEAD)) {
	require_avx512();
	zmm_integrity(NORMAL_RUN_TIME);
}

T_DECL(zmm_integrity_stress,
    "Extended soak test to verify that AVX-512 "
    "register state is maintained correctly",
    T_META_TIMEOUT(NORMAL_RUN_TIME + TIMEOUT_OVERHEAD),
    T_META_ENABLED(false)) {
	require_avx512();
	zmm_integrity(LONG_RUN_TIME);
}
