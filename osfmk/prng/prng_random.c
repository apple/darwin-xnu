/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <kern/locks.h>
#include <kern/cpu_number.h>
#include <libkern/section_keywords.h>
#include <libkern/crypto/sha2.h>
#include <machine/machine_cpu.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <sys/random.h>
#include <prng/random.h>
#include <prng/entropy.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/cckprng.h>
#include <corecrypto/ccsha2.h>

static struct cckprng_ctx *prng_ctx;

static SECURITY_READ_ONLY_LATE(struct cckprng_funcs) prng_funcs;
static SECURITY_READ_ONLY_LATE(int) prng_ready;

#define SEED_SIZE (SHA256_DIGEST_LENGTH)
static uint8_t bootseed[SEED_SIZE];

static void
bootseed_init_bootloader(const struct ccdigest_info * di, ccdigest_ctx_t ctx)
{
	uint8_t seed[64];
	uint32_t n;

	n = PE_get_random_seed(seed, sizeof(seed));
	if (n < sizeof(seed)) {
		/*
		 * Insufficient entropy is fatal.  We must fill the
		 * entire entropy buffer during initializaton.
		 */
		panic("Expected %lu seed bytes from bootloader, but got %u.\n", sizeof(seed), n);
	}

	ccdigest_update(di, ctx, sizeof(seed), seed);
	cc_clear(sizeof(seed), seed);
}

#if defined(__x86_64__)
#include <i386/cpuid.h>

static void
bootseed_init_native(const struct ccdigest_info * di, ccdigest_ctx_t ctx)
{
	uint64_t x;
	uint8_t ok;
	size_t i = 0;
	size_t n;

	if (cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_RDSEED) {
		n = SEED_SIZE / sizeof(x);

		while (i < n) {
			asm volatile ("rdseed %0; setc %1" : "=r"(x), "=qm"(ok) : : "cc");
			if (ok) {
				ccdigest_update(di, ctx, sizeof(x), &x);
				i += 1;
			} else {
				// Intel recommends to pause between unsuccessful rdseed attempts.
				cpu_pause();
			}
		}
	} else if (cpuid_features() & CPUID_FEATURE_RDRAND) {
		// The Intel documentation guarantees a reseed every 512 rdrand calls.
		n = (SEED_SIZE / sizeof(x)) * 512;

		while (i < n) {
			asm volatile ("rdrand %0; setc %1" : "=r"(x), "=qm"(ok) : : "cc");
			if (ok) {
				ccdigest_update(di, ctx, sizeof(x), &x);
				i += 1;
			} else {
				// Intel does not recommend pausing between unsuccessful rdrand attempts.
			}
		}
	}

	cc_clear(sizeof(x), &x);
}

#else

static void
bootseed_init_native(__unused const struct ccdigest_info * di, __unused ccdigest_ctx_t ctx)
{
}

#endif

static void
bootseed_init(void)
{
	const struct ccdigest_info * di = &ccsha256_ltc_di;

	ccdigest_di_decl(di, ctx);
	ccdigest_init(di, ctx);

	bootseed_init_bootloader(di, ctx);
	bootseed_init_native(di, ctx);

	ccdigest_final(di, ctx, bootseed);
	ccdigest_di_clear(di, ctx);
}

#define EARLY_RANDOM_STATE_STATIC_SIZE (264)

static struct {
	uint8_t drbg_state[EARLY_RANDOM_STATE_STATIC_SIZE];
	struct ccdrbg_info drbg_info;
	const struct ccdrbg_nisthmac_custom drbg_custom;
} erandom = {.drbg_custom = {
		     .di         = &ccsha256_ltc_di,
		     .strictFIPS = 0,
	     }};

static void read_erandom(void * buf, size_t nbytes);

/*
 * Return a uniformly distributed 64-bit random number.
 *
 * This interface should have minimal dependencies on kernel services,
 * and thus be available very early in the life of the kernel.
 *
 * This provides cryptographically secure randomness contingent on the
 * quality of the seed. It is seeded (lazily) with entropy provided by
 * the Booter.
 *
 * The implementation is a NIST HMAC-SHA256 DRBG instance used as
 * follows:
 *
 *  - When first called (on macOS this is very early while page tables
 *    are being built) early_random() calls ccdrbg_factory_hmac() to
 *    set-up a ccdbrg info structure.
 *
 *  - The boot seed (64 bytes) is hashed with SHA256. Where available,
 *    hardware RNG outputs are mixed into the seed. (See
 *    bootseed_init.) The resulting seed is 32 bytes.
 *
 *  - The ccdrbg state structure is a statically allocated area which
 *    is then initialized by calling the ccdbrg_init method. The
 *    initial entropy is the 32-byte seed described above. The nonce
 *    is an 8-byte timestamp from ml_get_timebase(). The
 *    personalization data provided is a fixed string.
 *
 *  - 64-bit outputs are generated via read_erandom, a wrapper around
 *    the ccdbrg_generate method. (Since "strict FIPS" is disabled,
 *    the DRBG will never request a reseed.)
 *
 *  - After the kernel PRNG is initialized, read_erandom defers
 *    generation to it via read_random_generate. (Note that this
 *    function acquires a per-processor mutex.)
 */
uint64_t
early_random(void)
{
	uint64_t result;
	uint64_t nonce;
	int rc;
	const char ps[] = "xnu early random";
	static int init = 0;

	if (init == 0) {
		bootseed_init();

		/* Init DRBG for NIST HMAC */
		ccdrbg_factory_nisthmac(&erandom.drbg_info, &erandom.drbg_custom);
		assert(erandom.drbg_info.size <= sizeof(erandom.drbg_state));

		/*
		 * Init our DBRG from the boot entropy and a timestamp as nonce
		 * and the cpu number as personalization.
		 */
		assert(sizeof(bootseed) > sizeof(nonce));
		nonce = ml_get_timebase();
		rc = ccdrbg_init(&erandom.drbg_info, (struct ccdrbg_state *)erandom.drbg_state, sizeof(bootseed), bootseed, sizeof(nonce), &nonce, sizeof(ps) - 1, ps);
		if (rc != CCDRBG_STATUS_OK) {
			panic("ccdrbg_init() returned %d", rc);
		}

		cc_clear(sizeof(nonce), &nonce);

		init = 1;
	}

	read_erandom(&result, sizeof(result));

	return result;
}

static void
read_random_generate(uint8_t *buffer, size_t numbytes);

static void
read_erandom(void * buf, size_t nbytes)
{
	uint8_t * buffer_bytes = buf;
	size_t n;
	int rc;

	// We defer to the kernel PRNG after it has been installed and
	// initialized. This happens during corecrypto kext
	// initialization.
	if (prng_ready) {
		read_random_generate(buf, nbytes);
		return;
	}

	// The DBRG request size is limited, so we break the request into
	// chunks.
	while (nbytes > 0) {
		n = MIN(nbytes, PAGE_SIZE);

		// Since "strict FIPS" is disabled, the DRBG will never
		// request a reseed; therefore, we panic on any error
		rc = ccdrbg_generate(&erandom.drbg_info, (struct ccdrbg_state *)erandom.drbg_state, n, buffer_bytes, 0, NULL);
		if (rc != CCDRBG_STATUS_OK) {
			panic("read_erandom ccdrbg error %d\n", rc);
		}

		buffer_bytes += n;
		nbytes -= n;
	}
}

void
read_frandom(void * buffer, u_int numBytes)
{
	read_erandom(buffer, numBytes);
}

void
register_and_init_prng(struct cckprng_ctx *ctx, const struct cckprng_funcs *funcs)
{
	assert(cpu_number() == master_cpu);
	assert(!prng_ready);

	entropy_init();

	prng_ctx = ctx;
	prng_funcs = *funcs;

	uint64_t nonce = ml_get_timebase();
	prng_funcs.init_with_getentropy(prng_ctx, MAX_CPUS, sizeof(bootseed), bootseed, sizeof(nonce), &nonce, entropy_provide, NULL);
	prng_funcs.initgen(prng_ctx, master_cpu);
	prng_ready = 1;

	cc_clear(sizeof(bootseed), bootseed);
	cc_clear(sizeof(erandom), &erandom);
}

void
random_cpu_init(int cpu)
{
	assert(cpu != master_cpu);

	if (!prng_ready) {
		panic("random_cpu_init: kernel prng has not been installed");
	}

	prng_funcs.initgen(prng_ctx, cpu);
}

/* export good random numbers to the rest of the kernel */
void
read_random(void * buffer, u_int numbytes)
{
	prng_funcs.refresh(prng_ctx);
	read_random_generate(buffer, numbytes);
}

static void
ensure_gsbase(void)
{
#if defined(__x86_64__) && (DEVELOPMENT || DEBUG)
	/*
	 * Calling cpu_number() before gsbase is initialized is potentially
	 * catastrophic, so assert that it's not set to the magic value set
	 * in i386_init.c before proceeding with the call.  We cannot use
	 * assert here because it ultimately calls panic, which executes
	 * operations that involve accessing %gs-relative data (and additionally
	 * causes a debug trap which will not work properly this early in boot.)
	 */
	if (rdmsr64(MSR_IA32_GS_BASE) == EARLY_GSBASE_MAGIC) {
		kprintf("[early_random] Cannot proceed: GSBASE is not initialized\n");
		hlt();
		/*NOTREACHED*/
	}
#endif
}

static void
read_random_generate(uint8_t *buffer, size_t numbytes)
{
	ensure_gsbase();

	while (numbytes > 0) {
		size_t n = MIN(numbytes, CCKPRNG_GENERATE_MAX_NBYTES);

		prng_funcs.generate(prng_ctx, cpu_number(), n, buffer);

		buffer += n;
		numbytes -= n;
	}
}

int
write_random(void * buffer, u_int numbytes)
{
	uint8_t seed[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	/* hash the input to minimize the time we need to hold the lock */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buffer, numbytes);
	SHA256_Final(seed, &ctx);

	prng_funcs.reseed(prng_ctx, sizeof(seed), seed);
	cc_clear(sizeof(seed), seed);

	return 0;
}

/*
 * Boolean PRNG for generating booleans to randomize order of elements
 * in certain kernel data structures. The algorithm is a
 * modified version of the KISS RNG proposed in the paper:
 * http://stat.fsu.edu/techreports/M802.pdf
 * The modifications have been documented in the technical paper
 * paper from UCL:
 * http://www0.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 */

/* Initialize the PRNG structures. */
void
random_bool_init(struct bool_gen * bg)
{
	/* Seed the random boolean generator */
	read_frandom(bg->seed, sizeof(bg->seed));
	bg->state = 0;
	simple_lock_init(&bg->lock, 0);
}

/* Generate random bits and add them to an entropy pool. */
void
random_bool_gen_entropy(struct bool_gen * bg, unsigned int * buffer, int count)
{
	simple_lock(&bg->lock, LCK_GRP_NULL);
	int i, t;
	for (i = 0; i < count; i++) {
		bg->seed[1] ^= (bg->seed[1] << 5);
		bg->seed[1] ^= (bg->seed[1] >> 7);
		bg->seed[1] ^= (bg->seed[1] << 22);
		t           = bg->seed[2] + bg->seed[3] + bg->state;
		bg->seed[2] = bg->seed[3];
		bg->state   = t < 0;
		bg->seed[3] = t & 2147483647;
		bg->seed[0] += 1411392427;
		buffer[i] = (bg->seed[0] + bg->seed[1] + bg->seed[3]);
	}
	simple_unlock(&bg->lock);
}

/* Get some number of bits from the entropy pool, refilling if necessary. */
unsigned int
random_bool_gen_bits(struct bool_gen * bg, unsigned int * buffer, unsigned int count, unsigned int numbits)
{
	unsigned int index = 0;
	unsigned int rbits = 0;
	for (unsigned int bitct = 0; bitct < numbits; bitct++) {
		/*
		 * Find a portion of the buffer that hasn't been emptied.
		 * We might have emptied our last index in the previous iteration.
		 */
		while (index < count && buffer[index] == 0) {
			index++;
		}

		/* If we've exhausted the pool, refill it. */
		if (index == count) {
			random_bool_gen_entropy(bg, buffer, count);
			index = 0;
		}

		/* Collect-a-bit */
		unsigned int bit = buffer[index] & 1;
		buffer[index]    = buffer[index] >> 1;
		rbits            = bit | (rbits << 1);
	}
	return rbits;
}
