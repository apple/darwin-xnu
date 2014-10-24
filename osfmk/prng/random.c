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

#include <mach/machine.h>
#include <mach/processor.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/kalloc.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/sched.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <machine/cpu_data.h>
#include <machine/simple_lock.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <sys/kdebug.h>
#include <sys/random.h>

#include <prng/random.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccsha1.h>

#include <pexpert/pexpert.h>
#include <console/serial_protos.h>
#include <IOKit/IOPlatformExpert.h>

static lck_grp_t *gPRNGGrp;
static lck_attr_t *gPRNGAttr;
static lck_grp_attr_t *gPRNGGrpAttr;
static lck_mtx_t *gPRNGMutex = NULL;

typedef struct prngContext {
	struct ccdrbg_info	*infop;
	struct ccdrbg_state	*statep;
	uint64_t		bytes_generated;
	uint64_t		bytes_reseeded;
} *prngContextp;

ccdrbg_factory_t prng_ccdrbg_factory = NULL;

entropy_data_t	EntropyData = { .index_ptr = EntropyData.buffer };

boolean_t		erandom_seed_set = FALSE;
char			erandom_seed[EARLY_RANDOM_SEED_SIZE];
typedef struct ccdrbg_state ccdrbg_state_t;
uint8_t			master_erandom_state[EARLY_RANDOM_STATE_STATIC_SIZE];
ccdrbg_state_t		*erandom_state[MAX_CPUS];
struct ccdrbg_info	erandom_info;
decl_simple_lock_data(,entropy_lock);

struct ccdrbg_nisthmac_custom erandom_custom = {
	.di = &ccsha1_eay_di,
	.strictFIPS = 0,
};

static void read_erandom(void *buffer, u_int numBytes);	/* Forward */

void 
entropy_buffer_read(char		*buffer,
		    unsigned int	*count)
{
	boolean_t       current_state;
	unsigned int    i, j;

	if (!erandom_seed_set) {
		panic("early_random was never invoked");
	}

	if ((*count) > (ENTROPY_BUFFER_SIZE * sizeof(unsigned int)))
		*count = ENTROPY_BUFFER_SIZE * sizeof(unsigned int);

	current_state = ml_set_interrupts_enabled(FALSE);
#if defined (__x86_64__)
	simple_lock(&entropy_lock);
#endif

	memcpy((char *) buffer, (char *) EntropyData.buffer, *count);

	for (i = 0, j = (ENTROPY_BUFFER_SIZE - 1); i < ENTROPY_BUFFER_SIZE; j = i, i++)
		EntropyData.buffer[i] = EntropyData.buffer[i] ^ EntropyData.buffer[j];

#if defined (__x86_64__)
	simple_unlock(&entropy_lock);
#endif
	(void) ml_set_interrupts_enabled(current_state);

#if DEVELOPMENT || DEBUG
	uint32_t	*word = (uint32_t *) (void *) buffer;
	/* Good for both 32-bit and 64-bit kernels. */
	for (i = 0; i < ENTROPY_BUFFER_SIZE; i += 4)
		/* 
		 * We use "EARLY" here so that we can grab early entropy on
		 * ARM, where tracing is not started until after PRNG is
		 * initialized.
		*/
		KERNEL_DEBUG_EARLY(ENTROPY_READ(i/4),
			word[i+0], word[i+1], word[i+2], word[i+3]);
#endif
}

/*
 * Return a uniformly distributed 64-bit random number.
 *
 * This interface should have minimal dependencies on kernel
 * services, and thus be available very early in the life
 * of the kernel.
 * This provides cryptographically secure randomness.
 * Each processor has its own generator instance.
 * It is seeded (lazily) with entropy provided by the Booter.
*
 * For <rdar://problem/17292592> the algorithm switched from LCG to
 * NIST HMAC DBRG as follows:
 *  - When first called (on OSX this is very early while page tables are being
 *    built) early_random() calls ccdrbg_factory_hmac() to set-up a ccdbrg info
 *    structure.
 *  - The boot processor's ccdrbg state structure is a statically allocated area
 *    which is then initialized by calling the ccdbrg_init method.
 *    The initial entropy is 16 bytes of boot entropy.
 *    The nonce is the first 8 bytes of entropy xor'ed with a timestamp
 *    from ml_get_timebase().
 *    The personalization data provided is null. 
 *  - The first 64-bit random value is returned on the boot processor from
 *    an invocation of the ccdbrg_generate method.
 *  - Non-boot processor's DRBG state structures are allocated dynamically
 *    from prng_init(). Each is initialized with the same 16 bytes of entropy
 *    but with a different timestamped nonce and cpu number as personalization.
 *  - Subsequent calls to early_random() pass to read_erandom() to generate
 *    an 8-byte random value.  read_erandom() ensures that pre-emption is
 *    disabled and selects the DBRG state from the current processor.
 *    The ccdbrg_generate method is called for the required random output.
 *    If this method returns CCDRBG_STATUS_NEED_RESEED, the erandom_seed buffer
 *    is re-filled with kernel-harvested entropy and the ccdbrg_reseed method is
 *    called with this new entropy. The kernel panics if a reseed fails.
 */
uint64_t
early_random(void)
{
	uint32_t	cnt = 0;
	uint64_t	result;
	uint64_t	nonce;
	int		rc;
	ccdrbg_state_t	*state;

	if (!erandom_seed_set) {
		simple_lock_init(&entropy_lock,0);
		erandom_seed_set = TRUE;
		cnt = PE_get_random_seed((unsigned char *) EntropyData.buffer,
					 sizeof(EntropyData.buffer));

		if (cnt < sizeof(EntropyData.buffer)) {
			/*
			 * Insufficient entropy is fatal.  We must fill the
			 * entire entropy buffer during initializaton.
			 */
			panic("EntropyData needed %lu bytes, but got %u.\n",
				sizeof(EntropyData.buffer), cnt);
		}		

		/*
		 * Use some of the supplied entropy as a basis for early_random;
		 * reuse is ugly, but simplifies things. Ideally, we would guard
		 * early random values well enough that it isn't safe to attack
		 * them, but this cannot be guaranteed; thus, initial entropy
		 * can be considered 8 bytes weaker for a given boot if any
		 * early random values are conclusively determined.
		 *
		 * early_random_seed could be larger than EntopyData.buffer...
		 * but it won't be.
		 */
		bcopy(EntropyData.buffer, &erandom_seed, sizeof(erandom_seed));

		/* Init DRBG for NIST HMAC */
		ccdrbg_factory_nisthmac(&erandom_info, &erandom_custom);
		assert(erandom_info.size <= sizeof(master_erandom_state));
		state = (ccdrbg_state_t *) master_erandom_state;
		erandom_state[0] = state;

		/*
		 * Init our DBRG from the boot entropy and a nonce composed of
		 * a timestamp swizzled with the first 8 bytes of this entropy.
		 */
		assert(sizeof(erandom_seed) > sizeof(nonce));
		bcopy(erandom_seed, &nonce, sizeof(nonce));
		nonce ^= ml_get_timebase();
		rc = ccdrbg_init(&erandom_info, state,
				 sizeof(erandom_seed), erandom_seed,
				 sizeof(nonce), &nonce,
				 0, NULL);
		assert(rc == CCDRBG_STATUS_OK);

		/* Generate output */
		rc = ccdrbg_generate(&erandom_info, state,
				     sizeof(result), &result,
				     0, NULL);
		assert(rc == CCDRBG_STATUS_OK);
	
		return result;
	};

	read_erandom(&result, sizeof(result));

	return result;
}

void
read_erandom(void *buffer, u_int numBytes)
{
	int		cpu;
	int		rc;
	uint32_t	cnt;
	ccdrbg_state_t	*state;

	mp_disable_preemption();
	cpu = cpu_number();
	state = erandom_state[cpu];
	assert(state);
	while (TRUE) {
		/* Generate output */
		rc = ccdrbg_generate(&erandom_info, state,
				     numBytes, buffer,
				     0, NULL);
		if (rc == CCDRBG_STATUS_OK)
			break;
		if (rc == CCDRBG_STATUS_NEED_RESEED) {
			/* It's time to reseed. Get more entropy */
			cnt = sizeof(erandom_seed);
			entropy_buffer_read(erandom_seed, &cnt);
			assert(cnt == sizeof(erandom_seed));
			rc = ccdrbg_reseed(&erandom_info, state,
					   sizeof(erandom_seed), erandom_seed,
					   0, NULL);
			if (rc == CCDRBG_STATUS_OK)
				continue;
			panic("read_erandom reseed error %d\n", rc);
		}
		panic("read_erandom ccdrbg error %d\n", rc);
	}
	mp_enable_preemption();
}

void
read_frandom(void *buffer, u_int numBytes)
{
	char		*cp = (char *) buffer;
	int		nbytes;

	/*
	 * Split up into requests for blocks smaller than
	 * than the DBRG request limit. iThis limit is private but
	 * for NISTHMAC it's known to be greater then 4096.
	 */
	while (numBytes) {
		nbytes = MIN(numBytes, PAGE_SIZE);
		read_erandom(cp, nbytes);
		cp += nbytes;
		numBytes -= nbytes;
	}
}

/*
 * Register a DRBG factory routine to e used in constructing the kernel PRNG.
 * XXX to be called from the corecrypto kext.
 */
void
prng_factory_register(ccdrbg_factory_t factory)
{
	prng_ccdrbg_factory = factory;
	thread_wakeup((event_t) &prng_ccdrbg_factory);
}

void
prng_cpu_init(int cpu)
{	
	uint64_t	nonce;
	int		rc;
	ccdrbg_state_t	*state;
	prngContextp	pp;

	/*
	 * Allocate state and initialize DBRG state for early_random()
	 * for this processor, if necessary.
	 */
	if (erandom_state[cpu] == NULL) {
		
		state = kalloc(erandom_info.size);
		if (state == NULL) {
			panic("prng_init kalloc failed\n");
		}
		erandom_state[cpu] = state;

		/*
		 * Init our DBRG from boot entropy, nonce as timestamp xor'ed
		 * with the first 8 bytes of entropy, and use the cpu number
		 * as the personalization parameter.
		 */
		bcopy(erandom_seed, &nonce, sizeof(nonce));
		nonce ^= ml_get_timebase();
		rc = ccdrbg_init(&erandom_info, state,
				 sizeof(erandom_seed), erandom_seed,
				 sizeof(nonce), &nonce,
				 sizeof(cpu), &cpu);
		assert(rc == CCDRBG_STATUS_OK);
	}

	/* Non-boot cpus use the master cpu's global context */
	if (cpu != master_cpu) {
		cpu_datap(cpu)->cpu_prng = master_prng_context();
		return;
	}

	assert(gPRNGMutex == NULL);		/* Once only, please */

	/* make a mutex to control access */
	gPRNGGrpAttr = lck_grp_attr_alloc_init();
	gPRNGGrp     = lck_grp_alloc_init("random", gPRNGGrpAttr);
	gPRNGAttr    = lck_attr_alloc_init();
	gPRNGMutex   = lck_mtx_alloc_init(gPRNGGrp, gPRNGAttr);

	pp = kalloc(sizeof(*pp));
	if (pp == NULL)
		panic("Unable to allocate prng context");
	pp->bytes_generated = 0;
	pp->bytes_reseeded = 0;
	pp->infop = NULL;

	/* XXX Temporary registration */
	prng_factory_register(ccdrbg_factory_yarrow);

	master_prng_context() = pp;
}

static ccdrbg_info_t *
prng_infop(prngContextp pp)
{
	lck_mtx_assert(gPRNGMutex, LCK_MTX_ASSERT_OWNED);

	/* Usual case: the info is all set */
	if (pp->infop)
		return pp->infop;

	/*
	 * Possibly wait for the CCDRBG factory routune to be registered
	 * by corecypto. But panic after waiting for more than 10 seconds.
	 */
	while (prng_ccdrbg_factory == NULL ) {
		wait_result_t	wait_result;
		assert_wait_timeout((event_t) &prng_ccdrbg_factory, TRUE,
				    10, NSEC_PER_USEC);
		lck_mtx_unlock(gPRNGMutex);
		wait_result = thread_block(THREAD_CONTINUE_NULL);
		if (wait_result == THREAD_TIMED_OUT)
			panic("prng_ccdrbg_factory registration timeout");
		lck_mtx_lock(gPRNGMutex);
	}
	/* Check we didn't lose the set-up race */
	if (pp->infop)
		return pp->infop;

	pp->infop = (ccdrbg_info_t *) kalloc(sizeof(ccdrbg_info_t));
	if (pp->infop == NULL)
		panic("Unable to allocate prng info");

	prng_ccdrbg_factory(pp->infop, NULL);

	pp->statep = kalloc(pp->infop->size);
	if (pp->statep == NULL)
		panic("Unable to allocate prng state");

	char rdBuffer[ENTROPY_BUFFER_BYTE_SIZE];
	unsigned int bytesToInput = sizeof(rdBuffer);

	entropy_buffer_read(rdBuffer, &bytesToInput);

	(void) ccdrbg_init(pp->infop, pp->statep,
			   bytesToInput, rdBuffer,
			   0, NULL,
			   0, NULL);
	return pp->infop;
}

static void
Reseed(prngContextp pp)
{
	char		rdBuffer[ENTROPY_BUFFER_BYTE_SIZE];
	unsigned int	bytesToInput = sizeof(rdBuffer);

	entropy_buffer_read(rdBuffer, &bytesToInput);

	PRNG_CCDRBG((void) ccdrbg_reseed(pp->infop, pp->statep,
					 bytesToInput, rdBuffer,
					 0, NULL)); 

	pp->bytes_reseeded = pp->bytes_generated;
}


/* export good random numbers to the rest of the kernel */
void
read_random(void* buffer, u_int numbytes)
{
	prngContextp	pp;
	ccdrbg_info_t	*infop;
	int		ccdrbg_err;

	lck_mtx_lock(gPRNGMutex);

	pp = current_prng_context();
	infop = prng_infop(pp);

	/*
	 * Call DRBG, reseeding and retrying if requested.
	 */
	while (TRUE) {
		PRNG_CCDRBG(
			ccdrbg_err = ccdrbg_generate(infop, pp->statep,
						     numbytes, buffer,
						     0, NULL));
		if (ccdrbg_err == CCDRBG_STATUS_OK)
			break;
		if (ccdrbg_err == CCDRBG_STATUS_NEED_RESEED) {
			Reseed(pp);
			continue;
		}
		panic("read_random ccdrbg error %d\n", ccdrbg_err);
	}

	pp->bytes_generated += numbytes;
	lck_mtx_unlock(gPRNGMutex);
}

int
write_random(void* buffer, u_int numbytes)
{
#if 0
	int		retval = 0;
	prngContextp	pp;

	lck_mtx_lock(gPRNGMutex);

	pp = current_prng_context();

	if (ccdrbg_reseed(prng_infop(pp), pp->statep,
			  bytesToInput, rdBuffer, 0, NULL) != 0)
		retval = EIO;

	lck_mtx_unlock(gPRNGMutex);
	return retval;
#else
#pragma  unused(buffer, numbytes)
    return 0;
#endif
}
