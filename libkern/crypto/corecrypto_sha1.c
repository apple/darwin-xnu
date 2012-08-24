
#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/sha1.h>
#include <kern/debug.h>
#include <corecrypto/ccdigest.h>


static uint64_t getCount(SHA1_CTX *ctx)
{
	return ctx->c.b64[0];
}

static void setCount(SHA1_CTX *ctx, uint64_t count)
{
	ctx->c.b64[0]=count;
}

/* Copy a ccdigest ctx into a legacy SHA1 context */
static void DiToSHA1(const struct ccdigest_info *di, struct ccdigest_ctx *di_ctx, SHA1_CTX *sha1_ctx)
{
	setCount(sha1_ctx, ccdigest_nbits(di, di_ctx)/8+ccdigest_num(di, di_ctx));
	memcpy(sha1_ctx->m.b8, ccdigest_data(di, di_ctx), di->block_size);
	memcpy(sha1_ctx->h.b8, ccdigest_state_ccn(di, di_ctx), di->state_size);
}

/* Copy a legacy SHA1 context into a ccdigest ctx  */
static void SHA1ToDi(const struct ccdigest_info *di, SHA1_CTX *sha1_ctx, struct ccdigest_ctx *di_ctx)
{
	uint64_t count = getCount(sha1_ctx);
	
	ccdigest_num(di, di_ctx)=count%di->block_size;
	ccdigest_nbits(di, di_ctx)=(count-ccdigest_num(di, di_ctx))*8;
	memcpy(ccdigest_data(di, di_ctx), sha1_ctx->m.b8, di->block_size);
	memcpy(ccdigest_state_ccn(di, di_ctx), sha1_ctx->h.b8, di->state_size);	
}

void SHA1Init(SHA1_CTX *ctx)
{
	const struct ccdigest_info *di=g_crypto_funcs->ccsha1_di;
	ccdigest_di_decl(di, di_ctx);
	
	g_crypto_funcs->ccdigest_init_fn(di, di_ctx);
	
	DiToSHA1(di, di_ctx, ctx);
}

void SHA1Update(SHA1_CTX *ctx, const void *data, size_t len)
{
	const struct ccdigest_info *di=g_crypto_funcs->ccsha1_di;
	ccdigest_di_decl(di, di_ctx);
	
	SHA1ToDi(di, ctx, di_ctx);
	g_crypto_funcs->ccdigest_update_fn(di, di_ctx, len, data);	
	DiToSHA1(di, di_ctx, ctx);
}

void SHA1Final(void *digest, SHA1_CTX *ctx)
{
	const struct ccdigest_info *di=g_crypto_funcs->ccsha1_di;
	ccdigest_di_decl(di, di_ctx);
	
	SHA1ToDi(di, ctx, di_ctx);
	ccdigest_final(di, di_ctx, digest);
}

#ifdef XNU_KERNEL_PRIVATE
void SHA1UpdateUsePhysicalAddress(SHA1_CTX *ctx, const void *data, size_t len)
{
	//TODO: What the hell ?
	SHA1Update(ctx, data, len);
}
#endif

/* This is not publicised in header, but exported in libkern.exports */ 
void SHA1Final_r(SHA1_CTX *context, void *digest);
void SHA1Final_r(SHA1_CTX *context, void *digest)
{
	SHA1Final(digest, context);
}


/*
 * This function is called by the SHA1 hardware kext during its init.
 * This will register the function to call to perform SHA1 using hardware.
 */
#include <sys/types.h>
#include <libkern/OSAtomic.h>
#include <sys/systm.h>

typedef kern_return_t (*InKernelPerformSHA1Func)(void *ref, const void *data, size_t dataLen, u_int32_t *inHash, u_int32_t options, u_int32_t *outHash, Boolean usePhysicalAddress);
void sha1_hardware_hook(Boolean option, InKernelPerformSHA1Func func, void *ref);
static void *SHA1Ref;
static InKernelPerformSHA1Func performSHA1WithinKernelOnly;

void sha1_hardware_hook(Boolean option, InKernelPerformSHA1Func func, void *ref)
{
	if(option) {
		// Establish the hook. The hardware is ready.
		OSCompareAndSwapPtr((void*)NULL, (void*)ref, (void * volatile*)&SHA1Ref);

		if(!OSCompareAndSwapPtr((void *)NULL, (void *)func, (void * volatile *)&performSHA1WithinKernelOnly)) {
			panic("sha1_hardware_hook: Called twice.. Should never happen\n");
		}
	}
	else {
		// The hardware is going away. Tear down the hook.
		performSHA1WithinKernelOnly = NULL;
		SHA1Ref = NULL;
	}
}
