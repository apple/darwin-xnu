#include <dispatch/dispatch.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <sys/random.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define BUF_SIZE ((size_t)(1 << 25))
#define BLOCK_SIZE ((size_t)16)

static int
cmp(const void *a, const void *b)
{
	return memcmp(a, b, 16);
}

static void
prng_sanitycheck(uint8_t *buf, size_t buf_size)
{
	size_t nblocks = buf_size / BLOCK_SIZE;
	qsort(buf, nblocks, BLOCK_SIZE, cmp);

	for (size_t i = 0; i < nblocks - 1; i += 1) {
		T_QUIET;
		T_ASSERT_NE(memcmp(buf, buf + BLOCK_SIZE, BLOCK_SIZE), 0, "duplicate block");
		buf += BLOCK_SIZE;
	}
}

static void
prng_getentropy(void *ctx, size_t i)
{
	uint8_t *buf = ((uint8_t *)ctx) + (BUF_SIZE * i);

	for (size_t j = 0; j < BUF_SIZE; j += 256) {
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(getentropy(&buf[j], 256), "getentropy");
	}

	prng_sanitycheck(buf, BUF_SIZE);
}

static void
prng_devrandom(void *ctx, size_t i)
{
	uint8_t *buf = ((uint8_t *)ctx) + (BUF_SIZE * i);

	int fd = open("/dev/random", O_RDONLY);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fd, "open");

	size_t n = BUF_SIZE;
	while (n > 0) {
		ssize_t m = read(fd, buf, n);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(m, "read");

		n -= (size_t)m;
		buf += m;
	}

	buf = ((uint8_t *)ctx) + (BUF_SIZE * i);
	prng_sanitycheck(buf, BUF_SIZE);
}

T_DECL(prng, "prng test")
{
	size_t ncpu = (size_t)dt_ncpu();

	uint8_t *buf = malloc(BUF_SIZE * ncpu);
	T_QUIET;
	T_ASSERT_NOTNULL(buf, "malloc");

	dispatch_apply_f(ncpu, DISPATCH_APPLY_AUTO, buf, prng_getentropy);

	dispatch_apply_f(ncpu, DISPATCH_APPLY_AUTO, buf, prng_devrandom);

	prng_sanitycheck(buf, BUF_SIZE * ncpu);

	free(buf);
}
