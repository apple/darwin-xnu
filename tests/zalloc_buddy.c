#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach.h>
#include <sys/mman.h>

#undef __abortlike
#define __abortlike
#define panic(fmt, ...) ({ T_FAIL(fmt, __VA_ARGS__); abort(); })

#define __security_const_late
#define ZALLOC_TEST 1
#include "../osfmk/kern/zalloc.c"

#define ZBA_TEST_SIZE  (1ul << 20)

static void
zba_populate_any(vm_address_t addr, vm_size_t size)
{
	int rc = mprotect((void *)addr, size, PROT_READ | PROT_WRITE);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "mprotect");
}

static void
zba_populate_nope(vm_address_t addr, vm_size_t size)
{
#pragma unused(addr, size)
	T_FAIL("Trying to extend the storage");
	T_END;
}

static void
zba_test_allow_extension(void)
{
	zba_test_info.zbats_populate = zba_populate_any;
}

static void
zba_test_disallow_extension(void)
{
	zba_test_info.zbats_populate = zba_populate_nope;
}

static void
zba_test_setup(void)
{
	kern_return_t kr;
	int rc;

	kr = vm_allocate(mach_task_self(), &zba_test_info.zbats_base,
	    ZBA_TEST_SIZE + ZBA_CHUNK_SIZE, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	zba_test_info.zbats_base = roundup(zba_test_info.zbats_base,
	    ZBA_CHUNK_SIZE);

	rc = mprotect(zba_base_header(), ZBA_TEST_SIZE, PROT_NONE);
	T_ASSERT_POSIX_SUCCESS(rc, "mprotect");

	T_LOG("SETUP allocator with base at %p", zba_base_header());

	zba_test_allow_extension();
	zba_populate(0);
	zba_init_chunk(0);
}

T_DECL(zone_buddy_allocator_encodings, "test the buddy allocator formulas")
{
	uint8_t bits[sizeof(zba_base_header()->zbah_bits)] = { };

	for (uint32_t o = ZBA_MAX_ORDER + 1; o-- > 0;) {
		for (vm_address_t pos = 0; pos < ZBA_CHUNK_SIZE; pos += ZBA_GRANULE << o) {
			struct zone_bits_chain *zbc;
			size_t node = zba_node(pos, o);

			zbc = zba_chain_for_node(NULL, node, o);
			T_QUIET; T_ASSERT_EQ(pos, (vm_offset_t)zbc,
			    "zba_node / zba_chain_for_node is reversible (pos: %lx, node %zd)",
			    pos, node);


			if (o == 0) {
				// leaf nodes aren't represented in the bitmap
				continue;
			}
			T_QUIET; T_ASSERT_LT(node, 8 * sizeof(bits), "fits in bitfield: %zd", pos);
			T_QUIET; T_ASSERT_EQ(0, bits[node / 8] & (1 << (node % 8)), "never seen");
			bits[node / 8] ^= 1 << (node % 8);
		}
	}

	T_PASS("zba_node, zba_chain_for_node look sane");
}

T_DECL(zone_buddy_allocator, "test the zone bits setup")
{
	vm_address_t base, pos;

	zba_test_setup();

	zba_test_disallow_extension();

	base = (vm_address_t)zba_slot_base();
	for (pos = zba_chunk_header_size(0); pos < ZBA_CHUNK_SIZE; pos += ZBA_GRANULE) {
		T_QUIET; T_ASSERT_EQ(base + pos, zba_alloc(0), "alloc");
		*(uint64_t *)(base + pos) = ~0ull;
	}
	for (pos = zba_chunk_header_size(0); pos < ZBA_CHUNK_SIZE; pos += ZBA_GRANULE) {
		zba_free(base + pos, 0);
	}

	for (pos = zba_chunk_header_size(0); pos < ZBA_CHUNK_SIZE; pos += ZBA_GRANULE) {
		T_QUIET; T_ASSERT_EQ(base + pos, zba_alloc(0), "alloc");
		*(uint64_t *)(base + pos) = ~0ull;
	}
	zba_test_allow_extension();

	base += ZBA_CHUNK_SIZE;
	for (pos = zba_chunk_header_size(1); pos < ZBA_CHUNK_SIZE; pos += ZBA_GRANULE) {
		T_QUIET; T_ASSERT_EQ(base + pos, zba_alloc(0), "alloc");
		*(uint64_t *)(base + pos) = ~0ull;
	}

	for (pos = zba_chunk_header_size(1); pos < ZBA_CHUNK_SIZE; pos += ZBA_GRANULE) {
		zba_free(base + pos, 0);
	}
	base -= ZBA_CHUNK_SIZE;
	for (pos = zba_chunk_header_size(0); pos < ZBA_CHUNK_SIZE; pos += ZBA_GRANULE) {
		zba_free(base + pos, 0);
	}
}
