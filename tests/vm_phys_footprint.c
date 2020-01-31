#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach_error.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/vm_map.h>

#include <sys/mman.h>

#include <Kernel/kern/ledger.h>
extern int ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3);

#if ENTITLED && defined(__arm64__)
#define LEGACY_FOOTPRINT 1
#else /* ENTITLED && __arm64__ */
#define LEGACY_FOOTPRINT 0
#endif /* ENTITLED && __arm64__ */

#define MEM_SIZE (100 * 1024 * 1024) /* 100 MB */

static int64_t ledger_count = -1;
static int footprint_index = -1;
static int pagetable_index = -1;
static struct ledger_entry_info *lei = NULL;

static void
ledger_init(void)
{
	static int                      ledger_inited = 0;
	struct ledger_info              li;
	struct ledger_template_info     *templateInfo;
	int64_t                         templateCnt;
	int                             i;

	if (ledger_inited) {
		return;
	}
	ledger_inited = 1;

	T_SETUPBEGIN;
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_EQ(ledger(LEDGER_INFO,
	    (caddr_t)(uintptr_t)getpid(),
	    (caddr_t)&li,
	    NULL),
	    0,
	    "ledger(LEDGER_INFO)");

	templateCnt = li.li_entries;
	templateInfo = malloc((size_t)li.li_entries * sizeof(struct ledger_template_info));
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_NE(templateInfo, NULL, "malloc()");

	ledger_count = li.li_entries;
	footprint_index = -1;
	pagetable_index = -1;
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_GE(ledger(LEDGER_TEMPLATE_INFO,
	    (caddr_t)templateInfo,
	    (caddr_t)&templateCnt,
	    NULL),
	    0,
	    "ledger(LEDGER_TEMPLATE_INFO)");
	for (i = 0; i < templateCnt; i++) {
		if (!strncmp(templateInfo[i].lti_name,
		    "phys_footprint",
		    strlen("phys_footprint"))) {
			footprint_index = i;
		} else if (!strncmp(templateInfo[i].lti_name,
		    "page_table",
		    strlen("page_table"))) {
			pagetable_index = i;
		}
	}
	free(templateInfo);

	lei = (struct ledger_entry_info *)
	    malloc((size_t)ledger_count * sizeof(*lei));
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_NE(lei, NULL, "malloc(ledger_entry_info)");

	T_QUIET;
	T_ASSERT_NE(footprint_index, -1, "no footprint_index");
	T_QUIET;
	T_ASSERT_NE(pagetable_index, -1, "no pagetable_index");

	T_SETUPEND;
}

static void
get_ledger_info(
	uint64_t        *phys_footprint,
	uint64_t        *page_table)
{
	int64_t count;

	count = ledger_count;
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_GE(ledger(LEDGER_ENTRY_INFO,
	    (caddr_t)(uintptr_t)getpid(),
	    (caddr_t)lei,
	    (caddr_t)&count),
	    0,
	    "ledger(LEDGER_ENTRY_INFO)");
	T_QUIET;
	T_ASSERT_GT(count, (int64_t)footprint_index, "no entry for footprint");
	T_QUIET;
	T_ASSERT_GT(count, (int64_t)pagetable_index, "no entry for pagetable");
	if (phys_footprint) {
		*phys_footprint = (uint64_t)(lei[footprint_index].lei_balance);
	}
	if (page_table) {
		*page_table = (uint64_t)(lei[pagetable_index].lei_balance);
	}
}

static mach_vm_address_t
pre_warm(
	mach_vm_size_t  vm_size)
{
	kern_return_t           kr;
	mach_vm_address_t       vm_addr;
	unsigned char           BigBufOnStack[100 * 1024];
	uint64_t                footprint, page_table;

	/* make sure ledgers are ready to be queried */
	ledger_init();

	T_SETUPBEGIN;

	/*
	 * Touch a few pages ahead on the stack, to make
	 * sure we don't see a footprint increase due to
	 * an extra stack page later.
	 */
	memset(BigBufOnStack, 0xb, sizeof(BigBufOnStack));
	T_QUIET;
	T_EXPECT_EQ(BigBufOnStack[0], 0xb,
	    "BigBufOnStack[0] == 0x%x",
	    BigBufOnStack[0]);
	T_QUIET;
	T_EXPECT_EQ(BigBufOnStack[sizeof(BigBufOnStack) - 1], 0xb,
	    "BigBufOnStack[%lu] == 0x%x",
	    sizeof(BigBufOnStack),
	    BigBufOnStack[sizeof(BigBufOnStack) - 1]);

	/*
	 * Pre-allocate, touch and then release the same amount
	 * of memory we'll be allocating later during the test,
	 * to account for any memory overhead (page tables, global
	 * variables, ...).
	 */
	vm_addr = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vm_addr,
	    vm_size,
	    VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_allocate(%lld) error 0x%x (%s)",
	    vm_size, kr, mach_error_string(kr));
	memset((char *)(uintptr_t)vm_addr, 'p', (size_t)vm_size);
	kr = mach_vm_deallocate(mach_task_self(),
	    vm_addr,
	    vm_size);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));

	/*
	 * Exercise the ledger code to make sure it's ready to run
	 * without any extra memory overhead later.
	 */
	get_ledger_info(&footprint, &page_table);

	T_SETUPEND;

	/*
	 * Return the start of the virtual range we pre-warmed, so that the
	 * test can check that it's using the same range.
	 */
	return vm_addr;
}

T_DECL(phys_footprint_anonymous,
    "phys_footprint for anonymous memory",
    T_META_NAMESPACE("xnu.vm"),
    T_META_LTEPHASE(LTE_POSTINIT))
{
	uint64_t                footprint_before, pagetable_before;
	uint64_t                footprint_after, pagetable_after;
	uint64_t                footprint_expected;
	kern_return_t           kr;
	mach_vm_address_t       pre_vm_addr, vm_addr;
	mach_vm_size_t          vm_size, dirty_size;

	/* pre-warm to account for page table expansion */
	pre_vm_addr = pre_warm(MEM_SIZE);

	/* allocating virtual memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	vm_addr = 0;
	vm_size = MEM_SIZE;
	kr = mach_vm_allocate(mach_task_self(), &vm_addr, vm_size,
	    VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_allocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(vm_addr, pre_vm_addr, "pre-warm mishap");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("virtual allocation does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "virtual allocation of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* touching memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	dirty_size = vm_size / 2;
	memset((char *)(uintptr_t)vm_addr, 'x', (size_t)dirty_size);
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("modifying anonymous memory increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "touched %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* deallocating memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	kr = mach_vm_deallocate(mach_task_self(), vm_addr, vm_size);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("deallocating dirty anonymous memory decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "deallocated %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
}

#define TEMP_FILE_TEMPLATE "/tmp/phys_footprint_data.XXXXXXXX"
#define TEMP_FILE_SIZE  (1 * 1024 * 1024)

T_DECL(phys_footprint_file,
    "phys_footprint for mapped file",
    T_META_NAMESPACE("xnu.vm"),
    T_META_LTEPHASE(LTE_POSTINIT))
{
	uint64_t                footprint_before, pagetable_before;
	uint64_t                footprint_after, pagetable_after;
	uint64_t                footprint_expected;
	mach_vm_address_t       pre_vm_addr;
	int                     fd;
	char                    *map_addr;
	size_t                  map_size, dirty_size;
	ssize_t                 nbytes;
	char                    tmp_file_name[PATH_MAX] = TEMP_FILE_TEMPLATE;
	char                    *buf;
	size_t                  buf_size;

	T_SETUPBEGIN;
	buf_size = TEMP_FILE_SIZE;
	T_QUIET;
	T_ASSERT_NOTNULL(buf = (char *)malloc(buf_size),
	    "allocate %zu-byte buffer", buf_size);
	memset(buf, 'f', buf_size);
	T_WITH_ERRNO;
	T_QUIET;
	T_ASSERT_NOTNULL(mktemp(tmp_file_name),
	    "create temporary file name");
	T_WITH_ERRNO;
	T_QUIET;
	T_ASSERT_GE(fd = open(tmp_file_name, O_CREAT | O_RDWR),
	    0,
	    "create temp file");
	T_WITH_ERRNO;
	T_QUIET;
	T_ASSERT_EQ(nbytes = write(fd, buf, buf_size),
	    (ssize_t)buf_size,
	    "write %zu bytes", buf_size);
	free(buf);
	T_SETUPEND;

	/* pre-warm to account for page table expansion */
	pre_vm_addr = pre_warm(TEMP_FILE_SIZE);

	/* mapping a file does not impact footprint... */
	get_ledger_info(&footprint_before, &pagetable_before);
	map_size = TEMP_FILE_SIZE;
	T_WITH_ERRNO;
	T_QUIET;
	T_ASSERT_NOTNULL(map_addr = (char *)mmap(NULL, map_size,
	    PROT_READ | PROT_WRITE,
	    MAP_FILE | MAP_SHARED, fd, 0),
	    "mmap()");
	T_QUIET;
	T_EXPECT_EQ((mach_vm_address_t)map_addr, pre_vm_addr,
	    "pre-warm mishap");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("mapping file does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "mapping file with %zu bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    map_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* touching file-backed memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	dirty_size = map_size / 2;
	memset(map_addr, 'F', dirty_size);
	/* ... should not impact footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("modifying file-backed memory does not impact phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "touched %zu bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* deallocating file-backed memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	T_WITH_ERRNO;
	T_QUIET;
	T_ASSERT_EQ(munmap(map_addr, map_size),
	    0,
	    "unmap file");
	/* ... should not impact footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("unmapping file-backed memory does not impact phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "unmapped %zu dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
}

T_DECL(phys_footprint_purgeable,
    "phys_footprint for purgeable memory",
    T_META_NAMESPACE("xnu.vm"),
    T_META_LTEPHASE(LTE_POSTINIT))
{
	uint64_t                footprint_before, pagetable_before;
	uint64_t                footprint_after, pagetable_after;
	uint64_t                footprint_expected;
	kern_return_t           kr;
	mach_vm_address_t       pre_vm_addr, vm_addr;
	mach_vm_size_t          vm_size, dirty_size;
	int                     state;

	/* pre-warm to account for page table expansion */
	pre_vm_addr = pre_warm(MEM_SIZE);

	/* allocating purgeable virtual memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	vm_addr = 0;
	vm_size = MEM_SIZE;
	kr = mach_vm_allocate(mach_task_self(), &vm_addr, vm_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_allocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(vm_addr, pre_vm_addr, "pre-warm mishap");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("purgeable virtual allocation does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "purgeable virtual allocation of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* touching memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	dirty_size = vm_size / 2;
	memset((char *)(uintptr_t)vm_addr, 'x', (size_t)dirty_size);
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("modifying anonymous memory increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "touched %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* making it volatile... */
	get_ledger_info(&footprint_before, &pagetable_before);
	state = VM_PURGABLE_VOLATILE;
	T_QUIET;
	T_ASSERT_EQ(mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state),
	    KERN_SUCCESS,
	    "vm_purgable_control(VOLATILE)");
	T_QUIET;
	T_ASSERT_EQ(state, VM_PURGABLE_NONVOLATILE,
	    "memory was non-volatile");
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making volatile decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* making it non-volatile... */
	get_ledger_info(&footprint_before, &pagetable_before);
	state = VM_PURGABLE_NONVOLATILE;
	T_QUIET;
	T_ASSERT_EQ(mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state),
	    KERN_SUCCESS,
	    "vm_purgable_control(NONVOLATILE)");
	T_QUIET;
	T_ASSERT_EQ(state, VM_PURGABLE_VOLATILE,
	    "memory was volatile");
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making non-volatile increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made non-volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* deallocating memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	kr = mach_vm_deallocate(mach_task_self(), vm_addr, vm_size);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("deallocating memory decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "deallocated %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
}

T_DECL(phys_footprint_purgeable_ownership,
    "phys_footprint for owned purgeable memory",
    T_META_NAMESPACE("xnu.vm"),
    T_META_LTEPHASE(LTE_POSTINIT))
{
	uint64_t                footprint_before, pagetable_before;
	uint64_t                footprint_after, pagetable_after;
	uint64_t                footprint_expected;
	kern_return_t           kr;
	mach_vm_address_t       pre_vm_addr, vm_addr;
	mach_vm_size_t          vm_size, dirty_size, me_size;
	int                     state;
	mach_port_t             me_port;

	/* pre-warm to account for page table expansion */
	pre_vm_addr = pre_warm(MEM_SIZE);

	/* allocating purgeable virtual memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	vm_addr = 0;
	vm_size = MEM_SIZE;
	kr = mach_vm_allocate(mach_task_self(), &vm_addr, vm_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_allocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(vm_addr, pre_vm_addr, "pre-warm mishap");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("purgeable virtual allocation does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "purgeable virtual allocation of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* touching memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	dirty_size = vm_size / 2;
	memset((char *)(uintptr_t)vm_addr, 'x', (size_t)dirty_size);
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("modifying anonymous memory increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "touched %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* making it volatile... */
	get_ledger_info(&footprint_before, &pagetable_before);
	state = VM_PURGABLE_VOLATILE;
	T_QUIET;
	T_ASSERT_EQ(mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state),
	    KERN_SUCCESS,
	    "vm_purgable_control(VOLATILE)");
	T_QUIET;
	T_ASSERT_EQ(state, VM_PURGABLE_NONVOLATILE,
	    "memory was non-volatile");
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making volatile decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* making it non-volatile... */
	get_ledger_info(&footprint_before, &pagetable_before);
	state = VM_PURGABLE_NONVOLATILE;
	T_QUIET;
	T_ASSERT_EQ(mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state),
	    KERN_SUCCESS,
	    "vm_purgable_control(NONVOLATILE)");
	T_QUIET;
	T_ASSERT_EQ(state, VM_PURGABLE_VOLATILE,
	    "memory was volatile");
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making non-volatile increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made non-volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* making a memory entry... */
	get_ledger_info(&footprint_before, &pagetable_before);
	me_size = vm_size;
	me_port = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &me_size,
	    vm_addr,
	    VM_PROT_READ | VM_PROT_WRITE,
	    &me_port,
	    MACH_PORT_NULL);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "make_memory_entry() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(me_size, vm_size, "memory entry size mismatch");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making a memory entry does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "making a memory entry of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* deallocating memory while holding memory entry... */
	get_ledger_info(&footprint_before, &pagetable_before);
	kr = mach_vm_deallocate(mach_task_self(), vm_addr, vm_size);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("deallocating owned memory while holding memory entry "
	    "does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "deallocated %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* releasing the memory entry... */
	kr = mach_port_deallocate(mach_task_self(), me_port);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "mach_port_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("releasing memory entry decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
}

#ifdef MAP_MEM_LEDGER_TAGGED
T_DECL(phys_footprint_ledger_purgeable_owned,
    "phys_footprint for ledger-tagged purgeable memory ownership",
    T_META_NAMESPACE("xnu.vm"),
    T_META_LTEPHASE(LTE_POSTINIT))
{
	uint64_t                footprint_before, pagetable_before;
	uint64_t                footprint_after, pagetable_after;
	uint64_t                footprint_expected;
	kern_return_t           kr;
	mach_vm_address_t       pre_vm_addr, vm_addr;
	mach_vm_size_t          vm_size, dirty_size, me_size;
	int                     state;
	mach_port_t             me_port;

	/* pre-warm to account for page table expansion */
	pre_vm_addr = pre_warm(MEM_SIZE);

	/* making a memory entry... */
	get_ledger_info(&footprint_before, &pagetable_before);
	vm_size = MEM_SIZE;
	me_size = vm_size;
	me_port = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &me_size,
	    0,
	    (MAP_MEM_NAMED_CREATE |
	    MAP_MEM_LEDGER_TAGGED |
	    MAP_MEM_PURGABLE |
	    VM_PROT_READ | VM_PROT_WRITE),
	    &me_port,
	    MACH_PORT_NULL);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "make_memory_entry() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(me_size, vm_size, "memory entry size mismatch");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making a memory entry does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "making a memory entry of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* mapping ledger-tagged virtual memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	vm_addr = 0;
	kr = mach_vm_map(mach_task_self(), &vm_addr, vm_size,
	    0, /* mask */
	    VM_FLAGS_ANYWHERE,
	    me_port,
	    0, /* offset */
	    FALSE, /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_map() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(vm_addr, pre_vm_addr, "pre-warm mishap");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("mapping ledger-tagged memory does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "ledger-tagged mapping of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* touching memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	dirty_size = vm_size / 2;
	memset((char *)(uintptr_t)vm_addr, 'x', (size_t)dirty_size);
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("modifying ledger-tagged memory increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "touched %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* making it volatile... */
	get_ledger_info(&footprint_before, &pagetable_before);
	state = VM_PURGABLE_VOLATILE;
	T_QUIET;
	T_ASSERT_EQ(mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state),
	    KERN_SUCCESS,
	    "vm_purgable_control(VOLATILE)");
	T_QUIET;
	T_ASSERT_EQ(state, VM_PURGABLE_NONVOLATILE,
	    "memory was non-volatile");
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making volatile decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* making it non-volatile... */
	get_ledger_info(&footprint_before, &pagetable_before);
	state = VM_PURGABLE_NONVOLATILE;
	T_QUIET;
	T_ASSERT_EQ(mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state),
	    KERN_SUCCESS,
	    "vm_purgable_control(NONVOLATILE)");
	T_QUIET;
	T_ASSERT_EQ(state, VM_PURGABLE_VOLATILE,
	    "memory was volatile");
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making non-volatile increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made non-volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* deallocating memory while holding memory entry... */
	get_ledger_info(&footprint_before, &pagetable_before);
	kr = mach_vm_deallocate(mach_task_self(), vm_addr, vm_size);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("deallocating owned memory while holding memory entry "
	    "does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "deallocated %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* releasing the memory entry... */
	kr = mach_port_deallocate(mach_task_self(), me_port);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "mach_port_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("releasing memory entry decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
}

T_DECL(phys_footprint_ledger_owned,
    "phys_footprint for ledger-tagged memory ownership",
    T_META_NAMESPACE("xnu.vm"),
    T_META_LTEPHASE(LTE_POSTINIT))
{
	uint64_t                footprint_before, pagetable_before;
	uint64_t                footprint_after, pagetable_after;
	uint64_t                footprint_expected;
	kern_return_t           kr;
	mach_vm_address_t       pre_vm_addr, vm_addr;
	mach_vm_size_t          vm_size, dirty_size, me_size;
	int                     state;
	mach_port_t             me_port;

	/* pre-warm to account for page table expansion */
	pre_vm_addr = pre_warm(MEM_SIZE);

	/* making a memory entry... */
	get_ledger_info(&footprint_before, &pagetable_before);
	vm_size = MEM_SIZE;
	me_size = vm_size;
	me_port = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &me_size,
	    0,
	    (MAP_MEM_NAMED_CREATE |
	    MAP_MEM_LEDGER_TAGGED |
	    VM_PROT_READ | VM_PROT_WRITE),
	    &me_port,
	    MACH_PORT_NULL);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "make_memory_entry() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(me_size, vm_size, "memory entry size mismatch");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making a memory entry does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "making a memory entry of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* mapping ledger-tagged virtual memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	vm_addr = 0;
	kr = mach_vm_map(mach_task_self(), &vm_addr, vm_size,
	    0, /* mask */
	    VM_FLAGS_ANYWHERE,
	    me_port,
	    0, /* offset */
	    FALSE, /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_map() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	T_QUIET;
	T_EXPECT_EQ(vm_addr, pre_vm_addr, "pre-warm mishap");
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("mapping ledger-tagged memory does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "ledger-tagged mapping of %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    vm_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* touching memory... */
	get_ledger_info(&footprint_before, &pagetable_before);
	dirty_size = vm_size / 2;
	memset((char *)(uintptr_t)vm_addr, 'x', (size_t)dirty_size);
	/* ... should increase footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before + dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("modifying ledger-tagged memory increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "touched %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* deallocating memory while holding memory entry... */
	get_ledger_info(&footprint_before, &pagetable_before);
	kr = mach_vm_deallocate(mach_task_self(), vm_addr, vm_size);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "vm_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should not change footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("deallocating owned memory while holding memory entry "
	    "does not change phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "deallocated %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);

	/* releasing the memory entry... */
	kr = mach_port_deallocate(mach_task_self(), me_port);
	T_QUIET;
	T_EXPECT_EQ(kr, KERN_SUCCESS, "mach_port_deallocate() error 0x%x (%s)",
	    kr, mach_error_string(kr));
	/* ... should decrease footprint */
	get_ledger_info(&footprint_after, &pagetable_after);
	footprint_expected = footprint_before - dirty_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("releasing memory entry decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made volatile %lld dirty bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    dirty_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
}
#endif /* MAP_MEM_LEDGER_TAGGED */

/* IOSurface code from: CoreImage/CoreImageTests/CIRender/SurfaceUtils.c */
#include <CoreFoundation/CoreFoundation.h>
#include <IOSurface/IOSurface.h>
#include <IOSurface/IOSurfacePrivate.h>
static size_t
bytes_per_element(uint32_t format)
{
	size_t bpe = 0;
	switch (format) {
	case 32:     // kCVPixelFormatType_32ARGB (ARGB8)
		bpe = 4;
		break;
	default:
		bpe = 0;
		break;
	}
	return bpe;
}
static size_t
bytes_per_pixel(uint32_t format)
{
	size_t bpe = 0;
	switch (format) {
	case 32:     // kCVPixelFormatType_32ARGB (ARGB8)
		bpe = 4;
		break;
	default:
		bpe = 0;
		break;
	}
	return bpe;
}
static inline size_t
roundSizeToMultiple(size_t size, size_t mult)
{
	return ((size + mult - 1) / mult) * mult;
}
static inline void
setIntValue(CFMutableDictionaryRef dict, const CFStringRef key, int value)
{
	CFNumberRef number = CFNumberCreate(0, kCFNumberIntType, &value);
	CFDictionarySetValue(dict, key, number);
	CFRelease(number);
}
typedef void (^SurfacePlaneBlock)(void *data, size_t planeIndex, size_t width, size_t height, size_t rowbytes);
static IOReturn
SurfaceApplyPlaneBlock(IOSurfaceRef surface, SurfacePlaneBlock block)
{
	if (surface == nil || block == nil) {
		return kIOReturnBadArgument;
	}

	IOReturn result = kIOReturnSuccess;
	size_t planeCount = IOSurfaceGetPlaneCount(surface);

	if (planeCount == 0) {
		result = IOSurfaceLock(surface, 0, NULL);
		if (result != kIOReturnSuccess) {
			return result;
		}

		void* base = IOSurfaceGetBaseAddress(surface);
		size_t rb = IOSurfaceGetBytesPerRow(surface);
		size_t w = IOSurfaceGetWidth(surface);
		size_t h = IOSurfaceGetHeight(surface);

		if (base && rb && w && h) {
			block(base, 0, w, h, rb);
		}

		IOSurfaceUnlock(surface, 0, NULL);
	} else if (planeCount == 2) {
		for (size_t i = 0; i < planeCount; i++) {
			result = IOSurfaceLock(surface, 0, NULL);
			if (result != kIOReturnSuccess) {
				return result;
			}

			void* base = IOSurfaceGetBaseAddressOfPlane(surface, i);
			size_t rb = IOSurfaceGetBytesPerRowOfPlane(surface, i);
			size_t w = IOSurfaceGetWidthOfPlane(surface, i);
			size_t h = IOSurfaceGetHeightOfPlane(surface, i);

			if (base && rb && w && h) {
				block(base, i, w, h, rb);
			}

			IOSurfaceUnlock(surface, 0, NULL);
		}
	}
	return result;
}
static void
ClearSurface(IOSurfaceRef surface)
{
	const int zero = 0;
	(void) SurfaceApplyPlaneBlock(surface, ^(void *p, size_t i, __unused size_t w, size_t h, size_t rb)
	{
		if (i == 0) {
		        memset(p, zero, rb * h);
		} else {
		        memset(p, 128, rb * h);
		}
	});
}
static IOSurfaceRef
CreateSurface(uint32_t pixelsWide, uint32_t pixelsHigh, uint32_t rowBytesAlignment, uint32_t fmt, bool purgeable, bool clear)
{
	IOSurfaceRef surface = nil;

	if (pixelsWide < 1 || pixelsHigh < 1 || fmt == 0) {
		return nil;
	}

	size_t bpp = bytes_per_pixel(fmt);
	size_t bpe = bytes_per_element(fmt);
	if (bpp == 0 || bpe == 0) {
		return nil;
	}

	size_t rowbytes = pixelsWide * bpp;
	if (rowBytesAlignment == 0) {
		rowBytesAlignment = 16;
	}
	rowbytes = roundSizeToMultiple(rowbytes, rowBytesAlignment);

	CFMutableDictionaryRef props = CFDictionaryCreateMutable(0, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	setIntValue(props, kIOSurfaceBytesPerRow, (int)rowbytes);
	setIntValue(props, kIOSurfaceWidth, (int)pixelsWide);
	setIntValue(props, kIOSurfaceHeight, (int)pixelsHigh);
	setIntValue(props, kIOSurfacePixelFormat, (int)fmt);
#if TARGET_OS_IPHONE
	setIntValue(props, kIOSurfaceNonPurgeable, purgeable);
#else /* TARGET_OS_IPHONE */
	(void)purgeable;
#endif /* TARGET_OS_IPHONE */
	{
		if (bpe != bpp) { // i.e. a 422 format such as 'yuvf' etc.
			setIntValue(props, kIOSurfaceElementWidth, 2);
			setIntValue(props, kIOSurfaceElementHeight, 1);
		}
		setIntValue(props, kIOSurfaceBytesPerElement, (int)bpe);
	}

	surface = IOSurfaceCreate(props);

	if (clear) {
		ClearSurface(surface);
	}

	CFRelease(props);
	return surface;
}
T_DECL(phys_footprint_purgeable_iokit,
    "phys_footprint for purgeable IOKit memory",
    T_META_NAMESPACE("xnu.vm"),
    T_META_LTEPHASE(LTE_POSTINIT))
{
	uint64_t        footprint_before, pagetable_before;
	uint64_t        footprint_after, pagetable_after;
	uint64_t        footprint_expected;
	IOSurfaceRef    surface;
	uint32_t        old_state;
	uint64_t        surface_size;

	T_SETUPBEGIN;
	ledger_init();
	surface = CreateSurface(1024, 1024, 0, 32, true, true);
	IOSurfaceSetPurgeable(surface, kIOSurfacePurgeableVolatile, &old_state);
	IOSurfaceSetPurgeable(surface, kIOSurfacePurgeableNonVolatile, &old_state);
	CFRelease(surface);
	T_SETUPEND;

	surface_size = 1024 * 1024 * 4;

	/* create IOsurface: footprint grows */
	get_ledger_info(&footprint_before, &pagetable_before);
	surface = CreateSurface(1024, 1024, 0, 32, true, true);
	get_ledger_info(&footprint_after, &pagetable_after);
#if LEGACY_FOOTPRINT
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("LEGACY FOOTPRINT: creating IOSurface: no footprint impact");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "create IOSurface %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#else /* LEGACY_FOOTPRINT */
	footprint_expected = footprint_before + surface_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("creating IOSurface increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "create IOSurface %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#endif /* LEGACY_FOOTPRINT */

	/* make IOSurface volatile: footprint shrinks */
	get_ledger_info(&footprint_before, &pagetable_before);
	IOSurfaceSetPurgeable(surface, kIOSurfacePurgeableVolatile, &old_state);
	get_ledger_info(&footprint_after, &pagetable_after);
#if LEGACY_FOOTPRINT
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("LEGACY FOOTPRINT: volatile IOSurface: no footprint impact");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "volatile IOSurface %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#else /* LEGACY_FOOTPRINT */
	footprint_expected = footprint_before - surface_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making IOSurface volatile decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made volatile %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#endif /* LEGACY_FOOTPRINT */

	/* make IOSurface non-volatile: footprint grows */
	get_ledger_info(&footprint_before, &pagetable_before);
	IOSurfaceSetPurgeable(surface, kIOSurfacePurgeableNonVolatile, &old_state);
	get_ledger_info(&footprint_after, &pagetable_after);
#if LEGACY_FOOTPRINT
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("LEGACY FOOTPRINT: non-volatile IOSurface: no footprint impact");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "non-volatile IOSurface %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#else /* LEGACY_FOOTPRINT */
	footprint_expected = footprint_before + surface_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("making IOSurface non-volatile increases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "made non-volatile %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#endif /* LEGACY_FOOTPRINT */

	/* accessing IOSurface re-mapping: no footprint impact */

	/* deallocating IOSurface re-mapping: no footprint impact */

	/* release IOSurface: footprint shrinks */
	get_ledger_info(&footprint_before, &pagetable_before);
	CFRelease(surface);
	get_ledger_info(&footprint_after, &pagetable_after);
#if LEGACY_FOOTPRINT
	footprint_expected = footprint_before;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("LEGACY FOOTPRINT: release IOSurface: no footprint impact");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "releasing IOSurface %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#else /* LEGACY_FOOTPRINT */
	footprint_expected = footprint_before - surface_size;
	footprint_expected += (pagetable_after - pagetable_before);
	T_LOG("releasing IOSurface decreases phys_footprint");
	T_EXPECT_EQ(footprint_after, footprint_expected,
	    "released IOSurface %lld bytes: "
	    "footprint %lld -> %lld expected %lld delta %lld",
	    surface_size, footprint_before, footprint_after,
	    footprint_expected, footprint_after - footprint_expected);
#endif /* LEGACY_FOOTPRINT */
}
