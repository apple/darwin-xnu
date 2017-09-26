#include <darwintest.h>
#include <inttypes.h>
#include <limits.h>
#include <os/assumes.h>
#include <os/overflow.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <System/sys/kdebug.h>
#include <unistd.h>

#define PRIVATE
#include <sys/proc_info.h>
#include <sys/event.h>
#include <libproc.h>
#undef PRIVATE

T_GLOBAL_META(T_META_NAMESPACE("xnu.all"));

#pragma mark proc_list_uptrs

#define NUPTRS 4
static uint64_t uptrs[NUPTRS] = {
	0x1122334455667788ULL,
	0x99aabbccddeeff00ULL,
	0xaabbaaddccaaffeeULL,
	0xcc000011ccaa7755ULL
};

static const char *uptr_names[NUPTRS];

static void
print_uptrs(int argc, char * const *argv)
{
	for (int i = 0; i < argc; i++) {
		char *end;
		unsigned long pid = strtoul(argv[i], &end, 0);
		if (pid > INT_MAX) {
			printf("error: pid '%lu' would overflow an integer\n", pid);
		}
		if (end == argv[i]) {
			printf("error: could not parse '%s' as a pid\n", argv[i]);
			continue;
		}
		int uptrs_count = proc_list_uptrs((int)pid, NULL, 0);
		if (uptrs_count == 0) {
			printf("no uptrs for process %d\n", (int)pid);
			return;
		}

		/* extra space */
		unsigned int uptrs_len = (unsigned int)uptrs_count + 32;

		uint64_t *uptrs_alloc = malloc(sizeof(uint64_t) * uptrs_len);
		os_assert(uptrs_alloc != NULL);

		uptrs_count = proc_list_uptrs((int)pid, uptrs_alloc,
				(uint32_t)(sizeof(uint64_t) * uptrs_len));
		printf("process %d has %d uptrs:\n", (int)pid, uptrs_count);
		if (uptrs_count > (int)uptrs_len) {
			uptrs_count = (int)uptrs_len;
		}
		for (int j = 0; j < uptrs_count; j++) {
			printf("%#17" PRIx64 "\n", uptrs_alloc[j]);
		}
	}
}

T_DECL(proc_list_uptrs,
	"the kernel should return any up-pointers it knows about",
	T_META_ALL_VALID_ARCHS(YES))
{
	if (argc > 0) {
		print_uptrs(argc, argv);
		T_SKIP("command line invocation of tool, not test");
	}

	unsigned int cur_uptr = 0;

	int kq = kqueue();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kq, "kqueue");

	/*
	 * Should find uptrs on file-type knotes and generic knotes (two
	 * different search locations, internally).
	 */
	struct kevent64_s events[2];
	memset(events, 0, sizeof(events));

	uptr_names[cur_uptr] = "kqueue file-backed knote";
	events[0].filter = EVFILT_WRITE;
	events[0].ident = STDOUT_FILENO;
	events[0].flags = EV_ADD;
	events[0].udata = uptrs[cur_uptr++];

	uptr_names[cur_uptr] = "kqueue non-file-backed knote";
	events[1].filter = EVFILT_USER;
	events[1].ident = 1;
	events[1].flags = EV_ADD;
	events[1].udata = uptrs[cur_uptr++];

	int kev_err = kevent64(kq, events, sizeof(events) / sizeof(events[0]), NULL,
			0, KEVENT_FLAG_IMMEDIATE, NULL);
	T_ASSERT_POSIX_SUCCESS(kev_err, "register events with kevent64");

	/*
	 * Should find uptrs both on a kevent_id kqueue and in a workloop
	 * kqueue's knote's udata field.
	 */
	uptr_names[cur_uptr] = "dynamic kqueue non-file-backed knote";
	struct kevent_qos_s events_id[] = {{
		.filter = EVFILT_USER,
		.ident = 1,
		.flags = EV_ADD,
		.udata = uptrs[cur_uptr++]
	}};

	uptr_names[cur_uptr] = "dynamic kqueue ID";
	kev_err = kevent_id(uptrs[cur_uptr++], events_id, 1, NULL, 0, NULL, NULL,
			KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_IMMEDIATE);
	T_ASSERT_POSIX_SUCCESS(kev_err, "register event with kevent_id");

	errno = 0;
	int uptrs_count = proc_list_uptrs(getpid(), NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(uptrs_count, "proc_list_uptrs");
	T_QUIET; T_EXPECT_EQ(uptrs_count, NUPTRS,
			"should see correct number of up-pointers");

	uint64_t uptrs_obs[NUPTRS] = { 0 };
	uptrs_count = proc_list_uptrs(getpid(), uptrs_obs, sizeof(uptrs_obs));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(uptrs_count, "proc_list_uptrs");

	for (int i = 0; i < uptrs_count; i++) {
		int found = -1;
		for (int j = 0; j < NUPTRS; j++) {
			if (uptrs_obs[i] == uptrs[j]) {
				found = j;
				goto next;
			}
		}
		T_FAIL("unexpected up-pointer found: %#" PRIx64, uptrs_obs[i]);
next:;
		if (found != -1) {
			T_PASS("found up-pointer for %s", uptr_names[found]);
		}
	}
}

#pragma mark dynamic kqueue info

#define EXPECTED_ID    UINT64_C(0x1122334455667788)
#define EXPECTED_UDATA UINT64_C(0x99aabbccddeeff00)
#ifndef KQ_WORKLOOP
#define KQ_WORKLOOP 0x80
#endif

static void
setup_kevent_id(kqueue_id_t id)
{
	struct kevent_qos_s events_id[] = {{
		.filter = EVFILT_USER,
		.ident = 1,
		.flags = EV_ADD,
		.udata = EXPECTED_UDATA
	}};

	int err = kevent_id(id, events_id, 1, NULL, 0, NULL, NULL,
			KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_IMMEDIATE);
	T_ASSERT_POSIX_SUCCESS(err, "register event with kevent_id");
}

static kqueue_id_t *
list_kqids(pid_t pid, int *nkqids_out)
{
	int kqids_len = 256;
	int nkqids;
	kqueue_id_t *kqids = NULL;
	uint32_t kqids_size;

retry:
	if (os_mul_overflow(sizeof(kqueue_id_t), kqids_len, &kqids_size)) {
		T_QUIET; T_ASSERT_GT(kqids_len, PROC_PIDDYNKQUEUES_MAX, NULL);
		kqids_len = PROC_PIDDYNKQUEUES_MAX;
		goto retry;
	}
	if (!kqids) {
		kqids = malloc(kqids_size);
		T_QUIET; T_ASSERT_NOTNULL(kqids, "malloc(%" PRIu32 ")", kqids_size);
	}

	nkqids = proc_list_dynkqueueids(pid, kqids, kqids_size);
	if (nkqids > kqids_len && kqids_len < PROC_PIDDYNKQUEUES_MAX) {
		kqids_len *= 2;
		if (kqids_len > PROC_PIDDYNKQUEUES_MAX) {
			kqids_len = PROC_PIDDYNKQUEUES_MAX;
		}
		free(kqids);
		kqids = NULL;
		goto retry;
	}

	*nkqids_out = nkqids;
	return kqids;
}

T_DECL(list_dynamic_kqueues,
		"the kernel should list IDs of dynamic kqueues",
		T_META_ALL_VALID_ARCHS(true))
{
	int nkqids;
	bool found = false;

	setup_kevent_id(EXPECTED_ID);
	kqueue_id_t *kqids = list_kqids(getpid(), &nkqids);
	T_ASSERT_GE(nkqids, 1, "at least one dynamic kqueue is listed");
	for (int i = 0; i < nkqids; i++) {
		if (kqids[i] == EXPECTED_ID) {
			found = true;
			T_PASS("found expected dynamic kqueue ID");
		} else {
			T_LOG("found another dynamic kqueue with ID %#" PRIx64, kqids[i]);
		}
	}

	if (!found) {
		T_FAIL("could not find dynamic ID of kqueue created");
	}

	free(kqids);
}

T_DECL(dynamic_kqueue_basic_info,
		"the kernel should report valid basic dynamic kqueue info",
		T_META_ALL_VALID_ARCHS(true))
{
	struct kqueue_info kqinfo;
	int ret;

	setup_kevent_id(EXPECTED_ID);
	ret = proc_piddynkqueueinfo(getpid(), PROC_PIDDYNKQUEUE_INFO, EXPECTED_ID,
			&kqinfo, sizeof(kqinfo));
	T_ASSERT_POSIX_SUCCESS(ret,
			"proc_piddynkqueueinfo(... PROC_PIDDYNKQUEUE_INFO ...)");
	T_QUIET; T_ASSERT_GE(ret, (int)sizeof(kqinfo),
			"PROC_PIDDYNKQUEUE_INFO should return the right size");

	T_EXPECT_NE(kqinfo.kq_state & KQ_WORKLOOP, 0U,
			"kqueue info should be for a workloop kqueue");
	T_EXPECT_EQ(kqinfo.kq_stat.vst_ino, EXPECTED_ID,
			"inode field should be the kqueue's ID");
}

T_DECL(dynamic_kqueue_extended_info,
		"the kernel should report valid extended dynamic kqueue info",
		T_META_ALL_VALID_ARCHS(true))
{
	struct kevent_extinfo kqextinfo[1];
	int ret;

	setup_kevent_id(EXPECTED_ID);
	ret = proc_piddynkqueueinfo(getpid(), PROC_PIDDYNKQUEUE_EXTINFO,
			EXPECTED_ID, kqextinfo, sizeof(kqextinfo));
	T_ASSERT_POSIX_SUCCESS(ret,
			"proc_piddynkqueueinfo(... PROC_PIDDYNKQUEUE_EXTINFO ...)");
	T_QUIET; T_ASSERT_EQ(ret, 1,
			"PROC_PIDDYNKQUEUE_EXTINFO should return a single knote");

	T_EXPECT_EQ(kqextinfo[0].kqext_kev.ident, 1ULL,
			"kevent identifier matches what was configured");
	T_EXPECT_EQ(kqextinfo[0].kqext_kev.filter, (short)EVFILT_USER,
			"kevent filter matches what was configured");
	T_EXPECT_EQ(kqextinfo[0].kqext_kev.udata, EXPECTED_UDATA,
			"kevent udata matches what was configured");
}

#pragma mark proc_listpids

T_DECL(list_kdebug_pids,
		"the kernel should report processes that are filtered by kdebug",
		T_META_ASROOT(YES))
{
	int mib[4] = { CTL_KERN, KERN_KDEBUG };
	int npids;
	int pids[1];
	int ret;
	kd_regtype reg = {};
	size_t regsize = sizeof(reg);

	mib[2] = KERN_KDREMOVE;
	ret = sysctl(mib, 3, NULL, NULL, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDREMOVE sysctl");

	mib[2] = KERN_KDSETBUF; mib[3] = 100000;
	ret = sysctl(mib, 4, NULL, NULL, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDSETBUF sysctl");

	mib[2] = KERN_KDSETUP;
	ret = sysctl(mib, 3, NULL, NULL, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDSETUP sysctl");

	npids = proc_listpids(PROC_KDBG_ONLY, 0, pids, sizeof(pids));
	T_EXPECT_EQ(npids, 0, "no processes should be filtered initially");

	reg.type = KDBG_TYPENONE;
	reg.value1 = getpid();
	reg.value2 = 1; /* set the pid in the filter */
	mib[2] = KERN_KDPIDTR;
	ret = sysctl(mib, 3, &reg, &regsize, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret,
			"KERN_KDPIDTR sysctl to set a pid in the filter");

	npids = proc_listpids(PROC_KDBG_ONLY, 0, pids, sizeof(pids));
	npids /= 4;
	T_EXPECT_EQ(npids, 1, "a process should be filtered");
	T_EXPECT_EQ(pids[0], getpid(),
			"process filtered should be the one that was set");

	mib[2] = KERN_KDREMOVE;
	ret = sysctl(mib, 3, NULL, NULL, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDREMOVE sysctl");
}
