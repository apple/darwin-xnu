#include <sys/queue.h>
#include <kern/backtrace.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/zalloc.h>
#include <kern/simple_lock.h>
#include <kern/locks.h>
#include <machine/machine_routines.h>
#include <libkern/libkern.h>
#include <libkern/tree.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/OSKextLib.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include "kasan.h"
#include "kasan_internal.h"

#if KASAN_DYNAMIC_BLACKLIST

#define MAX_FRAMES 8
#define HASH_NBUCKETS 128U
#define HASH_MASK (HASH_NBUCKETS-1)
#define HASH_CACHE_NENTRIES 128

struct blacklist_entry {
	const char *kext_name;
	const char *func_name;
	access_t type_mask;

	/* internal */
	uint64_t count;
};

#include "kasan_blacklist_dynamic.h"
/* defines 'blacklist' and 'blacklist_entries' */

decl_simple_lock_data(static, _dybl_lock);
static access_t blacklisted_types; /* bitmap of access types with blacklist entries */

static void
dybl_lock(boolean_t *b)
{
	*b = ml_set_interrupts_enabled(false);
	simple_lock(&_dybl_lock, LCK_GRP_NULL);
}

static void
dybl_unlock(boolean_t b)
{
	simple_unlock(&_dybl_lock);
	ml_set_interrupts_enabled(b);
}


/*
 * blacklist call site hash table
 */

struct blacklist_hash_entry {
	SLIST_ENTRY(blacklist_hash_entry) chain; // next element in chain
	struct blacklist_entry *ble;             // blacklist entry that this caller is an instance of
	uintptr_t addr;                          // callsite address
	uint64_t count;                          // hit count
};

struct hash_chain_head {
	SLIST_HEAD(, blacklist_hash_entry);
};

unsigned cache_next_entry = 0;
struct blacklist_hash_entry blhe_cache[HASH_CACHE_NENTRIES];
struct hash_chain_head hash_buckets[HASH_NBUCKETS];

static struct blacklist_hash_entry *
alloc_hash_entry(void)
{
	unsigned idx = cache_next_entry++;
	if (idx >= HASH_CACHE_NENTRIES) {
		cache_next_entry = HASH_CACHE_NENTRIES; // avoid overflow
		return NULL;
	}
	return &blhe_cache[idx];
}

static unsigned
hash_addr(uintptr_t addr)
{
	addr ^= (addr >> 7); /* mix in some of the bits likely to select the kext */
	return (unsigned)addr & HASH_MASK;
}

static struct blacklist_hash_entry *
blacklist_hash_lookup(uintptr_t addr)
{
	unsigned idx = hash_addr(addr);
	struct blacklist_hash_entry *blhe;

	SLIST_FOREACH(blhe, &hash_buckets[idx], chain) {
		if (blhe->addr == addr) {
			return blhe;
		}
	}

	return NULL;
}

static struct blacklist_hash_entry *
blacklist_hash_add(uintptr_t addr, struct blacklist_entry *ble)
{
	unsigned idx = hash_addr(addr);

	struct blacklist_hash_entry *blhe = alloc_hash_entry();
	if (!blhe) {
		return NULL;
	}

	blhe->ble = ble;
	blhe->addr = addr;
	blhe->count = 1;

	SLIST_INSERT_HEAD(&hash_buckets[idx], blhe, chain);

	return blhe;
}

static void
hash_drop(void)
{
	if (cache_next_entry > 0) {
		bzero(&hash_buckets, sizeof(hash_buckets));
		bzero(&blhe_cache, sizeof(struct blacklist_hash_entry) * cache_next_entry);
		cache_next_entry = 0;
	}
}

/*
 * kext range lookup tree
 */

struct range_tree_entry {
	RB_ENTRY(range_tree_entry) tree;

	uintptr_t base;

	struct {
		uint64_t size : 63;
		uint64_t accessed : 1; // blacklist entry exists in this range
	};

	/* kext name */
	const char *bundleid;

	/* mach header for corresponding kext */
	kernel_mach_header_t *mh;
};

static int NOINLINE
range_tree_cmp(const struct range_tree_entry *e1, const struct range_tree_entry *e2)
{
	if (e1->size == 0 || e2->size == 0) {
		/* lookup */
		if (e1->base + e1->size < e2->base) {
			return -1;
		} else if (e1->base > e2->base + e2->size) {
			return 1;
		} else {
			return 0;
		}
	} else {
		/* compare */
		if (e1->base + e1->size <= e2->base) {
			return -1;
		} else if (e1->base >= e2->base + e2->size) {
			return 1;
		} else {
			panic("bad compare\n");
			return 0;
		}
	}
}

RB_HEAD(range_tree, range_tree_entry) range_tree_root;
RB_PROTOTYPE(range_tree, range_tree_entry, tree, range_tree_cmp);
RB_GENERATE(range_tree, range_tree_entry, tree, range_tree_cmp);

/* for each executable section, insert a range tree entry */
void
kasan_dybl_load_kext(uintptr_t addr, const char *kextname)
{
	int i;

	struct load_command *cmd = NULL;
	kernel_mach_header_t *mh = (void *)addr;

	cmd = (struct load_command *)&mh[1];

	for (i = 0; i < (int)mh->ncmds; i++) {
		if (cmd->cmd == LC_SEGMENT_KERNEL) {
			kernel_segment_command_t *seg = (void *)cmd;
			bool is_exec = seg->initprot & VM_PROT_EXECUTE;

#if CONFIG_EMBEDDED
			if (is_exec && strcmp("__TEXT_EXEC", seg->segname) != 0) {
				is_exec = false;
			}
#endif

			if (is_exec) {
				struct range_tree_entry *e = kalloc(sizeof(struct range_tree_entry));
				bzero(e, sizeof(*e));

				e->base = seg->vmaddr;
				e->size = seg->vmsize;
				e->bundleid = kextname;
				e->mh = mh;

				boolean_t flag;
				dybl_lock(&flag);
				RB_INSERT(range_tree, &range_tree_root, e);
				dybl_unlock(flag);
			}
		}

		cmd = (void *)((uintptr_t)cmd + cmd->cmdsize);
	}
}

void
kasan_dybl_unload_kext(uintptr_t addr)
{
	int i;

	struct load_command *cmd = NULL;
	kernel_mach_header_t *mh = (void *)addr;

	cmd = (struct load_command *)&mh[1];

	for (i = 0; i < (int)mh->ncmds; i++) {
		if (cmd->cmd == LC_SEGMENT_KERNEL) {
			kernel_segment_command_t *seg = (void *)cmd;
			bool is_exec = seg->initprot & VM_PROT_EXECUTE;

#if CONFIG_EMBEDDED
			if (is_exec && strcmp("__TEXT_EXEC", seg->segname) != 0) {
				is_exec = false;
			}
#endif

			if (is_exec) {
				struct range_tree_entry key = { .base = seg->vmaddr, .size = 0 };
				struct range_tree_entry *e;
				boolean_t flag;
				dybl_lock(&flag);
				e = RB_FIND(range_tree, &range_tree_root, &key);
				if (e) {
					RB_REMOVE(range_tree, &range_tree_root, e);
					if (e->accessed) {
						/* there was a blacklist entry in this range */
						hash_drop();
					}
				}
				dybl_unlock(flag);

				if (e) {
					kfree(e, sizeof(*e));
				}
			}
		}

		cmd = (void *)((uintptr_t)cmd + cmd->cmdsize);
	}
}

/*
 * return the closest function name at or before addr
 */
static const NOINLINE char *
addr_to_func(uintptr_t addr, const kernel_mach_header_t *mh)
{
	int i;
	uintptr_t cur_addr = 0;

	const struct load_command *cmd = NULL;
	const struct symtab_command *st = NULL;
	const kernel_segment_command_t *le = NULL;
	const char *strings;
	const kernel_nlist_t *syms;
	const char *cur_name = NULL;

	cmd = (const struct load_command *)&mh[1];

	/*
	 * find the symtab command and linkedit segment
	 */
	for (i = 0; i < (int)mh->ncmds; i++) {
		if (cmd->cmd == LC_SYMTAB) {
			st = (const struct symtab_command *)cmd;
		} else if (cmd->cmd == LC_SEGMENT_KERNEL) {
			const kernel_segment_command_t *seg = (const void *)cmd;
			if (!strcmp(seg->segname, SEG_LINKEDIT)) {
				le = (const void *)cmd;
			}
		}
		cmd = (const void *)((uintptr_t)cmd + cmd->cmdsize);
	}

	/* locate the symbols and strings in the symtab */
	strings = (const void *)((le->vmaddr - le->fileoff) + st->stroff);
	syms    = (const void *)((le->vmaddr - le->fileoff) + st->symoff);

	/*
	 * iterate the symbols, looking for the closest one to `addr'
	 */
	for (i = 0; i < (int)st->nsyms; i++) {
		uint8_t n_type = syms[i].n_type;
		const char *name = strings + syms[i].n_un.n_strx;

		if (n_type & N_STAB) {
			/* ignore debug entries */
			continue;
		}

		n_type &= N_TYPE;
		if (syms[i].n_un.n_strx == 0 || !(n_type == N_SECT || n_type == N_ABS)) {
			/* only use named and defined symbols */
			continue;
		}

#if 0
		if (mh != &_mh_execute_header) {
			printf("sym '%s' 0x%x 0x%lx\n", name, (unsigned)syms[i].n_type, (unsigned long)syms[i].n_value);
		}
#endif

		if (*name == '_') {
			name += 1;
		}

		/* this symbol is closer than the one we had */
		if (syms[i].n_value <= addr && syms[i].n_value > cur_addr) {
			cur_name = name;
			cur_addr = syms[i].n_value;
		}
	}

	/* best guess for name of function at addr */
	return cur_name;
}

bool OS_NOINLINE
kasan_is_blacklisted(access_t type)
{
	uint32_t nframes = 0;
	uintptr_t frames[MAX_FRAMES];
	uintptr_t *bt = frames;

	assert(__builtin_popcount(type) == 1);

	if ((type & blacklisted_types) == 0) {
		/* early exit for types with no blacklist entries */
		return false;
	}

	nframes = backtrace_frame(bt, MAX_FRAMES, __builtin_frame_address(0),
	    NULL);
	boolean_t flag;

	if (nframes >= 1) {
		/* ignore direct caller */
		nframes -= 1;
		bt += 1;
	}

	struct blacklist_hash_entry *blhe = NULL;

	dybl_lock(&flag);

	/* First check if any frame hits in the hash */
	for (uint32_t i = 0; i < nframes; i++) {
		blhe = blacklist_hash_lookup(bt[i]);
		if (blhe) {
			if ((blhe->ble->type_mask & type) != type) {
				/* wrong type */
				continue;
			}

			/* hit */
			blhe->count++;
			blhe->ble->count++;
			// printf("KASan: blacklist cache hit (%s:%s [0x%lx] 0x%x)\n",
			//              ble->kext_name ?: "" , ble->func_name ?: "", VM_KERNEL_UNSLIDE(bt[i]), mask);
			dybl_unlock(flag);
			return true;
		}
	}

	/* no hits - slowpath */
	for (uint32_t i = 0; i < nframes; i++) {
		const char *kextname = NULL;
		const char *funcname = NULL;

		struct range_tree_entry key = { .base = bt[i], .size = 0 };
		struct range_tree_entry *e = RB_FIND(range_tree, &range_tree_root, &key);

		if (!e) {
			/* no match at this address - kinda weird? */
			continue;
		}

		/* get the function and bundle name for the current frame */
		funcname = addr_to_func(bt[i], e->mh);
		if (e->bundleid) {
			kextname = strrchr(e->bundleid, '.');
			if (kextname) {
				kextname++;
			} else {
				kextname = e->bundleid;
			}
		}

		// printf("%s: a = 0x%016lx,0x%016lx f = %s, k = %s\n", __func__, bt[i], VM_KERNEL_UNSLIDE(bt[i]), funcname, kextname);

		/* check if kextname or funcname are in the blacklist */
		for (size_t j = 0; j < blacklist_entries; j++) {
			struct blacklist_entry *ble = &blacklist[j];
			uint64_t count;

			if ((ble->type_mask & type) != type) {
				/* wrong type */
				continue;
			}

			if (ble->kext_name && kextname && strncmp(kextname, ble->kext_name, KMOD_MAX_NAME) != 0) {
				/* wrong kext name */
				continue;
			}

			if (ble->func_name && funcname && strncmp(funcname, ble->func_name, 128) != 0) {
				/* wrong func name */
				continue;
			}

			/* found a matching function or kext */
			blhe = blacklist_hash_add(bt[i], ble);
			count = ble->count++;
			e->accessed = 1;

			dybl_unlock(flag);

			if (count == 0) {
				printf("KASan: ignoring blacklisted violation (%s:%s [0x%lx] %d 0x%x)\n",
				    kextname, funcname, VM_KERNEL_UNSLIDE(bt[i]), i, type);
			}

			return true;
		}
	}

	dybl_unlock(flag);
	return false;
}

static void
add_blacklist_entry(const char *kext, const char *func, access_t type)
{
	assert(kext || func);
	struct blacklist_entry *ble = &blacklist[blacklist_entries++];

	if (blacklist_entries > blacklist_max_entries) {
		panic("KASan: dynamic blacklist entries exhausted\n");
	}

	if (kext) {
		size_t sz = __nosan_strlen(kext) + 1;
		if (sz > 1) {
			char *s = kalloc(sz);
			__nosan_strlcpy(s, kext, sz);
			ble->kext_name = s;
		}
	}

	if (func) {
		size_t sz = __nosan_strlen(func) + 1;
		if (sz > 1) {
			char *s = kalloc(sz);
			__nosan_strlcpy(s, func, sz);
			ble->func_name = s;
		}
	}

	ble->type_mask = type;
}

#define TS(x) { .type = TYPE_##x, .str = #x }

static const struct {
	const access_t type;
	const char * const str;
} typemap[] = {
	TS(LOAD),
	TS(STORE),
	TS(MEMR),
	TS(MEMW),
	TS(STRR),
	TS(STRW),
	TS(KFREE),
	TS(ZFREE),
	TS(FSFREE),
	TS(UAF),
	TS(POISON_GLOBAL),
	TS(POISON_HEAP),
	TS(MEM),
	TS(STR),
	TS(READ),
	TS(WRITE),
	TS(RW),
	TS(FREE),
	TS(NORMAL),
	TS(DYNAMIC),
	TS(POISON),
	TS(ALL),

	/* convenience aliases */
	{ .type = TYPE_POISON_GLOBAL, .str = "GLOB" },
	{ .type = TYPE_POISON_HEAP, .str = "HEAP" },
};
static size_t typemap_sz = sizeof(typemap) / sizeof(typemap[0]);

static inline access_t
map_type(const char *str)
{
	if (strlen(str) == 0) {
		return TYPE_NORMAL;
	}

	/* convert type string to integer ID */
	for (size_t i = 0; i < typemap_sz; i++) {
		if (strcasecmp(str, typemap[i].str) == 0) {
			return typemap[i].type;
		}
	}

	printf("KASan: unknown blacklist type `%s', assuming `normal'\n", str);
	return TYPE_NORMAL;
}

void
kasan_init_dybl(void)
{
	simple_lock_init(&_dybl_lock, 0);

	/*
	 * dynamic blacklist entries via boot-arg. Syntax is:
	 *  kasan.bl=kext1:func1:type1,kext2:func2:type2,...
	 */
	char buf[256] = {};
	char *bufp = buf;
	if (PE_parse_boot_arg_str("kasan.bl", bufp, sizeof(buf))) {
		char *kext;
		while ((kext = strsep(&bufp, ",")) != NULL) {
			access_t type = TYPE_NORMAL;
			char *func = strchr(kext, ':');
			if (func) {
				*func++ = 0;
			}
			char *typestr = strchr(func, ':');
			if (typestr) {
				*typestr++ = 0;
				type = map_type(typestr);
			}
			add_blacklist_entry(kext, func, type);
		}
	}

	/* collect bitmask of blacklisted types */
	for (size_t j = 0; j < blacklist_entries; j++) {
		struct blacklist_entry *ble = &blacklist[j];
		blacklisted_types |= ble->type_mask;
	}

	/* add the fake kernel kext */
	kasan_dybl_load_kext((uintptr_t)&_mh_execute_header, "__kernel__");
}

#else /* KASAN_DYNAMIC_BLACKLIST */

bool
kasan_is_blacklisted(access_t __unused type)
{
	return false;
}
#endif
