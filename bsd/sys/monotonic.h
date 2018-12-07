#ifndef SYS_MONOTONIC_H
#define SYS_MONOTONIC_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/ioccom.h>

__BEGIN_DECLS

/*
 * XXX These declarations are subject to change at any time.
 */

#define MT_IOC(x) _IO('m', (x))

#define MT_IOC_RESET MT_IOC(0)

#define MT_IOC_ADD MT_IOC(1)

struct monotonic_config {
	uint64_t event;
	uint64_t allowed_ctr_mask;
	uint64_t cpu_mask;
};

union monotonic_ctl_add {
	struct {
		struct monotonic_config config;
	} in;

	struct {
		uint32_t ctr;
	} out;
};

/*
 * - Consider a separate IOC for disable -- to avoid the copyin to determine
 *   which way to set it.
 */
#define MT_IOC_ENABLE MT_IOC(2)

union monotonic_ctl_enable {
	struct {
		bool enable;
	} in;
};

#define MT_IOC_COUNTS MT_IOC(3)

union monotonic_ctl_counts {
	struct {
		uint64_t ctr_mask;
	} in;

	struct {
		uint64_t counts[1];
	} out;
};

#define MT_IOC_GET_INFO MT_IOC(4)

union monotonic_ctl_info {
	struct {
		unsigned int nmonitors;
		unsigned int ncounters;
	} out;
};

#if XNU_KERNEL_PRIVATE

#include <kern/monotonic.h>
#include <machine/monotonic.h>
#include <sys/kdebug.h>
#include <kern/locks.h>

#ifdef MT_CORE_INSTRS
#define COUNTS_INSTRS __counts[MT_CORE_INSTRS]
#else /* defined(MT_CORE_INSTRS) */
#define COUNTS_INSTRS 0
#endif /* !defined(MT_CORE_INSTRS) */

/*
 * MT_KDBG_TMP* macros are meant for temporary (i.e. not checked-in)
 * performance investigations.
 */

/*
 * Record the current CPU counters.
 *
 * Preemption must be disabled.
 */
#define MT_KDBG_TMPCPU_EVT(CODE) \
	KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_TMPCPU, CODE)

#define MT_KDBG_TMPCPU_(CODE, FUNC) \
	do { \
		if (kdebug_enable && \
				kdebug_debugid_enabled(MT_KDBG_TMPCPU_EVT(CODE))) { \
			uint64_t __counts[MT_CORE_NFIXED]; \
			mt_fixed_counts(__counts); \
			KDBG(MT_KDBG_TMPCPU_EVT(CODE) | (FUNC), COUNTS_INSTRS, \
					__counts[MT_CORE_CYCLES]); \
		} \
	} while (0)

#define MT_KDBG_TMPCPU(CODE) MT_KDBG_TMPCPU_(CODE, DBG_FUNC_NONE)
#define MT_KDBG_TMPCPU_START(CODE) MT_KDBG_TMPCPU_(CODE, DBG_FUNC_START)
#define MT_KDBG_TMPCPU_END(CODE) MT_KDBG_TMPCPU_(CODE, DBG_FUNC_END)

/*
 * Record the current thread counters.
 *
 * Interrupts must be disabled.
 */
#define MT_KDBG_TMPTH_EVT(CODE) \
	KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_TMPTH, CODE)

#define MT_KDBG_TMPTH_(CODE, FUNC) \
	do { \
		if (kdebug_enable && \
				kdebug_debugid_enabled(MT_KDBG_TMPTH_EVT(CODE))) { \
			uint64_t __counts[MT_CORE_NFIXED]; \
			mt_cur_thread_fixed_counts(__counts); \
			KDBG(MT_KDBG_TMPTH_EVT(CODE) | (FUNC), COUNTS_INSTRS, \
					__counts[MT_CORE_CYCLES]); \
		} \
	} while (0)

#define MT_KDBG_TMPTH(CODE) MT_KDBG_TMPTH_(CODE, DBG_FUNC_NONE)
#define MT_KDBG_TMPTH_START(CODE) MT_KDBG_TMPTH_(CODE, DBG_FUNC_START)
#define MT_KDBG_TMPTH_END(CODE) MT_KDBG_TMPTH_(CODE, DBG_FUNC_END)

struct mt_device {
	const char *mtd_name;
	int (* const mtd_init)(struct mt_device *dev);
	int (* const mtd_add)(struct monotonic_config *config, uint32_t *ctr_out);
	void (* const mtd_reset)(void);
	void (* const mtd_enable)(bool enable);
	int (* const mtd_read)(uint64_t ctr_mask, uint64_t *counts_out);
	decl_lck_mtx_data(, mtd_lock);

	uint8_t mtd_nmonitors;
	uint8_t mtd_ncounters;
	bool mtd_inuse;
};
typedef struct mt_device *mt_device_t;

extern struct mt_device mt_devices[];

extern lck_grp_t *mt_lock_grp;

int mt_dev_init(void);

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* !defined(SYS_MONOTONIC_H) */
