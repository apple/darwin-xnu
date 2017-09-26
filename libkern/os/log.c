#include <stddef.h>
#undef offset

#include <kern/cpu_data.h>
#include <os/base.h>
#include <os/object.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdint.h>

#include <vm/vm_kern.h>
#include <mach/vm_statistics.h>
#include <kern/debug.h>
#include <libkern/libkern.h>
#include <libkern/kernel_mach_header.h>
#include <pexpert/pexpert.h>
#include <uuid/uuid.h>
#include <sys/msgbuf.h>

#include <mach/mach_time.h>
#include <kern/thread.h>
#include <kern/simple_lock.h>
#include <kern/kalloc.h>
#include <kern/clock.h>
#include <kern/assert.h>

#include <firehose/tracepoint_private.h>
#include <firehose/chunk_private.h>
#include <os/firehose_buffer_private.h>
#include <os/firehose.h>

#include <os/log_private.h>
#include "trace_internal.h"

#include "log_encode.h"

struct os_log_s {
	int a;
};

struct os_log_s _os_log_default;
struct os_log_s _os_log_replay;
extern vm_offset_t kernel_firehose_addr;
extern firehose_chunk_t firehose_boot_chunk;

extern void bsd_log_lock(void);
extern void bsd_log_unlock(void);
extern void logwakeup(void);

decl_lck_spin_data(extern, oslog_stream_lock)
extern void oslog_streamwakeup(void);
void oslog_streamwrite_locked(firehose_tracepoint_id_u ftid,
		uint64_t stamp, const void *pubdata, size_t publen);
extern void oslog_streamwrite_metadata_locked(oslog_stream_buf_entry_t m_entry);

extern int oslog_stream_open;

extern void *OSKextKextForAddress(const void *);

/* Counters for persistence mode */
uint32_t oslog_p_total_msgcount = 0;
uint32_t oslog_p_metadata_saved_msgcount = 0;
uint32_t oslog_p_metadata_dropped_msgcount = 0;
uint32_t oslog_p_error_count = 0;
uint32_t oslog_p_saved_msgcount = 0;
uint32_t oslog_p_dropped_msgcount = 0;
uint32_t oslog_p_boot_dropped_msgcount = 0;

/* Counters for streaming mode */
uint32_t oslog_s_total_msgcount = 0;
uint32_t oslog_s_error_count = 0;
uint32_t oslog_s_metadata_msgcount = 0;

static bool oslog_boot_done = false;
extern boolean_t early_boot_complete;

#ifdef XNU_KERNEL_PRIVATE
bool startup_serial_logging_active = true;
uint64_t startup_serial_num_procs = 300;
#endif /* XNU_KERNEL_PRIVATE */

// XXX
firehose_tracepoint_id_t
firehose_debug_trace(firehose_stream_t stream, firehose_tracepoint_id_t trace_id,
		uint64_t timestamp, const char *format, const void *pubdata, size_t publen);

static inline firehose_tracepoint_id_t
_firehose_trace(firehose_stream_t stream, firehose_tracepoint_id_u ftid,
		uint64_t stamp, const void *pubdata, size_t publen);

static oslog_stream_buf_entry_t
oslog_stream_create_buf_entry(oslog_stream_link_type_t type, firehose_tracepoint_id_u ftid,
				uint64_t stamp, const void* pubdata, size_t publen);

static void
_os_log_with_args_internal(os_log_t oslog __unused, os_log_type_t type __unused,
		const char *format, va_list args, void *addr, void *dso);

static void
_os_log_to_msgbuf_internal(const char *format, va_list args, bool safe, bool logging);

static void
_os_log_to_log_internal(os_log_t oslog, os_log_type_t type,
		const char *format, va_list args, void *addr, void *dso);


static void
_os_log_actual(os_log_t oslog, os_log_type_t type, const char *format, void
		*dso, void *addr, os_log_buffer_context_t context);

bool
os_log_info_enabled(os_log_t log __unused)
{
	return true;
}

bool
os_log_debug_enabled(os_log_t log __unused)
{
	return true;
}

os_log_t
os_log_create(const char *subsystem __unused, const char *category __unused)
{
	return &_os_log_default;
}

bool
_os_log_string_is_public(const char *str __unused)
{
	return true;
}

__attribute__((noinline,not_tail_called)) void
_os_log_internal(void *dso, os_log_t log, uint8_t type, const char *message, ...)
{
    va_list args;
    void *addr = __builtin_return_address(0);

    va_start(args, message);

    _os_log_with_args_internal(log, type, message, args, addr, dso);

    va_end(args);

    return;
}

#pragma mark - shim functions

__attribute__((noinline,not_tail_called)) void
os_log_with_args(os_log_t oslog, os_log_type_t type, const char *format, va_list args, void *addr)
{
    // if no address passed, look it up
    if (addr == NULL) {
        addr = __builtin_return_address(0);
    }

    _os_log_with_args_internal(oslog, type, format, args, addr, NULL);
}

static void
_os_log_with_args_internal(os_log_t oslog, os_log_type_t type,
		const char *format, va_list args, void *addr, void *dso)
{
    uint32_t  logging_config = atm_get_diagnostic_config();
    boolean_t safe;
    boolean_t logging;

    if (format[0] == '\0') {
        return;
    }

    /* early boot can log to dmesg for later replay (27307943) */
    safe = (!early_boot_complete || oslog_is_safe());

	if (logging_config & ATM_TRACE_DISABLE || logging_config & ATM_TRACE_OFF) {
		logging = false;
	} else {
		logging = true;
	}

    if (oslog != &_os_log_replay) {
        _os_log_to_msgbuf_internal(format, args, safe, logging);
    }

    if (safe && logging) {
        _os_log_to_log_internal(oslog, type, format, args, addr, dso);
    }
}

static void
_os_log_to_msgbuf_internal(const char *format, va_list args, bool safe, bool logging)
{
    static int msgbufreplay = -1;
    va_list args_copy;

    bsd_log_lock();

    if (!safe) {
        if (-1 == msgbufreplay) msgbufreplay = msgbufp->msg_bufx;
    } else if (logging && (-1 != msgbufreplay)) {
        uint32_t i;
        uint32_t localbuff_size;
        int newl, position;
        char *localbuff, *p, *s, *next, ch;

        position = msgbufreplay;
        msgbufreplay = -1;
        localbuff_size = (msgbufp->msg_size + 2); /* + '\n' + '\0' */
        /* Size for non-blocking */
        if (localbuff_size > 4096) localbuff_size = 4096;
        bsd_log_unlock();
        /* Allocate a temporary non-circular buffer */
        if ((localbuff = (char *)kalloc_noblock(localbuff_size))) {
            /* in between here, the log could become bigger, but that's fine */
            bsd_log_lock();
            /*
             * The message buffer is circular; start at the replay pointer, and
             * make one loop up to write pointer - 1.
             */
            p = msgbufp->msg_bufc + position;
            for (i = newl = 0; p != msgbufp->msg_bufc + msgbufp->msg_bufx - 1; ++p) {
                if (p >= msgbufp->msg_bufc + msgbufp->msg_size)
                    p = msgbufp->msg_bufc;
                ch = *p;
                if (ch == '\0') continue;
                newl = (ch == '\n');
                localbuff[i++] = ch;
                if (i >= (localbuff_size - 2)) break;
            }
            bsd_log_unlock();

            if (!newl) localbuff[i++] = '\n';
            localbuff[i++] = 0;

            s = localbuff;
            while ((next = strchr(s, '\n'))) {
                next++;
                ch = next[0];
                next[0] = 0;
                os_log(&_os_log_replay, "%s", s);
                next[0] = ch;
                s = next;
            }
            kfree(localbuff, localbuff_size);
        }
        bsd_log_lock();
    }

    va_copy(args_copy, args);
    vprintf_log_locked(format, args_copy);
    va_end(args_copy);

    bsd_log_unlock();

    if (safe) logwakeup();
}

static void
_os_log_to_log_internal(os_log_t oslog, os_log_type_t type,
		const char *format, va_list args, void *addr, void *dso)
{
    struct os_log_buffer_context_s context;
    unsigned char buffer_data[OS_LOG_BUFFER_MAX_SIZE] __attribute__((aligned(8)));
    os_log_buffer_t buffer = (os_log_buffer_t)buffer_data;
    uint8_t pubdata[OS_LOG_BUFFER_MAX_SIZE];
    va_list args_copy;

    if (dso == NULL) {
        dso = (void *) OSKextKextForAddress(format);
        if (dso == NULL) {
            return;
        }
    }

    if (!_os_trace_addr_in_text_segment(dso, format)) {
        return;
    }

    if (addr == NULL) {
        return;
    }

    void *dso_addr = (void *) OSKextKextForAddress(addr);
    if (dso != dso_addr) {
        return;
    }

    memset(&context, 0, sizeof(context));
    memset(buffer, 0, OS_LOG_BUFFER_MAX_SIZE);

    context.shimmed = true;
    context.buffer = buffer;
    context.content_sz = OS_LOG_BUFFER_MAX_SIZE - sizeof(*buffer);
    context.pubdata = pubdata;
    context.pubdata_sz = sizeof(pubdata);

    va_copy(args_copy, args);

    (void)hw_atomic_add(&oslog_p_total_msgcount, 1);
    if (_os_log_encode(format, args_copy, 0, &context)) {
        _os_log_actual(oslog, type, format, dso, addr, &context);
    }
    else {
        (void)hw_atomic_add(&oslog_p_error_count, 1);
    }

    va_end(args_copy);
}

static inline size_t
_os_trace_write_location_for_address(uint8_t buf[static sizeof(uint64_t)],
		void *dso, const void *address, firehose_tracepoint_flags_t *flags)
{
	kernel_mach_header_t *mh = dso;

	if (mh->filetype == MH_EXECUTE) {
		*flags = _firehose_tracepoint_flags_pc_style_main_exe;
		memcpy(buf, (uint32_t[]){ (uintptr_t)address - (uintptr_t)dso },
				sizeof(uint32_t));
		return sizeof(uint32_t);
	} else {
		*flags = _firehose_tracepoint_flags_pc_style_absolute;
		memcpy(buf, (uintptr_t[]){ VM_KERNEL_UNSLIDE(address) }, sizeof(uintptr_t));
#if __LP64__
		return 6; // 48 bits are enough
#else
		return sizeof(uintptr_t);
#endif
	}
}


OS_ALWAYS_INLINE
static inline size_t
_os_log_buffer_pack(uint8_t *buffdata, size_t buffdata_sz,
		os_log_buffer_context_t ctx)
{
	os_log_buffer_t buffer = ctx->buffer;
	size_t buffer_sz = sizeof(*ctx->buffer) + ctx->content_sz;
	size_t total_sz  = buffer_sz + ctx->pubdata_sz;

	if (total_sz > buffdata_sz) {
		return 0;
	}

	memcpy(buffdata, buffer, buffer_sz);
	memcpy(&buffdata[buffer_sz], ctx->pubdata, ctx->pubdata_sz);
	return total_sz;
}

static void
_os_log_actual(os_log_t oslog __unused, os_log_type_t type, const char *format,
		void *dso, void *addr, os_log_buffer_context_t context)
{
	firehose_stream_t stream;
	firehose_tracepoint_flags_t flags = 0;
	firehose_tracepoint_id_u trace_id;
	uint8_t buffdata[OS_LOG_BUFFER_MAX_SIZE];
	size_t addr_len = 0, buffdata_sz;
	uint64_t timestamp;
	uint64_t thread_id;

	// dso == the start of the binary that was loaded
	addr_len = _os_trace_write_location_for_address(buffdata, dso, addr, &flags);
	buffdata_sz = _os_log_buffer_pack(buffdata + addr_len,
			sizeof(buffdata) - addr_len, context);
	if (buffdata_sz == 0) {
		return;
	}
	buffdata_sz += addr_len;

	timestamp = firehose_tracepoint_time(firehose_activity_flags_default);
	thread_id = thread_tid(current_thread());

	// create trace_id after we've set additional flags
	trace_id.ftid_value = FIREHOSE_TRACE_ID_MAKE(firehose_tracepoint_namespace_log,
			type, flags, _os_trace_offset(dso, format, flags));

	if (FALSE) {
		firehose_debug_trace(stream, trace_id.ftid_value, timestamp,
					format, buffdata, buffdata_sz);
	}
	if (type == OS_LOG_TYPE_INFO || type == OS_LOG_TYPE_DEBUG) {
		stream = firehose_stream_memory;
	}
	else {
		stream = firehose_stream_persist;
	}
	_firehose_trace(stream, trace_id, timestamp, buffdata, buffdata_sz);
}

static inline firehose_tracepoint_id_t
_firehose_trace(firehose_stream_t stream, firehose_tracepoint_id_u ftid,
		uint64_t stamp, const void *pubdata, size_t publen)
{
	const uint16_t ft_size = offsetof(struct firehose_tracepoint_s, ft_data);
	const size_t _firehose_chunk_payload_size =
			sizeof(((struct firehose_chunk_s *)0)->fc_data);

	firehose_tracepoint_t ft;

	if (slowpath(ft_size + publen > _firehose_chunk_payload_size)) {
		// We'll need to have some handling here. For now - return 0
		(void)hw_atomic_add(&oslog_p_error_count, 1);
		return 0;
	}

	if (oslog_stream_open && (stream != firehose_stream_metadata)) {

		lck_spin_lock(&oslog_stream_lock);
		if (!oslog_stream_open) {
			lck_spin_unlock(&oslog_stream_lock);
			goto out;
		}

		oslog_s_total_msgcount++;
		oslog_streamwrite_locked(ftid, stamp, pubdata, publen);
		lck_spin_unlock(&oslog_stream_lock);
		oslog_streamwakeup();
	}

out:
	ft = __firehose_buffer_tracepoint_reserve(stamp, stream, (uint16_t)publen, 0, NULL);
	if (!fastpath(ft)) {
		if (oslog_boot_done) {
			if (stream == firehose_stream_metadata) {
				(void)hw_atomic_add(&oslog_p_metadata_dropped_msgcount, 1);
			}
			else {
				// If we run out of space in the persistence buffer we're
				// dropping the message.
				(void)hw_atomic_add(&oslog_p_dropped_msgcount, 1);
			}
			return 0;
		}
		firehose_chunk_t fbc = firehose_boot_chunk;
		long offset;

		//only stream available during boot is persist
		offset = firehose_chunk_tracepoint_try_reserve(fbc, stamp,
				firehose_stream_persist, 0, publen, 0, NULL);
		if (offset <= 0) {
			(void)hw_atomic_add(&oslog_p_boot_dropped_msgcount, 1);
			return 0;
		}

		ft = firehose_chunk_tracepoint_begin(fbc, stamp, publen,
				thread_tid(current_thread()), offset);
		memcpy(ft->ft_data, pubdata, publen);
		firehose_chunk_tracepoint_end(fbc, ft, ftid);
		(void)hw_atomic_add(&oslog_p_saved_msgcount, 1);
		return ftid.ftid_value;
	}
	if (!oslog_boot_done) {
		oslog_boot_done = true;
	}
	memcpy(ft->ft_data, pubdata, publen);

	__firehose_buffer_tracepoint_flush(ft, ftid);
	if (stream == firehose_stream_metadata) {
		(void)hw_atomic_add(&oslog_p_metadata_saved_msgcount, 1);
	}
	else {
		(void)hw_atomic_add(&oslog_p_saved_msgcount, 1);
	}
	return ftid.ftid_value;
}

static oslog_stream_buf_entry_t
oslog_stream_create_buf_entry(oslog_stream_link_type_t type, firehose_tracepoint_id_u ftid,
				uint64_t stamp, const void* pubdata, size_t publen)
{
	oslog_stream_buf_entry_t m_entry = NULL;
	firehose_tracepoint_t ft = NULL;
	size_t m_entry_len = 0;

	if (!pubdata) {
		return NULL;
	}

	m_entry_len = sizeof(struct oslog_stream_buf_entry_s) +
			sizeof(struct firehose_tracepoint_s) + publen;
	m_entry = (oslog_stream_buf_entry_t) kalloc(m_entry_len);
	if (!m_entry) {
		return NULL;
	}

	m_entry->type = type;
	m_entry->timestamp = stamp;
	m_entry->size = sizeof(struct firehose_tracepoint_s) + publen;

	ft = m_entry->metadata;
	ft->ft_thread = thread_tid(current_thread());
	ft->ft_id.ftid_value = ftid.ftid_value;
	ft->ft_length = publen;
	memcpy(ft->ft_data, pubdata, publen);

	return m_entry;
}

#ifdef KERNEL
void
firehose_trace_metadata(firehose_stream_t stream, firehose_tracepoint_id_u ftid,
		uint64_t stamp, const void *pubdata, size_t publen)
{
	oslog_stream_buf_entry_t m_entry = NULL;

	// If streaming mode is not on, only log  the metadata
	// in the persistence buffer

	lck_spin_lock(&oslog_stream_lock);
	if (!oslog_stream_open) {
		lck_spin_unlock(&oslog_stream_lock);
		goto finish;
	}
	lck_spin_unlock(&oslog_stream_lock);

	// Setup and write the stream metadata entry
	m_entry = oslog_stream_create_buf_entry(oslog_stream_link_type_metadata, ftid,
							stamp, pubdata, publen);
	if (!m_entry) {
		(void)hw_atomic_add(&oslog_s_error_count, 1);
		goto finish;
	}

	lck_spin_lock(&oslog_stream_lock);
	if (!oslog_stream_open) {
		lck_spin_unlock(&oslog_stream_lock);
		kfree(m_entry, sizeof(struct oslog_stream_buf_entry_s) +
			sizeof(struct firehose_tracepoint_s) + publen);
		goto finish;
	}
	oslog_s_metadata_msgcount++;
	oslog_streamwrite_metadata_locked(m_entry);
	lck_spin_unlock(&oslog_stream_lock);

finish:
	_firehose_trace(stream, ftid, stamp, pubdata, publen);
}
#endif

firehose_tracepoint_id_t
firehose_debug_trace(firehose_stream_t stream, firehose_tracepoint_id_t trace_id,
		uint64_t timestamp, const char *format, const void *pubdata, size_t publen)
{
	kprintf("[os_log stream 0x%x trace_id 0x%llx timestamp %llu format '%s' data %p len %lu]\n",
			(unsigned int)stream, (unsigned long long)trace_id, timestamp,
			format, pubdata, publen);
	size_t i;
	const unsigned char *cdata = (const unsigned char *)pubdata;
	for (i=0; i < publen; i += 8) {
		kprintf(">oslog 0x%08x: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
				(unsigned int)i,
				(i+0) < publen ? cdata[i+0] : 0,
				(i+1) < publen ? cdata[i+1] : 0,
				(i+2) < publen ? cdata[i+2] : 0,
				(i+3) < publen ? cdata[i+3] : 0,
				(i+4) < publen ? cdata[i+4] : 0,
				(i+5) < publen ? cdata[i+5] : 0,
				(i+6) < publen ? cdata[i+6] : 0,
				(i+7) < publen ? cdata[i+7] : 0
			);
	}
	return trace_id;
}

void
__firehose_buffer_push_to_logd(firehose_buffer_t fb __unused, bool for_io __unused) {
        oslogwakeup();
        return;
}

void
__firehose_allocate(vm_offset_t *addr, vm_size_t size __unused)
{
        firehose_chunk_t kernel_buffer = (firehose_chunk_t)kernel_firehose_addr;

        if (kernel_firehose_addr) {
                *addr = kernel_firehose_addr;
        }
        else {
                *addr = 0;
                return;
        }
        // Now that we are done adding logs to this chunk, set the number of writers to 0
        // Without this, logd won't flush when the page is full
        firehose_boot_chunk->fc_pos.fcp_refcnt = 0;
        memcpy(&kernel_buffer[FIREHOSE_BUFFER_KERNEL_CHUNK_COUNT - 1], (const void *)firehose_boot_chunk, FIREHOSE_CHUNK_SIZE);
        return;
}
// There isnt a lock held in this case.
void
__firehose_critical_region_enter(void) {
        disable_preemption();
        return;
}

void
__firehose_critical_region_leave(void) {
        enable_preemption();
        return;
}

