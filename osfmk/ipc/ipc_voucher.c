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

#include <mach/mach_types.h>
#include <mach/notify.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_voucher.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <kern/mach_param.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>

#include <libkern/OSAtomic.h>

#include <mach/mach_voucher_server.h>
#include <mach/mach_voucher_attr_control_server.h>
#include <mach/mach_host_server.h>

/*
 * Sysctl variable; enable and disable tracing of voucher contents
 */
uint32_t ipc_voucher_trace_contents = 0;

static zone_t ipc_voucher_zone;
static zone_t ipc_voucher_attr_control_zone;

/*
 * Voucher hash table
 */
#define IV_HASH_BUCKETS 127
#define IV_HASH_BUCKET(x) ((x) % IV_HASH_BUCKETS)

static queue_head_t ivht_bucket[IV_HASH_BUCKETS];
static lck_spin_t ivht_lock_data;
static uint32_t ivht_count = 0;

#define ivht_lock_init() \
	lck_spin_init(&ivht_lock_data, &ipc_lck_grp, &ipc_lck_attr)
#define ivht_lock_destroy() \
	lck_spin_destroy(&ivht_lock_data, &ipc_lck_grp)
#define	ivht_lock() \
	lck_spin_lock(&ivht_lock_data)
#define	ivht_lock_try() \
	lck_spin_try_lock(&ivht_lock_data)
#define	ivht_unlock() \
	lck_spin_unlock(&ivht_lock_data)

/*
 * Global table of resource manager registrations
 *
 * NOTE: For now, limited to well-known resource managers
 * eventually, will include dynamic allocations requiring
 * table growth and hashing by key.
 */
static iv_index_t ivgt_keys_in_use = MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN;
static ipc_voucher_global_table_element iv_global_table[MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN];
static lck_spin_t ivgt_lock_data; 

#define ivgt_lock_init() \
	lck_spin_init(&ivgt_lock_data, &ipc_lck_grp, &ipc_lck_attr)
#define ivgt_lock_destroy() \
	lck_spin_destroy(&ivgt_lock_data, &ipc_lck_grp)
#define	ivgt_lock() \
	lck_spin_lock(&ivgt_lock_data)
#define	ivgt_lock_try() \
	lck_spin_try_lock(&ivgt_lock_data)
#define	ivgt_unlock() \
	lck_spin_unlock(&ivgt_lock_data)

ipc_voucher_t iv_alloc(iv_index_t entries);
void iv_dealloc(ipc_voucher_t iv, boolean_t unhash);

static inline iv_refs_t
iv_reference(ipc_voucher_t iv)
{
	iv_refs_t refs;

	refs = hw_atomic_add(&iv->iv_refs, 1);
	return refs;
}

static inline void
iv_release(ipc_voucher_t iv)
{
	iv_refs_t refs;

	assert(0 < iv->iv_refs);
	refs = hw_atomic_sub(&iv->iv_refs, 1);
	if (0 == refs)
		iv_dealloc(iv, TRUE);
}

/*
 * freelist helper macros
 */
#define IV_FREELIST_END ((iv_index_t) 0)

/*
 * Attribute value hashing helper macros
 */
#define IV_HASH_END UINT32_MAX
#define IV_HASH_VAL(sz, val) \
	(((val) >> 3) % (sz))

static inline iv_index_t
iv_hash_value(
	iv_index_t key_index,
	mach_voucher_attr_value_handle_t value)
{
	ipc_voucher_attr_control_t ivac;

	ivac = iv_global_table[key_index].ivgte_control;
	assert(IVAC_NULL != ivac);
	return IV_HASH_VAL(ivac->ivac_init_table_size, value);
}

/*
 * Convert a key to an index.  This key-index is used to both index
 * into the voucher table of attribute cache indexes and also the
 * table of resource managers by key.
 *
 * For now, well-known keys have a one-to-one mapping of indexes
 * into these tables.  But as time goes on, that may not always
 * be the case (sparse use over time).  This isolates the code from
 * having to change in these cases - yet still lets us keep a densely
 * packed set of tables.
 */
static inline iv_index_t
iv_key_to_index(mach_voucher_attr_key_t key)
{
	if (MACH_VOUCHER_ATTR_KEY_ALL == key ||
	    MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN < key)
		return IV_UNUSED_KEYINDEX;
	return (iv_index_t)key - 1;
}

static inline mach_voucher_attr_key_t
iv_index_to_key(iv_index_t key_index)
{
	if (MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN > key_index)
		return iv_global_table[key_index].ivgte_key;
	return MACH_VOUCHER_ATTR_KEY_NONE;
		
}

static void ivace_release(iv_index_t key_index, iv_index_t value_index);
static void ivace_lookup_values(iv_index_t key_index, iv_index_t value_index, 
				mach_voucher_attr_value_handle_array_t	values,
				mach_voucher_attr_value_handle_array_size_t *count);

static iv_index_t iv_lookup(ipc_voucher_t, iv_index_t);

				
static void ivgt_lookup(iv_index_t,
			boolean_t,
			ipc_voucher_attr_manager_t *,
			ipc_voucher_attr_control_t *);


#if defined(MACH_VOUCHER_ATTR_KEY_USER_DATA) || defined(MACH_VOUCHER_ATTR_KEY_TEST)
void user_data_attr_manager_init(void);
#endif 

void
ipc_voucher_init(void)
{
	natural_t ipc_voucher_max = (task_max + thread_max) * 2;
	natural_t attr_manager_max = MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN;
	iv_index_t i;

	ipc_voucher_zone = zinit(sizeof(struct ipc_voucher),
				 ipc_voucher_max * sizeof(struct ipc_voucher),
				 sizeof(struct ipc_voucher),
				 "ipc vouchers");
	zone_change(ipc_voucher_zone, Z_NOENCRYPT, TRUE);

	ipc_voucher_attr_control_zone = zinit(sizeof(struct ipc_voucher_attr_control),
				 attr_manager_max * sizeof(struct ipc_voucher_attr_control),
				 sizeof(struct ipc_voucher_attr_control),
				 "ipc voucher attr controls");
	zone_change(ipc_voucher_attr_control_zone, Z_NOENCRYPT, TRUE);

	/* initialize voucher hash */
	ivht_lock_init();
	for (i = 0; i < IV_HASH_BUCKETS; i++)
		queue_init(&ivht_bucket[i]);

	/* initialize global table locking */
	ivgt_lock_init();

#if defined(MACH_VOUCHER_ATTR_KEY_USER_DATA) || defined(MACH_VOUCHER_ATTR_KEY_TEST)
	user_data_attr_manager_init();
#endif
}

ipc_voucher_t
iv_alloc(iv_index_t entries)
{
	ipc_voucher_t iv;
	iv_index_t i;


	iv = (ipc_voucher_t)zalloc(ipc_voucher_zone);
	if (IV_NULL == iv)
		return IV_NULL;
		
	iv->iv_refs = 1;
	iv->iv_sum = 0;
	iv->iv_hash = 0;
	iv->iv_port = IP_NULL;

	if (entries > IV_ENTRIES_INLINE) {
		iv_entry_t table;

		/* TODO - switch to ipc_table method of allocation */
		table = (iv_entry_t) kalloc(sizeof(*table) * entries);
		if (IVE_NULL == table) {
			zfree(ipc_voucher_zone, iv);
			return IV_NULL;
		}
		iv->iv_table = table;
		iv->iv_table_size = entries;
	} else {
		iv->iv_table = iv->iv_inline_table;
		iv->iv_table_size = IV_ENTRIES_INLINE;
	}

	/* initialize the table entries */
	for (i=0; i < iv->iv_table_size; i++)
		iv->iv_table[i] = IV_UNUSED_VALINDEX;
		
	return (iv);
}

/*
 *	Routine:	iv_set
 *	Purpose:
 *		Set the voucher's value index for a given key index.
 *	Conditions:
 *		This is only called during voucher creation, as
 *		they are immutable once references are distributed.
 */
static void
iv_set(ipc_voucher_t iv, 
       iv_index_t key_index,
       iv_index_t value_index)
{
	assert(key_index < iv->iv_table_size);
	iv->iv_table[key_index] = value_index;
}

void
iv_dealloc(ipc_voucher_t iv, boolean_t unhash)
{
	ipc_port_t port = iv->iv_port;
	natural_t i;

	/*
	 * Do we have to remove it from the hash?
	 */
	if (unhash) {
		ivht_lock();
		assert(0 == iv->iv_refs);
		assert(IV_HASH_BUCKETS > iv->iv_hash);
		queue_remove(&ivht_bucket[iv->iv_hash], iv, ipc_voucher_t, iv_hash_link);
		ivht_count--;
		ivht_unlock();

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC,MACH_IPC_VOUCHER_DESTROY) | DBG_FUNC_NONE,
				      VM_KERNEL_ADDRPERM((uintptr_t)iv), 0, ivht_count, 0, 0);

	} else
		assert(0 == --iv->iv_refs);

	/*
	 * if a port was allocated for this voucher,
	 * it must not have any remaining send rights,
	 * because the port's reference on the voucher
	 * is gone.  We can just discard it now.
	 */
	if (IP_VALID(port)) {
		assert(ip_active(port));
		assert(port->ip_srights == 0);

		ipc_port_dealloc_kernel(port);
	}

	/* release the attribute references held by this voucher */
	for (i = 0; i < iv->iv_table_size; i++) {
		ivace_release(i, iv->iv_table[i]);
#if MACH_ASSERT
		iv_set(iv, i, ~0);
#endif
	}
			
	if (iv->iv_table != iv->iv_inline_table)
		kfree(iv->iv_table, 
		      iv->iv_table_size * sizeof(*iv->iv_table));

	zfree(ipc_voucher_zone, iv);
}

/*
 *	Routine:	iv_lookup
 *	Purpose:
 *		Find the voucher's value index for a given key_index
 *	Conditions:
 *		Vouchers are immutable, so no locking required to do
 *		a lookup.
 */
static inline iv_index_t
iv_lookup(ipc_voucher_t iv, iv_index_t key_index)
{
	if (key_index < iv->iv_table_size)
		return iv->iv_table[key_index];
	return IV_UNUSED_VALINDEX;
}

/*
 *	Routine:	unsafe_convert_port_to_voucher
 *	Purpose:
 *		Unsafe conversion of a port to a voucher.
 *		Intended only for use by trace and debugging
 *		code. Consumes nothing, validates very little,
 *		produces an unreferenced voucher, which you
 *		MAY NOT use as a voucher, only log as an
 *		address.
 *	Conditions:
 *		Caller has a send-right reference to port.
 *		Port may or may not be locked.
 */
uintptr_t
unsafe_convert_port_to_voucher(
	ipc_port_t	port)
{
	if (IP_VALID(port)) {
		uintptr_t voucher = (uintptr_t) port->ip_kobject;

		/*
		 * No need to lock because we have a reference on the
		 * port, and if it is a true voucher port, that reference
		 * keeps the voucher bound to the port (and active).
		 */
		if (ip_kotype(port) == IKOT_VOUCHER)
			return (voucher);
	}
	return (uintptr_t)IV_NULL;
}

/*
 *	Routine:	convert_port_to_voucher
 *	Purpose:
 *		Convert from a port to a voucher.
 *		Doesn't consume the port [send-right] ref;
 *		produces a voucher ref,	which may be null.
 *	Conditions:
 *		Caller has a send-right reference to port.
 *		Port may or may not be locked.
 */
ipc_voucher_t
convert_port_to_voucher(
	ipc_port_t	port)
{
	if (IP_VALID(port)) {
		ipc_voucher_t voucher = (ipc_voucher_t) port->ip_kobject;

		/*
		 * No need to lock because we have a reference on the
		 * port, and if it is a true voucher port, that reference
		 * keeps the voucher bound to the port (and active).
		 */
		if (ip_kotype(port) != IKOT_VOUCHER)
			return IV_NULL;

		assert(ip_active(port));

		ipc_voucher_reference(voucher);
		return (voucher);
	}
	return IV_NULL;
}

/*
 *	Routine:	convert_port_name_to_voucher
 *	Purpose:
 *		Convert from a port name in the current space to a voucher.
 *		Produces a voucher ref,	which may be null.
 *	Conditions:
 *		Nothing locked.
 */

ipc_voucher_t
convert_port_name_to_voucher(
	mach_port_name_t	voucher_name)
{
	ipc_voucher_t iv;
	kern_return_t kr;
	ipc_port_t port;

	if (MACH_PORT_VALID(voucher_name)) {
		kr = ipc_port_translate_send(current_space(), voucher_name, &port);
		if (KERN_SUCCESS != kr)
			return IV_NULL;

		iv = convert_port_to_voucher(port);
		ip_unlock(port);
		return iv;
	}
	return IV_NULL;
}


void
ipc_voucher_reference(ipc_voucher_t voucher)
{
	iv_refs_t refs;

	if (IPC_VOUCHER_NULL == voucher)
		return;

	refs = iv_reference(voucher);
	assert(1 < refs);
}

void
ipc_voucher_release(ipc_voucher_t voucher)
{
	if (IPC_VOUCHER_NULL != voucher)
		iv_release(voucher);
}

/*
 * Routine:	ipc_voucher_notify
 * Purpose:
 *	Called whenever the Mach port system detects no-senders
 *	on the voucher port.
 *
 *	Each time the send-right count goes positive, a no-senders 
 *	notification is armed (and a voucher reference is donated).
 *	So, each notification that comes in must release a voucher
 *	reference.  If more send rights have been added since it
 *	fired (asynchronously), they will be protected by a different
 *	reference hold.
 */
void
ipc_voucher_notify(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	ipc_voucher_t iv;

	assert(ip_active(port));
	assert(IKOT_VOUCHER == ip_kotype(port));
	iv = (ipc_voucher_t)port->ip_kobject;

	ipc_voucher_release(iv);
}

/*
 * Convert a voucher to a port.
 */
ipc_port_t
convert_voucher_to_port(ipc_voucher_t voucher)
{
	ipc_port_t	port, send;

	if (IV_NULL == voucher)
		return (IP_NULL);

	assert(0 < voucher->iv_refs);

	/* create a port if needed */
	port = voucher->iv_port;
	if (!IP_VALID(port)) {
		port = ipc_port_alloc_kernel();
		assert(IP_VALID(port));
		ipc_kobject_set_atomically(port, (ipc_kobject_t) voucher, IKOT_VOUCHER);

		/* If we lose the race, deallocate and pick up the other guy's port */
		if (!OSCompareAndSwapPtr(IP_NULL, port, &voucher->iv_port)) {
			ipc_port_dealloc_kernel(port);
			port = voucher->iv_port;
			assert(ip_kotype(port) == IKOT_VOUCHER);
			assert(port->ip_kobject == (ipc_kobject_t)voucher);
		}
	}
	
	ip_lock(port);
	assert(ip_active(port));
	send = ipc_port_make_send_locked(port);

	if (1 == port->ip_srights) {
		ipc_port_t old_notify;

		/* transfer our ref to the port, and arm the no-senders notification */
		assert(IP_NULL == port->ip_nsrequest);
		ipc_port_nsrequest(port, port->ip_mscount, ipc_port_make_sonce_locked(port), &old_notify);
		/* port unlocked */
		assert(IP_NULL == old_notify);
	} else {
		/* piggyback on the existing port reference, so consume ours */
		ip_unlock(port);
		ipc_voucher_release(voucher);
	}
	return (send);
}

#define ivace_reset_data(ivace_elem, next_index) {       \
	(ivace_elem)->ivace_value = 0xDEADC0DEDEADC0DE;  \
	(ivace_elem)->ivace_refs = 0;                    \
	(ivace_elem)->ivace_made = 0;                    \
	(ivace_elem)->ivace_free = TRUE;                 \
	(ivace_elem)->ivace_releasing = FALSE;           \
	(ivace_elem)->ivace_layered = 0;                 \
	(ivace_elem)->ivace_index = IV_HASH_END;         \
	(ivace_elem)->ivace_next = (next_index);         \
}

#define ivace_copy_data(ivace_src_elem, ivace_dst_elem) {  \
	(ivace_dst_elem)->ivace_value = (ivace_src_elem)->ivace_value; \
	(ivace_dst_elem)->ivace_refs = (ivace_src_elem)->ivace_refs;   \
	(ivace_dst_elem)->ivace_made = (ivace_src_elem)->ivace_made;   \
	(ivace_dst_elem)->ivace_free = (ivace_src_elem)->ivace_free;   \
	(ivace_dst_elem)->ivace_layered = (ivace_src_elem)->ivace_layered;   \
	(ivace_dst_elem)->ivace_releasing = (ivace_src_elem)->ivace_releasing; \
	(ivace_dst_elem)->ivace_index = (ivace_src_elem)->ivace_index; \
	(ivace_dst_elem)->ivace_next = (ivace_src_elem)->ivace_next; \
}

ipc_voucher_attr_control_t
ivac_alloc(iv_index_t key_index)
{
	ipc_voucher_attr_control_t ivac;
	ivac_entry_t table;
	natural_t i;


	ivac = (ipc_voucher_attr_control_t)zalloc(ipc_voucher_attr_control_zone);
	if (IVAC_NULL == ivac)
		return IVAC_NULL;
		
	ivac->ivac_refs = 1;
	ivac->ivac_is_growing = FALSE;
	ivac->ivac_port = IP_NULL;

	/* start with just the inline table */
	table =	(ivac_entry_t) kalloc(IVAC_ENTRIES_MIN * sizeof(ivac_entry));
	ivac->ivac_table = table;
	ivac->ivac_table_size = IVAC_ENTRIES_MIN;
	ivac->ivac_init_table_size = IVAC_ENTRIES_MIN;
	for (i = 0; i < ivac->ivac_table_size; i++) {
		ivace_reset_data(&table[i], i+1);
	}

	/* the default table entry is never on freelist */
	table[0].ivace_next = IV_HASH_END;
	table[0].ivace_free = FALSE;
	table[i-1].ivace_next = IV_FREELIST_END;
	ivac->ivac_freelist = 1;
	ivac_lock_init(ivac);
	ivac->ivac_key_index = key_index;
	return (ivac);
}
	

void
ivac_dealloc(ipc_voucher_attr_control_t ivac)
{
	ipc_voucher_attr_manager_t ivam = IVAM_NULL;
	iv_index_t key_index = ivac->ivac_key_index;
	ipc_port_t port = ivac->ivac_port;
	natural_t i;

	/*
	 * If the control is in the global table, we
	 * have to remove it from there before we (re)confirm
	 * that the reference count is still zero.
	 */
	ivgt_lock();
	if (ivac->ivac_refs > 0) {
		ivgt_unlock();
		return;
	}

	/* take it out of the global table */
	if (iv_global_table[key_index].ivgte_control == ivac) {
		ivam = iv_global_table[key_index].ivgte_manager;
		iv_global_table[key_index].ivgte_manager = IVAM_NULL;
		iv_global_table[key_index].ivgte_control = IVAC_NULL;
		iv_global_table[key_index].ivgte_key = MACH_VOUCHER_ATTR_KEY_NONE;
	}
	ivgt_unlock();

	/* release the reference held on the resource manager */
	if (IVAM_NULL != ivam)
		(ivam->ivam_release)(ivam);

	/*
	 * if a port was allocated for this voucher,
	 * it must not have any remaining send rights,
	 * because the port's reference on the voucher
	 * is gone.  We can just discard it now.
	 */
	if (IP_VALID(port)) {
		assert(ip_active(port));
		assert(port->ip_srights == 0);

		ipc_port_dealloc_kernel(port);
	}

	/*
	 * the resource manager's control reference and all references
	 * held by the specific value caches are gone, so free the
	 * table.
	 */
#ifdef MACH_DEBUG
	for (i = 0; i < ivac->ivac_table_size; i++)
		if (ivac->ivac_table[i].ivace_refs != 0)
			panic("deallocing a resource manager with live refs to its attr values\n");
#endif
	kfree(ivac->ivac_table, ivac->ivac_table_size * sizeof(*ivac->ivac_table));
	ivac_lock_destroy(ivac);
	zfree(ipc_voucher_attr_control_zone, ivac);
}

void
ipc_voucher_attr_control_reference(ipc_voucher_attr_control_t control)
{
	ivac_reference(control);
}

void
ipc_voucher_attr_control_release(ipc_voucher_attr_control_t control)
{
	ivac_release(control);
}

/*
 *	Routine:	convert_port_to_voucher_attr_control reference
 *	Purpose:
 *		Convert from a port to a voucher attribute control.
 *		Doesn't consume the port ref; produces a voucher ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
ipc_voucher_attr_control_t
convert_port_to_voucher_attr_control(
	ipc_port_t	port)
{
	if (IP_VALID(port)) {
		ipc_voucher_attr_control_t ivac = (ipc_voucher_attr_control_t) port->ip_kobject;

		/*
		 * No need to lock because we have a reference on the
		 * port, and if it is a true voucher control port,
		 * that reference keeps the voucher bound to the port
		 * (and active).
		 */
		if (ip_kotype(port) != IKOT_VOUCHER_ATTR_CONTROL)
			return IVAC_NULL;

		assert(ip_active(port));

		ivac_reference(ivac);
		return (ivac);
	}
	return IVAC_NULL;
}

void
ipc_voucher_attr_control_notify(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	ipc_voucher_attr_control_t ivac;

	assert(IKOT_VOUCHER_ATTR_CONTROL == ip_kotype(port));
	ip_lock(port);
	assert(ip_active(port));

	/* if no new send rights, drop a control reference */
	if (port->ip_mscount == notification->not_count) {
		ivac = (ipc_voucher_attr_control_t)port->ip_kobject;
		ip_unlock(port);

		ivac_release(ivac);
	}
	ip_unlock(port);
}

/*
 * Convert a voucher attr control to a port.
 */
ipc_port_t
convert_voucher_attr_control_to_port(ipc_voucher_attr_control_t control)
{
	ipc_port_t	port, send;

	if (IVAC_NULL == control)
		return (IP_NULL);

	/* create a port if needed */
	port = control->ivac_port;
	if (!IP_VALID(port)) {
		port = ipc_port_alloc_kernel();
		assert(IP_VALID(port));
		if (OSCompareAndSwapPtr(IP_NULL, port, &control->ivac_port)) {
			ip_lock(port);
			ipc_kobject_set_atomically(port, (ipc_kobject_t) control, IKOT_VOUCHER_ATTR_CONTROL);
		} else {
			ipc_port_dealloc_kernel(port);
			port = control->ivac_port;
			ip_lock(port);
			assert(ip_kotype(port) == IKOT_VOUCHER_ATTR_CONTROL);
			assert(port->ip_kobject == (ipc_kobject_t)control);
		}
	} else 
		ip_lock(port);

	assert(ip_active(port));
	send = ipc_port_make_send_locked(port);

	if (1 == port->ip_srights) {
		ipc_port_t old_notify;

		/* transfer our ref to the port, and arm the no-senders notification */
		assert(IP_NULL == port->ip_nsrequest);
		ipc_port_nsrequest(port, port->ip_mscount, ipc_port_make_sonce_locked(port), &old_notify);
		assert(IP_NULL == old_notify);
		ip_unlock(port);
	} else {
		/* piggyback on the existing port reference, so consume ours */
		ip_unlock(port);
		ivac_release(control);
	}
	return (send);
}

/*
 * Look up the values for a given <key, index> pair.
 */
static void
ivace_lookup_values(
	iv_index_t		 		key_index,
	iv_index_t				value_index,
	mach_voucher_attr_value_handle_array_t		values,
	mach_voucher_attr_value_handle_array_size_t	*count)
{
	ipc_voucher_attr_control_t ivac;
	ivac_entry_t ivace;

	if (IV_UNUSED_VALINDEX == value_index ||
	    MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN <= key_index) {
		*count = 0;
		return;
	}

	ivac = iv_global_table[key_index].ivgte_control;
	assert(IVAC_NULL != ivac);

	/*
	 * Get the entry and then the linked values.
	 */
	ivac_lock(ivac);
	assert(value_index < ivac->ivac_table_size);
	ivace = &ivac->ivac_table[value_index];

	/*
	 * TODO: support chained values (for effective vouchers).
	 */
	assert(ivace->ivace_refs > 0);
	values[0] = ivace->ivace_value;
	ivac_unlock(ivac);
	*count = 1;
}

/*
 *  ivac_grow_table - Allocate a bigger table of attribute values
 *
 *  Conditions:	ivac is locked on entry and again on return
 */
static void
ivac_grow_table(ipc_voucher_attr_control_t ivac)
{
	iv_index_t i = 0;

	/* NOTE: do not modify *_table and *_size values once set */
	ivac_entry_t new_table = NULL, old_table = NULL;
	iv_index_t new_size, old_size;

	if (ivac->ivac_is_growing) {
		ivac_sleep(ivac);
		return;
	}

	ivac->ivac_is_growing = 1;
	if (ivac->ivac_table_size >= IVAC_ENTRIES_MAX) {
		panic("Cannot grow ipc space beyond IVAC_ENTRIES_MAX. Some process is leaking vouchers");
		return;
	}

	old_size = ivac->ivac_table_size;
	ivac_unlock(ivac);

	new_size = old_size * 2;

	assert(new_size > old_size);
	assert(new_size < IVAC_ENTRIES_MAX);

	new_table = kalloc(sizeof(ivac_entry) * new_size);
	if (!new_table){
		panic("Failed to grow ivac table to size %d\n", new_size);
		return;
	}

	/* setup the free list for new entries */
	for (i = old_size; i < new_size; i++) {
		ivace_reset_data(&new_table[i], i+1);
	}

	ivac_lock(ivac);
	
	for (i = 0; i < ivac->ivac_table_size; i++){
		ivace_copy_data(&ivac->ivac_table[i], &new_table[i]);
	}

	old_table = ivac->ivac_table;

	ivac->ivac_table = new_table;
	ivac->ivac_table_size = new_size;
	
	/* adding new free entries at head of freelist */
	ivac->ivac_table[new_size - 1].ivace_next = ivac->ivac_freelist;
	ivac->ivac_freelist = old_size;
	ivac->ivac_is_growing = 0;
	ivac_wakeup(ivac);

	if (old_table){
		ivac_unlock(ivac);
		kfree(old_table, old_size * sizeof(ivac_entry));
		ivac_lock(ivac);
	}
}

/*
 * ivace_reference_by_index
 *
 * Take an additional reference on the <key_index, val_index>
 * cached value. It is assumed the caller already holds a
 * reference to the same cached key-value pair.
 */
static void
ivace_reference_by_index(
	iv_index_t 	key_index,
	iv_index_t	val_index)
{
	ipc_voucher_attr_control_t ivac;
	ivac_entry_t ivace;

	if (IV_UNUSED_VALINDEX == val_index)
		return;

	ivgt_lookup(key_index, FALSE, NULL, &ivac);
	assert(IVAC_NULL != ivac);

	ivac_lock(ivac);
	assert(val_index < ivac->ivac_table_size);
	ivace = &ivac->ivac_table[val_index];

	assert(0xdeadc0dedeadc0de != ivace->ivace_value);
	assert(0 < ivace->ivace_refs);
	assert(!ivace->ivace_free);
	ivace->ivace_refs++;
	ivac_unlock(ivac);
}


/*
 * Look up the values for a given <key, index> pair.
 *
 * Consumes a reference on the passed voucher control.
 * Either it is donated to a newly-created value cache
 * or it is released (if we piggy back on an existing
 * value cache entry).
 */
static iv_index_t
ivace_reference_by_value(
	ipc_voucher_attr_control_t	ivac,
	mach_voucher_attr_value_handle_t  	value)
{
	ivac_entry_t ivace = IVACE_NULL;
	iv_index_t hash_index;
	iv_index_t index;

	if (IVAC_NULL == ivac) {
		return IV_UNUSED_VALINDEX;
	}

 	ivac_lock(ivac);
restart:
	hash_index = IV_HASH_VAL(ivac->ivac_init_table_size, value);
	index = ivac->ivac_table[hash_index].ivace_index;
	while (index != IV_HASH_END) {
		assert(index < ivac->ivac_table_size);
		ivace = &ivac->ivac_table[index];
		assert(!ivace->ivace_free);

		if (ivace->ivace_value == value)
			break;

		assert(ivace->ivace_next != index);
		index = ivace->ivace_next;
	}

	/* found it? */
	if (index != IV_HASH_END) { 
		/* only add reference on non-default value */
		if (IV_UNUSED_VALINDEX != index) {
			ivace->ivace_refs++;
			ivace->ivace_made++;
		}

		ivac_unlock(ivac);
		ivac_release(ivac);
		return index;
	}

	/* insert new entry in the table */
	index = ivac->ivac_freelist;
	if (IV_FREELIST_END == index) {
		/* freelist empty */
		ivac_grow_table(ivac);
		goto restart;
	}

	/* take the entry off the freelist */
	ivace = &ivac->ivac_table[index];
	ivac->ivac_freelist = ivace->ivace_next;

	/* initialize the new entry */
	ivace->ivace_value = value;
	ivace->ivace_refs = 1;
	ivace->ivace_made = 1;
	ivace->ivace_free = FALSE;

	/* insert the new entry in the proper hash chain */
	ivace->ivace_next = ivac->ivac_table[hash_index].ivace_index;
	ivac->ivac_table[hash_index].ivace_index = index;
	ivac_unlock(ivac);

	/* donated passed in ivac reference to new entry */

	return index;
}

/*
 * Release a reference on the given <key_index, value_index> pair.
 *
 * Conditions:	called with nothing locked, as it may cause
 *		callouts and/or messaging to the resource 
 *		manager.
 */
static void ivace_release(
	iv_index_t key_index,	  
	iv_index_t value_index)
{
	ipc_voucher_attr_control_t ivac;
	ipc_voucher_attr_manager_t ivam;
	mach_voucher_attr_value_handle_t value;
	mach_voucher_attr_value_reference_t made;
	mach_voucher_attr_key_t key;
	iv_index_t hash_index;
	ivac_entry_t ivace;
	kern_return_t kr;

	/* cant release the default value */
	if (IV_UNUSED_VALINDEX == value_index)
		return;

	ivgt_lookup(key_index, FALSE, &ivam, &ivac);
	assert(IVAC_NULL != ivac);
	assert(IVAM_NULL != ivam);

	ivac_lock(ivac);
	assert(value_index < ivac->ivac_table_size);
	ivace = &ivac->ivac_table[value_index];

	assert(0 < ivace->ivace_refs);

	if (0 < --ivace->ivace_refs) {
		ivac_unlock(ivac);
		return;
	}

	key = iv_index_to_key(key_index);
	assert(MACH_VOUCHER_ATTR_KEY_NONE != key);

	/*
	 * if last return reply is still pending,
	 * let it handle this later return when
	 * the previous reply comes in.
	 */
	if (ivace->ivace_releasing) {
		ivac_unlock(ivac);
		return;
	}

	/* claim releasing */
	ivace->ivace_releasing = TRUE;
	value = ivace->ivace_value;

 redrive:
	assert(value == ivace->ivace_value);
	assert(!ivace->ivace_free);
	made = ivace->ivace_made;
	ivac_unlock(ivac);

	/* callout to manager's release_value */
	kr = (ivam->ivam_release_value)(ivam, key, value, made);

	/* recalculate entry address as table may have changed */
	ivac_lock(ivac);
	ivace = &ivac->ivac_table[value_index];
	assert(value == ivace->ivace_value);

	/*
	 * new made values raced with this return.  If the
	 * manager OK'ed the prior release, we have to start
	 * the made numbering over again (pretend the race
	 * didn't happen). If the entry has zero refs again,
	 * re-drive the release.
	 */
	if (ivace->ivace_made != made) {
		assert(made < ivace->ivace_made);

		if (KERN_SUCCESS == kr)
			ivace->ivace_made -= made;

		if (0 == ivace->ivace_refs)
			goto redrive;

		ivace->ivace_releasing = FALSE;
		ivac_unlock(ivac);
		return;
	} else {
		/*
		 * If the manager returned FAILURE, someone took a 
		 * reference on the value but have not updated the ivace,
		 * release the lock and return since thread who got
		 * the new reference will update the ivace and will have
		 * non-zero reference on the value.
		 */
		if (KERN_SUCCESS != kr) {
			ivace->ivace_releasing = FALSE;
			ivac_unlock(ivac);
			return;
		}
	}

	assert(0 == ivace->ivace_refs);

	/*
	 * going away - remove entry from its hash
	 * If its at the head of the hash bucket list (common), unchain
	 * at the head. Otherwise walk the chain until the next points
	 * at this entry, and remove it from the the list there.
	 */
	hash_index = iv_hash_value(key_index, value);
	if (ivac->ivac_table[hash_index].ivace_index == value_index) {
		ivac->ivac_table[hash_index].ivace_index = ivace->ivace_next;
	} else {
		hash_index = ivac->ivac_table[hash_index].ivace_index;
		assert(IV_HASH_END != hash_index);
		while (ivac->ivac_table[hash_index].ivace_next != value_index) {
			hash_index = ivac->ivac_table[hash_index].ivace_next;
			assert(IV_HASH_END != hash_index);
		}
		ivac->ivac_table[hash_index].ivace_next = ivace->ivace_next;
	}

	/* Put this entry on the freelist */
	ivace->ivace_value = 0xdeadc0dedeadc0de;
	ivace->ivace_releasing = FALSE;
	ivace->ivace_free = TRUE;
	ivace->ivace_made = 0;
	ivace->ivace_next = ivac->ivac_freelist;
	ivac->ivac_freelist = value_index;
	ivac_unlock(ivac);

	/* release the reference this value held on its cache control */
	ivac_release(ivac);

	return;
}


/*
 * ivgt_looup
 *
 * Lookup an entry in the global table from the context of a manager
 * registration.  Adds a reference to the control to keep the results
 * around (if needed).
 *
 * Because of the calling point, we can't be sure the manager is
 * [fully] registered yet.  So, we must hold the global table lock
 * during the lookup to synchronize with in-parallel registrations
 * (and possible table growth).
 */
static void
ivgt_lookup(iv_index_t key_index,
	    boolean_t take_reference,
	    ipc_voucher_attr_manager_t *manager,
	    ipc_voucher_attr_control_t *control)
{
	ipc_voucher_attr_control_t ivac;

	if (key_index < MACH_VOUCHER_ATTR_KEY_NUM_WELL_KNOWN) {
		ivgt_lock();
		if (NULL != manager)
			*manager = iv_global_table[key_index].ivgte_manager;
		ivac = iv_global_table[key_index].ivgte_control;
		if (IVAC_NULL != ivac) {
			assert(key_index == ivac->ivac_key_index);
			if (take_reference) {
				assert(NULL != control);
				ivac_reference(ivac);
			}
		}
		ivgt_unlock();
		if (NULL != control)
			*control = ivac;
	} else {
		if (NULL != manager)
			*manager = IVAM_NULL;
		if (NULL != control)
			*control = IVAC_NULL;
	}
}

/*
 *	Routine: 	ipc_replace_voucher_value
 *	Purpose:
 *		Replace the <voucher, key> value with the results of
 *		running the supplied command through the resource
 *		manager's get-value callback.
 *	Conditions:
 *		Nothing locked (may invoke user-space repeatedly).
 *		Caller holds references on voucher and previous voucher.
 */
static kern_return_t
ipc_replace_voucher_value(
	ipc_voucher_t				voucher,
	mach_voucher_attr_key_t 		key,
	mach_voucher_attr_recipe_command_t	command,
	ipc_voucher_t				prev_voucher,
	mach_voucher_attr_content_t		content,
	mach_voucher_attr_content_size_t        content_size)
{
	mach_voucher_attr_value_handle_t previous_vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
	mach_voucher_attr_value_handle_array_size_t previous_vals_count;
	mach_voucher_attr_value_handle_t new_value;
	ipc_voucher_t new_value_voucher;
	ipc_voucher_attr_manager_t ivam;
	ipc_voucher_attr_control_t ivac;
	iv_index_t prev_val_index;
	iv_index_t save_val_index;
	iv_index_t val_index;
	iv_index_t key_index;
	kern_return_t kr;
	
	/*
	 * Get the manager for this key_index.
	 * Returns a reference on the control.
	 */
	key_index = iv_key_to_index(key);
	ivgt_lookup(key_index, TRUE, &ivam, &ivac);
	if (IVAM_NULL == ivam)
		return KERN_INVALID_ARGUMENT;

	/* save the current value stored in the forming voucher */
	save_val_index = iv_lookup(voucher, key_index);

	/*
	 * Get the previous value(s) for this key creation.
	 * If a previous voucher is specified, they come from there.
	 * Otherwise, they come from the intermediate values already
	 * in the forming voucher.
	 */
	prev_val_index = (IV_NULL != prev_voucher) ?
		         iv_lookup(prev_voucher, key_index) :
		         save_val_index;
	ivace_lookup_values(key_index, prev_val_index,
			    previous_vals, &previous_vals_count);

	/* Call out to resource manager to get new value */
	new_value_voucher = IV_NULL;
	kr = (ivam->ivam_get_value)(
				    ivam, key, command,
				    previous_vals, previous_vals_count,
				    content, content_size,
				    &new_value, &new_value_voucher);
	if (KERN_SUCCESS != kr) {
		ivac_release(ivac);
		return kr;
	}

	/* TODO: value insertion from returned voucher */
	if (IV_NULL != new_value_voucher)
		iv_release(new_value_voucher);

	/*
	 * Find or create a slot in the table associated
	 * with this attribute value.  The ivac reference
	 * is transferred to a new value, or consumed if
	 * we find a matching existing value.
	 */
	val_index = ivace_reference_by_value(ivac, new_value);
	iv_set(voucher, key_index, val_index);

	/*
	 * release saved old value from the newly forming voucher
	 * This is saved until the end to avoid churning the
	 * release logic in cases where the same value is returned
	 * as was there before.
	 */
	ivace_release(key_index, save_val_index);
	
	return KERN_SUCCESS;
}

/*
 *	Routine: 	ipc_directly_replace_voucher_value
 *	Purpose:
 *		Replace the <voucher, key> value with the value-handle
 *		supplied directly by the attribute manager.
 *	Conditions:
 *		Nothing locked.
 *		Caller holds references on voucher.
 *		A made reference to the value-handle is donated by the caller.
 */
static kern_return_t
ipc_directly_replace_voucher_value(
	ipc_voucher_t				voucher,
	mach_voucher_attr_key_t 		key,
	mach_voucher_attr_value_handle_t	new_value)
{
	ipc_voucher_attr_manager_t ivam;
	ipc_voucher_attr_control_t ivac;
	iv_index_t save_val_index;
	iv_index_t val_index;
	iv_index_t key_index;
	
	/*
	 * Get the manager for this key_index.
	 * Returns a reference on the control.
	 */
	key_index = iv_key_to_index(key);
	ivgt_lookup(key_index, TRUE, &ivam, &ivac);
	if (IVAM_NULL == ivam)
		return KERN_INVALID_ARGUMENT;

	/* save the current value stored in the forming voucher */
	save_val_index = iv_lookup(voucher, key_index);

	/*
	 * Find or create a slot in the table associated
	 * with this attribute value.  The ivac reference
	 * is transferred to a new value, or consumed if
	 * we find a matching existing value.
	 */
	val_index = ivace_reference_by_value(ivac, new_value);
	iv_set(voucher, key_index, val_index);

	/*
	 * release saved old value from the newly forming voucher
	 * This is saved until the end to avoid churning the
	 * release logic in cases where the same value is returned
	 * as was there before.
	 */
	ivace_release(key_index, save_val_index);
	
	return KERN_SUCCESS;
}

static kern_return_t
ipc_execute_voucher_recipe_command(
	ipc_voucher_t 				voucher,
	mach_voucher_attr_key_t			key,
	mach_voucher_attr_recipe_command_t	command,
	ipc_voucher_t				prev_iv,
	mach_voucher_attr_content_t		content,
	mach_voucher_attr_content_size_t	content_size,
	boolean_t				key_priv)
{
	iv_index_t prev_val_index;
	iv_index_t val_index;
	kern_return_t kr;

	switch (command) {

	/*
	 * MACH_VOUCHER_ATTR_COPY
	 *	Copy the attribute(s) from the previous voucher to the new
	 *	one.  A wildcard key is an acceptable value - indicating a
	 *	desire to copy all the attribute values from the previous
	 *	voucher.
	 */
	case MACH_VOUCHER_ATTR_COPY:
		
		/* no recipe data on a copy */
		if (0 < content_size)
			return KERN_INVALID_ARGUMENT;

		/* nothing to copy from? - done */
		if (IV_NULL == prev_iv)
			return KERN_SUCCESS;

		if (MACH_VOUCHER_ATTR_KEY_ALL == key) {
			iv_index_t limit, j;

			/* reconcile possible difference in voucher sizes */
			limit = (prev_iv->iv_table_size < voucher->iv_table_size) ?
			        prev_iv->iv_table_size :
				voucher->iv_table_size;

			/* wildcard matching */
			for (j = 0; j < limit; j++) {
				/* release old value being replaced */
				val_index = iv_lookup(voucher, j);
				ivace_release(j, val_index);

				/* replace with reference to prev voucher's value */
				prev_val_index = iv_lookup(prev_iv, j);
				ivace_reference_by_index(j, prev_val_index);
				iv_set(voucher, j, prev_val_index);
			}
		} else {
			iv_index_t key_index;

			/* copy just one key */
			key_index = iv_key_to_index(key);
			if (ivgt_keys_in_use < key_index)
				return KERN_INVALID_ARGUMENT;

			/* release old value being replaced */
			val_index = iv_lookup(voucher, key_index);
			ivace_release(key_index, val_index);

			/* replace with reference to prev voucher's value */
			prev_val_index = iv_lookup(prev_iv, key_index);
			ivace_reference_by_index(key_index, prev_val_index);
			iv_set(voucher, key_index, prev_val_index);
		}
		break;

	/*
	 * MACH_VOUCHER_ATTR_REMOVE
	 *	Remove the attribute(s) from the under construction voucher.
	 *	A wildcard key is an acceptable value - indicating a desire
	 *	to remove all the attribute values set up so far in the voucher.
	 *	If a previous voucher is specified, only remove the value it
	 *	it matches the value in the previous voucher.
	 */
	case MACH_VOUCHER_ATTR_REMOVE:
		/* no recipe data on a remove */
		if (0 < content_size)
			return KERN_INVALID_ARGUMENT;

		if (MACH_VOUCHER_ATTR_KEY_ALL == key) {
			iv_index_t limit, j;

			/* reconcile possible difference in voucher sizes */
			limit = (IV_NULL == prev_iv) ? voucher->iv_table_size :
				((prev_iv->iv_table_size < voucher->iv_table_size) ?
				 prev_iv->iv_table_size : voucher->iv_table_size);

			/* wildcard matching */
			for (j = 0; j < limit; j++) {
				val_index = iv_lookup(voucher, j);

				/* If not matched in previous, skip */
				if (IV_NULL != prev_iv) {
					prev_val_index = iv_lookup(prev_iv, j);
					if (val_index != prev_val_index)
						continue;
				}
				/* release and clear */
				ivace_release(j, val_index);
				iv_set(voucher, j, IV_UNUSED_VALINDEX);
			}
		} else {
			iv_index_t key_index;

			/* copy just one key */
			key_index = iv_key_to_index(key);
			if (ivgt_keys_in_use < key_index)
				return KERN_INVALID_ARGUMENT;

			val_index = iv_lookup(voucher, key_index);

			/* If not matched in previous, skip */
			if (IV_NULL != prev_iv) {
				prev_val_index = iv_lookup(prev_iv, key_index);
				if (val_index != prev_val_index)
					break;
			}

			/* release and clear */
			ivace_release(key_index, val_index);
			iv_set(voucher, key_index, IV_UNUSED_VALINDEX);
		}
		break;

	/*
	 * MACH_VOUCHER_ATTR_SET_VALUE_HANDLE
	 *	Use key-privilege to set a value handle for the attribute directly,
	 *	rather than triggering a callback into the attribute manager to
	 *	interpret a recipe to generate the value handle.
	 */
	case MACH_VOUCHER_ATTR_SET_VALUE_HANDLE:
		if (key_priv) {
			mach_voucher_attr_value_handle_t new_value;

			if (sizeof(mach_voucher_attr_value_handle_t) != content_size)
				return KERN_INVALID_ARGUMENT;
			
			new_value = *(mach_voucher_attr_value_handle_t *)(void *)content;
			kr = ipc_directly_replace_voucher_value(voucher,
								key,
								new_value);
			if (KERN_SUCCESS != kr)
				return kr;
		} else
			return KERN_INVALID_CAPABILITY;
		break;

	/*
	 * MACH_VOUCHER_ATTR_REDEEM
	 *	Redeem the attribute(s) from the previous voucher for a possibly
	 *	new value in the new voucher. A wildcard key is an acceptable value,
	 *	indicating a desire to redeem all the values.
	 */ 	
	case MACH_VOUCHER_ATTR_REDEEM:

		if (MACH_VOUCHER_ATTR_KEY_ALL == key) {
			iv_index_t limit, j;

			/* reconcile possible difference in voucher sizes */
			if (IV_NULL != prev_iv)
				limit = (prev_iv->iv_table_size < voucher->iv_table_size) ?
					prev_iv->iv_table_size :
					voucher->iv_table_size;
			else
				limit = voucher->iv_table_size;

			/* wildcard matching */
			for (j = 0; j < limit; j++) {
				mach_voucher_attr_key_t j_key;

				j_key = iv_index_to_key(j);

				/* skip non-existent managers */
				if (MACH_VOUCHER_ATTR_KEY_NONE == j_key)
					continue;

				/* get the new value from redeem (skip empty previous) */
				kr = ipc_replace_voucher_value(voucher,
							       j_key,
							       command,
							       prev_iv,
							       content,
							       content_size);
				if (KERN_SUCCESS != kr)
					return kr;
			}
			break;
		}
		/* fall thru for single key redemption */

	/*
	 * DEFAULT:
	 *	Replace the current value for the <voucher, key> pair with whatever
	 *	value the resource manager returns for the command and recipe
	 *	combination provided.
	 */
	default:
		kr = ipc_replace_voucher_value(voucher,
					       key,
					       command,
					       prev_iv,
					       content,
					       content_size);
		if (KERN_SUCCESS != kr)
			return kr;

		break;
	}
	return KERN_SUCCESS;
}

/*
 *	Routine: 	iv_checksum
 *	Purpose:
 *		Compute the voucher sum.  This is more position-
 *		relevant than many other checksums - important for
 *		vouchers (arrays of low, oft-reused, indexes).
 */
static inline iv_index_t
iv_checksum(ipc_voucher_t voucher, boolean_t *emptyp)
{
	iv_index_t c = 0;

	boolean_t empty = TRUE;
	if (0 < voucher->iv_table_size) {
		iv_index_t i = voucher->iv_table_size - 1;
	
		do {
			iv_index_t v = voucher->iv_table[i];
			c = c << 3 | c >> (32 - 3);		/* rotate */
			c = ~c;					/* invert */
			if (0 < v) {
				c += v;				/* add in */
				empty = FALSE;
			}
		} while (0 < i--);
	}
	*emptyp = empty;
	return c;
}

/*
 *	Routine: 	iv_dedup
 *	Purpose:
 *		See if the set of values represented by this new voucher
 *		already exist in another voucher.  If so return a reference
 *		to the existing voucher and deallocate the voucher provided.
 *		Otherwise, insert this one in the hash and return it.
 *	Conditions:
 *		A voucher reference is donated on entry.
 *	Returns:
 *		A voucher reference (may be different than on entry).
 */
static ipc_voucher_t
iv_dedup(ipc_voucher_t new_iv)
{
	boolean_t empty;
	iv_index_t sum; 
	iv_index_t hash;
	ipc_voucher_t iv;

	sum = iv_checksum(new_iv, &empty);

	/* If all values are default, that's the empty (NULL) voucher */
	if (empty) {
		iv_dealloc(new_iv, FALSE);
		return IV_NULL;
	}

	hash = IV_HASH_BUCKET(sum);

	ivht_lock();
	queue_iterate(&ivht_bucket[hash], iv, ipc_voucher_t, iv_hash_link) {
		assert(iv->iv_hash == hash);

		/* if not already deallocating and sums match... */
		if (0 < iv->iv_refs && iv->iv_sum == sum) {
			iv_refs_t refs;
			iv_index_t i;

			assert(iv->iv_table_size <= new_iv->iv_table_size);
		
			/* and common entries match... */
			for (i = 0; i < iv->iv_table_size; i++)
				if (iv->iv_table[i] != new_iv->iv_table[i])
					break;
			if (i < iv->iv_table_size)
				continue;

			/* and all extra entries in new one are unused... */
			while (i < new_iv->iv_table_size)
				if (new_iv->iv_table[i++] != IV_UNUSED_VALINDEX)
					break;
			if (i < new_iv->iv_table_size)
				continue;

			/* ... we found a match... */

			/* can we get a ref before it hits 0
			 *
			 * This is thread safe. The reference is just an atomic
			 * add. If the reference count is zero when we adjust it,
			 * no other thread can have a reference to the voucher.
			 * The dealloc code requires holding the ivht_lock, so
			 * the voucher cannot be yanked out from under us.
			 */
			refs = iv_reference(iv);
			if (1 == refs) {
				/* drats! going away. Put back to zero */
				iv->iv_refs = 0;
				continue;
			}

			ivht_unlock();

			/* referenced previous, so deallocate the new one */
			iv_dealloc(new_iv, FALSE);
			return iv;
		}
	}

	/* add the new voucher to the hash, and return it */
	new_iv->iv_sum = sum;
	new_iv->iv_hash = hash;
	queue_enter(&ivht_bucket[hash], new_iv, ipc_voucher_t, iv_hash_link);
	ivht_count++;
	ivht_unlock();

	/*
	 * This code is disabled for KDEBUG_LEVEL_IST and KDEBUG_LEVEL_NONE
	 */
#if (KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD)
	if (kdebug_enable & ~KDEBUG_ENABLE_PPT) {
		uintptr_t voucher_addr = VM_KERNEL_ADDRPERM((uintptr_t)new_iv);
		uintptr_t attr_tracepoints_needed = 0;

		if (ipc_voucher_trace_contents) {
			/*
			 * voucher_contents sizing is a bit more constrained
			 * than might be obvious.
			 *
			 * This is typically a uint8_t typed array. However,
			 * we want to access it as a uintptr_t to efficiently
			 * copyout the data in tracepoints.
			 *
			 * This constrains the size to uintptr_t bytes, and
			 * adds a minimimum alignment requirement equivalent
			 * to a uintptr_t.
			 *
			 * Further constraining the size is the fact that it
			 * is copied out 4 uintptr_t chunks at a time. We do
			 * NOT want to run off the end of the array and copyout
			 * random stack data.
			 *
			 * So the minimum size is 4 * sizeof(uintptr_t), and
			 * the minimum alignment is uintptr_t aligned.
			 */

#define PAYLOAD_PER_TRACEPOINT (4 * sizeof(uintptr_t))
#define PAYLOAD_SIZE 1024

			_Static_assert(PAYLOAD_SIZE % PAYLOAD_PER_TRACEPOINT == 0, "size invariant violated");

			mach_voucher_attr_raw_recipe_array_size_t payload_size = PAYLOAD_SIZE;
			uintptr_t payload[PAYLOAD_SIZE / sizeof(uintptr_t)];
			kern_return_t kr;

			kr = mach_voucher_extract_all_attr_recipes(new_iv, (mach_voucher_attr_raw_recipe_array_t)payload, &payload_size);
			if (KERN_SUCCESS == kr) {
				attr_tracepoints_needed = (payload_size + PAYLOAD_PER_TRACEPOINT - 1) / PAYLOAD_PER_TRACEPOINT;

				/*
				 * To prevent leaking data from the stack, we
				 * need to zero data to the end of a tracepoint
				 * payload.
				 */
				size_t remainder = payload_size % PAYLOAD_PER_TRACEPOINT;
				if (remainder) {
					bzero((uint8_t*)payload + payload_size,
					      PAYLOAD_PER_TRACEPOINT - remainder);
				}
			}

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC,MACH_IPC_VOUCHER_CREATE) | DBG_FUNC_NONE,
					      voucher_addr,
					      new_iv->iv_table_size, ivht_count, payload_size, 0);

			uintptr_t index = 0;
			while (attr_tracepoints_needed--) {
				KERNEL_DEBUG_CONSTANT1(MACHDBG_CODE(DBG_MACH_IPC,MACH_IPC_VOUCHER_CREATE_ATTR_DATA) | DBG_FUNC_NONE,
						       payload[index],
						       payload[index+1],
						       payload[index+2],
						       payload[index+3],
						       voucher_addr);
				index += 4;
			}
		} else {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC,MACH_IPC_VOUCHER_CREATE) | DBG_FUNC_NONE,
					      voucher_addr,
					      new_iv->iv_table_size, ivht_count, 0, 0);
		}
	}
#endif /* KDEBUG_LEVEL >= KDEBUG_LEVEL_STANDARD */

	return new_iv;
}

/*
 *	Routine: 	ipc_create_mach_voucher
 *	Purpose:
 *		Create a new mach voucher and initialize it with the
 *		value(s) created by having the appropriate resource
 *		managers interpret the supplied recipe commands and
 *		data.
 *	Conditions:
 *		Nothing locked (may invoke user-space repeatedly).
 *		Caller holds references on previous vouchers.
 *		Previous vouchers are passed as voucher indexes.
 */
kern_return_t
ipc_create_mach_voucher(
	ipc_voucher_attr_raw_recipe_array_t 		recipes,
	ipc_voucher_attr_raw_recipe_array_size_t	recipe_size,
	ipc_voucher_t 					*new_voucher)
{
	ipc_voucher_attr_recipe_t sub_recipe;
	ipc_voucher_attr_recipe_size_t recipe_used = 0;
	ipc_voucher_t voucher;
	kern_return_t kr = KERN_SUCCESS;

	/* if nothing to do ... */
	if (0 == recipe_size) {
		*new_voucher = IV_NULL;
		return KERN_SUCCESS;
	}

	/* allocate a voucher */
	voucher = iv_alloc(ivgt_keys_in_use);
	if (IV_NULL == voucher)
		return KERN_RESOURCE_SHORTAGE;

	/* iterate over the recipe items */
	while (0 < recipe_size - recipe_used) {

		if (recipe_size - recipe_used < sizeof(*sub_recipe)) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}

		/* find the next recipe */
		sub_recipe = (ipc_voucher_attr_recipe_t)(void *)&recipes[recipe_used];
		if (recipe_size - recipe_used - sizeof(*sub_recipe) < sub_recipe->content_size) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}
		recipe_used += sizeof(*sub_recipe) + sub_recipe->content_size;

		kr = ipc_execute_voucher_recipe_command(voucher,
							sub_recipe->key,
							sub_recipe->command,
							sub_recipe->previous_voucher,
							sub_recipe->content,
							sub_recipe->content_size,
							FALSE);
		if (KERN_SUCCESS != kr)
			break;
	}

	if (KERN_SUCCESS == kr) {
		*new_voucher = iv_dedup(voucher);
	} else {
		iv_dealloc(voucher, FALSE);
		*new_voucher = IV_NULL;
	}
	return kr;
}

/*
 *	Routine: 	ipc_voucher_attr_control_create_mach_voucher
 *	Purpose:
 *		Create a new mach voucher and initialize it with the
 *		value(s) created by having the appropriate resource
 *		managers interpret the supplied recipe commands and
 *		data.
 *
 *		The resource manager control's privilege over its
 *		particular key value is reflected on to the execution
 *		code, allowing internal commands (like setting a
 *		key value handle directly, rather than having to
 *		create a recipe, that will generate a callback just
 *		to get the value.
 *
 *	Conditions:
 *		Nothing locked (may invoke user-space repeatedly).
 *		Caller holds references on previous vouchers.
 *		Previous vouchers are passed as voucher indexes.
 */
kern_return_t
ipc_voucher_attr_control_create_mach_voucher(
	ipc_voucher_attr_control_t			control,
	ipc_voucher_attr_raw_recipe_array_t 		recipes,
	ipc_voucher_attr_raw_recipe_array_size_t	recipe_size,
	ipc_voucher_t 					*new_voucher)
{
	mach_voucher_attr_key_t control_key;
	ipc_voucher_attr_recipe_t sub_recipe;
	ipc_voucher_attr_recipe_size_t recipe_used = 0;
	ipc_voucher_t voucher = IV_NULL;
	kern_return_t kr = KERN_SUCCESS;

	if (IPC_VOUCHER_ATTR_CONTROL_NULL == control)
		return KERN_INVALID_CAPABILITY;

	/* if nothing to do ... */
	if (0 == recipe_size) {
		*new_voucher = IV_NULL;
		return KERN_SUCCESS;
	}

	/* allocate new voucher */
	voucher = iv_alloc(ivgt_keys_in_use);
	if (IV_NULL == voucher)
		return KERN_RESOURCE_SHORTAGE;

	control_key = iv_index_to_key(control->ivac_key_index);

	/* iterate over the recipe items */
	while (0 < recipe_size - recipe_used) {

		if (recipe_size - recipe_used < sizeof(*sub_recipe)) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}

		/* find the next recipe */
		sub_recipe = (ipc_voucher_attr_recipe_t)(void *)&recipes[recipe_used];
		if (recipe_size - recipe_used - sizeof(*sub_recipe) < sub_recipe->content_size) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}
		recipe_used += sizeof(*sub_recipe) + sub_recipe->content_size;

		kr = ipc_execute_voucher_recipe_command(voucher,
							sub_recipe->key,
							sub_recipe->command,
							sub_recipe->previous_voucher,
							sub_recipe->content,
							sub_recipe->content_size,
							(sub_recipe->key == control_key));
		if (KERN_SUCCESS != kr)
			break;
	}

	if (KERN_SUCCESS == kr) {
		*new_voucher = iv_dedup(voucher);
	} else {
		*new_voucher = IV_NULL;
		iv_dealloc(voucher, FALSE);
	}
	return kr;
}

/*
 * 	ipc_register_well_known_mach_voucher_attr_manager
 *
 *	Register the resource manager responsible for a given key value.
 */
kern_return_t
ipc_register_well_known_mach_voucher_attr_manager(
	ipc_voucher_attr_manager_t manager,
	mach_voucher_attr_value_handle_t default_value,
        mach_voucher_attr_key_t key,
	ipc_voucher_attr_control_t *control)
{
	ipc_voucher_attr_control_t new_control;
	iv_index_t key_index;
	iv_index_t hash_index;

	if (IVAM_NULL == manager)
		return KERN_INVALID_ARGUMENT;

	key_index = iv_key_to_index(key);
	if (IV_UNUSED_KEYINDEX == key_index)
		return KERN_INVALID_ARGUMENT;

	new_control = ivac_alloc(key_index);
	if (IVAC_NULL == new_control)
		return KERN_RESOURCE_SHORTAGE;

	/* insert the default value into slot 0 */
	new_control->ivac_table[IV_UNUSED_VALINDEX].ivace_value = default_value;
	new_control->ivac_table[IV_UNUSED_VALINDEX].ivace_refs = IVACE_REFS_MAX;
	new_control->ivac_table[IV_UNUSED_VALINDEX].ivace_made = IVACE_REFS_MAX;
	assert(IV_HASH_END == new_control->ivac_table[IV_UNUSED_VALINDEX].ivace_next);

	ivgt_lock();
	if (IVAM_NULL != iv_global_table[key_index].ivgte_manager) {
		ivgt_unlock();
		ivac_release(new_control);
		return KERN_INVALID_ARGUMENT;
	}

	/* fill in the global table slot for this key */
	iv_global_table[key_index].ivgte_manager = manager;
	iv_global_table[key_index].ivgte_control = new_control;
	iv_global_table[key_index].ivgte_key = key;

	/* insert the default value into the hash (in case it is returned later) */
	hash_index = iv_hash_value(key_index, default_value);
	assert(IV_HASH_END == new_control->ivac_table[hash_index].ivace_index);
	new_control->ivac_table[hash_index].ivace_index = IV_UNUSED_VALINDEX;

	ivgt_unlock();
	
	/* return the reference on the new cache control to the caller */
	*control = new_control;

	return KERN_SUCCESS;
}

/*
 * 	Routine:	mach_voucher_extract_attr_content
 *	Purpose:
 *		Extract the content for a given <voucher, key> pair.
 *
 *		If a value other than the default is present for this
 *		<voucher,key> pair, we need to contact the resource
 *		manager to extract the content/meaning of the value(s)
 *		present.  Otherwise, return success (but no data).
 *
 *	Conditions:
 *		Nothing locked - as it may upcall to user-space.
 *		The caller holds a reference on the voucher.
 */
kern_return_t
mach_voucher_extract_attr_content(
	ipc_voucher_t				voucher,
	mach_voucher_attr_key_t			key,
	mach_voucher_attr_content_t		content,
	mach_voucher_attr_content_size_t	*in_out_size)
{
	mach_voucher_attr_value_handle_t vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
	mach_voucher_attr_value_handle_array_size_t vals_count;
	mach_voucher_attr_recipe_command_t command;
	ipc_voucher_attr_manager_t manager;
	iv_index_t value_index;
	iv_index_t key_index;
	kern_return_t kr;


	if (IV_NULL == voucher)
		return KERN_INVALID_ARGUMENT;

	key_index = iv_key_to_index(key);

	value_index = iv_lookup(voucher, key_index);
	if (IV_UNUSED_VALINDEX == value_index) {
		*in_out_size = 0;
		return KERN_SUCCESS;
	}

	/*
	 * Get the manager for this key_index.  The
	 * existence of a non-default value for this
	 * slot within our voucher will keep the
	 * manager referenced during the callout.
	 */
	ivgt_lookup(key_index, FALSE, &manager, NULL);
	assert(IVAM_NULL != manager);

	/*
	 * Get the value(s) to pass to the manager
	 * for this value_index.
	 */
	ivace_lookup_values(key_index, value_index,
			    vals, &vals_count);
	assert(0 < vals_count);

	/* callout to manager */
	
	kr = (manager->ivam_extract_content)(manager, key, 
					     vals, vals_count,
					     &command,
					     content, in_out_size);
	return kr;
}

/*
 * 	Routine:	mach_voucher_extract_attr_recipe
 *	Purpose:
 *		Extract a recipe for a given <voucher, key> pair.
 *
 *		If a value other than the default is present for this
 *		<voucher,key> pair, we need to contact the resource
 *		manager to extract the content/meaning of the value(s)
 *		present.  Otherwise, return success (but no data).
 *
 *	Conditions:
 *		Nothing locked - as it may upcall to user-space.
 *		The caller holds a reference on the voucher.
 */
kern_return_t
mach_voucher_extract_attr_recipe(
	ipc_voucher_t				voucher,
	mach_voucher_attr_key_t			key,
	mach_voucher_attr_raw_recipe_t		raw_recipe,
	mach_voucher_attr_raw_recipe_size_t	*in_out_size)
{
	mach_voucher_attr_value_handle_t vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
	mach_voucher_attr_value_handle_array_size_t vals_count;
	ipc_voucher_attr_manager_t manager;
	mach_voucher_attr_recipe_t recipe;
	iv_index_t value_index;
	iv_index_t key_index;
	kern_return_t kr;


	if (IV_NULL == voucher)
		return KERN_INVALID_ARGUMENT;

	key_index = iv_key_to_index(key);

	value_index = iv_lookup(voucher, key_index);
	if (IV_UNUSED_VALINDEX == value_index) {
		*in_out_size = 0;
		return KERN_SUCCESS;
	}

	if (*in_out_size < sizeof(*recipe))
		return KERN_NO_SPACE;

	recipe = (mach_voucher_attr_recipe_t)(void *)raw_recipe;
	recipe->key = key;
	recipe->command = MACH_VOUCHER_ATTR_NOOP;
	recipe->previous_voucher = MACH_VOUCHER_NAME_NULL;
	recipe->content_size = *in_out_size - sizeof(*recipe);

	/*
	 * Get the manager for this key_index.  The
	 * existence of a non-default value for this
	 * slot within our voucher will keep the
	 * manager referenced during the callout.
	 */
	ivgt_lookup(key_index, FALSE, &manager, NULL);
	assert(IVAM_NULL != manager);

	/*
	 * Get the value(s) to pass to the manager
	 * for this value_index.
	 */
	ivace_lookup_values(key_index, value_index,
			    vals, &vals_count);
	assert(0 < vals_count);

	/* callout to manager */
	kr = (manager->ivam_extract_content)(manager, key, 
					     vals, vals_count,
					     &recipe->command,
					     recipe->content, &recipe->content_size);
	if (KERN_SUCCESS == kr) {
	  assert(*in_out_size - sizeof(*recipe) >= recipe->content_size);
	  *in_out_size = sizeof(*recipe) + recipe->content_size;
	}

	return kr;
}



/*
 *	Routine: 	mach_voucher_extract_all_attr_recipes
 *	Purpose:
 *		Extract all the (non-default) contents for a given voucher,
 *		building up a recipe that could be provided to a future 
 *		voucher creation call.
 *	Conditions:		
 *		Nothing locked (may invoke user-space).
 *		Caller holds a reference on the supplied voucher.
 */
kern_return_t
mach_voucher_extract_all_attr_recipes(
	ipc_voucher_t					voucher,
	mach_voucher_attr_raw_recipe_array_t		recipes,
	mach_voucher_attr_raw_recipe_array_size_t	*in_out_size)
{
	mach_voucher_attr_recipe_size_t recipe_size = *in_out_size;
	mach_voucher_attr_recipe_size_t recipe_used = 0;
	iv_index_t key_index;

	if (IV_NULL == voucher)
		return KERN_INVALID_ARGUMENT;

	for (key_index = 0; key_index < voucher->iv_table_size; key_index++) {
		mach_voucher_attr_value_handle_t vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
		mach_voucher_attr_value_handle_array_size_t vals_count;
		mach_voucher_attr_content_size_t content_size;
		ipc_voucher_attr_manager_t manager;
		mach_voucher_attr_recipe_t recipe;
		mach_voucher_attr_key_t key;
		iv_index_t value_index;
		kern_return_t kr;

		/* don't output anything for a default value */
		value_index = iv_lookup(voucher, key_index);
		if (IV_UNUSED_VALINDEX == value_index)
			continue;

		if (recipe_size - recipe_used < sizeof(*recipe))
			return KERN_NO_SPACE;

		recipe = (mach_voucher_attr_recipe_t)(void *)&recipes[recipe_used];
		content_size = recipe_size - recipe_used - sizeof(*recipe);
		
		/*
		 * Get the manager for this key_index.  The
		 * existence of a non-default value for this
		 * slot within our voucher will keep the
		 * manager referenced during the callout.
		 */
		ivgt_lookup(key_index, FALSE, &manager, NULL);
		assert(IVAM_NULL != manager);

		/*
		 * Get the value(s) to pass to the manager
		 * for this value_index.
		 */
		ivace_lookup_values(key_index, value_index,
				    vals, &vals_count);
		assert(0 < vals_count);

		key = iv_index_to_key(key_index);

		recipe->key = key;
		recipe->command = MACH_VOUCHER_ATTR_NOOP;
		recipe->content_size = content_size;

		/* callout to manager */
		kr = (manager->ivam_extract_content)(manager, key, 
					     vals, vals_count,
					     &recipe->command,
					     recipe->content, &recipe->content_size);
		if (KERN_SUCCESS != kr)
			return kr;

		assert(recipe->content_size <= content_size);
		recipe_used += sizeof(*recipe) + recipe->content_size;
	}

	*in_out_size = recipe_used;
	return KERN_SUCCESS;
}

/*
 *	Routine: 	mach_voucher_debug_info
 *	Purpose:
 *		Extract all the (non-default) contents for a given mach port name,
 *		building up a recipe that could be provided to a future 
 *		voucher creation call.
 *	Conditions:
 *		Nothing locked (may invoke user-space).
 *		Caller may not hold a reference on the supplied voucher.
 */
#if !(DEVELOPMENT || DEBUG)
kern_return_t
mach_voucher_debug_info(
	ipc_space_t 					__unused space,
	mach_port_name_t				__unused voucher_name,
	mach_voucher_attr_raw_recipe_array_t		__unused recipes,
	mach_voucher_attr_raw_recipe_array_size_t	__unused *in_out_size)
{
	return KERN_NOT_SUPPORTED;
}
#else
kern_return_t
mach_voucher_debug_info(
	ipc_space_t 					space,
	mach_port_name_t				voucher_name,
	mach_voucher_attr_raw_recipe_array_t		recipes,
	mach_voucher_attr_raw_recipe_array_size_t	*in_out_size)
{
	ipc_voucher_t voucher = IPC_VOUCHER_NULL;
	kern_return_t kr;
	ipc_port_t port = MACH_PORT_NULL;

	if (!MACH_PORT_VALID(voucher_name)) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = ipc_port_translate_send(space, voucher_name, &port);
	if (KERN_SUCCESS != kr)
		return KERN_INVALID_ARGUMENT;

	voucher = convert_port_to_voucher(port);
	ip_unlock(port);

	if (voucher) {
		kr = mach_voucher_extract_all_attr_recipes(voucher, recipes, in_out_size);
		ipc_voucher_release(voucher);
		return kr;
	}

	return KERN_FAILURE;
}
#endif

/*
 * 	Routine:	mach_voucher_attr_command
 *	Purpose:
 *		Invoke an attribute-specific command through this voucher.
 *
 *		The voucher layout, membership, etc... is not altered
 *		through the execution of this command.
 *
 *	Conditions:
 *		Nothing locked - as it may upcall to user-space.
 *		The caller holds a reference on the voucher.
 */
kern_return_t
mach_voucher_attr_command(
	ipc_voucher_t						voucher,
	mach_voucher_attr_key_t				key,
	mach_voucher_attr_command_t			command,
	mach_voucher_attr_content_t			in_content,
	mach_voucher_attr_content_size_t	in_content_size,
	mach_voucher_attr_content_t			out_content,
	mach_voucher_attr_content_size_t	*out_content_size)
{
	mach_voucher_attr_value_handle_t vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
	mach_voucher_attr_value_handle_array_size_t vals_count;
	ipc_voucher_attr_manager_t manager;
	ipc_voucher_attr_control_t control;
	iv_index_t value_index;
	iv_index_t key_index;
	kern_return_t kr;


	if (IV_NULL == voucher)
		return KERN_INVALID_ARGUMENT;

	key_index = iv_key_to_index(key);

	/*
	 * Get the manager for this key_index.
	 * Allowing commands against the default value
	 * for an attribute means that we have to hold
	 * reference on the attribute manager control
	 * to keep the manager around during the command
	 * execution.
	 */
	ivgt_lookup(key_index, TRUE, &manager, &control);
	assert(IVAM_NULL != manager);

	/*
	 * Get the values for this <voucher, key> pair
	 * to pass to the attribute manager.  It is still
	 * permissible to execute a command against the
	 * default value (empty value array).
	 */
	value_index = iv_lookup(voucher, key_index);
	ivace_lookup_values(key_index, value_index,
			    vals, &vals_count);

	/* callout to manager */
	kr = (manager->ivam_command)(manager, key, 
				     vals, vals_count,
				     command,
				     in_content, in_content_size,
				     out_content, out_content_size);

	/* release reference on control */
	ivac_release(control);

	return kr;
}

/*
 * 	Routine:	mach_voucher_attr_control_get_values
 *	Purpose:
 *		For a given voucher, get the value handle associated with the
 *		specified attribute manager.
 */
kern_return_t
mach_voucher_attr_control_get_values(
	ipc_voucher_attr_control_t control,
	ipc_voucher_t voucher,
	mach_voucher_attr_value_handle_array_t out_values,
	mach_voucher_attr_value_handle_array_size_t *in_out_size)
{
	iv_index_t key_index, value_index;

	if (IPC_VOUCHER_ATTR_CONTROL_NULL == control)
		return KERN_INVALID_CAPABILITY;

	if (IV_NULL == voucher)
		return KERN_INVALID_ARGUMENT;

	if (0 == *in_out_size)
		return KERN_SUCCESS;

	key_index = control->ivac_key_index;

	assert(0 < voucher->iv_refs);
	value_index = iv_lookup(voucher, key_index);
	ivace_lookup_values(key_index, value_index,
			    out_values, in_out_size);
	return KERN_SUCCESS;
}


/*
 * 	Routine:	mach_voucher_attr_control_create_mach_voucher
 *	Purpose:
 *		Create a new mach voucher and initialize it by processing the
 *		supplied recipe(s).
 *
 *		Coming in on the attribute control port denotes special privileges
 *		over they key associated with the control port.
 *
 *		Coming in from user-space, each recipe item will have a previous
 *		recipe port name that needs to be converted to a voucher.  Because
 *		we can't rely on the port namespace to hold a reference on each
 *		previous voucher port for the duration of processing that command,
 *		we have to convert the name to a voucher reference and release it
 *		after the command processing is done.
 */
kern_return_t
mach_voucher_attr_control_create_mach_voucher(
	ipc_voucher_attr_control_t control,
	mach_voucher_attr_raw_recipe_array_t recipes,
	mach_voucher_attr_raw_recipe_size_t recipe_size,
	ipc_voucher_t *new_voucher)
{
	mach_voucher_attr_key_t control_key;
	mach_voucher_attr_recipe_t sub_recipe;
	mach_voucher_attr_recipe_size_t recipe_used = 0;
	ipc_voucher_t voucher = IV_NULL;
	kern_return_t kr = KERN_SUCCESS;

	if (IPC_VOUCHER_ATTR_CONTROL_NULL == control)
		return KERN_INVALID_CAPABILITY;

	/* if nothing to do ... */
	if (0 == recipe_size) {
		*new_voucher = IV_NULL;
		return KERN_SUCCESS;
	}

	/* allocate new voucher */
	voucher = iv_alloc(ivgt_keys_in_use);
	if (IV_NULL == voucher)
		return KERN_RESOURCE_SHORTAGE;

	control_key = iv_index_to_key(control->ivac_key_index);

	/* iterate over the recipe items */
	while (0 < recipe_size - recipe_used) {
		ipc_voucher_t prev_iv;

		if (recipe_size - recipe_used < sizeof(*sub_recipe)) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}

		/* find the next recipe */
		sub_recipe = (mach_voucher_attr_recipe_t)(void *)&recipes[recipe_used];
		if (recipe_size - recipe_used - sizeof(*sub_recipe) < sub_recipe->content_size) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}
		recipe_used += sizeof(*sub_recipe) + sub_recipe->content_size;

		/* convert voucher port name (current space) into a voucher reference */
		prev_iv = convert_port_name_to_voucher(sub_recipe->previous_voucher);
		if (MACH_PORT_NULL != sub_recipe->previous_voucher && IV_NULL == prev_iv) {
			kr = KERN_INVALID_CAPABILITY;
			break;
		}

		kr = ipc_execute_voucher_recipe_command(voucher,
							sub_recipe->key,
							sub_recipe->command,
							prev_iv,
							sub_recipe->content,
							sub_recipe->content_size,
							(sub_recipe->key == control_key));
		ipc_voucher_release(prev_iv);

		if (KERN_SUCCESS != kr)
			break;
	}

	if (KERN_SUCCESS == kr) {
		*new_voucher = iv_dedup(voucher);
	} else {
		*new_voucher = IV_NULL;
		iv_dealloc(voucher, FALSE);
	}
	return kr;
}

/*
 * 	Routine:	host_create_mach_voucher
 *	Purpose:
 *		Create a new mach voucher and initialize it by processing the
 *		supplied recipe(s).
 *
 *		Comming in from user-space, each recipe item will have a previous
 *		recipe port name that needs to be converted to a voucher.  Because
 *		we can't rely on the port namespace to hold a reference on each
 *		previous voucher port for the duration of processing that command,
 *		we have to convert the name to a voucher reference and release it
 *		after the command processing is done.
 */
kern_return_t
host_create_mach_voucher(
	host_t host,
	mach_voucher_attr_raw_recipe_array_t recipes,
	mach_voucher_attr_raw_recipe_size_t recipe_size,
	ipc_voucher_t *new_voucher)
{
	mach_voucher_attr_recipe_t sub_recipe;
	mach_voucher_attr_recipe_size_t recipe_used = 0;
	ipc_voucher_t voucher = IV_NULL;
	kern_return_t kr = KERN_SUCCESS;

	if (host == HOST_NULL)
		return KERN_INVALID_ARGUMENT;

	/* if nothing to do ... */
	if (0 == recipe_size) {
		*new_voucher = IV_NULL;
		return KERN_SUCCESS;
	}

	/* allocate new voucher */
	voucher = iv_alloc(ivgt_keys_in_use);
	if (IV_NULL == voucher)
		return KERN_RESOURCE_SHORTAGE;

	/* iterate over the recipe items */
	while (0 < recipe_size - recipe_used) {
		ipc_voucher_t prev_iv;

		if (recipe_size - recipe_used < sizeof(*sub_recipe)) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}

		/* find the next recipe */
		sub_recipe = (mach_voucher_attr_recipe_t)(void *)&recipes[recipe_used];
		if (recipe_size - recipe_used - sizeof(*sub_recipe) < sub_recipe->content_size) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}
		recipe_used += sizeof(*sub_recipe) + sub_recipe->content_size;

		/* convert voucher port name (current space) into a voucher reference */
		prev_iv = convert_port_name_to_voucher(sub_recipe->previous_voucher);
		if (MACH_PORT_NULL != sub_recipe->previous_voucher && IV_NULL == prev_iv) {
			kr = KERN_INVALID_CAPABILITY;
			break;
		}

		kr = ipc_execute_voucher_recipe_command(voucher,
							sub_recipe->key,
							sub_recipe->command,
							prev_iv,
							sub_recipe->content,
							sub_recipe->content_size,
							FALSE);
		ipc_voucher_release(prev_iv);

		if (KERN_SUCCESS != kr)
			break;
	}

	if (KERN_SUCCESS == kr) {
		*new_voucher = iv_dedup(voucher);
	} else {
		*new_voucher = IV_NULL;
		iv_dealloc(voucher, FALSE);
	}
	return kr;
}

/*
 * 	Routine:	host_register_well_known_mach_voucher_attr_manager
 *	Purpose:
 *		Register the user-level resource manager responsible for a given
 * 		key value.  
 *	Conditions:
 *		The manager port passed in has to be converted/wrapped
 *		in an ipc_voucher_attr_manager_t structure and then call the
 *		internal variant.  We have a generic ipc voucher manager
 *		type that implements a MIG proxy out to user-space just for
 *		this purpose.
 */
kern_return_t
host_register_well_known_mach_voucher_attr_manager(
        host_t host,
	mach_voucher_attr_manager_t __unused manager,
	mach_voucher_attr_value_handle_t __unused default_value,
        mach_voucher_attr_key_t __unused key,
	ipc_voucher_attr_control_t __unused *control)
{
	if (HOST_NULL == host)
		return KERN_INVALID_HOST;

#if 1
	return KERN_NOT_SUPPORTED;
#else
	/*
	 * Allocate a mig_voucher_attr_manager_t that provides the
	 * MIG proxy functions for the three manager callbacks and
	 * store the port right in there.
	 *
	 * If the user-space manager dies, we'll detect it on our
	 * next upcall, and cleanup the proxy at that point.
	 */
	mig_voucher_attr_manager_t proxy;
	kern_return_t kr;

	proxy = mvam_alloc(manager);

	kr = ipc_register_well_known_mach_voucher_attr_manager(&proxy->mvam_manager,
							       default_value,
							       key,
							       control);
	if (KERN_SUCCESS != kr)
		mvam_release(proxy);

	return kr;
#endif
}

/*
 * 	Routine:	host_register_mach_voucher_attr_manager
 *	Purpose:
 *		Register the user-space resource manager and return a
 *		dynamically allocated key.
 *	Conditions:
 *		Wrap the supplied port with the MIG proxy ipc
 *		voucher resource manager, and then call the internal
 *		variant.
 */
kern_return_t
host_register_mach_voucher_attr_manager(
        host_t host,
	mach_voucher_attr_manager_t __unused manager,
	mach_voucher_attr_value_handle_t __unused default_value,
        mach_voucher_attr_key_t __unused *key,
	ipc_voucher_attr_control_t __unused *control)
{
	if (HOST_NULL == host)
		return KERN_INVALID_HOST;

	return KERN_NOT_SUPPORTED;
}


#if defined(MACH_VOUCHER_ATTR_KEY_USER_DATA) || defined(MACH_VOUCHER_ATTR_KEY_TEST)

/*
 * Build-in a simple User Data Resource Manager
 */
#define USER_DATA_MAX_DATA	(16*1024)

struct user_data_value_element {
	mach_voucher_attr_value_reference_t	e_made;
	mach_voucher_attr_content_size_t	e_size;
	iv_index_t				e_sum;
	iv_index_t				e_hash;
	queue_chain_t				e_hash_link;
	uint8_t					e_data[];
};

typedef struct user_data_value_element *user_data_element_t;

/*
 * User Data Voucher Hash Table
 */
#define USER_DATA_HASH_BUCKETS 127
#define USER_DATA_HASH_BUCKET(x) ((x) % USER_DATA_HASH_BUCKETS)

static queue_head_t user_data_bucket[USER_DATA_HASH_BUCKETS];
static lck_spin_t user_data_lock_data;

#define user_data_lock_init() \
	lck_spin_init(&user_data_lock_data, &ipc_lck_grp, &ipc_lck_attr)
#define user_data_lock_destroy() \
	lck_spin_destroy(&user_data_lock_data, &ipc_lck_grp)
#define	user_data_lock() \
	lck_spin_lock(&user_data_lock_data)
#define	user_data_lock_try() \
	lck_spin_try_lock(&user_data_lock_data)
#define	user_data_unlock() \
	lck_spin_unlock(&user_data_lock_data)

static kern_return_t
user_data_release_value(
	ipc_voucher_attr_manager_t		manager,
	mach_voucher_attr_key_t			key,
	mach_voucher_attr_value_handle_t	value,
	mach_voucher_attr_value_reference_t	sync);

static kern_return_t
user_data_get_value(
	ipc_voucher_attr_manager_t			manager,
	mach_voucher_attr_key_t				key,
	mach_voucher_attr_recipe_command_t		command,
	mach_voucher_attr_value_handle_array_t		prev_values,
	mach_voucher_attr_value_handle_array_size_t	prev_value_count,
	mach_voucher_attr_content_t			content,
	mach_voucher_attr_content_size_t		content_size,
	mach_voucher_attr_value_handle_t		*out_value,
	ipc_voucher_t					*out_value_voucher);

static kern_return_t
user_data_extract_content(
	ipc_voucher_attr_manager_t			manager,
	mach_voucher_attr_key_t				key,
	mach_voucher_attr_value_handle_array_t		values,
	mach_voucher_attr_value_handle_array_size_t	value_count,
	mach_voucher_attr_recipe_command_t		*out_command,
	mach_voucher_attr_content_t			out_content,
	mach_voucher_attr_content_size_t		*in_out_content_size);

static kern_return_t
user_data_command(
	ipc_voucher_attr_manager_t				manager,
	mach_voucher_attr_key_t					key,
	mach_voucher_attr_value_handle_array_t	values,
	mach_msg_type_number_t					value_count,
	mach_voucher_attr_command_t				command,
	mach_voucher_attr_content_t				in_content,
	mach_voucher_attr_content_size_t		in_content_size,
	mach_voucher_attr_content_t				out_content,
	mach_voucher_attr_content_size_t		*out_content_size);

static void
user_data_release(
	ipc_voucher_attr_manager_t		manager);

struct ipc_voucher_attr_manager user_data_manager = {
	.ivam_release_value =	user_data_release_value,
	.ivam_get_value =	user_data_get_value,
	.ivam_extract_content =	user_data_extract_content,
	.ivam_command = 	user_data_command,
	.ivam_release =		user_data_release,
};

ipc_voucher_attr_control_t user_data_control;
ipc_voucher_attr_control_t test_control;

#if defined(MACH_VOUCHER_ATTR_KEY_USER_DATA) && defined(MACH_VOUCHER_ATTR_KEY_TEST)
#define USER_DATA_ASSERT_KEY(key)				\
	assert(MACH_VOUCHER_ATTR_KEY_USER_DATA == (key) || 	\
	       MACH_VOUCHER_ATTR_KEY_TEST == (key));
#elif defined(MACH_VOUCHER_ATTR_KEY_USER_DATA)
#define USER_DATA_ASSERT_KEY(key) assert(MACH_VOUCHER_ATTR_KEY_USER_DATA == (key))
#else
#define USER_DATA_ASSERT_KEY(key) assert(MACH_VOUCHER_ATTR_KEY_TEST == (key))
#endif

/*
 *	Routine: 	user_data_release_value
 *	Purpose:
 *		Release a made reference on a specific value managed by
 *		this voucher attribute manager.
 *	Conditions:
 *		Must remove the element associated with this value from
 *		the hash if this is the last know made reference.
 */
static kern_return_t
user_data_release_value(
	ipc_voucher_attr_manager_t		__assert_only manager,
	mach_voucher_attr_key_t			__assert_only key,
	mach_voucher_attr_value_handle_t	value,
	mach_voucher_attr_value_reference_t	sync)
{
	user_data_element_t elem;
	iv_index_t hash;

	assert (&user_data_manager == manager);
	USER_DATA_ASSERT_KEY(key);

	elem = (user_data_element_t)value;
	hash = elem->e_hash;

	user_data_lock();
	if (sync == elem->e_made) {
		queue_remove(&user_data_bucket[hash], elem, user_data_element_t, e_hash_link);
		user_data_unlock();
		kfree(elem, sizeof(*elem) + elem->e_size);
		return KERN_SUCCESS;
	}
	assert(sync < elem->e_made);
	user_data_unlock();

	return KERN_FAILURE;
}

/*
 *	Routine: 	user_data_checksum
 *	Purpose:
 *		Provide a rudimentary checksum for the data presented
 *		to these voucher attribute managers.
 */
static iv_index_t
user_data_checksum(
	mach_voucher_attr_content_t			content,
	mach_voucher_attr_content_size_t		content_size)
{
	mach_voucher_attr_content_size_t i;
	iv_index_t cksum = 0;

	for(i = 0; i < content_size; i++, content++) {
		cksum = (cksum << 8) ^ (cksum + *(unsigned char *)content);
	}

	return (~cksum);
}

/*
 *	Routine: 	user_data_dedup
 *	Purpose:
 *		See if the content represented by this request already exists
 *		in another user data element.  If so return a made reference
 *		to the existing element.  Otherwise, create a new element and
 *		return that (after inserting it in the hash).
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		A made reference on the user_data_element_t
 */
static user_data_element_t
user_data_dedup(
	mach_voucher_attr_content_t			content,
	mach_voucher_attr_content_size_t		content_size)
{
	iv_index_t sum; 
	iv_index_t hash;
	user_data_element_t elem;
	user_data_element_t alloc = NULL;

	sum = user_data_checksum(content, content_size);
	hash = USER_DATA_HASH_BUCKET(sum);

 retry:
	user_data_lock();
	queue_iterate(&user_data_bucket[hash], elem, user_data_element_t, e_hash_link) {
		assert(elem->e_hash == hash);

		/* if sums match... */
		if (elem->e_sum == sum && elem->e_size == content_size) {
			iv_index_t i;

			/* and all data matches */
			for (i = 0; i < content_size; i++)
				if (elem->e_data[i] != content[i])
					break;
			if (i < content_size)
				continue;

			/* ... we found a match... */

			elem->e_made++;
			user_data_unlock();

			if (NULL != alloc)
				kfree(alloc, sizeof(*alloc) + content_size);

			return elem;
		}
	}

	if (NULL == alloc) {
		user_data_unlock();

		alloc = (user_data_element_t)kalloc(sizeof(*alloc) + content_size);
		alloc->e_made = 1;
		alloc->e_size = content_size;
		alloc->e_sum = sum;
		alloc->e_hash = hash;
		memcpy(alloc->e_data, content, content_size);
		goto retry;
	}

	queue_enter(&user_data_bucket[hash], alloc, user_data_element_t, e_hash_link);
	user_data_unlock();

	return alloc;
}

static kern_return_t
user_data_get_value(
	ipc_voucher_attr_manager_t			__assert_only manager,
	mach_voucher_attr_key_t				__assert_only key,
	mach_voucher_attr_recipe_command_t		command,
	mach_voucher_attr_value_handle_array_t		prev_values,
	mach_voucher_attr_value_handle_array_size_t	prev_value_count,
	mach_voucher_attr_content_t			content,
	mach_voucher_attr_content_size_t		content_size,
	mach_voucher_attr_value_handle_t		*out_value,
	ipc_voucher_t					*out_value_voucher)
{
	user_data_element_t elem;

	assert (&user_data_manager == manager);
	USER_DATA_ASSERT_KEY(key);

	/* never an out voucher */
	*out_value_voucher = IPC_VOUCHER_NULL;

	switch (command) {

	case MACH_VOUCHER_ATTR_REDEEM:

		/* redeem of previous values is the value */
		if (0 < prev_value_count) {
			elem = (user_data_element_t)prev_values[0];
			assert(0 < elem->e_made);
			elem->e_made++;
			*out_value = prev_values[0];
			return KERN_SUCCESS;
		}

		/* redeem of default is default */
		*out_value = 0;
		return KERN_SUCCESS;

	case MACH_VOUCHER_ATTR_USER_DATA_STORE:
		if (USER_DATA_MAX_DATA < content_size)
			return KERN_RESOURCE_SHORTAGE;

		/* empty is the default */
		if (0 == content_size) {
			*out_value = 0;
			return KERN_SUCCESS;
		}

		elem = user_data_dedup(content, content_size);
		*out_value = (mach_voucher_attr_value_handle_t)elem;
		return KERN_SUCCESS;

	default:
		/* every other command is unknown */
		return KERN_INVALID_ARGUMENT;
	}
}

static kern_return_t
user_data_extract_content(
	ipc_voucher_attr_manager_t			__assert_only manager,
	mach_voucher_attr_key_t				__assert_only key,
	mach_voucher_attr_value_handle_array_t		values,
	mach_voucher_attr_value_handle_array_size_t	value_count,
	mach_voucher_attr_recipe_command_t		*out_command,
	mach_voucher_attr_content_t			out_content,
	mach_voucher_attr_content_size_t		*in_out_content_size)
{
	mach_voucher_attr_content_size_t size = 0;
	user_data_element_t elem;
	unsigned int i;

	assert (&user_data_manager == manager);
	USER_DATA_ASSERT_KEY(key);

	/* concatenate the stored data items */
	for (i = 0; i < value_count ; i++) {
		elem = (user_data_element_t)values[i];
		assert(USER_DATA_MAX_DATA >= elem->e_size);

		if (size + elem->e_size > *in_out_content_size)
			return KERN_NO_SPACE;

		memcpy(&out_content[size], elem->e_data, elem->e_size);
		size += elem->e_size;
	}
	*out_command = MACH_VOUCHER_ATTR_BITS_STORE;
	*in_out_content_size = size;
	return KERN_SUCCESS;
}

static kern_return_t
user_data_command(
	ipc_voucher_attr_manager_t				__assert_only manager,
	mach_voucher_attr_key_t					__assert_only key,
	mach_voucher_attr_value_handle_array_t	__unused values,
	mach_msg_type_number_t					__unused value_count,
	mach_voucher_attr_command_t				__unused command,
	mach_voucher_attr_content_t				__unused in_content,
	mach_voucher_attr_content_size_t		__unused in_content_size,
	mach_voucher_attr_content_t				__unused out_content,
	mach_voucher_attr_content_size_t		__unused *out_content_size)
{
	assert (&user_data_manager == manager);
	USER_DATA_ASSERT_KEY(key);
	return KERN_FAILURE;
}

static void
user_data_release(
	ipc_voucher_attr_manager_t		manager)
{
	if (manager != &user_data_manager)
		return;

	panic("Voucher user-data manager released");
}

static int user_data_manager_inited = 0;

void
user_data_attr_manager_init()
{
	kern_return_t kr;

#if defined(MACH_VOUCHER_ATTR_KEY_USER_DATA)	
	if ((user_data_manager_inited & 0x1) != 0x1) {
		kr = ipc_register_well_known_mach_voucher_attr_manager(&user_data_manager,
						(mach_voucher_attr_value_handle_t)0,
						MACH_VOUCHER_ATTR_KEY_USER_DATA,
						&user_data_control);
		if (KERN_SUCCESS != kr)
			printf("Voucher user-data manager register(USER-DATA) returned %d", kr);
		else
			user_data_manager_inited |= 0x1;
	}
#endif
#if defined(MACH_VOUCHER_ATTR_KEY_TEST)
	if ((user_data_manager_inited & 0x2) != 0x2) {
		kr = ipc_register_well_known_mach_voucher_attr_manager(&user_data_manager,
						(mach_voucher_attr_value_handle_t)0,
						MACH_VOUCHER_ATTR_KEY_TEST,
						&test_control);
		if (KERN_SUCCESS != kr)
			printf("Voucher user-data manager register(TEST) returned %d", kr);
		else
			user_data_manager_inited |= 0x2;
	}
#endif
#if defined(MACH_VOUCHER_ATTR_KEY_USER_DATA) || defined(MACH_VOUCHER_ATTR_KEY_TEST)
	int i;

	for (i=0; i < USER_DATA_HASH_BUCKETS; i++)
		queue_init(&user_data_bucket[i]);

	user_data_lock_init();
#endif
}

#endif /* MACH_DEBUG */
