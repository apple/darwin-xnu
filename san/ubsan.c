/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <stdatomic.h>
#include <kern/debug.h>
#include <libkern/libkern.h>
#include "ubsan.h"

static const bool ubsan_print = false;
static const uint32_t line_acquired = 0x80000000UL;
static const char *get_type_check_kind(uint8_t kind);
static size_t
format_loc(struct san_src_loc *loc, char *dst, size_t sz)
{
	return snprintf(dst, sz, "  loc: %s:%d:%d\n",
	           loc->filename,
	           loc->line & ~line_acquired,
	           loc->col
	           );
}

/*
 * return true for the first visit to this loc, false every subsequent time
 */
static bool
ubsan_loc_acquire(struct san_src_loc *loc)
{
	uint32_t line = loc->line;
	if (line & line_acquired) {
		return false;
	}
	uint32_t acq = line | line_acquired;
	return atomic_compare_exchange_strong((_Atomic uint32_t *)&loc->line, &line, acq);
}

static const char *const
overflow_str[] = {
	NULL,
	"add",
	"sub",
	"mul",
	"divrem",
	"negate",
	NULL
};

static size_t
format_overflow(struct ubsan_violation *v, char *buf, size_t sz)
{
	struct san_type_desc *ty = v->overflow->ty;
	return snprintf(buf, sz,
	           "%s overflow, op = %s, ty = %s, width = %d, lhs = 0x%llx, rhs = 0x%llx\n",
	           ty->issigned ? "signed" : "unsigned",
	           overflow_str[v->ubsan_type],
	           ty->name,
	           1 << ty->width,
	           v->lhs,
	           v->rhs
	           );
}

static size_t
format_shift(struct ubsan_violation *v, char *buf, size_t sz)
{
	size_t n = 0;
	struct san_type_desc *l = v->shift->lhs_t;
	struct san_type_desc *r = v->shift->rhs_t;

	n += snprintf(buf + n, sz - n, "bad shift\n");
	n += snprintf(buf + n, sz - n, "  lhs: 0x%llx, ty = %s, signed = %d, width = %d\n", v->lhs, l->name, l->issigned, 1 << l->width);
	n += snprintf(buf + n, sz - n, "  rhs: 0x%llx, ty = %s, signed = %d, width = %d\n", v->rhs, r->name, r->issigned, 1 << r->width);

	return n;
}

static const char * const
type_check_kinds[] = {
	"load of", "store to", "reference binding to", "member access within",
	"member call on", "constructor call on", "downcast of", "downcast of",
	"upcast of", "cast to virtual base of", "_Nonnull binding to"
};

static const char *
get_type_check_kind(uint8_t kind)
{
	return (kind < (sizeof(type_check_kinds) / sizeof(type_check_kinds[0])))
	       ? type_check_kinds[kind]
	       : "some";
}

static size_t
format_type_mismatch(struct ubsan_violation *v, char *buf, size_t sz)
{
	size_t n = 0;
	size_t alignment = 1 << v->align->align;
	void *ptr = (void*)v->lhs;
	const char * kind = get_type_check_kind(v->align->kind);
	if (NULL == ptr) {
		//null pointer use
		n += snprintf(buf + n, sz - n, "%s NULL pointer of type %s\n", kind, v->align->ty->name);
	} else if (alignment && ((uintptr_t)ptr & (alignment - 1))) {
		//misaligned pointer use
		n += snprintf(buf + n, sz - n, "%s mis-aligned address %p for type %s ", kind, (void*)v->lhs, v->align->ty->name);
		n += snprintf(buf + n, sz - n, "which requires %d byte alignment\n", 1 << v->align->align);
	} else {
		//insufficient object size
		n += snprintf(buf + n, sz - n, "%s address %p with insufficient space for an object of type %s\n",
		    kind, ptr, v->align->ty->name);
	}

	return n;
}

static size_t
format_oob(struct ubsan_violation *v, char *buf, size_t sz)
{
	size_t n = 0;
	struct san_type_desc *aty = v->oob->array_ty;
	struct san_type_desc *ity = v->oob->index_ty;
	uintptr_t idx = v->lhs;

	n += snprintf(buf + n, sz - n, "OOB array access\n");
	n += snprintf(buf + n, sz - n, "  idx %ld\n", idx);
	n += snprintf(buf + n, sz - n, "  aty: ty = %s, signed = %d, width = %d\n", aty->name, aty->issigned, 1 << aty->width);
	n += snprintf(buf + n, sz - n, "  ity: ty = %s, signed = %d, width = %d\n", ity->name, ity->issigned, 1 << ity->width);

	return n;
}

size_t
ubsan_format(struct ubsan_violation *v, char *buf, size_t sz)
{
	size_t n = 0;

	switch (v->ubsan_type) {
	case UBSAN_OVERFLOW_add ... UBSAN_OVERFLOW_negate:
		n += format_overflow(v, buf + n, sz - n);
		break;
	case UBSAN_UNREACHABLE:
		n += snprintf(buf + n, sz - n, "unreachable\n");
		break;
	case UBSAN_SHIFT:
		n += format_shift(v, buf + n, sz - n);
		break;
	case UBSAN_TYPE_MISMATCH:
		n += format_type_mismatch(v, buf + n, sz - n);
		break;
	case UBSAN_POINTER_OVERFLOW:
		n += snprintf(buf + n, sz - n, "pointer overflow, before = 0x%llx, after = 0x%llx\n", v->lhs, v->rhs);
		break;
	case UBSAN_OOB:
		n += format_oob(v, buf + n, sz - n);
		break;
	case UBSAN_GENERIC:
		n += snprintf(buf + n, sz - n, "%s\n", v->func);
		break;
	default:
		panic("unknown violation");
	}

	n += format_loc(v->loc, buf + n, sz - n);

	return n;
}

static void
ubsan_handle(struct ubsan_violation *v, bool fatal)
{
	const size_t sz = 256;
	static char buf[sz];
	size_t n = 0;
	buf[0] = '\0';

	if (!ubsan_loc_acquire(v->loc)) {
		/* violation site already reported */
		return;
	}

	ubsan_log_append(v);

	if (ubsan_print || fatal) {
		n += ubsan_format(v, buf + n, sz - n);
	}

	if (ubsan_print) {
		printf("UBSan: %s", buf);
	}

	if (fatal) {
		panic("UBSan: %s", buf);
	}
}

void
__ubsan_handle_builtin_unreachable(struct ubsan_unreachable_desc *desc)
{
	struct ubsan_violation v = { UBSAN_UNREACHABLE, 0, 0, .unreachable = desc, &desc->loc };
	ubsan_handle(&v, true);
}

void
__ubsan_handle_shift_out_of_bounds(struct ubsan_shift_desc *desc, uint64_t lhs, uint64_t rhs)
{
	struct ubsan_violation v = { UBSAN_SHIFT, lhs, rhs, .shift = desc, &desc->loc };
	ubsan_handle(&v, false);
}

void
__ubsan_handle_shift_out_of_bounds_abort(struct ubsan_shift_desc *desc, uint64_t lhs, uint64_t rhs)
{
	struct ubsan_violation v = { UBSAN_SHIFT, lhs, rhs, .shift = desc, &desc->loc };
	ubsan_handle(&v, true);
}

#define DEFINE_OVERFLOW(op) \
	void __ubsan_handle_##op##_overflow(struct ubsan_overflow_desc *desc, uint64_t lhs, uint64_t rhs) { \
	        struct ubsan_violation v = { UBSAN_OVERFLOW_##op, lhs, rhs, .overflow = desc, &desc->loc }; \
	        ubsan_handle(&v, false); \
	} \
	void __ubsan_handle_##op##_overflow_abort(struct ubsan_overflow_desc *desc, uint64_t lhs, uint64_t rhs) { \
	        struct ubsan_violation v = { UBSAN_OVERFLOW_##op, lhs, rhs, .overflow = desc, &desc->loc }; \
	        ubsan_handle(&v, true); \
	}

DEFINE_OVERFLOW(add)
DEFINE_OVERFLOW(sub)
DEFINE_OVERFLOW(mul)
DEFINE_OVERFLOW(divrem)
DEFINE_OVERFLOW(negate)

void
__ubsan_handle_type_mismatch_v1(struct ubsan_align_desc *desc, uint64_t val)
{
	struct ubsan_violation v = { UBSAN_TYPE_MISMATCH, val, 0, .align = desc, &desc->loc };
	ubsan_handle(&v, false);
}

void
__ubsan_handle_type_mismatch_v1_abort(struct ubsan_align_desc *desc, uint64_t val)
{
	struct ubsan_violation v = { UBSAN_TYPE_MISMATCH, val, 0, .align = desc, &desc->loc };
	ubsan_handle(&v, true);
}

void
__ubsan_handle_pointer_overflow(struct ubsan_ptroverflow_desc *desc, uint64_t before, uint64_t after)
{
	struct ubsan_violation v = { UBSAN_POINTER_OVERFLOW, before, after, .ptroverflow = desc, &desc->loc };
	ubsan_handle(&v, false);
}

void
__ubsan_handle_pointer_overflow_abort(struct ubsan_ptroverflow_desc *desc, uint64_t before, uint64_t after)
{
	struct ubsan_violation v = { UBSAN_POINTER_OVERFLOW, before, after, .ptroverflow = desc, &desc->loc };
	ubsan_handle(&v, true);
}

void
__ubsan_handle_out_of_bounds(struct ubsan_oob_desc *desc, uint64_t idx)
{
	struct ubsan_violation v = { UBSAN_OOB, idx, 0, .oob = desc, &desc->loc };
	ubsan_handle(&v, false);
}

void
__ubsan_handle_out_of_bounds_abort(struct ubsan_oob_desc *desc, uint64_t idx)
{
	struct ubsan_violation v = { UBSAN_OOB, idx, 0, .oob = desc, &desc->loc };
	ubsan_handle(&v, true);
}

#define DEFINE_GENERIC(check) \
	void __ubsan_handle_##check (struct san_src_loc* loc) \
	{ \
	        struct ubsan_violation v = { UBSAN_GENERIC, 0, 0, .func = __func__, loc }; \
	        ubsan_handle(&v, false); \
	} \
	void __ubsan_handle_##check##_abort(struct san_src_loc* loc) \
	{ \
	        struct ubsan_violation v = { UBSAN_GENERIC, 0, 0, .func = __func__, loc }; \
	        ubsan_handle(&v, true); \
	}

DEFINE_GENERIC(invalid_builtin)
DEFINE_GENERIC(load_invalid_value)
DEFINE_GENERIC(nonnull_arg)
DEFINE_GENERIC(vla_bound_not_positive)
DEFINE_GENERIC(float_cast_overflow)
DEFINE_GENERIC(function_type_mismatch)
DEFINE_GENERIC(missing_return)
DEFINE_GENERIC(nonnull_return)
DEFINE_GENERIC(nullability_arg)
DEFINE_GENERIC(nullability_return)
DEFINE_GENERIC(implicit_conversion)
