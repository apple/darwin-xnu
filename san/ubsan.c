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
#include <kern/assert.h>
#include <libkern/libkern.h>
#include "ubsan.h"

static const bool ubsan_print = false;
static const uint32_t line_acquired = 0x80000000UL;
static const char *get_type_check_kind(uint8_t kind);

static void
ubsan_buf_log(struct ubsan_buf *ub, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	int n = vscnprintf(ub->ub_buf + ub->ub_logged, ub->ub_buf_size - ub->ub_logged, fmt, ap);
	va_end(ap);

	ub->ub_logged += n;
	assert(ub->ub_logged <= ub->ub_buf_size);
}

static void
ubsan_buf_log_loc(struct ubsan_buf *ub, const char *desc, struct san_src_loc *loc)
{
	ubsan_buf_log(ub, "%s:{ file:\"%s\", line:%d, column:%d }",
	    desc,
	    loc->filename,
	    loc->line & ~line_acquired,
	    loc->col);
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

static void
format_overflow(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct san_type_desc *ty = v->overflow->ty;
	ubsan_buf_log(ub,
	    "problem:\"%s overflow\", op:\"%s\", ty:\"%s\", width:%d, lhs:0x%llx, rhs:0x%llx",
	    ty->issigned ? "signed" : "unsigned",
	    overflow_str[v->ubsan_type],
	    ty->name,
	    1 << ty->width,
	        v->lhs,
	        v->rhs
	    );
}

static void
format_shift(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct san_type_desc *l = v->shift->lhs_t;
	struct san_type_desc *r = v->shift->rhs_t;

	ubsan_buf_log(ub, "problem:\"bad shift\", ");
	ubsan_buf_log(ub, "lhs:0x%llx, lty:\"%s\", lsigned:%d, lwidth:%d, ", v->lhs, l->name, l->issigned, 1 << l->width);
	ubsan_buf_log(ub, "rhs:0x%llx, rty:\"%s\", rsigned:%d, rwidth:%d", v->rhs, r->name, r->issigned, 1 << r->width);
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

static void
format_type_mismatch(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	size_t alignment = 1 << v->align->align;
	void *ptr = (void*)v->lhs;
	const char *kind = get_type_check_kind(v->align->kind);

	if (NULL == ptr) {
		//null pointer use
		ubsan_buf_log(ub, "problem:\"%s NULL pointer\", ty:\"%s\"", kind, v->align->ty->name);
	} else if (alignment && ((uintptr_t)ptr & (alignment - 1))) {
		//misaligned pointer use
		ubsan_buf_log(ub, "problem:\"%s mis-aligned\", address:%p, ty:\"%s\", ",
		    kind, (void*)v->lhs, v->align->ty->name);
		ubsan_buf_log(ub, "required_alignment:%d", 1 << v->align->align);
	} else {
		//insufficient object size
		ubsan_buf_log(ub, "problem:\"%s insufficient object size\", ty:\"%s\", address:%p",
		    kind, v->align->ty->name, ptr);
	}
}

static void
format_oob(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct san_type_desc *aty = v->oob->array_ty;
	struct san_type_desc *ity = v->oob->index_ty;
	uintptr_t idx = v->lhs;

	ubsan_buf_log(ub, "problem:\"OOB array access\", ");
	ubsan_buf_log(ub, "idx:%ld, ", idx);
	ubsan_buf_log(ub, "aty:\"%s\", asigned:%d, awidth:%d, ", aty->name, aty->issigned, 1 << aty->width);
	ubsan_buf_log(ub, "ity:\"%s\", isigned:%d, iwidth:%d", ity->name, ity->issigned, 1 << ity->width);
}

static void
format_nullability_arg(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct ubsan_nullability_arg_desc *data = v->nonnull_arg;

	const int arg_index = data->arg_index;
	const char *attr_type = v->lhs ? "nonnull attribute" : "_Nonnull annotation";

	ubsan_buf_log(ub, "problem:\"null in argument %d declared with %s\", ", arg_index, attr_type);
	ubsan_buf_log_loc(ub, "declared", &data->attr_loc);
}

static void
format_nonnull_return(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct san_src_loc *declaration = (struct san_src_loc *)v->rhs;
	const char *return_type = v->lhs ? "returns_nonnull attribute" : "_Nonnull return type annotation";

	ubsan_buf_log(ub, "problem:\"null returned from function declared with %s\", ", return_type);
	ubsan_buf_log_loc(ub, "declared", declaration);
}

static void
format_load_invalid_value(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	ubsan_buf_log(ub, "problem:\"invalid value load\", type:\"%s\", value:0x%llx",
	    v->invalid->type->name, v->lhs);
}

static void
format_missing_return(struct ubsan_violation *v __unused, struct ubsan_buf *ub)
{
	ubsan_buf_log(ub, "problem:\"no value returned from value-returning function\"");
}

static void
format_float_cast_overflow(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct ubsan_float_desc *data = v->flt;
	/*
	 * Cannot print out offending value (e.g. using %A, %f and so on) as kernel logging
	 * does not support float types (yet).
	 */
	ubsan_buf_log(ub, "problem:\"%s type value outside the range of %s\"",
	    data->type_from->name, data->type_to->name);
}

static const char *
get_implicit_conv_type(unsigned char kind)
{
	static const char * const conv_types[] = {
		"integer truncation",
		"unsigned integer truncation",
		"signed integer truncation",
		"integer sign change",
		"signed integer truncation or sign change"
	};
	static const size_t conv_types_cnt = sizeof(conv_types) / sizeof(conv_types[0]);

	return kind < conv_types_cnt ? conv_types[kind] : "unknown implicit integer conversion";
}

static void
format_implicit_conversion(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct ubsan_implicit_conv_desc *data = v->implicit;
	struct san_type_desc *from = data->type_from;
	struct san_type_desc *to = data->type_to;

	ubsan_buf_log(ub, "problem:\"%s\", ", get_implicit_conv_type(data->kind));
	ubsan_buf_log(ub, "src value:%#llx type:\"%s\", signed:%d, width:%d, ",
	    v->lhs, from->name, from->issigned, 1 << from->width);
	ubsan_buf_log(ub, "dst value:%#llx type:\"%s\", signed:%d, width:%d",
	    v->rhs, to->name, to->issigned, 1 << to->width);
}

static void
format_function_type_mismatch(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct ubsan_func_type_mismatch_desc *data = v->func_mismatch;
	ubsan_buf_log(ub, "problem:\"indirect function call through %p of a wrong type %s\"",
	    (void *)v->lhs, data->type->name);
}

static void
format_vla_bound_not_positive(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	struct ubsan_vla_bound_desc *data = v->vla_bound;
	ubsan_buf_log(ub, "problem:\"VLA %s bound %#llx not positive\"", data->type->name, v->lhs);
}

static void
format_invalid_builtin(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	ubsan_buf_log(ub, "problem:\"passing invalid zero argument to %s\"",
	    v->invalid_builtin->kind == 0 ? "ctz()" : "clz()");
}

void
ubsan_format(struct ubsan_violation *v, struct ubsan_buf *ub)
{
	ubsan_buf_log(ub, "{ ");

	switch (v->ubsan_type) {
	case UBSAN_OVERFLOW_add ... UBSAN_OVERFLOW_negate:
		format_overflow(v, ub);
		break;
	case UBSAN_UNREACHABLE:
		ubsan_buf_log(ub, "problem:\"unreachable\", ");
		break;
	case UBSAN_SHIFT:
		format_shift(v, ub);
		break;
	case UBSAN_TYPE_MISMATCH:
		format_type_mismatch(v, ub);
		break;
	case UBSAN_POINTER_OVERFLOW:
		ubsan_buf_log(ub, "problem:\"pointer overflow\", before:0x%llx, after:0x%llx", v->lhs, v->rhs);
		break;
	case UBSAN_OOB:
		format_oob(v, ub);
		break;
	case UBSAN_NULLABILITY_ARG:
		format_nullability_arg(v, ub);
		break;
	case UBSAN_NULLABILITY_RETURN:
		format_nonnull_return(v, ub);
		break;
	case UBSAN_MISSING_RETURN:
		format_missing_return(v, ub);
		break;
	case UBSAN_FLOAT_CAST_OVERFLOW:
		format_float_cast_overflow(v, ub);
		break;
	case UBSAN_IMPLICIT_CONVERSION:
		format_implicit_conversion(v, ub);
		break;
	case UBSAN_FUNCTION_TYPE_MISMATCH:
		format_function_type_mismatch(v, ub);
		break;
	case UBSAN_VLA_BOUND_NOT_POSITIVE:
		format_vla_bound_not_positive(v, ub);
		break;
	case UBSAN_INVALID_BUILTIN:
		format_invalid_builtin(v, ub);
		break;
	case UBSAN_LOAD_INVALID_VALUE:
		format_load_invalid_value(v, ub);
		break;
	default:
		panic("unknown violation");
	}

	ubsan_buf_log_loc(ub, ", found", v->loc);
	ubsan_buf_log(ub, " },\n");
}

enum UBFatality { Fatal, FleshWound };

static void
ubsan_handle(struct ubsan_violation *v, enum UBFatality fatality)
{
	if (!ubsan_loc_acquire(v->loc)) {
		/* violation site already reported */
		return;
	}

	ubsan_log_append(v);

	if (ubsan_print || (fatality == Fatal)) {
		static char buf[256] = { 0 };
		struct ubsan_buf ubsan_buf = {
			.ub_logged = 0,
			.ub_buf_size = sizeof(buf),
			.ub_buf = buf
		};
		ubsan_format(v, &ubsan_buf);
		printf("UBSan: %s", buf);
	}
}

void
__ubsan_handle_builtin_unreachable(struct ubsan_unreachable_desc *desc)
{
	struct ubsan_violation v = { UBSAN_UNREACHABLE, 0, 0, .unreachable = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_shift_out_of_bounds(struct ubsan_shift_desc *desc, uint64_t lhs, uint64_t rhs)
{
	struct ubsan_violation v = { UBSAN_SHIFT, lhs, rhs, .shift = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_shift_out_of_bounds_abort(struct ubsan_shift_desc *desc, uint64_t lhs, uint64_t rhs)
{
	struct ubsan_violation v = { UBSAN_SHIFT, lhs, rhs, .shift = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

#define DEFINE_OVERFLOW(op) \
	void __ubsan_handle_##op##_overflow(struct ubsan_overflow_desc *desc, uint64_t lhs, uint64_t rhs) { \
	        struct ubsan_violation v = { UBSAN_OVERFLOW_##op, lhs, rhs, .overflow = desc, &desc->loc }; \
	        ubsan_handle(&v, FleshWound); \
	} \
	void __ubsan_handle_##op##_overflow_abort(struct ubsan_overflow_desc *desc, uint64_t lhs, uint64_t rhs) { \
	        struct ubsan_violation v = { UBSAN_OVERFLOW_##op, lhs, rhs, .overflow = desc, &desc->loc }; \
	        ubsan_handle(&v, Fatal); \
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
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_type_mismatch_v1_abort(struct ubsan_align_desc *desc, uint64_t val)
{
	struct ubsan_violation v = { UBSAN_TYPE_MISMATCH, val, 0, .align = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_pointer_overflow(struct ubsan_ptroverflow_desc *desc, uint64_t before, uint64_t after)
{
	struct ubsan_violation v = { UBSAN_POINTER_OVERFLOW, before, after, .ptroverflow = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_pointer_overflow_abort(struct ubsan_ptroverflow_desc *desc, uint64_t before, uint64_t after)
{
	struct ubsan_violation v = { UBSAN_POINTER_OVERFLOW, before, after, .ptroverflow = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_out_of_bounds(struct ubsan_oob_desc *desc, uint64_t idx)
{
	struct ubsan_violation v = { UBSAN_OOB, idx, 0, .oob = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_out_of_bounds_abort(struct ubsan_oob_desc *desc, uint64_t idx)
{
	struct ubsan_violation v = { UBSAN_OOB, idx, 0, .oob = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nullability_arg(struct ubsan_nullability_arg_desc *desc)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_ARG, 0, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nullability_arg_abort(struct ubsan_nullability_arg_desc *desc)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_ARG, 0, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nonnull_arg(struct ubsan_nullability_arg_desc *desc)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_ARG, 1, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nonnull_arg_abort(struct ubsan_nullability_arg_desc *desc)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_ARG, 1, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nullability_return_v1(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_RETURN, 0, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nullability_return_v1_abort(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_RETURN, 0, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nonnull_return_v1(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_RETURN, 1, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nonnull_return_v1_abort(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	struct ubsan_violation v = { UBSAN_NULLABILITY_RETURN, 1, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_missing_return(struct ubsan_missing_ret_desc *desc)
{
	struct ubsan_violation v = { UBSAN_MISSING_RETURN, 0, 0, .missing_ret = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_missing_return_abort(struct ubsan_missing_ret_desc *desc)
{
	struct ubsan_violation v = { UBSAN_MISSING_RETURN, 0, 0, .missing_ret = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_float_cast_overflow(struct ubsan_float_desc *desc, uint64_t value)
{
	struct ubsan_violation v = { UBSAN_FLOAT_CAST_OVERFLOW, value, 0, .flt = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_float_cast_overflow_abort(struct ubsan_float_desc *desc, uint64_t value)
{
	struct ubsan_violation v = { UBSAN_FLOAT_CAST_OVERFLOW, value, 0, .flt = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_implicit_conversion(struct ubsan_implicit_conv_desc *desc, uint64_t from, uint64_t to)
{
	struct ubsan_violation v = { UBSAN_IMPLICIT_CONVERSION, from, to, .implicit = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_implicit_conversion_abort(struct ubsan_implicit_conv_desc *desc, uint64_t from, uint64_t to)
{
	struct ubsan_violation v = { UBSAN_IMPLICIT_CONVERSION, from, to, .implicit = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_function_type_mismatch(struct ubsan_func_type_mismatch_desc *desc, uint64_t func)
{
	struct ubsan_violation v = { UBSAN_FUNCTION_TYPE_MISMATCH, func, 0, .func_mismatch = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_function_type_mismatch_abort(struct ubsan_func_type_mismatch_desc *desc, uint64_t func)
{
	struct ubsan_violation v = { UBSAN_FUNCTION_TYPE_MISMATCH, func, 0, .func_mismatch = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_vla_bound_not_positive(struct ubsan_vla_bound_desc *desc, uint64_t length)
{
	struct ubsan_violation v = { UBSAN_VLA_BOUND_NOT_POSITIVE, length, 0, .vla_bound = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_vla_bound_not_positive_abort(struct ubsan_vla_bound_desc *desc, uint64_t length)
{
	struct ubsan_violation v = { UBSAN_VLA_BOUND_NOT_POSITIVE, length, 0, .vla_bound = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_invalid_builtin(struct ubsan_invalid_builtin *desc)
{
	struct ubsan_violation v = { UBSAN_INVALID_BUILTIN, 0, 0, .invalid_builtin = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_invalid_builtin_abort(struct ubsan_invalid_builtin *desc)
{
	struct ubsan_violation v = { UBSAN_INVALID_BUILTIN, 0, 0, .invalid_builtin = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_load_invalid_value(struct ubsan_load_invalid_desc *desc, uint64_t invalid_value)
{
	struct ubsan_violation v = { UBSAN_LOAD_INVALID_VALUE, invalid_value, 0, .invalid = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_load_invalid_value_abort(struct ubsan_load_invalid_desc *desc, uint64_t invalid_value)
{
	struct ubsan_violation v = { UBSAN_LOAD_INVALID_VALUE, invalid_value, 0, .invalid = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}
