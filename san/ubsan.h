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

#ifndef _UBSAN_H_
#define _UBSAN_H_

#include <stdint.h>
#include <stdbool.h>

struct san_type_desc {
	uint16_t type; // 0: integer, 1: float
	union {
		struct {
			uint16_t issigned : 1;
			uint16_t width    : 15;
		}; /* int descriptor */
		struct {
			uint16_t float_desc;
		}; /* float descriptor */
	};
	const char name[];
};

struct san_src_loc {
	const char *filename;
	uint32_t line;
	uint32_t col;
};

struct ubsan_overflow_desc {
	struct san_src_loc loc;
	struct san_type_desc *ty;
};

struct ubsan_unreachable_desc {
	struct san_src_loc loc;
};

struct ubsan_shift_desc {
	struct san_src_loc loc;
	struct san_type_desc *lhs_t;
	struct san_type_desc *rhs_t;
};

struct ubsan_align_desc {
	struct san_src_loc loc;
	struct san_type_desc *ty;
	uint8_t align;
	uint8_t kind;
};

struct ubsan_ptroverflow_desc {
	struct san_src_loc loc;
};

struct ubsan_oob_desc {
	struct san_src_loc loc;
	struct san_type_desc *array_ty;
	struct san_type_desc *index_ty;
};

struct ubsan_load_invalid_desc {
	struct san_src_loc loc;
	struct san_type_desc *type;
};

struct ubsan_nullability_arg_desc {
	struct san_src_loc loc;
	struct san_src_loc attr_loc;
	int arg_index;
};

struct ubsan_nullability_ret_desc {
	struct san_src_loc loc;
};

struct ubsan_missing_ret_desc {
	struct san_src_loc loc;
};

struct ubsan_float_desc {
	struct san_src_loc loc;
	struct san_type_desc *type_from;
	struct san_type_desc *type_to;
};

struct ubsan_implicit_conv_desc {
	struct san_src_loc loc;
	struct san_type_desc *type_from;
	struct san_type_desc *type_to;
	unsigned char kind;
};

struct ubsan_func_type_mismatch_desc {
	struct san_src_loc loc;
	struct san_type_desc *type;
};

struct ubsan_vla_bound_desc {
	struct san_src_loc loc;
	struct san_type_desc *type;
};

struct ubsan_invalid_builtin {
	struct san_src_loc loc;
	unsigned char kind;
};

enum {
	UBSAN_OVERFLOW_add = 1,
	UBSAN_OVERFLOW_sub,
	UBSAN_OVERFLOW_mul,
	UBSAN_OVERFLOW_divrem,
	UBSAN_OVERFLOW_negate,
	UBSAN_UNREACHABLE,
	UBSAN_SHIFT,
	UBSAN_ALIGN,
	UBSAN_POINTER_OVERFLOW,
	UBSAN_OOB,
	UBSAN_TYPE_MISMATCH,
	UBSAN_LOAD_INVALID_VALUE,
	UBSAN_NULLABILITY_ARG,
	UBSAN_NULLABILITY_RETURN,
	UBSAN_MISSING_RETURN,
	UBSAN_FLOAT_CAST_OVERFLOW,
	UBSAN_IMPLICIT_CONVERSION,
	UBSAN_FUNCTION_TYPE_MISMATCH,
	UBSAN_VLA_BOUND_NOT_POSITIVE,
	UBSAN_INVALID_BUILTIN,
	UBSAN_VIOLATION_MAX
};

struct ubsan_violation {
	uint8_t ubsan_type;
	uint64_t lhs;
	uint64_t rhs;
	union {
		struct ubsan_overflow_desc *overflow;
		struct ubsan_unreachable_desc *unreachable;
		struct ubsan_shift_desc *shift;
		struct ubsan_align_desc *align;
		struct ubsan_ptroverflow_desc *ptroverflow;
		struct ubsan_oob_desc *oob;
		struct ubsan_load_invalid_desc *invalid;
		struct ubsan_nullability_arg_desc *nonnull_arg;
		struct ubsan_nullability_ret_desc *nonnull_ret;
		struct ubsan_missing_ret_desc *missing_ret;
		struct ubsan_float_desc *flt;
		struct ubsan_implicit_conv_desc *implicit;
		struct ubsan_func_type_mismatch_desc *func_mismatch;
		struct ubsan_vla_bound_desc *vla_bound;
		struct ubsan_invalid_builtin *invalid_builtin;
		const char *func;
	};
	struct san_src_loc *loc;
};

struct ubsan_buf {
	size_t  ub_logged;
	size_t  ub_buf_size;
	char    *ub_buf;
};

void ubsan_log_append(struct ubsan_violation *);
void ubsan_format(struct ubsan_violation *, struct ubsan_buf *);

/*
 * UBSan ABI
 */

void __ubsan_handle_add_overflow(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_add_overflow_abort(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_builtin_unreachable(struct ubsan_unreachable_desc *);
void __ubsan_handle_divrem_overflow(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_divrem_overflow_abort(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_float_cast_overflow(struct ubsan_float_desc *, uint64_t);
void __ubsan_handle_float_cast_overflow_abort(struct ubsan_float_desc *, uint64_t);
void __ubsan_handle_function_type_mismatch(struct ubsan_func_type_mismatch_desc*, uint64_t);
void __ubsan_handle_function_type_mismatch_abort(struct ubsan_func_type_mismatch_desc *, uint64_t);
void __ubsan_handle_implicit_conversion(struct ubsan_implicit_conv_desc *, uint64_t, uint64_t);
void __ubsan_handle_implicit_conversion_abort(struct ubsan_implicit_conv_desc *, uint64_t, uint64_t);
void __ubsan_handle_invalid_builtin(struct ubsan_invalid_builtin *);
void __ubsan_handle_invalid_builtin_abort(struct ubsan_invalid_builtin *);
void __ubsan_handle_load_invalid_value(struct ubsan_load_invalid_desc *, uint64_t);
void __ubsan_handle_load_invalid_value_abort(struct ubsan_load_invalid_desc *, uint64_t);
void __ubsan_handle_missing_return(struct ubsan_missing_ret_desc *);
void __ubsan_handle_missing_return_abort(struct ubsan_missing_ret_desc *);
void __ubsan_handle_mul_overflow(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_mul_overflow_abort(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_negate_overflow(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_negate_overflow_abort(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_nonnull_arg(struct ubsan_nullability_arg_desc *);
void __ubsan_handle_nonnull_arg_abort(struct ubsan_nullability_arg_desc *);
void __ubsan_handle_nonnull_return_v1(struct ubsan_nullability_ret_desc *, uint64_t);
void __ubsan_handle_nonnull_return_v1_abort(struct ubsan_nullability_ret_desc *, uint64_t);
void __ubsan_handle_nullability_arg(struct ubsan_nullability_arg_desc *);
void __ubsan_handle_nullability_arg_abort(struct ubsan_nullability_arg_desc *);
void __ubsan_handle_nullability_return_v1(struct ubsan_nullability_ret_desc *, uint64_t);
void __ubsan_handle_nullability_return_v1_abort(struct ubsan_nullability_ret_desc *, uint64_t);
void __ubsan_handle_out_of_bounds(struct ubsan_oob_desc *, uint64_t idx);
void __ubsan_handle_out_of_bounds_abort(struct ubsan_oob_desc *, uint64_t idx);
void __ubsan_handle_pointer_overflow(struct ubsan_ptroverflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_pointer_overflow_abort(struct ubsan_ptroverflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_shift_out_of_bounds(struct ubsan_shift_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_shift_out_of_bounds_abort(struct ubsan_shift_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_sub_overflow(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_sub_overflow_abort(struct ubsan_overflow_desc *, uint64_t lhs, uint64_t rhs);
void __ubsan_handle_type_mismatch_v1(struct ubsan_align_desc *, uint64_t val);
void __ubsan_handle_type_mismatch_v1_abort(struct ubsan_align_desc *, uint64_t val);
void __ubsan_handle_vla_bound_not_positive(struct ubsan_vla_bound_desc *, uint64_t);
void __ubsan_handle_vla_bound_not_positive_abort(struct ubsan_vla_bound_desc *, uint64_t);

#endif /* _UBSAN_H_ */
