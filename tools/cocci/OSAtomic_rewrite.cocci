// To apply, at the top of xnu.git:
// $ spatch --max-width=120 --use-gitgrep --in-place --include-headers --sp-file tools/cocci/OSAtomic_rewrite.cocci -dir .
//
// coccinelle insists on adding a space for (void) casts which can be fixed with:
// $ git grep -l '(void) os_atomic' | xargs -n1 sed -i '' -e 's/(void) os_atomic/(void)os_atomic/'

@@ expression E; @@

(
- OSIncrementAtomic(E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSIncrementAtomic8(E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSIncrementAtomic16(E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSIncrementAtomic32(E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSIncrementAtomic64(E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSIncrementAtomicLong(E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSAddAtomic(1, E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSAddAtomic8(1, E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSAddAtomic16(1, E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSAddAtomic32(1, E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSAddAtomic64(1, E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSAddAtomicLong(1, E)
+ os_atomic_inc_orig(E, relaxed)
|
- OSDecrementAtomic(E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSDecrementAtomic8(E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSDecrementAtomic16(E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSDecrementAtomic32(E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSDecrementAtomic64(E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSDecrementAtomicLong(E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSAddAtomic(-1, E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSAddAtomic8(-1, E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSAddAtomic16(-1, E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSAddAtomic32(-1, E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSAddAtomic64(-1, E)
+ os_atomic_dec_orig(E, relaxed)
|
- OSAddAtomicLong(-1, E)
+ os_atomic_dec_orig(E, relaxed)
)

@@ expression E, F; @@

(
- OSAddAtomic(-F, E)
+ os_atomic_sub_orig(E, F, relaxed)
|
- OSAddAtomic8(-F, E)
+ os_atomic_sub_orig(E, F, relaxed)
|
- OSAddAtomic16(-F, E)
+ os_atomic_sub_orig(E, F, relaxed)
|
- OSAddAtomic32(-F, E)
+ os_atomic_sub_orig(E, F, relaxed)
|
- OSAddAtomic64(-F, E)
+ os_atomic_sub_orig(E, F, relaxed)
|
- OSAddAtomicLong(-F, E)
+ os_atomic_sub_orig(E, F, relaxed)
|
- OSAddAtomic(F, E)
+ os_atomic_add_orig(E, F, relaxed)
|
- OSAddAtomic8(F, E)
+ os_atomic_add_orig(E, F, relaxed)
|
- OSAddAtomic16(F, E)
+ os_atomic_add_orig(E, F, relaxed)
|
- OSAddAtomic32(F, E)
+ os_atomic_add_orig(E, F, relaxed)
|
- OSAddAtomic64(F, E)
+ os_atomic_add_orig(E, F, relaxed)
|
- OSAddAtomicLong(F, E)
+ os_atomic_add_orig(E, F, relaxed)
|
- OSBitOrAtomic(F, E)
+ os_atomic_or_orig(E, F, relaxed)
|
- OSBitOrAtomic8(F, E)
+ os_atomic_or_orig(E, F, relaxed)
|
- OSBitOrAtomic16(F, E)
+ os_atomic_or_orig(E, F, relaxed)
|
- OSBitOrAtomic32(F, E)
+ os_atomic_or_orig(E, F, relaxed)
|
- OSBitOrAtomic64(F, E)
+ os_atomic_or_orig(E, F, relaxed)
|
- OSBitOrAtomicLong(F, E)
+ os_atomic_or_orig(E, F, relaxed)
|
- OSBitXorAtomic(F, E)
+ os_atomic_xor_orig(E, F, relaxed)
|
- OSBitXorAtomic8(F, E)
+ os_atomic_xor_orig(E, F, relaxed)
|
- OSBitXorAtomic16(F, E)
+ os_atomic_xor_orig(E, F, relaxed)
|
- OSBitXorAtomic32(F, E)
+ os_atomic_xor_orig(E, F, relaxed)
|
- OSBitXorAtomic64(F, E)
+ os_atomic_xor_orig(E, F, relaxed)
|
- OSBitXorAtomicLong(F, E)
+ os_atomic_xor_orig(E, F, relaxed)
|
- OSBitAndAtomic(F, E)
+ os_atomic_and_orig(E, F, relaxed)
|
- OSBitAndAtomic8(F, E)
+ os_atomic_and_orig(E, F, relaxed)
|
- OSBitAndAtomic16(F, E)
+ os_atomic_and_orig(E, F, relaxed)
|
- OSBitAndAtomic32(F, E)
+ os_atomic_and_orig(E, F, relaxed)
|
- OSBitAndAtomic64(F, E)
+ os_atomic_and_orig(E, F, relaxed)
|
- OSBitAndAtomicLong(F, E)
+ os_atomic_and_orig(E, F, relaxed)
)

@@ expression E, F, A; @@

(
- OSCompareAndSwap(F, E, A)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- OSCompareAndSwapPtr(F, E, A)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- OSCompareAndSwap8(F, E, A)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- OSCompareAndSwap16(F, E, A)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- OSCompareAndSwap32(F, E, A)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- OSCompareAndSwap64(F, E, A)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- OSCompareAndSwapLong(F, E, A)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
)

// vim:ft=diff:
