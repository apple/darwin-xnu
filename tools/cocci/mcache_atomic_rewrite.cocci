// To apply, at the top of xnu.git:
// $ spatch --max-width=120 --use-gitgrep --in-place --include-headers --sp-file tools/cocci/mcache_atomic_rewrite.cocci -dir .
//
// coccinelle insists on adding a space for (void) casts which can be fixed with:
// $ git grep -l '(void) os_atomic' | xargs -n1 sed -i '' -e 's/(void) os_atomic/(void)os_atomic/'

@@ expression E, F, A; @@

(
- atomic_add_16_ov(E, 1)
+ os_atomic_inc_orig(E, relaxed)
|
- atomic_add_16(E, 1)
+ os_atomic_inc(E, relaxed)
|
- atomic_add_32_ov(E, 1)
+ os_atomic_inc_orig(E, relaxed)
|
- atomic_add_32(E, 1)
+ os_atomic_inc(E, relaxed)
|
- atomic_add_64_ov(E, 1)
+ os_atomic_inc_orig(E, relaxed)
|
- atomic_add_64(E, 1)
+ os_atomic_inc(E, relaxed)
|
- atomic_add_16_ov(E, -1)
+ os_atomic_dec_orig(E, relaxed)
|
- atomic_add_16(E, -1)
+ os_atomic_dec(E, relaxed)
|
- atomic_add_32_ov(E, -1)
+ os_atomic_dec_orig(E, relaxed)
|
- atomic_add_32(E, -1)
+ os_atomic_dec(E, relaxed)
|
- atomic_add_64_ov(E, -1)
+ os_atomic_dec_orig(E, relaxed)
|
- atomic_add_64(E, -1)
+ os_atomic_dec(E, relaxed)
|
- atomic_add_16_ov(E, F)
+ os_atomic_add_orig(E, F, relaxed)
|
- atomic_add_16(E, F)
+ os_atomic_add(E, F, relaxed)
|
- atomic_add_32_ov(E, F)
+ os_atomic_add_orig(E, F, relaxed)
|
- atomic_add_32(E, F)
+ os_atomic_add(E, F, relaxed)
|
- atomic_add_64_ov(E, F)
+ os_atomic_add_orig(E, F, relaxed)
|
- atomic_add_64(E, F)
+ os_atomic_add(E, F, relaxed)
|
- atomic_test_set_32(A, E, F)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- atomic_test_set_64(A, E, F)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- atomic_test_set_ptr(A, E, F)
+ os_atomic_cmpxchg(A, E, F, acq_rel)
|
- atomic_set_32(E, F)
+ os_atomic_store(E, F, release)
|
- atomic_set_64(E, F)
+ os_atomic_store(E, F, release)
|
- atomic_set_ptr(E, F)
+ os_atomic_store(E, F, release)
|
- atomic_get_64(E, A)
+ E = os_atomic_load(A, relaxed)
|
- membar_sync()
+ os_atomic_thread_fence(seq_cst)
|
- atomic_or_8_ov(E, F)
+ os_atomic_or_orig(E, F, relaxed)
|
- atomic_or_16_ov(E, F)
+ os_atomic_or_orig(E, F, relaxed)
|
- atomic_or_32_ov(E, F)
+ os_atomic_or_orig(E, F, relaxed)
|
- atomic_or_8(E, F)
+ os_atomic_or(E, F, relaxed)
|
- atomic_or_16(E, F)
+ os_atomic_or(E, F, relaxed)
|
- atomic_or_32(E, F)
+ os_atomic_or(E, F, relaxed)
|
- atomic_and_8_ov(E, F)
+ os_atomic_and_orig(E, F, relaxed)
|
- atomic_and_16_ov(E, F)
+ os_atomic_and_orig(E, F, relaxed)
|
- atomic_and_32_ov(E, F)
+ os_atomic_and_orig(E, F, relaxed)
|
- atomic_and_8(E, F)
+ os_atomic_and(E, F, relaxed)
|
- atomic_and_16(E, F)
+ os_atomic_and(E, F, relaxed)
|
- atomic_and_32(E, F)
+ os_atomic_and(E, F, relaxed)
|
- atomic_bitset_8_ov(E, F)
+ os_atomic_or_orig(E, F, relaxed)
|
- atomic_bitset_16_ov(E, F)
+ os_atomic_or_orig(E, F, relaxed)
|
- atomic_bitset_32_ov(E, F)
+ os_atomic_or_orig(E, F, relaxed)
|
- atomic_bitset_8(E, F)
+ os_atomic_or(E, F, relaxed)
|
- atomic_bitset_16(E, F)
+ os_atomic_or(E, F, relaxed)
|
- atomic_bitset_32(E, F)
+ os_atomic_or(E, F, relaxed)
|
- atomic_bitclear_8_ov(E, F)
+ os_atomic_andnot_orig(E, F, relaxed)
|
- atomic_bitclear_16_ov(E, F)
+ os_atomic_andnot_orig(E, F, relaxed)
|
- atomic_bitclear_32_ov(E, F)
+ os_atomic_andnot_orig(E, F, relaxed)
|
- atomic_bitclear_8(E, F)
+ os_atomic_andnot(E, F, relaxed)
|
- atomic_bitclear_16(E, F)
+ os_atomic_andnot(E, F, relaxed)
|
- atomic_bitclear_32(E, F)
+ os_atomic_andnot(E, F, relaxed)
)
