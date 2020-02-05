// To apply, at the top of xnu.git:
// $ spatch --max-width=120 --use-gitgrep --in-place --include-headers --sp-file tools/cocci/c11_atomic_builtin_rewrite.cocci

@memory_order@
identifier m =~ "(memory_order_(relaxed|consume|acquire|release|acq_rel|seq_cst)(|_smp)|__ATOMIC_(RELAXED|CONSUME|ACQUIRE|RELEASE|ACQ_REL|SEQ_CST))";
@@

m

@script:ocaml os_memory_order@
m << memory_order.m;
new_m;
@@

new_m := make_ident (String.lowercase_ascii (Str.global_replace (Str.regexp "memory_order_\\|__ATOMIC_\\|_smp") "" m))

@fence@
identifier memory_order.m;
identifier os_memory_order.new_m;
@@

- __c11_atomic_thread_fence(m)
+ os_atomic_thread_fence(new_m)

@load@
expression E;
type T;
identifier memory_order.m;
identifier os_memory_order.new_m;
@@

- __c11_atomic_load
+ os_atomic_load
 (
(
-((T)E)
+E
|
-(T)E
+E
|
E
)
 ,
-m
+new_m
 )

@inc@
expression E;
type T;
identifier memory_order.m;
identifier os_memory_order.new_m;
@@

- __c11_atomic_fetch_add
+ os_atomic_inc_orig
 (
(
-((T)E)
+E
|
-(T)E
+E
|
E
)
 ,
-1, m
+new_m
 )

@dec@
expression E;
type T;
identifier memory_order.m;
identifier os_memory_order.new_m;
@@

- __c11_atomic_fetch_sub
+ os_atomic_dec_orig
 (
(
-((T)E)
+E
|
-(T)E
+E
|
E
)
 ,
-1, m
+new_m
 )

@single_arg@
expression E, F;
type T;
identifier memory_order.m;
identifier os_memory_order.new_m;
@@

(
- __c11_atomic_store
+ os_atomic_store
|
- __c11_atomic_fetch_add
+ os_atomic_add_orig
|
- __c11_atomic_fetch_sub
+ os_atomic_sub_orig
|
- __c11_atomic_fetch_and
+ os_atomic_and_orig
|
- __c11_atomic_fetch_or
+ os_atomic_or_orig
|
- __c11_atomic_fetch_xor
+ os_atomic_xor_orig
)
 (
(
-((T)E)
+E
|
-(T)E
+E
|
E
)
 , F,
-m
+new_m
 )

@cmpxcgh@
expression E, F, G;
type T;
identifier memory_order.m;
identifier os_memory_order.new_m;
@@

- __c11_atomic_compare_exchange_strong
+ os_atomic_cmpxchgv
 (
(
-((T)E)
+E
|
-(T)E
+E
|
E
)
 ,
- &F, G, m, memory_order_relaxed
+ F, G, &F, new_m
 )

// vim:ft=diff:
