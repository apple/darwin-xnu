// To apply, at the top of xnu.git:
// $ spatch --max-width=120 --use-gitgrep --in-place --include-headers --sp-file tools/cocci/os_atomic_normalize.cocci -dir .
//
// coccinelle insists on adding a space for (void) casts which can be fixed with:
// $ git grep -l '(void) os_atomic' | xargs -n1 sed -i '' -e 's/(void) os_atomic/(void)os_atomic/'

@os_atomic@
identifier fn =~ "^os_atomic";
@@

fn

@script:ocaml unorig@
fn << os_atomic.fn;
new_fn;
@@

new_fn := make_ident (Str.global_replace (Str.regexp "_orig") "" fn)

@@
identifier os_atomic.fn;
identifier unorig.new_fn;
expression A, B, C;
@@

-(void)fn
+new_fn
 (...)

@@ expression E, F, m; @@

(
- os_atomic_add(E, 1, m)
+ os_atomic_inc(E, m)
|
- os_atomic_add_orig(E, 1, m)
+ os_atomic_inc_orig(E, m)
|
- os_atomic_sub(E, -1, m)
+ os_atomic_inc(E, m)
|
- os_atomic_sub_orig(E, -1, m)
+ os_atomic_inc_orig(E, m)
|
- os_atomic_add(E, -1, m)
+ os_atomic_dec(E, m)
|
- os_atomic_add_orig(E, -1, m)
+ os_atomic_dec_orig(E, m)
|
- os_atomic_sub(E, 1, m)
+ os_atomic_dec(E, m)
|
- os_atomic_sub_orig(E, 1, m)
+ os_atomic_dec_orig(E, m)
|
- os_atomic_add(E, -(F), m)
+ os_atomic_sub(E, F, m)
|
- os_atomic_add_orig(E, -(F), m)
+ os_atomic_sub_orig(E, F, m)
|
- os_atomic_add(E, -F, m)
+ os_atomic_sub(E, F, m)
|
- os_atomic_add_orig(E, -F, m)
+ os_atomic_sub_orig(E, F, m)
|
- os_atomic_sub(E, -(F), m)
+ os_atomic_add(E, F, m)
|
- os_atomic_sub_orig(E, -(F), m)
+ os_atomic_add_orig(E, F, m)
|
- os_atomic_sub(E, -F, m)
+ os_atomic_add(E, F, m)
|
- os_atomic_sub_orig(E, -F, m)
+ os_atomic_add_orig(E, F, m)
|
- os_atomic_and(E, ~(F), m)
+ os_atomic_andnot(E, F, m)
|
- os_atomic_and_orig(E, ~(F), m)
+ os_atomic_andnot_orig(E, F, m)
|
- os_atomic_and(E, ~F, m)
+ os_atomic_andnot(E, F, m)
|
- os_atomic_and_orig(E, ~F, m)
+ os_atomic_andnot_orig(E, F, m)
)

// vim:ft=diff:
