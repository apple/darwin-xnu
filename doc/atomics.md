XNU use of Atomics and Memory Barriers
======================================

Goal
----

This document discusses the use of atomics and memory barriers in XNU. It is
meant as a guide to best practices, and warns against a variety of possible
pitfalls in the handling of atomics in C.

It is assumed that the reader has a decent understanding of
the [C11 memory model](https://en.cppreference.com/w/c/atomic/memory_order)
as this document builds on it, and explains the liberties XNU takes with said
model.

All the interfaces discussed in this document are available through
the `<machine/atomic.h>` header.

Note: Linux has thorough documentation around memory barriers
(Documentation/memory-barriers.txt), some of which is Linux specific,
but most is not and is a valuable read.


Vocabulary
----------

In the rest of this document we'll refer to the various memory ordering defined
by C11 as relaxed, consume, acquire, release, acq\_rel and seq\_cst.

`os_atomic` also tries to make the distinction between compiler **barriers**
(which limit how much the compiler can reorder code), and memory **fences**.


The dangers and pitfalls of C11's `<stdatomic.h>`
-------------------------------------------------

While the C11 memory model has likely been one of the most important additions
to modern C, in the purest C tradition, it is a sharp tool.

By default, C11 comes with two variants of each atomic "operation":

- an *explicit* variant where memory orderings can be specified,
- a regular variant which is equivalent to the former with the *seq_cst*
  memory ordering.

When an `_Atomic` qualified variable is accessed directly without using
any `atomic_*_explicit()` operation, then the compiler will generate the
matching *seq_cst* atomic operations on your behalf.

The sequentially consistent world is extremely safe from a lot of compiler
and hardware reorderings and optimizations, which is great, but comes with
a huge cost in terms of memory barriers. It is also completely wasted when
building for a non SMP configuration.


It seems very tempting to use `atomic_*_explicit()` functions with explicit
memory orderings, however, the compiler is entitled to perform a number of
optimizations with relaxed atomics, that most developers will not expect.
Indeed, the compiler is perfectly allowed to perform various optimizations it
does with other plain memory accesess such as coalescing, reordering, hoisting
out of loops, ...

For example, when the compiler can know what `doit` is doing (which due to LTO
is almost always the case for XNU), is allowed to transform this code:

```c
    void
    perform_with_progress(int steps, long _Atomic *progress)
    {
        for (int i = 0; i < steps; i++) {
            doit(i);
            atomic_store_explicit(progress, i, memory_order_relaxed);
        }
    }
```

Into this, which obviously defeats the entire purpose of `progress`:

```c
    void
    perform_with_progress(int steps, long _Atomic *progress)
    {
        for (int i = 0; i < steps; i++) {
            doit(i);
        }
        atomic_store_explicit(progress, steps, memory_order_relaxed);
    }
```


How `os_atomic_*` tries to address `<stdatomic.h>` pitfalls
-----------------------------------------------------------

1. the memory locations passed to the various `os_atomic_*`
   functions do not need to be marked `_Atomic` or `volatile`
   (or `_Atomic volatile`), which allow for use of atomic
   operations in code written before C11 was even a thing.

   It is however recommended in new code to use the `_Atomic`
   specifier.

2. `os_atomic_*` cannot be coalesced by the compiler:
   all accesses are performed on the specified locations
   as if their type was `_Atomic volatile` qualified.

3. `os_atomic_*` only comes with the explicit variants:
   orderings must be provided and can express either memory orders
   where the name is the same as in C11 without the `memory_order_` prefix,
   or a compiler barrier ordering `compiler_acquire`, `compiler_release`,
   `compiler_acq_rel`.

4. `os_atomic_*` elides barriers for non SMP configurations
   by default, however, it emits the proper compiler barriers
   that correspond to the requested memory ordering (using
   `atomic_signal_fence()`), even on UP configuration, so that
   the compiler cannot possibly reorder code on UP systems.


Best practices for the use of atomics in XNU
--------------------------------------------

For most generic code, the `os_atomic_*` functions from
`<machine/atomic.h>` are the perferred interfaces.

`__sync_*`, `__c11_*` and `__atomic_*` compiler builtins should not be used.

`<stdatomic.h>` functions may be used if:

- compiler coalescing / reordering is desired (refcounting
  implementations may desire this for example).

- defaulting to relaxed atomics for non SMP platforms doesn't make sense
  (such as device access which may require memory fences even on UP systems).


Qualifying atomic variables with `_Atomic` or even
`_Atomic volatile` is encouraged, however authors must
be aware that a direct access to this variable will
result in quite heavy memory barriers.

The *consume* memory ordering should not be used
(See *dependency* memory order later in this documentation).

**Note**: `<libkern/OSAtomic.h>` provides a bunch of legacy
atomic interfaces, but this header is considered obsolete
and these functions should not be used in new code.


High level overview of `os_atomic_*` interfaces
-----------------------------------------------

### Compiler barriers and memory fences

`os_compiler_barrier(mem_order?)` provides a compiler barrier,
with an optional barrier ordering. It is implemented with C11's
`atomic_signal_fence()`. The barrier ordering argument is optional
and defaults to the `acq_rel` compiler barrier (which prevents the
compiler to reorder code in any direction around this barrier).

`os_atomic_thread_fence(mem_order)` provides a memory barrier
according to the semantics of `atomic_thread_fence()`. It always
implies the equivalent `os_compiler_barrier()` even on UP systems.

### Init, load and store

`os_atomic_init`, `os_atomic_load` and `os_atomic_store` provide
facilities equivalent to `atomic_init`, `atomic_load_explicit`
and `atomic_store_explicit` respectively.

Note that `os_atomic_load` and `os_atomic_store` promise that they will
compile to a plain load or store. `os_atomic_load_wide` and
`os_atomic_store_wide` can be used to have access to atomic loads and store
that involve more costly codegen (such as compare exchange loops).

### Basic RMW (read/modify/write) atomic operations

The following basic atomic RMW operations exist:

- `inc`: atomic increment (equivalent to an atomic add of `1`),
- `dec`: atomic decrement (equivalent to an atomic sub of `1`),
- `add`: atomic add,
- `sub`: atomic sub,
- `or`: atomic bitwise or,
- `xor`: atomic bitwise xor,
- `and`: atomic bitwise and,
- `andnot`: atomic bitwise andnot (equivalent to atomic and of ~value),
- `min`: atomic min,
- `max`: atomic max.

For any such operation, two variants exist:

- `os_atomic_${op}_orig` (for example `os_atomic_add_orig`)
  which returns the value stored at the specified location
  *before* the atomic operation took place
- `os_atomic_${op}` (for example `os_atomic_add`) which
  returns the value stored at the specified location
  *after* the atomic operation took place

This convention is picked for two reasons:

1. `os_atomic_add(p, value, ...)` is essentially equivalent to the C
   in place addition `(*p += value)` which returns the result of the
   operation and not the original value of `*p`.

2. Most subtle atomic algorithms do actually require the original value
   stored at the location, especially for bit manipulations:
   `(os_atomic_or_orig(p, bit, relaxed) & bit)` will atomically perform
   `*p |= bit` but also tell you whether `bit` was set in the original value.

   Making it more explicit that the original value is used is hence
   important for readers and worth the extra five keystrokes.

Typically:

```c
    static int _Atomic i = 0;

    printf("%d\n", os_atomic_inc_orig(&i)); // prints 0
    printf("%d\n", os_atomic_inc(&i)); // prints 2
```

### Atomic swap / compare and swap

`os_atomic_xchg` is a simple wrapper around `atomic_exchange_explicit`.

There are two variants of `os_atomic_cmpxchg` which are wrappers around
`atomic_compare_exchange_strong_explicit`. Both of these variants will
return false/0 if the compare exchange failed, and true/1 if the expected
value was found at the specified location and the new value was stored.

1. `os_atomic_cmpxchg(address, expected, new_value, mem_order)` which
   will atomically store `new_value` at `address` if the current value
   is equal to `expected`.

2. `os_atomic_cmpxchgv(address, expected, new_value, orig_value, mem_order)`
   which has an extra `orig_value` argument which must be a pointer to a local
   variable and will be filled with the current value at `address` whether the
   compare exchange was successful or not. In case of success, the loaded value
   will always be `expected`, however in case of failure it will be filled with
   the current value, which is helpful to redrive compare exchange loops.

Unlike `atomic_compare_exchange_strong_explicit`, a single ordering is
specified, which only takes effect in case of a successful compare exchange.
In C11 speak, `os_atomic_cmpxchg*` always specifies `memory_order_relaxed`
for the failure case ordering, as it is what is used most of the time.

There is no wrapper around `atomic_compare_exchange_weak_explicit`,
as `os_atomic_rmw_loop` offers a much better alternative for CAS-loops.

### `os_atomic_rmw_loop`

This expressive and versatile construct allows for really terse and
way more readable compare exchange loops. It also uses LL/SC constructs more
efficiently than a compare exchange loop would allow.

Instead of a typical CAS-loop in C11:

```c
    int _Atomic *address;
    int old_value, new_value;
    bool success = false;

    old_value = atomic_load_explicit(address, memory_order_relaxed);
    do {
        if (!validate(old_value)) {
            break;
        }
        new_value = compute_new_value(old_value);
        success = atomic_compare_exchange_weak_explicit(address, &old_value,
                new_value, memory_order_acquire, memory_order_relaxed);
    } while (__improbable(!success));
```

`os_atomic_rmw_loop` allows this form:

```c
    int _Atomic *address;
    int old_value, new_value;
    bool success;

    success = os_atomic_rmw_loop(address, old_value, new_value, acquire, {
        if (!validate(old_value)) {
            os_atomic_rmw_loop_give_up(break);
        }
        new_value = compute_new_value(old_value);
    });
```

Unlike the C11 variant, it lets the reader know in program order that this will
be a CAS loop, and exposes the ordering upfront, while for traditional CAS loops
one has to jump to the end of the code to understand what it does.

Any control flow that attempts to exit its scope of the loop needs to be
wrapped with `os_atomic_rmw_loop_give_up` (so that LL/SC architectures can
abort their opened LL/SC transaction).

Because these loops are LL/SC transactions, it is undefined to perform
any store to memory (register operations are fine) within these loops,
as these may cause the store-conditional to always fail.
In particular nesting of `os_atomic_rmw_loop` is invalid.

Use of `continue` within an `os_atomic_rmw_loop` is also invalid, instead an
`os_atomic_rmw_loop_give_up(goto again)` jumping to an `again:` label placed
before the loop should be used in this way:

```c
    int _Atomic *address;
    int old_value, new_value;
    bool success;

again:
    success = os_atomic_rmw_loop(address, old_value, new_value, acquire, {
        if (needs_some_store_that_can_thwart_the_transaction(old_value)) {
            os_atomic_rmw_loop_give_up({
                // Do whatever you need to do/store to central memory
                // that would cause the loop to always fail
                do_my_rmw_loop_breaking_store();

                // And only then redrive.
                goto again;
            });
        }
        if (!validate(old_value)) {
            os_atomic_rmw_loop_give_up(break);
        }
        new_value = compute_new_value(old_value);
    });
```

### the *dependency* memory order

Because the C11 *consume* memory order is broken in various ways,
most compilers, clang included, implement it as an equivalent
for `memory_order_acquire`. However, its concept is useful
for certain algorithms.

As an attempt to provide a replacement for this, `<machine/atomic.h>`
implements an entirely new *dependency* memory ordering.

The purpose of this ordering is to provide a relaxed load followed by an
implicit compiler barrier, that can be used as a root for a chain of hardware
dependencies that would otherwise pair with store-releases done at this address,
very much like the *consume* memory order is intended to provide.

However, unlike the *consume* memory ordering where the compiler had to follow
the dependencies, the *dependency* memory ordering relies on explicit
annotations of when the dependencies are expected:

- loads through a pointer loaded with a *dependency* memory ordering
  will provide a hardware dependency,

- dependencies may be injected into other loads not performed through this
  particular pointer with the `os_atomic_load_with_dependency_on` and
  `os_atomic_inject_dependency` interfaces.

Here is an example of how it is meant to be used:

```c
    struct foo {
        long value;
        long _Atomic flag;
    };

    void
    publish(struct foo *p, long value)
    {
        p->value = value;
        os_atomic_store(&p->flag, 1, release);
    }


    bool
    broken_read(struct foo *p, long *value)
    {
        /*
         * This isn't safe, as there's absolutely no hardware dependency involved.
         * Using an acquire barrier would of course fix it but is quite expensive...
         */
        if (os_atomic_load(&p->flag, relaxed)) {
            *value = p->value;
            return true;
        }
        return false;
    }

    bool
    valid_read(struct foo *p, long *value)
    {
        long flag = os_atomic_load(&p->flag, dependency);
        if (flag) {
            /*
             * Further the chain of dependency to any loads through `p`
             * which properly pair with the release barrier in `publish`.
             */
            *value = os_atomic_load_with_dependency_on(&p->value, flag);
            return true;
        }
        return false;
    }
```

There are 4 interfaces involved with hardware dependencies:

1. `os_atomic_load(..., dependency)` to initiate roots of hardware dependencies,
   that should pair with a store or rmw with release semantics or stronger
   (release, acq\_rel or seq\_cst),

2. `os_atomic_inject_dependency` can be used to inject the dependency provided
   by a *dependency* load, or any other value that has had a dependency
   injected,

3. `os_atomic_load_with_dependency_on` to do an otherwise related relaxed load
   that still prolongs a dependency chain,

4. `os_atomic_make_dependency` to create an opaque token out of a given
   dependency root to inject into multiple loads.


**Note**: this technique is NOT safe when the compiler can reason about the
pointers that you are manipulating, for example if the compiler can know that
the pointer can only take a couple of values and ditch all these manually
crafted dependency chains. Hopefully there will be a future C2Y standard that
provides a similar construct as a language feature instead.
