ARMv8.3 Pointer Authentication in xnu
=====================================

Introduction
------------

This document describes xnu's use of the ARMv8.3-PAuth extension. Specifically,
xnu uses ARMv8.3-PAuth to protect against Return-Oriented-Programming (ROP)
and Jump-Oriented-Programming (JOP) attacks, which attempt to gain control flow
over a victim program by overwriting return addresses or function pointers
stored in memory.

It is assumed the reader is already familar with the basic concepts behind
ARMv8.3-PAuth and what its instructions do.  The "ARMv8.3-A Pointer
Authentication" section of Google Project Zero's ["Examining Pointer
Authentication on the iPhone
XS"](https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html)
provides a good introduction to ARMv8.3-PAuth. The reader may find more
comprehensive background material in:

* The "Pointer authentication in AArch64 state" section of the [ARMv8
  ARM](https://developer.arm.com/docs/ddi0487/latest/arm-architecture-reference-manual-armv8-for-armv8-a-architecture-profile)
  describes the new instructions and registers associated with ARMv8.3-PAuth.

* [LLVM's Pointer Authentication
  documentation](https://github.com/apple/llvm-project/blob/apple/master/clang/docs/PointerAuthentication.rst)
  outlines how clang uses ARMv8.3-PAuth instructions to harden key C, C++,
  Swift, and Objective-C language constructs.

### Threat model

Pointer authentication's threat model assumes that an attacker has found a gadget
to read and write arbitrary memory belonging to a victim process, which may
include the kernel. The attacker does *not* have the ability to execute
arbitrary code in that process's context.  Pointer authentication aims to
prevent the attacker from gaining control flow over the victim process by
overwriting sensitive pointers in its address space (e.g., return addresses
stored on the stack).

Following this threat model, xnu takes a two-pronged approach to prevent the
attacker from gaining control flow over the victim process:

1. Both xnu and first-party binaries are built with LLVM's `-arch arm64e` flag,
   which generates pointer-signing and authentication instructions to protect
   addresses stored in memory (including ones pushed to the stack).  This
   process is generally transparent to xnu, with exceptions discussed below.

2. On exception entry, xnu hashes critical register state before it is spilled
   to memory.  On exception return, the reloaded state is validated against this
   hash.

The ["xnu PAC infrastructure"](#xnu-pac-infrastructure) section discusses how
these hardening techniques are implemented in xnu in more detail.


Key generation on Apple CPUs
----------------------------

ARMv8.3-PAuth implementations may use an <span style="font-variant:
small-caps">implementation defined</span> cipher.  Apple CPUs implement an
optional custom cipher with two key-generation changes relevant to xnu.


### Per-boot diversifier

Apple's optional cipher adds a per-boot diversifier.  In effect, even if xnu
initializes the "ARM key" registers (`APIAKey`, `APGAKey`, etc.) with constants,
signing a given value will still produce different signatures from boot to boot.


### Kernel/userspace diversifier

Apple CPUs also contain a second diversifier known as `KERNKey`.  `KERNKey` is
automatically mixed into the final signing key (or not) based on the CPU's
exception level. When xnu needs to sign or authenticate userspace-signed
pointers, it uses the `ml_enable_user_jop_key` and `ml_disable_user_jop_key`
routines to manually enable or disable `KERNKey`. `KERNKey` allows the CPU to
effectively use different signing keys for userspace and kernel, without needing
to explicitly reprogram the generic ARM keys on every kernel entry and exit.


xnu PAC infrastructure
----------------------

For historical reasons, the xnu codebase collectively refers to xnu + iOS's
pointer authentication infrastructure as Pointer Authentication Codes (PAC). The
remainder of this document will follow this terminology for consistency with
xnu.

### arm64e binary "slice"

Binaries with PAC instructions are not fully backwards-compatible with non-PAC
CPUs. Hence LLVM/iOS treat PAC-enabled binaries as a distinct ABI "slice" named
arm64e. xnu enforces this distinction by disabling the PAC keys when returning
to non-arm64e userspace, effectively turning ARMv8.3-PAuth auth and sign
instructions into no-ops (see the ["SCTLR_EL1"](#sctlr-el1) heading below for
more details).

### Kernel pointer signing

xnu is built with `-arch arm64e`, which causes LLVM to automatically sign and
authenticate function pointers and return addresses spilled onto the stack. This
process is largely transparent to software, with some exceptions:

- During early boot, xnu rebases and signs the pointers stored in its own
  `__thread_starts` section (see `rebase_threaded_starts` in
  `osfmk/arm/arm_init.c`).

- As parts of the userspace shared region are paged in, the page-in handler must
  also slide and re-sign any signed pointers stored in it.  The ["Signed
  pointers in shared regions"](#signed-pointers-in-shared-regions) section
  discusses this in further detail.

- Assembly routines must manually sign the return address with `pacibsp` before
  pushing it onto the stack, and use an authenticating `retab` instruction in
  place of `ret`.  xnu provides assembly macros `ARM64_STACK_PROLOG` and
  `ARM64_STACK_EPILOG` which emit the appropriate instructions for both arm64
  and arm64e targets.

  Likewise, branches in assembly to signed C function pointers must use the
  authenticating `blraa` instruction in place of `blr`.

- Signed pointers must be stripped with `ptrauth_strip` before they can be
  compared against compile-time constants like `VM_MIN_KERNEL_ADDRESS`.

### Testing data pointer signing

xnu contains tests for each manually qualified data pointer that should be
updated as new pointers are qualified. The tests allocate a structure
containing a __ptrauth qualified member, and write a pointer to that member.
We can then compare the stored value, which should be signed, with a manually
constructed signature. See `ALLOC_VALIDATE_DATA_PTR`.

Tests are triggered by setting the `kern.run_ptrauth_data_tests` sysctl. The
sysctl is implemented, and BSD structures are tested, in `bsd/tests/ptrauth_data_tests_sysctl.c`.
Mach structures are tested in `osfmk/tests/ptrauth_data_tests.c`.

### Managing PAC register state

xnu generally tries to avoid reprogramming the CPU's PAC-related registers on
kernel entry and exit, since this could add significant overhead to a hot
codepath. Instead, xnu uses the following strategies to manage the PAC register
state.

#### A keys

Userspace processes' A keys (`AP{IA,DA,GA}Key`) are derived from the field
`jop_pid` inside `struct task`.  For implementation reasons, an exact duplicate
of this field is cached in the corresponding `struct machine_thread`.


A keys are randomly generated at shared region initialization time (see ["Signed
pointers in shared regions"](#signed-pointers-in-shared-regions) below) and
copied into `jop_pid` during process activation.  This shared region, and hence
associated A keys, may be shared among arm64e processes under specific
circumstances:

1. "System processes" (i.e., processes launched from first-party signed binaries
   on the iOS system image) generally use a common shared region with a default
   `jop_pid` value, separate from non-system processes.

   If a system process wishes to isolate its A keys even from other system
   processes, it may opt into a custom shared region using an entitlement in
   the form `com.apple.pac.shared_region_id=[...]`.  That is, two processes with
   the entitlement `com.apple.pac.shared_region_id=foo` would share A keys and
   shared regions with each other, but not with other system processes.

2. Other arm64e processes automatically use the same shared region/A keys if
   their respective binaries are signed with the same team-identifier strings.

3. `posix_spawnattr_set_ptrauth_task_port_np()` allows explicit "inheriting" of
   A keys during `posix_spawn()`, using a supplied mach task port.  This API is
   intended to support debugging tools that may need to auth or sign pointers
   using the target process's keys.

#### B keys

Each process is assigned a random set of "B keys" (`AP{IB,DB}Key`) on process
creation.  As a special exception, processes which inherit their parents' memory
address space (e.g., during `fork`) will also inherit their parents' B keys.
These keys are stored as the field `rop_pid` inside `struct task`, with an exact
duplicate in `struct machine_thread` for implementation reasons.

xnu reprograms the ARM B-key registers during context switch, via the macro
`set_process_dependent_keys_and_sync_context` in `cswitch.s`.

xnu uses the B keys internally to sign pointers pushed onto the kernel stack,
such as stashed LR values.  Note that xnu does *not* need to explicitly switch
to a dedicated set of "kernel B keys" to do this:

1. The `KERNKey` diversifier already ensures that the actual signing keys are
   different between xnu and userspace.

2. Although reprogramming the ARM B-key registers will affect xnu's signing keys
   as well, pointers pushed onto the stack are inherently short-lived.
   Specifically, there will never be a situation where a stack pointer value is
   signed with one `current_task()`, but needs to be authed under a different
   active `current_task()`.

#### SCTLR_EL1

As discussed above, xnu disables the ARM keys when returning to non-arm64e
userspace processes.  This is implemented by manipulating the `EnIA`, `EnIB`,
and `EnDA`, and `EnDB` bits in the ARM `SCTLR_EL1` system register.  When
these bits are cleared, auth or sign instruction using the respective keys
will simply pass through their inputs unmodified.

Initially, xnu cleared these bits during every `exception_return` to a
non-arm64e process.  Since xnu itself uses these keys, the exception vector
needs to restore the same bits on every exception entry (implemented in the
`EL0_64_VECTOR` macro).

Apple A13 CPUs now have controls that allow xnu to keep the PAC keys enabled at
EL1, independent of `SCTLR_EL1` settings.  On these CPUs, xnu only needs to
reconfigure `SCTLR_EL1` when context-switching from a "vanilla" arm64 process to
an arm64e process, or vice-versa (`pmap_switch_user_ttb_internal`).

### Signed pointers in shared regions

Each userspace process has a *shared region* mapped into its address space,
consisting of code and data shared across all processes of the same processor
type, bitness, root directory, and (for arm64e processes) team ID.  Comments at
the top of `osfmk/vm/vm_shared_region.c` discuss this region, and the process of
populating it, in more detail.

As the VM layer pages in parts of the shared region, any embedded pointers must
be rebased.  Although this process is not new, PAC adds a new step: these
embedded pointers may be signed, and must be re-signed after they are rebased.
This process is implemented as `vm_shared_region_slide_page_v3` in
`osfmk/vm/vm_shared_region.c`.

xnu signs these embedded pointers using a shared-region-specific A key
(`sr_jop_key`), which is randomly generated when the shared region is created.
Since these pointers will be consumed by userspace processes, xnu temporarily
switches to the userspace A keys when re-signing them.

### Signing spilled register state

xnu saves register state into kernel memory when taking exceptions, and reloads
this state on exception return.  If an attacker has write access to kernel
memory, it can modify this saved state and effectively get control over a
victim thread's control flow.

xnu hardens against this attack by calling `ml_sign_thread_state` on exception
entry to hash certain registers before they're saved to memory.  On exception
return, it calls the complementary `ml_check_signed_state` function to ensure
that the reloaded values still match this hash.  `ml_sign_thread_state` hashes a
handful of particularly sensitive registers:

* `pc, lr`: directly affect control-flow
* `cpsr`: controls process's exception level
* `x16, x17`: used by LLVM to temporarily store unauthenticated addresses

`ml_sign_thread_state` also uses the address of the thread's `arm_saved_state_t`
as a diversifier.  This step keeps attackers from using `ml_sign_thread_state`
as a signing oracle.  An attacker may attempt to create a sacrificial thread,
set this thread to some desired state, and use kernel memory access gadgets to
transplant the xnu-signed state onto a victim thread.  Because the victim
process has a different `arm_saved_state_t` address as a diversifier,
`ml_check_signed_state` will detect a hash mismatch in the victim thread.

Apart from exception entry and return, xnu calls `ml_check_signed_state` and
`ml_sign_thread_state` whenever it needs to mutate one of these sensitive
registers (e.g., advancing the PC to the next instruction).  This process looks
like:

1. Disable interrupts
2. Load `pc, lr, cpsr, x16, x17` values and hash from thread's
   `arm_saved_state_t` into registers
3. Call `ml_check_signed_state` to ensure values have not been tampered with
4. Mutate one or more of these values using *only* register-to-register
   instructions
5. Call `ml_sign_thread_state` to re-hash the mutated thread state
6. Store the mutated values and new hash back into thread's `arm_saved_state_t`.
7. Restore old interrupt state

Critically, none of the sensitive register values can be spilled to memory
between steps 1 and 7.  Otherwise an attacker with kernel memory access could
modify one of these values and use step 5 as a signing oracle. xnu implements
these routines entirely in assembly to ensure full control over register use,
using a macro `MANIPULATE_SIGNED_THREAD_STATE()` to generate boilerplate
instructions.

Interrupts must be disabled whenever `ml_check_signed_state` or
`ml_sign_thread_state` are called, starting *before* their inputs (`x0`--`x5`)
are populated.  To understand why, consider what would happen if the CPU could
be interrupted just before step 5 above.  xnu's exception handler would spill
the entire register state to memory.  If an attacker has kernel memory access,
they could attempt to replace the spilled `x0`--`x5` values.  These modified
values would then be reloaded into the CPU during exception return; and
`ml_sign_thread_state` would be called with new, attacker-controlled inputs.

### thread_set_state

The `thread_set_state` call lets userspace modify the register state of a target
thread.  Signed userspace state adds a wrinkle to this process, since the
incoming FP, LR, SP, and PC values are signed using the *userspace process's*
key.

xnu handles this in two steps.  First, `machine_thread_state_convert_from_user`
converts the userspace thread state representation into an in-kernel
representation.  Signed values are authenticated using `pmap_auth_user_ptr`,
which involves temporarily switching to the userspace keys.

Second, `thread_state64_to_saved_state` applies this converted state to the
target thread.  Whenever `thread_state64_to_saved_state` modifies a register
that makes up part of the thread state hash, it uses
`MANIPULATE_SIGNED_THREAD_STATE()` as described above to update this hash.


### Signing arbitrary data blobs

xnu provides `ptrauth_utils_sign_blob_generic` and `ptrauth_utils_auth_blob_generic`
to sign and authenticate arbitrary blobs of data. Callers are responsible for
storing the pointer-sized signature returned. The signature is a rolling MAC
of the data, using the `pacga` instruction, mixed with a provided salt and optionally
further diversified by storage address.

Use of these functions is inherently racy. The data must be read from memory
before each pointer-sized block can be added to the signature. In normal operation,
standard thread-safety semantics protect from corruption, however in the malicious
case, it may be possible to time overwriting the buffer before signing or after
authentication.

Callers of these functions must take care to minimise these race windows by
using them immediately preceeding/following a write/read of the blob's data.
