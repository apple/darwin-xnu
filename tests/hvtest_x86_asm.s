#include <machine/asm.h>

	.text

	.balign 0x1000

	.global _hvtest_begin
_hvtest_begin:

	/*
	 * Everything between _hvtest_begin and _hvtest_end will be copied for
	 * tests that don't use the page faulting of the test harness.
	 * You can put constants here.
	 */

.code64

	.balign 16

	.global _save_restore_regs_entry
_save_restore_regs_entry:

    pushq %rax
    pushq %rcx

    xor %rcx, %rcx

    pushq %rbx


    /*
     * For all registers to test, each of these blocks:
     * 1. increments rcx (to keep track in case of test failure),
     * 2. checks the register's value against a (constant) template
     * 3. flips all bits for the VMM to later verify that the changes value is available.
     *
     * For a second pass, bits are all flipped back to their original state after
     * the vmcall.
     */


    // segment registers (pass 1)

    incq %rcx
    movq $0x1010, %rax
    movq %ds, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $1, %rbx
    movq %rbx, %ds

    incq %rcx
    movq $0x2020, %rax
    movq %es, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $2, %rbx
    movq %rbx, %es

    incq %rcx
    movq $0x3030, %rax
    movq %fs, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $3, %rbx
    movq %rbx, %fs

    incq %rcx
    movq $0x4040, %rax
    movq %gs, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $1, %rbx
    movq %rbx, %gs

    popq %rbx

    jmp .pass

.pass2:
    pushq %rax
    pushq %rcx

    xor %rcx, %rcx

    pushq %rbx

    // segment registers (pass 2)

    incq %rcx
    movq $0x1, %rax
    movq %ds, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $1, %rbx
    movq %rbx, %ds

    incq %rcx
    movq $0x2, %rax
    movq %es, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $2, %rbx
    movq %rbx, %es

    incq %rcx
    movq $0x3, %rax
    movq %fs, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $3, %rbx
    movq %rbx, %fs

    incq %rcx
    movq $0x1, %rax
    movq %gs, %rbx
    cmpq %rbx, %rax
    jne .foul
    movq $1, %rbx
    movq %rbx, %gs

    popq %rbx

.pass:
    // general purpose registers

    incq %rcx
    movq $0x0101010101010101, %rax
    cmpq 8(%rsp), %rax // %rax on stack
    jne .foul
    notq 8(%rsp)

    incq %rcx
    movq $0x0202020202020202, %rax
    cmpq %rbx, %rax
    jne .foul
    notq %rbx

    incq %rcx
    movq $0x0303030303030303, %rax
    cmpq (%rsp), %rax // %rcx on stack
    jne .foul
    notq (%rsp)

    incq %rcx
    movq $0x0404040404040404, %rax
    cmpq %rdx, %rax
    jne .foul
    notq %rdx

    incq %rcx
    movq $0x0505050505050505, %rax
    cmpq %rsi, %rax
    jne .foul
    notq %rsi

    incq %rcx
    movq $0x0606060606060606, %rax
    cmpq %rdi, %rax
    jne .foul
    notq %rdi

    incq %rcx
    movq $0x0707070707070707, %rax
    cmpq %rbp, %rax
    jne .foul
    notq %rbp

    incq %rcx
    movq $0x0808080808080808, %rax
    cmpq %r8, %rax
    jne .foul
    notq %r8

    incq %rcx
    movq $0x0909090909090909, %rax
    cmpq %r9, %rax
    jne .foul
    notq %r9

    incq %rcx
    movq $0x0a0a0a0a0a0a0a0a, %rax
    cmpq %r10, %rax
    jne .foul
    notq %r10

    incq %rcx
    movq $0x0b0b0b0b0b0b0b0b, %rax
    cmpq %r11, %rax
    jne .foul
    notq %r11

    incq %rcx
    movq $0x0c0c0c0c0c0c0c0c, %rax
    cmpq %r12, %rax
    jne .foul
    notq %r12

    incq %rcx
    movq $0x0d0d0d0d0d0d0d0d, %rax
    cmpq %r13, %rax
    jne .foul
    notq %r13

    incq %rcx
    movq $0x0e0e0e0e0e0e0e0e, %rax
    cmpq %r14, %rax
    jne .foul
    notq %r14

    incq %rcx
    movq $0x0f0f0f0f0f0f0f0f, %rax
    cmpq %r15, %rax
    jne .foul
    notq %r15

    popq %rcx
    movq (%rsp), %rax
    vmcall

    notq %rax
    notq %rbx
    notq %rcx
    notq %rdx
    notq %rsi
    notq %rdi
    notq %rbp
    notq %r8
    notq %r9
    notq %r10
    notq %r11
    notq %r12
    notq %r13
    notq %r14
    notq %r15

    jmp .pass2

.foul:
    movq %rcx, %rax
    vmcall

	.global _save_restore_debug_regs_entry
_save_restore_debug_regs_entry:

    pushq %rax
    xor %rcx, %rcx

    /*
     * For all registers to test, each of these blocks:
     * 1. increments rcx (to keep track in case of test failure),
     * 2. checks the register's value against a (constant) template
     * 3. flips all bits for the VMM to later verify that the changes value is available.
     *
     * For a second pass, bits are all flipped back to their original state after
     * the vmcall.
     */

    incq %rcx
    movq $0x1111111111111111, %rbx
    movq %dr0, %rax
    cmpq %rbx, %rax
    jne .foul
    notq %rbx
    movq %rbx, %dr0

    incq %rcx
    movq $0x2222222222222222, %rbx
    movq %dr1, %rax
    cmpq %rbx, %rax
    jne .foul
    notq %rbx
    movq %rbx, %dr1

    incq %rcx
    movq $0x3333333333333333, %rbx
    movq %dr2, %rax
    cmpq %rbx, %rax
    jne .foul
    notq %rbx
    movq %rbx, %dr2

    incq %rcx
    movq $0x4444444444444444, %rbx
    movq %dr3, %rax
    cmpq %rbx, %rax
    jne .foul
    notq %rbx
    movq %rbx, %dr3

    /*
     * flip only defined bits for debug status and control registers
     * (and also don't flip General Detect Enable, as the next access
     * to any debug register would generate an exception)
     */

    incq %rcx
    movq $0x5555555555555555, %rbx
    mov $0xffff0ff0, %rax
    orq %rax, %rbx
    movq $0xffffefff, %rax
    andq %rax, %rbx
    movq %dr6, %rax
    cmpq %rbx, %rax
    jne .foul
    notq %rbx
    mov $0xffff0ff0, %rax
    orq %rax, %rbx
    movq $0xffffefff, %rax
    andq %rax, %rbx
    movq %rbx, %dr6

    incq %rcx
    movq $0x5555555555555555, %rbx
    orq $0x400, %rbx
    movq $0xffff0fff, %rax
    andq %rax, %rbx
    movq %dr7, %rax
    cmpq %rbx, %rax
    jne .foul
    notq %rbx
    orq $0x400, %rbx
    movq $0xffff0fff, %rax
    andq %rax, %rbx
    movq %rbx, %dr7

    popq %rax
    vmcall

    movq %dr0, %rbx
    notq %rbx
    movq %rbx, %dr0

    movq %dr1, %rbx
    notq %rbx
    movq %rbx, %dr1

    movq %dr2, %rbx
    notq %rbx
    movq %rbx, %dr2

    movq %dr3, %rbx
    notq %rbx
    movq %rbx, %dr3

    movq %dr6, %rbx
    notq %rbx
    mov $0xffff0ff0, %rax
    orq %rax, %rbx
    movq $0xffffefff, %rax
    andq %rax, %rbx
    movq %rbx, %dr6

    movq %dr7, %rbx
    notq %rbx
    orq $0x400, %rbx
    movq $0xffff0fff, %rax
    andq %rax, %rbx
    movq %rbx, %dr7

    jmp _save_restore_debug_regs_entry // 2nd pass

.code32

	.global _simple_protected_mode_vcpu_entry
_simple_protected_mode_vcpu_entry:

    movl $0x23456, %eax
    vmcall

.code16

	.global _simple_real_mode_vcpu_entry
_simple_real_mode_vcpu_entry:

    movl $0x23456, %eax
    vmcall

.code32

	.global _radar61961809_entry
_radar61961809_entry:

	mov		$0x99999999, %ebx	// sentinel address, see _radar61961809_loop64

	mov		$0xc0000080,%ecx	// IA32_EFER
	rdmsr
	or		$0x100,%eax			// .LME
	wrmsr

	vmcall

	mov		%cr0,%ecx
	or		$0x80000000,%ecx	// CR0.PG
	mov		%ecx,%cr0

	// first (%edi) 6 bytes are _radar61961809_prepare far ptr
	ljmp	*(%edi)

.code32

	.global _radar61961809_prepare
_radar61961809_prepare:

	/*
	 * We switched into long mode, now immediately out, and the test
	 * will switch back in.
	 *
	 * This is done to suppress (legitimate) EPT and Page Fault exits.
	 * Until CR0.PG is enabled (which is what effectively activates
	 * long mode), the page tables are never looked at. Right after
	 * setting PG, that changes immediately, effecting transparently
	 * handled EPT violations. Additionally, the far jump that
	 * would be necessary to switch into a 64bit code segment would
	 * also cause EPT violations and PFs when fetching the segment
	 * descriptor from the GDT.
	 *
	 * By first jumping into a 32bit code segment after enabling PG
	 * once, we "warm up" both EPT and (harness managed) page tables,
	 * so the next exit after the far jump will most likely be an
	 * IRQ exit, most faithfully reproducing the problem.
	 */

	mov		%cr0,%ecx
	and		$~0x80000000,%ecx
	mov		%ecx,%cr0

	mov		$0x1111, %eax
	vmcall

	// This is where the actual test really starts.
	mov		%cr0,%ecx
	or		$0x80000000,%ecx
	mov		%ecx,%cr0	// enable PG => long mode

	xor		%ecx, %ecx

	add		$8,%edi
	ljmp	*(%edi)		// _radar61961809_loop64

.code64

	.global _radar61961809_loop64
_radar61961809_loop64:
1:
	// as 16bit code, this instruction will be:
	//   add %al,(%bx,%si)
	// and cause an obvious EPT violation (%bx is 0x9999)
	mov		$0x1,%ebp

	// loop long enough for a good chance to an IRQ exit
	dec		%ecx
	jnz		1b

	// if we reach here, we stayed in long mode.
	mov		$0x2222, %eax
	vmcall

	.global _radar60691363_entry
_radar60691363_entry:
	movq $0x800, %rsi // VMCS_GUEST_ES
	vmreadq %rsi, %rax
	vmcall
	movq $0x6400, %rsi // VMCS_RO_EXIT_QUALIFIC
	vmreadq %rsi, %rax
	vmcall
	movq $0x6402, %rsi // VMCS_RO_IO_RCX
	vmreadq %rsi, %rax
	vmcall

	movq $0x800, %rsi // VMCS_GUEST_ES
	movq $0x9191, %rax
	vmwriteq %rax, %rsi
	movq $0x6400, %rsi // VMCS_RO_EXIT_QUALIFIC
	movq $0x9898, %rax
	vmwriteq %rax, %rsi
	movq $0x6402, %rsi // VMCS_RO_IO_RCX
	movq $0x7979, %rax
	vmwriteq %rax, %rsi

	movq $0x4567, %rax

	vmcall

	.global _hvtest_end
_hvtest_end:
