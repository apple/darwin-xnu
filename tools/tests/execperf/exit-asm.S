.text
	.align 2
	.globl _main
_main:
#if defined(__x86_64__)
	pushq $0
	mov %rsp, %rbp
	andq $0xfffffffffffffff0, %rsp
	movl $42, %edi
	movl $0x2000001, %eax
	movl $0, %ecx
	movq %rcx, %r10
	syscall
	jmp 1f
1:	
	hlt
	nop
	nop
	nop
	nop
#elif defined(__i386__)
	pushl $0
	mov %esp, %ebp
	andl $0xfffffff0, %esp
	subl $12, %esp
	pushl $42
	mov $0x40001, %eax
	call _sysenter_trap
	jmp 1f
1:	
	hlt
	nop
	nop
	nop
	nop
_sysenter_trap:
	pop %edx
	mov %esp, %ecx
	sysenter
	nop
#else
#error Unsupported architecture
#endif
