.text
/*
 * Taken from Libc
 */
.globl _cpu_number
_cpu_number:
#if defined(__x86_64__)
        push    %rbp
        mov     %rsp,%rbp
        sub     $16,%rsp                // space to read IDTR

        sidt    (%rsp)                  // store limit:base on stack
        movw    (%rsp), %ax             // get limit
        and     $0xfff, %rax            // mask off lower 12 bits to return

        mov     %rbp,%rsp
        pop     %rbp
        ret
#elif defined(__i386__)
        push    %ebp
	mov     %esp,%ebp
	sub     $8, %esp                // space to read IDTR

	sidt    (%esp)                  // store limit:base on stack
	movw    (%esp), %ax             // get limit
	and     $0xfff, %eax            // mask off lower 12 bits to return
	
	mov     %ebp,%esp
	pop     %ebp
	ret
#else
#error Unsupported architecture
#endif
