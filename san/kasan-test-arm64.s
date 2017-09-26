#include <arm64/proc_reg.h>
#include <mach/arm64/asm.h>
#include <architecture/arm/asm_help.h>

#define JMP_r19_20      #0x00
#define JMP_r21_22      #0x10
#define JMP_r23_24      #0x20
#define JMP_r25_26      #0x30
#define JMP_r27_28      #0x40
#define JMP_r29_lr      #0x50
#define JMP_fp_sp       #0x60

#define JMP_d8_d9       #0x70
#define JMP_d10_d11     #0x80
#define JMP_d12_d13     #0x90
#define JMP_d14_d15     #0xA0

.text

.align 5
.globl EXT(_setjmp)
LEXT(_setjmp)
        add             x1, sp, #0      /* can't STP from sp */
        stp             x19, x20,       [x0, JMP_r19_20]
        stp             x21, x22,       [x0, JMP_r21_22]
        stp             x23, x24,       [x0, JMP_r23_24]
        stp             x25, x26,       [x0, JMP_r25_26]
        stp             x27, x28,       [x0, JMP_r27_28]
        stp             x29, lr,        [x0, JMP_r29_lr]
        stp             fp, x1,         [x0, JMP_fp_sp]
        stp             d8, d9,         [x0, JMP_d8_d9]
        stp             d10, d11,       [x0, JMP_d10_d11]
        stp             d12, d13,       [x0, JMP_d12_d13]
        stp             d14, d15,       [x0, JMP_d14_d15]
        mov             x0, #0
        ret

.align 5
.globl EXT(_longjmp)
LEXT(_longjmp)
        ldp             x19, x20,       [x0, JMP_r19_20]
        ldp             x21, x22,       [x0, JMP_r21_22]
        ldp             x23, x24,       [x0, JMP_r23_24]
        ldp             x25, x26,       [x0, JMP_r25_26]
        ldp             x27, x28,       [x0, JMP_r27_28]
        ldp             x29, lr,        [x0, JMP_r29_lr]
        ldp             fp, x2,         [x0, JMP_fp_sp]
        ldp             d8, d9,         [x0, JMP_d8_d9]
        ldp             d10, d11,       [x0, JMP_d10_d11]
        ldp             d12, d13,       [x0, JMP_d12_d13]
        ldp             d14, d15,       [x0, JMP_d14_d15]
        add             sp, x2, #0
        mov             x0, x1
        cmp             x0, #0          /* longjmp returns 1 if val is 0 */
        b.ne    1f
        add             x0, x0, #1
1:      ret

