/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_PROTOS_H
#define _PEXPERT_ARM_PROTOS_H

#if defined __arm64__
#define SHMCON 1
#endif

extern vm_offset_t pe_arm_get_soc_base_phys(void);
extern uint32_t pe_arm_get_soc_revision(void);
extern uint32_t pe_arm_init_interrupts(void *args);
extern void pe_arm_init_debug(void *args);


#ifdef  PEXPERT_KERNEL_PRIVATE
extern void cnputc(char);
#endif
int serial_init(void);
int serial_getc(void);
void serial_putc(char);
void uart_putc(char);
int uart_getc(void);

int switch_to_serial_console(void);
void switch_to_old_console(int);

__BEGIN_DECLS
int pe_shmcon_set_child(uint64_t paddr, uint32_t entry);
__END_DECLS

#endif /* _PEXPERT_ARM_PROTOS_H */
