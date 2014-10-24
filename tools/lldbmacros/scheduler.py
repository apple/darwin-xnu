from xnu import *
from utils import *
from process import *

# TODO: write scheduler related macros here

# Macro: showinterrupts
@lldb_command('showinterrupts')
def ShowInterrupts(cmd_args=None):
    """ Prints IRQ, IPI and TMR counts for each CPU
    """
    bcdata = kern.GetValueFromAddress(kern.GetLoadAddressForSymbol('BootCpuData'), 'cpu_data_t *')
    print "CPU 0 IRQ: {:d}\n".format(bcdata.cpu_stat.irq_ex_cnt)
    print "CPU 0 IPI: {:d}\n".format(bcdata.cpu_stat.ipi_cnt)
    print "CPU 0 TMR: {:d}\n".format(bcdata.cpu_stat.timer_cnt)
    if (kern.globals.machine_info.physical_cpu == 2):
        if kern.arch == 'arm':
            cdentries = kern.GetValueFromAddress(kern.GetLoadAddressForSymbol('CpuDataEntries') + 20, 'uintptr_t *')
            cpu_data_entry = Cast(dereference(cdentries), 'cpu_data_t *')
            print "CPU 1 IRQ: {:d}\n".format(cpu_data_entry.cpu_stat.irq_ex_cnt)
            print "CPU 1 IPI: {:d}\n".format(cpu_data_entry.cpu_stat.ipi_cnt)
            print "CPU 1 TMR: {:d}\n".format(cpu_data_entry.cpu_stat.timer_cnt)
        elif kern.arch == 'arm64':
                cdentries = kern.GetValueFromAddress(kern.GetLoadAddressForSymbol('CpuDataEntries') + 24, 'uintptr_t *')
                cpu_data_entry = Cast(dereference(cdentries), 'cpu_data_t *')
                print "CPU 1 IRQ: {:d}\n".format(cpu_data_entry.cpu_stat.irq_ex_cnt)
                print "CPU 1 IPI: {:d}\n".format(cpu_data_entry.cpu_stat.ipi_cnt)
                print "CPU 1 TMR: {:d}\n".format(cpu_data_entry.cpu_stat.timer_cnt)

# EndMacro: showinterrupts

# Macro: showactiveinterrupts
@lldb_command('showactiveinterrupts')
def ShowActiveInterrupts(cmd_args=None):
    """  Prints the interrupts that are unmasked & active with the Interrupt Controller
         Usage: showactiveinterrupts <address of Interrupt Controller object>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowActiveInterrupts.__doc__
        return False
    aic = kern.GetValueFromAddress(cmd_args[0], 'AppleInterruptController *')
    if not aic:
        print "unknown arguments:", str(cmd_args)
        return False

    aic_base = unsigned(aic._aicBaseAddress)
    current_interrupt = 0
    aic_imc_base = aic_base + 0x4180
    aic_him_offset = 0x80
    current_pointer = aic_imc_base
    unmasked = dereference(kern.GetValueFromAddress(current_pointer, 'uintptr_t *'))
    active = dereference(kern.GetValueFromAddress(current_pointer + aic_him_offset, 'uintptr_t *'))
    group_count = 0
    mask = 1
    while current_interrupt < 192:
        if (((unmasked & mask) == 0) and (active & mask)):
            print "Interrupt {:d} unmasked and active\n".format(current_interrupt)
        current_interrupt = current_interrupt + 1
        if (current_interrupt % 32 == 0):
            mask = 1
            group_count = group_count + 1
            unmasked = dereference(kern.GetValueFromAddress(current_pointer + (4 * group_count), 'uintptr_t *'))
            active = dereference(kern.GetValueFromAddress((current_pointer + aic_him_offset) + (4 * group_count), 'uintptr_t *'))
        else:
            mask = mask << 1
    
# EndMacro: showactiveinterrupts

