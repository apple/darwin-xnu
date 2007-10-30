MACH_INSTHDRS += mach.h \
                 mach_error.h \
                 mach_init.h \
                 mach_interface.h \
                 port_obj.h \
                 sync.h \
                 task.h \
                 thread_act.h \
                 vm_task.h
MACH_INSTHDRS := ${MACH_INSTHDRS:S/^/${.CURDIR}\/mach\/headers\//}
