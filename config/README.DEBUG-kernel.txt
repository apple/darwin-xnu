This directory contains a universal DEBUG kernel, built for 32-bit and
64-bit Intel. It includes a dSYM bundle for remote kernel debugging
and live kernel debugging.

INSTALLATION

!!!WARNING!!! These steps will overwrite the default kernel and
System.kext. Backup all files before attempting these steps.

To install the DEBUG kernel, do:
bash-3.2$ sudo -s
bash-3.2# cd /
bash-3.2# ditto /AppleInternal/Developer/Extras/Kernel\ Debugging/System.kext /System/Library/Extensions/System.kext
bash-3.2# cp -r /AppleInternal/Developer/Extras/Kernel\ Debugging/mach_kernel* /
bash-3.2# chown -R root:wheel /System/Library/Extensions/System.kext /mach_kernel*
bash-3.2# chmod -R g-w /System/Library/Extensions/System.kext /mach_kernel*
bash-3.2# touch /System/Library/Extensions
bash-3.2# shutdown -r now

REMOTE KERNEL DEBUGGING

See the documentation that accompanies the Kernel Debug Kit

LIVE KERNEL DEBUGGING

With the DEBUG kernel installed, set "kmem=1" in your "boot-args"
NVRAM variable, reboot, and do:

bash-3.2$ sudo gdb -a <arch> --quiet /mach_kernel
(gdb) target darwin-kernel
(gdb) source /AppleInternal/Developer/Extras/Kernel\ Debugging/kgmacros
Loading Kernel GDB Macros package.  Type "help kgm" for more info.
(gdb) attach
Connected.

<arch> should reflect the currently booted kernel architecture, either
"i386" or "x86_64"


