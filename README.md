# What is XNU?

XNU kernel is part of the Darwin operating system for use in macOS and iOS operating systems. XNU is an acronym for X is Not Unix.
XNU is a hybrid kernel combining the Mach kernel developed at Carnegie Mellon University with components from FreeBSD and C++ API
for writing drivers called IOKit. XNU runs on `i386` and `x86_64` for both single processor and multi-processor configurations.

# XNU Source Tree

- `config` - configurations for exported apis for supported architecture and platform
- `SETUP` - Basic set of tools used for configuring the kernel, versioning and kextsymbol management.
- `EXTERNAL_HEADERS` - Headers sourced from other projects to avoid dependency cycles when building. These headers should be
regularly synced when source is updated.
- `libkern` - C++ IOKit library code for handling of drivers and kexts.
- `libsa` -  kernel bootstrap code for startup
- `libsyscall` - syscall library interface for userspace programs
- `libkdd` - source for user library for parsing kernel data like kernel chunked data.
- `makedefs` - top level rules and defines for kernel build.
- `osfmk` - Mach kernel based subsystems
- `pexpert` - Platform specific code like interrupt handling, atomics etc.
- `security` - Mandatory Access Check policy interfaces and related implementation.
- `bsd` - BSD subsystems code
- `tools` - A set of utilities for testing, debugging and profiling kernel.

# How to build XNU

## Building `DEVELOPMENT` kernel

The xnu make system can build kernel based on `KERNEL_CONFIGS` & `ARCH_CONFIGS` variables as arguments.
Here is the syntax:
```sh
$ make ARCH_CONFIGS=<arch> SDKROOT=<sdkroot> KERNEL_CONFIGS=<variant>
```

Where:
- `<arch>` can be valid arch to build for (e.g. `I386` or `X86_64`)
- `<sdkroot>` is the path to macOS SDK on disk (defaults to `/`)
- `<variant>` can be `DEBUG`, `DEVELOPMENT`, `RELEASE`, `PROFILE`, or some combination thereof when surrounded by double-quotes.
    - These configure compilation flags and assertions throughout kernel code.

To build a kernel for the same architecture as running OS, just type

```sh
$ make
$ make SDKROOT=macosx.internal
```

Additionally, there is support for configuring architectures through `ARCH_CONFIGS` and kernel configurations with `KERNEL_CONFIGS`;
```sh
$ make SDKROOT=macosx.internal ARCH_CONFIGS=X86_64 KERNEL_CONFIGS=DEVELOPMENT
$ make SDKROOT=macosx.internal ARCH_CONFIGS=X86_64 KERNEL_CONFIGS="RELEASE DEVELOPMENT DEBUG"
```

**Note:**
- By default, architecture is set to the build machine architecture, and the default kernel config is set to build for
`DEVELOPMENT`.
    - This will also create a bootable image, `kernel.[config]`, and a kernel binary with symbols,\
    `kernel.[config].unstripped`.

- To build with `RELEASE` kernel configuration:
    ```sh
    $ make KERNEL_CONFIGS=RELEASE SDKROOT=/path/to/SDK
    ```

## Building FAT kernel binary

Define architectures in your environment or when running a make command.
```sh
$ make ARCH_CONFIGS="I386 X86_64" exporthdrs all
```

## Other `Makefile` options

- Use 8 processes during the build. The default is 2x the number of active CPUS.
    ```sh
    $ make MAKEJOBS=-j8
    # Equivalently:
    $ make -j8
    ```

- Trace recursive `make` invocations _(useful in combination with `VERBOSE=YES`)_:
    ```sh
    $ make -w
    ```

- Build without LLVM Link Time Optimization:
    ```sh
    $ make BUILD_LTO=0
    ```

- Perform build on remote host:
    ```sh
    $ make REMOTEBUILD=user@remotehost
    ```

- Build Clang JSON Compilation Database:
    ```sh
    $ make BUILD_JSON_COMPILATION_DATABASE=1
    ```

The XNU build system can optionally output color-formatted build output. To enable this, you can either
set the `XNU_LOGCOLORS` environment variable to `y`, or you can pass `LOGCOLORS=y` to the make command.

## Debug information formats

By default, a DWARF debug information repository is created during the install phase; this is a "bundle" named
`kernel.development.<variant>.dSYM`. To select the older STABS debug information format (where debug information is embedded in the
`kernel.development.unstripped` image), set the BUILD_STABS environment variable.
```sh
$ export BUILD_STABS=1
$ make
```

## Building KernelCaches

To test the xnu kernel, you need to build a `kernelcache` which links the kernel extensions and kernel together into a single,
bootable image. To build a `kernelcache` you can use the following mechanisms:

- **Using automatic `kernelcache` generation with `kextd`**

    The `kextd` daemon keeps watching for changing in `/System/Library/Extensions` directory. You can set up a new kernel with:
    ```sh
    $ cp BUILD/obj/DEVELOPMENT/X86_64/kernel.development /System/Library/Kernels/
    $ touch /System/Library/Extensions
    $ ps -e | grep kextd
    ```

- **Manually invoking `kextcache` to build new `kernelcache`:**
    ```sh
    $ kextcache -q -z -a x86_64 -l -n -c /var/tmp/kernelcache.test -K /var/tmp/kernel.test /System/Library/Extensions
    ```

## Running KernelCache on a Target machine

The development kernel and iBoot supports configuring boot arguments so that we can safely boot into test kernel and, if things go
wrong, safely fall back to previously used `kernelcache`.

Following these steps to get such a setup:

1. Create kernel cache using the `kextcache` command as `/kernelcache.test`.
1. Copy existing boot configurations to an alternate file:
    ```sh
    $ cp /Library/Preferences/SystemConfiguration/com.apple.Boot.plist /next_boot.plist
    ```
1. Update the `kernelcache` and boot-args for your setup:
    ```sh
    $ plutil -insert "Kernel Cache" -string "kernelcache.test" /next_boot.plist
    $ plutil -replace "Kernel Flags" -string "debug=0x144 -v kernelsuffix=test " /next_boot.plist
    ```
1. Copy the new config to `/Library/Preferences/SystemConfiguration/`:
    ```sh
    $ cp /next_boot.plist /Library/Preferences/SystemConfiguration/boot.plist
    ```
1. Bless the volume with new configs:
    ```sh
    $ sudo -n bless  --mount / --setBoot --nextonly --options "config=boot"
    ```
    The `--nextonly` flag specifies that use the `boot.plist` configs only for one boot.
    So if the kernel panic's you can easily power reboot and recover back to original kernel.

## Creating tags and cscope

Set up your build environment and from the top directory, run:
```sh
$ make tags    # this will build ctags and etags on a case-sensitive volume, only ctags on case-insensitive
$ make TAGS    # this will build etags
$ make cscope  # this will build cscope database
```

## Coding styles (Re-indenting files)

Source files can be re-indented using clang-format setup in `.clang-format`. XNU follows a variant of WebKit style for source code
formatting. Please refer to format styles at [WebKit website]. Further options about
style options is available at [clang docs].

**Note:**
The clang-format binary may not be part of base installation. It can be compiled from llvm clang sources, and is reachable in
`$PATH`.

From this project's root directory, run:
```sh
$ make reindent    # reindent all source files using clang format.
```

## How to install a new header file from XNU

To install IOKit headers, see additional comments in [iokit/IOKit/Makefile]().

XNU installs header files at the following locations -

- `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers`
- `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders`
- `$(DSTROOT)/usr/include/`
- `$(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders`

    - `Kernel.framework` is used by kernel extensions.
    - The `System.framework` and `/usr/include` are used by user level applications.
    - The header files in framework's `PrivateHeaders` are only available for **Apple Internal Development**.

The directory containing the header file should have a `Makefile` that creates the list of files that should be installed in
different locations. If you are adding first header file in a directory, you will need to create `Makefile` similar to
`xnu/bsd/sys/Makefile`.

Add your header file to the correct file list depending on where you want to install it. The default locations where the header
files are installed from each file list are -

- `DATAFILES` : To make header file available in user level -
    `$(DSTROOT)/usr/include`

- `PRIVATE_DATAFILES` : To make header file available to Apple internal in
    user level -
    `$(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders`

- `KERNELFILES` : To make header file available in kernel level -
    `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers`
    `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders`

- `PRIVATE_KERNELFILES` : To make header file available to Apple internal
   for kernel extensions -
   `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders`

The `Makefile` combines the file lists mentioned above into different install lists which are used by build system to install the
header files.

If the install list that you are interested does not exist, create it by adding the appropriate file lists. The default install
lists, its member file lists and their default location are described below -

- `INSTALL_MI_LIST` : Installs header file to a location that is available to everyone in user level.
    Locations -
        `$(DSTROOT)/usr/include`
    Definition -
        INSTALL_MI_LIST = `${DATAFILES}`

-  `INSTALL_MI_LCL_LIST` : Installs header file to a location that is available for Apple internal in user level.
    Locations -
        `$(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders`
    Definition -
        INSTALL_MI_LCL_LIST = `${PRIVATE_DATAFILES}`

- `INSTALL_KF_MI_LIST` : Installs header file to location that is available to everyone for kernel extensions.
    Locations -
        `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers`
    Definition -
        INSTALL_KF_MI_LIST = `${KERNELFILES}`

- `INSTALL_KF_MI_LCL_LIST` : Installs header file to location that is available for Apple internal for kernel extensions.
    Locations -
        `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders`
    Definition -
        INSTALL_KF_MI_LCL_LIST = `${KERNELFILES}` `${PRIVATE_KERNELFILES}`

- `EXPORT_MI_LIST` : Exports header file to all of XNU (`bsd/`, `osfmk/`, etc.) for compilation only. Does not install anything into
the SDK.
    Definition -
        EXPORT_MI_LIST = `${KERNELFILES}` `${PRIVATE_KERNELFILES}`

If you want to install the header file in a sub-directory of the paths described in (1), specify the directory name using two
variables `INSTALL_MI_DIR` and `EXPORT_MI_DIR` as follows -
```
INSTALL_MI_DIR = dirname
EXPORT_MI_DIR = dirname
```

A single header file can exist at different locations using the steps mentioned above.  However it might not be desirable to make
all the code in the header file available at all the locations. For example, you want to export a function only to kernel level but
not user level.

You can use C-language pre-processor directives (`#ifdef`, `#endif`, `#ifndef`) to control the text generated before a header file
is installed.  The kernel only includes the code if the conditional macro is TRUE and strips out code for FALSE conditions from the
header file.

Some pre-defined macros and their descriptions are -

- `PRIVATE` : If true, code is available to all of the XNU kernel and is not available in kernel extensions and user level header
files. The header files installed in all the paths described above in (1) will not have code enclosed within this macro.

- `KERNEL_PRIVATE` : If true, code is available to all of the XNU kernel and Apple internal kernel extensions.

- `BSD_KERNEL_PRIVATE` : If true, code is available to the xnu/bsd part of the kernel and is not available to rest of the kernel,
kernel extensions and user level header files. The header files installed in all the paths described above in (1) will not have code
enclosed within this macro.

- `KERNEL` :  If true, code is available only in kernel and kernel extensions and is not available in user level header files. Only
the header files installed in following paths will have the code -

    - `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers`
    - `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders`

you should check [Testing the kernel] for details.

## How to add a new syscall

## Testing the kernel

XNU kernel has multiple mechanisms for testing.

- Assertions - The `DEVELOPMENT` and `DEBUG` kernel configs are compiled with assertions enabled. This allows developers to easily
    test invariants and conditions.

- XNU Power On Self Tests (`XNUPOST`): The `f` config allows for building the kernel with basic set of test functions
    that are run before first user space process is launched. Since XNU is hybrid between MACH and BSD, we have two locations where
    tests can be added.
        ```
        xnu/osfmk/tests/     # For testing mach-based kernel structures and apis.
        bsd/tests/           # For testing BSD interfaces.
        ```
    Please follow the documentation at [osfmk/tests/README.md](???)

- User level tests: The `tools/tests/` directory holds all the tests that verify syscalls and other features of the XNU kernel.
    The make target `xnu_tests` can be used to build all the tests supported.
        ```sh
        $ make RC_ProjectName=xnu_tests SDKROOT=/path/to/SDK
        ```
    These tests are individual programs that can be run from Terminal and report tests status by means of std posix exit codes
    (0 -> success) and/or stdout. Please read the detailed [unit testing documentation] for more information.

## Kernel data descriptors

XNU uses different data formats for passing data in its api. The most standard way is using syscall arguments. But for complex data
it often relies of sending memory saved by C structs. This packaged data transport mechanism is fragile and leads to broken
interfaces between user space programs and kernel apis. `libkdd` directory holds user space library that can parse custom data
provided by the same version of kernel. The kernel chunked data format is described in detail at [libkdd/README.md](libkdd/README.md).

## Debugging the kernel

The XNU kernel supports debugging with a remote kernel debugging protocol (`kdp`). Please refer documentation at [technical note] [TN2063]
By default the kernel is setup to reboot on a panic. To debug a live kernel, the `kdp` server is setup to listen for UDP connections
over ethernet. For machines without ethernet port, this behavior can be altered with use of kernel boot-args.

The following are some common options:
- `debug=0x144` sets up debug variables to start `kdp` `debugserver` on panic
- `-v` prints kernel logs on screen. By default XNU only shows grey screen with boot art.
- `kdp_match_name=en1` overrides default port selection for `kdp`. Supported for ethernet, thunderbolt, and serial debugging.

To debug a panic'ed kernel, use llvm debugger (lldb) along with unstripped symbol rich kernel binary.
    ```sh
    $ lldb kernel.development.unstripped
    ```

And then you can connect to panic'ed machine with `kdp_remote [ip addr]` or `gdb_remote [hostip : port]` commands.

Each kernel is packaged with kernel specific debug scripts as part of the build process. For security reasons these special commands
and scripts do not get loaded automatically when lldb is connected to machine. Please add the following setting to your
`~/.lldbinit` if you wish to always load these macros.
    ```
    settings set target.load-script-from-symbol-file true
    ```

The `tools/lldbmacros` directory contains the source for each of these commands. Please follow the [the lldbmacros README] for
detailed explanation of commands and their usage.

[//]: # (External Links)
[TN2118]: https://developer.apple.com/library/mac/technotes/tn2004/tn2118.html#//apple_ref/doc/uid/DTS10003352 "Kernel Core Dumps"
[the documentation on Understanding and Debugging Kernel Panics]: https://developer.apple.com/library/mac/technotes/tn2063/_index.html "Understanding and Debugging Kernel Panics"
[Kernel Programming Guide]: https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/build/build.html#//apple_ref/doc/uid/TP30000905-CH221-BABDGEGF
[WebKit website]: http://www.webkit.org/coding/coding-style.html
[clang docs]: http://clang.llvm.org/docs/ClangFormatStyleOptions.html

[//]: # (Internal Links)
[osfmk/tests/README.md](osfmk/tests/README.md)
[the IOKit Makefile]: (iokit/IOKit/Makefile)
[unit testing documentation]: (tools/tests/unit_tests/README.md)
[the libkdd README]: libkdd/README.md
[the lldbmacros README]: tools/lldbmacros/README.md
