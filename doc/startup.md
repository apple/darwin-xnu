XNU startup sequence
====================

### General Principles

XNU Startup sequence is driven by the `<kern/startup.h>` module.

The startup sequence is made of individual subsystems (the `STARTUP_SUB_*`
values of the `startup_subsystem_id_t` type) that get initialized in sequence.

A subsystem can use ranks to order the various initializers that make up its
initialization sequence. Usage of ranks is custom to each subsystem and must be
documented in this file.

The subsystem module will basically run hooks in that order:

```
for (subsystem 0 -> N) {
  for (rank 0 -> N) {
    // run in no particular order for a given rank in the given subsystem
    init(subsystem, rank);
  }
}
```

### Extending the startup sequence

When extending the startup sequence:

1. add a new value to the `startup_subsystem_id_t` enum in the right order
2. document what services this phase provides, and how it uses ranks in this
   file.


When hooking with a given subsystem, consult this documentation to use the
proper rank for your callback.

If a new rank needs to be used, update this documentation in the proper section.

---------------------------------------------------------------------------------


`STARTUP_SUB_TUNABLES`
----------------------

### Description

Initializes various globals that alter the behavior of the kernel, lookup
tables, ... Available hooks are:

- `TUNABLES`: parses a boot arg into a global that will become read-only at
  lockdown time,
- `TUNABLE_WRITEABLE`: same as `TUNABLE` but the global will not be locked down.

### Rank usage

- Rank 1: `TUNABLE`, `TUNABLE_WRITEABLE`
- Middle: globals that require complex initialization (e.g. SFI classes).


`STARTUP_SUB_LOCKS_EARLY`
-------------------------

### Description

Initializes early locks that do not require any memory allocations to be
initialized. Available hooks are:

- `LCK_GRP_DECLARE*`: automatically initialized lock groups,
- `LCK_GRP_ATTR_DECLARE`: automatically initialized lock group attributes,
- `LCK_ATTR_DECLARE`: automatically initialized lock attributes,
- `LCK_SPIN_DECLARE*`: automatically initialized spinlocks,
- `LCK_RW_DECLARE`: automatically initialized reader/writer lock,
- `LCK_MTX_EARLY_DECLARE*`: automatically initialized mutexes, with statically
  allocated buffers for statistics/tracing,
- `SIMPLE_LOCK_DECLARE*`: automatically initialized simple locks.

### Rank usage

- Rank 1: Initializes the module (`lck_mod_init`),
- Rank 2: `LCK_GRP_ATTR_DECLARE`, `LCK_ATTR_DECLARE`,
- Rank 3: `LCK_GRP_DECLARE*`
- Rank 4: `LCK_SPIN_DECLARE*`, `LCK_MTX_EARLY_DECLARE*`,
  `LCK_RW_DECLARE`, `SIMPLE_LOCK_DECLARE*`.


`STARTUP_SUB_KPRINTF`
---------------------

### Description

Initializes the kprintf subsystem.

### Rank usage

- Rank 1: calls the module initializer (`PE_init_kprintf`).


`STARTUP_SUB_PMAP_STEAL`
------------------------

### Description

Allows for subsystems to steal early memory.

### Rank usage

N/A.


`STARTUP_SUB_VM_KERNEL`
-----------------------

### Description

Denotes that the early kernel VM is initialized.

### Rank usage

N/A.


`STARTUP_SUB_KMEM`
------------------

### Description

Denotes that `kernel_memory_allocate` is now usable.

### Rank usage

N/A.


`STARTUP_SUB_KMEM_ALLOC`
------------------------

### Description

Denotes that `kmem_alloc` is now usable.

### Rank usage

N/A.


`STARTUP_SUB_ZALLOC`
--------------------

### Description

Initializes the zone allocator.

- `ZONE_DECLARE`, `ZONE_INIT`: automatically initialized permanent zones.
- `ZONE_VIEW_DEFINE`, `KALLOC_HEAP_DEFINE`: zone and kalloc heap views.


### Rank usage

- Rank 1: `zone_init`: setup the zone subsystem, this allows for the already
  created VM/pmap zones to become dynamic.

- Rank 2: `vm_page_module_init`: create the "vm pages" zone.
  The `vm_page_zone` must be created prior to `kalloc_init`; that routine can
  trigger `zalloc()`s (for e.g. mutex statistic structure initialization).

  The `vm_page_zone` must exist to satisfy fictitious page allocations
  (which are used for guard pages by the guard mode zone allocator).

- Rank 3: Initialize kalloc.

- Rank 4: Enable zone caching (uses kalloc)

- Middle: for any initialization that only requires kalloc/zalloc
          runs `ZONE_DECLARE` and `ZONE_INIT`.

- Last:   zone and kalloc heaps (`ZONE_VIEW_DEFINE`, `KALLOC_HEAP_DEFINE`).


`STARTUP_SUB_PERCPU`
--------------------

### Description

Initializes the percpu subsystem.

### Rank usage

Rank 1: allocates the percpu memory, `percpu_foreach_base` and `percpu_foreach`
        become usable.


`STARTUP_SUB_LOCKS`
-------------------

### Description

Initializes kernel locks that might require allocations (due to statistics and
tracing features). Available hooks are:

- `LCK_MTX_DECLARE`: automatically initialized mutex,


### Rank usage

- Rank 1: `LCK_MTX_DECLARE`.


`STARTUP_SUB_CODESIGNING`
-------------------------

### Description

Initializes the codesigning subsystem.

### Rank usage

- Rank 1: calls the module initializer (`cs_init`).


`STARTUP_SUB_OSLOG`
-------------------

### Description

Initializes the `os_log` facilities.

### Rank usage

- Rank 1: Calls the module initializer (`oslog_init`).


`STARTUP_SUB_MACH_IPC`
-------------------

### Description

Initializes the Mach IPC subsystem.

### Rank usage

- Rank 1: Initializes IPC submodule globals (ipc tables, voucher hashes, ...)
- Rank last: Final IPC initialization.


`STARTUP_SUB_EARLY_BOOT`
------------------------

### Description

Denotes that subsystems that expect to operate with
interrupts or preemption enabled may begin enforcement.

### Rank usage

N/A.


`STARTUP_SUB_LOCKDOWN`
----------------------

### Description

Denotes that the kernel is locking down, this phase should never be hooked.
When the kernel locks down:

- data marked `__startup_data` and code marked `__startup_func` is unmapped,
- data marked `__security_const_late` or `SECURITY_READ_ONLY_LATE` becomes
  read-only.

### Rank usage

N/A.


