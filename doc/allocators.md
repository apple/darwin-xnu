# XNU General purpose allocators

## Introduction

XNU proposes two ways to allocate memory:
- the VM subsystem that provides allocations at the granularity of pages (with
  `kernel_memory_allocate` and similar interfaces);
- the zone allocator subsystem (`<kern/zalloc.h>`) which is a slab-allocator of
  objects of fixed size.

This document describes all the allocator variants around the zone allocator,
how to use them and what their security model is.

In addition to that, `<kern/kalloc.h>` provides a variable-size general purpose
allocator implemented as a collection of zones of fixed size, and overflowing to
`kernel_memory_allocate` for allocations larger than a few pages (32KB when this
document was being written but this is subject to change/tuning in the future).


The Core Kernel allocators rely on the following headers:
- `<kern/zalloc.h>` and `<kern/kalloc.h>` for its API surface, which most
  clients should find sufficient,
- `<kern/zalloc_internal.h>` and `<kern/zcache_internal.h>` for interfaces that
  need to be exported for introspection and implementation purposes, and is not
  meant for general consumption.

## TL;DR

This section will give a rapid decision tree of which allocation method to use,
and general best practices. The rest of the document goes into more details and
offers more information that can explain the rationale behind these
recommendations.

### Which allocator to use, and other advices

1. If you are allocating memory that is never freed, use `zalloc_permanent*`. If
   the allocation is larger than a page, then it will use
   `kernel_memory_allocate` with the `KMA_PERMANENT` flag on your behalf.
   The allocation is assumed to always succeed (this is mostly reserved for early
   allocations that need to scale with the configuration of the machine and
   cannot be decided at compile time), and will be zeroed.

2. If the memory you are allocating is temporary and will not escape the scope
   of the syscall it's used for, use `kheap_alloc` and `kheap_free` with the
   `KHEAP_TEMP` heap. Note that temporary paths should use `zalloc(ZV_NAMEI)`.

3. If the memory you are allocating will not hold pointers, and even more so
   when the content of that piece of memory can be directly influenced by
   user-space, then use `kheap_alloc` and `kheap_free` with the
   `KHEAP_DATA_BUFFERS` heap.

4. In general we prefer zalloc or kalloc interfaces, and would like to abandon
   any legacy MALLOC/FREE interfaces over time.

For all `kalloc` or `kheap_alloc` variants, these advices apply:

- If your allocation size is of fixed size, of a sub-page size, and done with
  the `Z_WAITOK` semantics (allocation can block), consider adding `Z_NOFAIL`,
- If you `bzero` the memory on allocation, prefer passing `Z_ZERO` which can be
  optimized away more often than not.

### Considerations for zones

Performance wise, it is problematic to make a zone when the kernel tends to have
less than several pages worth of elements allocated at all times (think commonly
200k+ objects). When a zone is underutilized, then fragmentation becomes a
problem.

Zones with a really high traffic of allocation and frees should consider using
zone caching, but this comes at a memory usage cost and needs to be evaluated.

Security wise, the following questions need answering:
- Is this type "interesting" to confuse with another, if yes, having a separate
  zone allows for usage of `zone_require()` and will by default sequester the
  virtual address space;
- Is this type holding user "bytes", if yes, then it might be interesting to use
  a zone view (like the `ZV_NAMEI` one for paths) instead;
- Is the type zeroed on allocation all the time? if yes, enabling
  `ZC_ZFREE_CLEARMEM` will likely be a really marginal incremental cost that can
  discover write-after-free bugs.

## Variants

There are several allocation wrappers in XNU, present for various reasons
ranging from additional accounting features (IOKit's `IONew`), conformance to
langauge requirements (C++ various `new` operators) or organical historical
reasons.

`zalloc` and `kalloc` are considered the primitive allocation interfaces which
are used to implement all the other ones.  The following table documents all
interfaces and their various properties.

<table>
  <tr>
    <th>Interface</th>
    <th>Core XNU</th>
    <th>Private Export</th>
    <th>Public Export</th>
    <th>Comments</th>
  </tr>
  <tr><th colspan="5">Core primitives</th></tr>
  <tr>
    <th>zalloc</th>
    <td>Yes</td>
    <td>Yes</td>
    <td>No</td>
    <td>
      The number of zones due to their implementation is limited.

      Until this limitation is lifted, general exposition to arbitrary
      kernel extensions is problematic.
    </td>
  </tr>
  <tr>
    <th>kheap_alloc</th>
    <td>Yes</td>
    <td>No</td>
    <td>No</td>
    <td>
      This is the true core implementation of `kalloc`, see documentation about
      kalloc heaps.
    </td>
  </tr>
  <tr>
    <th>kalloc</th>
    <td>Yes</td>
    <td>Yes, Redirected</td>
    <td>No</td>
    <td>
      In XNU, `kalloc` is equivalent to `kheap_alloc(KHEAP_DEFAULT)`.
      <br />
      In kernel extensions, `kalloc` is equivalent to `kheap_alloc(KHEAP_KEXT)`.
      <br />
      Due to legacy contracts where allocation and deallocation happen on
      different sides of the XNU/Kext boundary, `kfree` will allow to free to
      either heaps. New code should consider using the proper `kheap_*` variant
      instead.
    </td>
  </tr>

  <tr><th colspan="5">Popular wrappers</th></tr>
  <tr>
    <th>IOMalloc</th>
    <td>Yes</td>
    <td>Yes, Redirected</td>
    <td>Yes, Redirected</td>
    <td>
      `IOMalloc` is a straight wrapper around `kalloc` and behaves like
      `kalloc`. It does provide some debugging features integrated with `IOKit`
      and is the allocator that Drivers should use.
      <br/>
      Only kernel extensions that are providing core infrastructure
      (filesystems, sandbox, ...) and are out-of-tree core kernel components
      should use the primitive `zalloc` or `kalloc` directly.
    </td>
  </tr>
  <tr>
    <th>C++ new</th>
    <td>Yes</td>
    <td>Yes, Redirected</td>
    <td>Yes, Redirected</td>
    <td>
      C++'s various operators around `new` and `delete` are implemented by XNU.
      It redirects to the `KHEAP_KEXT` kalloc heap as there is no use of C++
      default operator new in Core Kernel.
      <br/>
      When creating a subclass of `OSObject` with the IOKit macros to do so, an
      `operator new` and `operator delete` is provided for this object that will
      anchor this type to the `KHEAP_DEFAULT` heap when the class is defined in
      Core XNU, or to the `KHEAP_KEXT` heap when the class is defined in a
      kernel extension.
    </td>
  </tr>
  <tr>
    <th>MALLOC</th>
    <td>Yes</td>
    <td>Obsolete, Redirected</td>
    <td>No</td>
    <td>
      This is a legacy BSD interface that functions mostly like `kalloc`.
      For kexts, `FREE()` will allow to free either to `KHEAP_DEFAULT` or
      `KHEAP_KEXT` due to legacy interfaces that allocate on one side of the
      kext/core kernel boundary and free on the other.
    </td>
  </tr>

  <tr><th colspan="5">Obsolete wrappers</th></tr>
  <tr>
    <th>mcache</th>
    <td>Yes</td>
    <td>Kinda</td>
    <td>Kinda</td>
    <td>
      The mcache/mbuf subsystem is mostly used by the BSD networking subsystem.
      Code that is not interacting with these interfaces should not adopt
      mcaches.
    </td>
  </tr>
  <tr>
    <th>OSMalloc</th>
    <td>No</td>
    <td>Obsolete, Redirected</td>
    <td>Obsolete, Redirected</td>
    <td>
      `<libkern/OSMalloc.h>` is a legacy subsystem that is no longer
      recommended. It provides extremely slow and non scalable accounting
      and no new code should use it. `IOMalloc` should be used instead.
    </td>
  </tr>
  <tr>
    <th>MALLOC_ZONE</th>
    <td>No</td>
    <td>Obsolete, Redirected</td>
    <td>No</td>
    <td>
      `MALLOC_ZONE` used to be a weird wrapper around `zalloc` but with poorer
      security guarantees. It has been completely removed from XNU and should
      not be used.
      <br/>
      For backward compatbility reasons, it is still exported, but behaves
      exactly like `MALLOC` otherwise.
    </td>
  </tr>
  <tr>
    <th>kern_os_*</th>
    <td>No</td>
    <td>Obsolete, Redirected</td>
    <td>Obsolete, Redirected</td>
    <td>
      These symbols used to back the implementation of C++ `operator new` and
      are only kept for backward compatibility reasons. Those should not be used
      by anyone directly.
    </td>
  </tr>
</table>


## The Zone allocator: concepts, performance and security

Zones are created with `zone_create()`, and really meant never to be destroyed.
Destructible zones are here for legacy reasons, and not all features are
available to them.

Zones allocate their objects from a specific fixed size map called the Zone Map.
This map is subdivided in a few submaps that provide different security
properties:

- the VA Restricted map: it is used by the VM subsystem only, and allows for
  extremely tight packing of pointers used by the VM subsystem. This submap
  doesn't use sequestering.
- the general map: it is used by default by zones, and on embedded
  defaults to using full VA sequestering (see below).
- the "bag of bytes" map: it is used for zones that provide various buffers
  whose content is under the control of user-space. Segregating these
  allocations from the other submaps closes attacks using such allocations to
  spray kernel objects that live in the general map.

It is worth noting that use of any allocation function in interrupt context is
never allowed in XNU, as none of our allocators are re-entrant and interrupt
safe.

### Basic features

`<kern/zalloc.h>` defines several flags that can be used to alter the blocking
behavior of `zalloc` and `kalloc`:

- `Z_NOWAIT` can be used to require a fully non blocking behavior, which can be
  used for allocations under spinlock and other preemption disabled contexts;
- `Z_NOPAGEWAIT` allows for the allocator to block (typically on mutexes),
  but not to wait for available pages if there are none;
- `Z_WAITOK` means that the zone allocator can wait and block.

It is worth noting that unless the zone is exhaustible or "special" (which is
mostly the case for VM zones), then `zalloc` will never fail (but might block
for arbitrarily long if the zone map is under a lot of pressure).  This is not
true of `kalloc` when the allocation is served by the VM.

It is worth noting that `Z_ZERO` is provided so that the allocation returned by
the allocator is always zeroed. This should be used instead of manual usage of
`bzero` as the zone allocator is able to optimize it away when certain security
features that already guarantee the zeroing are engaged.


### Zone Caching

Zones that have relatively fast allocation/deallocation patterns can use zone
caching (passing `ZC_CACHING`) to `zone_create()`. This enables per-CPU caches,
which hold onto several allocations per CPU. This should not be done lightly,
especially for zones holding onto large elements.

### Type confusion (Zone Sequestering and `zone_require()`)

In order to be slightly more resilient to Use after Free (UaF) bugs, XNU
provides two techniques:

- using the `ZC_SEQUESTER` flag to `zone_create()`;
- manual use of `zone_require()` or `zone_id_require()`.

The first form will cause the virtual address ranges that a given zone uses
to never be returned to the system, which essentially pins this address range
for holding allocations of this particular zone forever. When a zone is strongly
typed, it means that only objects of that particular type can ever be located
at this address.

`zone_require()` is an interface that can be used prior to memory use to assert
that the memory belongs to a given zone.

Both these techniques can be used to dramatically reduce type confusion bugs.
For example, the task zone uses both sequestering and judicious usage of
`zone_require()` in crucial parts which makes faking a `task_t` and using it
to confuse the kernel extremely difficult.

When `zone_require()` can be used exhaustively in choking points, then
sequestering is no longer necessary to protect this type. For example, the
`ipc_port_t`, will take the `ip_lock()` or an `ip_reference()` prior to any
interesting use. These primitives have been extended to include a
`zone_id_require()` (the fastest existing form of `zone_require()`) which gives
us an exhaustive protection. As a result, it allows us not to sequester the
ports zone. This is interesting because userspace can cause spikes of
allocations of ports and this protects us from zone map exhaustion or more
generally increase cost to describe the sequestered address space of this zone
due to a high peak usage.

### Usage of Zones in IOKit

IOKit is a subsystem that is often used by attackers, and reducing type
confusion attacks against it is desireable. For this purpose, XNU exposes the
ability to create a zone rather than being allocated in a kalloc heap.

Using the `OSDefineMetaClassAndStructorsWithZone` or any other
`OSDefineMetaClass.*WithZone` interface will cause the object's `operator new`
and `operator delete` to back the storage of these objects with zones. This is
available to first party kexts, and usage should be reserved to types that can
easily be allocated by user-space and in large quantities enough that the
induced fragmentation is acceptable.

### Auto-zeroing

A lot of bugs come from partially initialized data, or write-after-free.
To mitigate these issues, zones provide two level of protection:

- page clearing
- element clear on free (`ZC_ZFREE_CLEARMEM`).

Page clearing is used when new pages are added to the zone. The original version
of the zone allocator would cram pages into zones without changing their
content. Memory crammed into a zone will be cleared from its content.
This helps mitigate leaking/using uninitialized data.

Element clear on free is an increased protection that causes `zfree()` to erase
the content of elements when they are returned to the zone.  When an element is
allocated from a zone with this property set, then the allocator will check that
the element hasn't been tampered with before it is handed back. This is
particularly interesting when the allocation codepath always clears the returned
element: when using the `Z_ZERO` (resp. `M_ZERO`) with `zalloc` or `kalloc`
(resp. `MALLOC`), then the zone allocator knows not to issue this extraneous
zeroing.

`ZC_ZFREE_CLEARMEM` at the time this document was written was default for any
zone where elements are smaller than 2 cachelines.  This technique is
particularly interesting because things such as locks, refcounts or pointers
valid states can't be all zero. It makes exploitation of a Use-after-free more
difficult when this is engaged.

### Poisoning

The zone allocator also does statistical poisoning (see source for details).

It also always zeroes the first 2 cachelines of any allocation on free, when
`ZC_ZFREE_CLEARMEM` isn't engaged. It sometimes mitigates certain kind of linear
buffer overflows. It also can be leveraged by types that have refcounts or locks
if those are placed "early" in the type definition, as zero is not a valid value
for such concepts.

### Per-CPU allocations

The zone allocator provides `ZC_PERCPU` as a way to declare a per-cpu zone.
Allocations from this zone are returning NCPU elements with a known stride.

It is expected that such allocations are not performed in a rapid pattern, and
zone caching is not available for them.  (zone caching actually is implemented
on top of a per-cpu zone).

Usage of per-cpu zone should be limited to extremely performance sensitive
codepaths or global counters due to the enormous amplification factor on
many-core systems.

### Permanent allocations

The kernel sometimes needs to provide persistent allocations that depend on
parameters that aren't compile time constants, but will not vary over time (NCPU
is an obvious example here).

The zone subsystem provides a `zalloc_permanent*` family of functions that help
allocating memory in such a fashion in a very compact way.

Unlike the typical zone allocators, this allows for arbitrary sizes, in a
similar fashion to `kalloc`. These functions will never fail (if the allocation
fails, the kernel will panic), and always return zeroed memory. Trying to free
these allocations results in a kernel panic.


## kalloc: a heap of zones

Kalloc is a general malloc-like allocator that is backed by zones when the size
of the allocation is sub-page (actually smaller than 32K at the time this
document was written, but under KASAN or other memory debugging techniques, this
limit for the usable payload might actually be lower). Larger allocations use
`kernel_memory_allocate` (KMA).

The kernel calls the collection of zones that back kalloc a "kalloc heap", and
provides 3 builtin ones:

- `KHEAP_DEFAULT`, the "default" heap, is the one that serves `kalloc` in Core
  Kernel (XNU proper);
- `KHEAP_KEXT`, the kernel extension heap, is the one that serves `kalloc` in
  kernel extensions (see "redirected" symbols in the Variants table above);
- `KHEAP_DATA_BUFFERS` which is a special heap, which allocates out of the "User
  Data" submap, and is meant for allocation of payloads that hold no pointer and
  tend to be under the control of user space (paths, pipe buffers, OSData
  backing stores, ...).

In addition to that, the kernel provides an extra "magical" kalloc heap:
`KHEAP_TEMP`, it is for all purposes an alias of `KHEAP_DEFAULT` but enforces
extra semantics: allocations and deallocations out of this heap must be
performed "in scope". It is meant for allocations that are made to support a
syscall, and that will be freed before that syscall returns to user-space.

The usage of `KHEAP_TEMP` will ensure that there is no outstanding allocation at
various points (such as return-to-userspace) and will panic the system if this
property is broken. The `kheap_temp_debug=1` boot-arg can be used on development
kernels to debug such issues when the occur.

As far as security policies are concerned, the default and kext heap are fully
segregated per size-class. The data buffers heap is isolated in the user data
submaps, and hence can never produce adresses aliasing with any other kind of
allocations in the system.


## Accounting (Zone Views and Kalloc Heap Aliases)

The zone subsystem provides several accounting properties that are reported by
the `zprint(1)` command. Historically, some zones have been introduced to help
with accounting, to the cost of increased fragmentation (the more allocations
are issued from the same zone, the lower the fragmentation).  It is now possible
to define zone views and kalloc heap aliases, which are two similar concepts for
zones and kalloc heaps respectively.

Zone views are declared (in headers) and defined (in modules) with
`ZONE_VIEW_DECLARE` and `ZONE_VIEW_DEFINE`, and can be an alias either for
another regular zone, or a specific zone of a kalloc heap. This is for example
used for the `ZV_NAMEI` zone out of which temporary paths are allocated (this is
an alias to the `KHEAP_DATA_BUFFERS` 1024 bytes zone).  Extra accounting is
issued for these views and are also reported by `zprint(1)`.

In a similar fashion, `KALLOC_HEAP_DECLARE` and `KALLOC_HEAP_DEFINE` can be used
to declare a kalloc heap alias that gets its own accounting. It is particularly
useful to track leaks and various other things.

The accounting of zone and heap views isn't free (and has a per-CPU cost) and
should be used wisely. However, if the alternative is a fully separated zone,
then the memory cost of the accounting would likely be dwarfed by the
fragmentation cost of the new zone.

At this time, views can only be made by Core Kernel.

