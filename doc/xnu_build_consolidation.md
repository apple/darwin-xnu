# XNU Build Consolidation

## Introduction and motivation

XNU is supported on approximately 20 different targets. Whilst in some cases the differences between two
given targets are small (e.g. when they both support the same ISA), XNU has traditionally required to have
separate builds in cases where the topology of the targets differ (for example, when they feature different
core/cluster counts or cache sizes). Similarly, SoC-specific fix-ups are usually conditionally compiled
based on the target.

Given the time it takes to compile all three different variants (release, debug and development) for each
supported SoC, usually several times a day for various teams across Apple, the goal of this project was to
reduce the number of existing builds, as well as to set up a simple framework that makes it easier to share
builds across different SoCs moving forward.

Although this effort could be extended to KEXTs, and hence lead to shared KernelCaches across devices, the
scope of this document only includes XNU. In cases where KEXTs also differ across targets, or perhaps the
required KEXTs are completely different in the first place, the kernel still needs to be linked
appropriately with different sets of KEXTs and hence KernelCaches cannot be shared.


## Changes required in XNU

The kernel itself is relatively SoC-agnostic, although strongly architecture-dependent; this is because most
of the SoC-specific aspects of the KernelCache are abstracted by the KEXTs. Things that pertain to the
kernel include:

* Number of cores/clusters in the system, their physical IDs and type.
* Addresses of PIO registers that are to be accessed from the XNU side.
* L1/L2 cache geometry parameters (e.g. size, number of set/ways).
* Just like other components, the kernel has its share of responsibility when it comes to setting up HID
registers and applying fix-ups at various points during boot or elsewhere at runtime.
* Certain kernel-visible architectural features are optional, which means that two same-generation SoCs may
still differ in their feature set.

All of these problems can be solved through a mix of relying more heavily on device tree information and
performing runtime checks. The latter is possible because both the ARM architecture and the Apple's
extensions provide r/o registers that can be checked at runtime to discover supported features as well as
various CPU-specific parameters.

### Obtaining cache geometry parameters at runtime

Although not often, the kernel may still require deriving, one way or another, parameters like cache sizes
and number of set/ways. XNU needs most of this information to perform set/way clean/invalidate operations.
Prior to this work, these values were hardcoded for each supported target in `proc_reg.h`, and used in
`caches_asm.s`. The ARM architecture provides the `CCSIDR_EL1` register, which can be used in conjunction
with `CSSELR_EL1` to select the target cache and obtain geometry information.


### Performing CPU/Revision-specific checks at runtime

CPU and revision checks may be required at various places, although the focus here has been the application
of tunables at boot time.

Tunables are often applied:

* On a specific core type of a specific SoC.
* On a subset of all of the CPU revisions.
* On all P-cores or all E-cores.

This has led in the past to a number of nested, conditionally-compiled blocks of code that are not easy to
understand or manage as new tunables are added or SoCs/revisions are deprecated.

The changes applied as part of this work focus mainly on:

1. Decoupling the tunable-application code from `start.s`.
2. Splitting the tunable-application code across different files, one per supported architecture (e.g.
`tunables_h7.h`, or `tunables_h11.h`).
3. Providing "templates" for the most commonly-used combinations of tunables.
4. Providing a family of assembly macros that can be used to conditionally execute code on a specific core
type, CPU ID, revision(s), or a combination of these.

All of the macros live in the 64-bit version of `proc_reg.h`, and are SoC-agnostic; they simply check the
`MIDR_EL1` register against a CPU revision that is passed as a parameter to the macro, where applicable.
Similarly, where a block of code is to be executed on a core type, rather than a specific core ID, a couple
of the provided macros can check this against `MPIDR_EL1`.


### Checking for feature compatibility at runtime

Some architectural features are optional, which means that, when disabled at compile-time, this may cause
two same-generation SoCs to diverge.


Rather than disabling features, and assuming this does not pose security risks or performance regressions,
the preferred approach is to compile them in, but perform runtime checks to enable/disable them, possibly in
early boot. The way these checks are performed varies from feature to feature (for example, VHE is an ARM
feature, and the ARM ARM specifies how it can be discovered). For Apple-specific features, these are all
advertised through the `AIDR_EL1` register. One of the changes is the addition of a function,
ml_feature_supported(), that may be used to check for the presence of a feature at runtime.


### Deriving core/cluster counts from device tree

One of the aspects that until now has been hardcoded in XNU is the system topology: number of cores/clusters
and their physical IDs. This effort piggybacks on other recent XNU changes which aimed to consolidate
topology-related information into XNU, by parsing it from the device tree and exporting it to KEXTs through
well-defined APIs.

Changes applied as part of the XNU consolidation project include:

* Extending the `ml_*` API to extract cluster information from the topology parser. New APIs include the following:
    * `ml_get_max_cluster_number()`
    * `ml_get_cluster_count()`
    * `ml_get_first_cpu_id()`
* Removing hardcoded core counts (`CPU_COUNT`) and cluster counts (`ARM_CLUSTER_COUNT`) from XNU, and
replacing them with `ml_*` calls.
* Similarly, deriving CPU physical IDs from the topology parser.


### Allocating memory that is core size/cluster size/cache size aligned

In some cases, certain statically-allocated arrays/structures need to be cache line-aligned, or have one
element per core or cluster. Whilst this information is not known precisely at compile time anymore, the
following macros have been added to provide a reasonably close upper bound:

* `MAX_CPUS`
* `MAX_CPU_CLUSTERS`
* `MAX_L2_CLINE`

These macros are defined in `board_config.h`, and should be set to the same value for a group of targets
sharing a single build. Note that these no longer reflect actual counts and sizes, and the real values need
to be queried at runtime through the `ml_` API.

The L1 cache line size is still hardcoded, and defined as `MMU_CLINE`. Since this value is always the same
and very often checked at various places across XNU and elsewhere, it made sense to keep it as a compile
time macro rather than relying on runtime checks.

### Restrictions on conditional compilation

Currently, a family of per-SoC macros are defined at build time to enable XNU to conditionally compile code
for different targets. These are named `ARM[64]_BOARD_CONFIG_[TARGET_NAME]`, and have historically been used
in different places across the kernel; for example, when applying tunables, various fixes, or enabling
disabling features. In order not to create divergences in the future across same-generation SoCs, but also
to keep the codebase consistent, the recommendation is to avoid the use of these macros whenever possible.

Instead, XNU itself defines yet another family of macros that are defined for all targets of a particular
generation. These are named after the P-CORE introduced by each (for example, `APPLEMONSOON`, or
`APPLEVORTEX`), and are preferred over the SoC-specific ones. Where a generation macro is not enough to
provide correctness (which happens, for example, when the code block at hand should not be executed on a
given SoC of the same family), appropriate runtime checks can be performed inside the conditionally-compiled
code block. `machine_read_midr()` and `get_arm_cpu_version()` may be used for this purpose.
