Kernel Data Descriptors
=======================

This project allows for dynamic data to be passed from the kernel to userspace tools without binding them to particular version of
struct definition. The `libkdd` library provides convenient API for parsing and interpreting `kernel chunked data`.

The libkdd APIs are defined in [kdd.h](./kdd.h)

The `KCDATA` format
===================

The format for data is setup in a generic format as follows

Layout of data structure
------------------------

	|         8 - bytes         |
	|---------------------------|  ------ offset = 00
	|  type = MAGIC |  LENGTH   |  # BEGIN Header
	|            0              |
	|---------------------------|  ------ offset = 16
	|      type     |  size     |  # chunk header
	|          flags            |
	|---------------------------|  ------ offset = 32
	|           data            |  # arbitrary data (len=16)
	|___________data____________|
	|---------------------------|  ------ offset = 48
	|      type     |   size    |  # chunk header
	|          flags            |
	|---------------------------|  ------ offset = 64
	|           data            |  # arbitrary data (len=32)
	|           data            |
	|           data            |
	|___________data____________|
	|---------------------------|  ------ offset = 96
	|  type = END   |  size=0   |  # chunk header
	|            0              |


The type field describes what kind of data is passed. For example type = `TASK_CRASHINFO_UUID` means the following data is a uuid.
These types need to be defined in task_corpses.h for easy consumption by userspace inspection tools.

Some range of types is reserved for special types like ints, longs etc. A cool new functionality made possible with this
extensible data format is that kernel can decide to put more information as required without requiring user space tools to
re-compile to be compatible. The case of `rusage` struct versions could be introduced without breaking existing tools.

Feature description: Generic data with description
-------------------
Further more generic data with description is very much possible now. For example

	- kcdata_add_uint64_with_description(cdatainfo, 0x700, "NUM MACH PORTS");
	- and more functions that allow adding description.

The userspace tools can then look at the description and print the data even if they are not compiled with knowledge of the field apriori.

	Example data:
	0000  57 f1 ad de 00 00 00 00 00 00 00 00 00 00 00 00  W...............
	0010  01 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00  ........0.......
	0020  50 49 44 00 00 00 00 00 00 00 00 00 00 00 00 00  PID.............
	0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0040  9c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0050  01 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00  ........0.......
	0060  50 41 52 45 4e 54 20 50 49 44 00 00 00 00 00 00  PARENT PID......
	0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0080  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0090  ed 58 91 f1


Feature description: Container markers for compound data
------------------

If a given kernel data type is complex and requires adding multiple optional fields inside a container
object for a consumer to understand arbitrary data, we package it using container markers.

For example, the stackshot code gathers information and describes the state of a given task with respect
to many subsystems. It includes data such as io stats, vm counters, process names/flags and syscall counts.

	kcdata_add_container_marker(kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN, STACKSHOT_KCCONTAINER_TASK, task_uniqueid);
	// add multiple data, or add_<type>_with_description()s here

	kcdata_add_container_marker(kcdata_p, KCDATA_TYPE_CONTAINER_END, STACKSHOT_KCCONTAINER_TASK, task_uniqueid);


Feature description: Custom Data formats on demand
--------------------

With the self describing nature of format, the kernel provider can describe a data type (uniquely identified by a number) and use
it in the buffer for sending data. The consumer can parse the type information and have knowledge of describing incoming data.
Following is an example of how we can describe a kernel specific struct sample_disk_io_stats in buffer.

	struct sample_disk_io_stats {
	    uint64_t        disk_reads_count;
	    uint64_t        disk_reads_size;
	    uint64_t        io_priority_count[4];
	    uint64_t        io_priority_size;
	} __attribute__ ((packed));


	struct kcdata_subtype_descriptor disk_io_stats_def[] = {
	    {KCS_SUBTYPE_FLAGS_NONE, KC_ST_UINT64, 0 * sizeof(uint64_t), sizeof(uint64_t), "disk_reads_count"},
	    {KCS_SUBTYPE_FLAGS_NONE, KC_ST_UINT64, 1 * sizeof(uint64_t), sizeof(uint64_t), "disk_reads_size"},
	    {KCS_SUBTYPE_FLAGS_ARRAY, KC_ST_UINT64, 2 * sizeof(uint64_t), KCS_SUBTYPE_PACK_SIZE(4, sizeof(uint64_t)), "io_priority_count"},
	    {KCS_SUBTYPE_FLAGS_ARRAY, KC_ST_UINT64, (2 + 4) * sizeof(uint64_t), sizeof(uint64_t), "io_priority_size"},
	};

Now you can add this custom type definition into the buffer as
	kcdata_add_type_definition(kcdata_p, KCTYPE_SAMPLE_DISK_IO_STATS, "sample_disk_io_stats",
	         &disk_io_stats_def[0], sizeof(disk_io_stats_def)/sizeof(struct kcdata_subtype_descriptor));

