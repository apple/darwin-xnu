/*
 *  ucode.h
 *
 *  Interface definitions for the microcode updater interface sysctl
 */

/* Intel defined microcode format */
struct intel_ucupdate {
	/* Header information */
	uint32_t header_version;
	uint32_t update_revision;
	uint32_t date;
	uint32_t processor_signature;
	uint32_t checksum;
	uint32_t loader_revision;
	uint32_t processor_flags;
	uint32_t data_size;
	uint32_t total_size;

	/* Reserved for future expansion */
	uint32_t reserved0;
	uint32_t reserved1;
	uint32_t reserved2;

	/* First word of the update data */
	uint32_t data;
};

extern int ucode_interface(uint64_t addr);
extern void ucode_update_wake(void);
