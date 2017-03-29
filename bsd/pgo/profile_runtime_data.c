/*
 * This tells compiler_rt not to include userspace-specific stuff writing
 * profile data to a file.
 */
int __llvm_profile_runtime = 0;
