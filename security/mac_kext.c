#include <sys/param.h>
#include <sys/kauth.h>
#include <security/mac_framework.h>
#include <security/mac_internal.h>

int
mac_kext_check_load(kauth_cred_t cred, const char *identifier) {
	int error;

	MAC_CHECK(kext_check_load, cred, identifier);

	return (error);
}

int
mac_kext_check_unload(kauth_cred_t cred, const char *identifier) {
	int error;

	MAC_CHECK(kext_check_unload, cred, identifier);

	return (error);
}
