#include <darwintest.h>

#include <mach/mach_error.h>
#include <mach/mach_host.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.debugging"));

/*
 * The low 8 bits may be in use, so modify one
 * of the upper 8 bits to ensure round-tripping. 
 */
#define LIBTRACE_PRIVATE_DATA  0x01000000

extern void drop_priv(void);

static bool _needs_reset;
static uint32_t _original;

static uint32_t
_save_atm_diagnostic_flag(void)
{
    kern_return_t kr;
    kr = host_get_atm_diagnostic_flag(mach_host_self(), &_original);
    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_get_atm_diagnostic_flag()");
    T_LOG("Original ATM diagnostic flag: 0x%08x", _original);
    return _original;
}

static kern_return_t
_mutate_atm_diagnostic_flag(uint32_t v)
{
    T_LOG("Try to set ATM diagnostic flag to: 0x%08x", v);
    kern_return_t kr = host_set_atm_diagnostic_flag(mach_host_self(), v);
    if (kr == KERN_SUCCESS) _needs_reset = true;
    return kr;
}

static void
_reset_atm_diagnostic_flag(void)
{
    if (!_needs_reset) return;
    T_LOG("Reset ATM diagnostic flag to: 0x%08x", _original);
    kern_return_t kr;
    kr = host_set_atm_diagnostic_flag(mach_host_self(), _original);
    if (kr != KERN_SUCCESS) {
        T_ASSERT_FAIL("host_set_atm_diagnostic_flag() failed: %s",
                mach_error_string(kr));
    }
}

T_DECL(toggle_atm_diagnostic_flag,
        "change the atm_diagnostic_flag, which should use the commpage",
        T_META_ASROOT(true))
{
    T_ATEND(_reset_atm_diagnostic_flag);
    uint32_t f = _save_atm_diagnostic_flag();
    f ^= LIBTRACE_PRIVATE_DATA;
    kern_return_t kr = _mutate_atm_diagnostic_flag(f);
    if (kr == KERN_NOT_SUPPORTED) {
        T_SKIP("Seems ATM is disabled on this platform. "
                "Ignoring host_set_atm_diagnostic_flag functionality. "
                "Bailing gracefully.");
    }
    T_EXPECT_MACH_SUCCESS(kr, "Set atm_diagnostic_flag");
}

T_DECL(unprivileged_atm_diagnostic_flag,
        "expect to fail to set the atm_diagnostic_flag",
        T_META_ASROOT(false))
{
    drop_priv();
    T_ATEND(_reset_atm_diagnostic_flag);
    uint32_t f = _save_atm_diagnostic_flag();
    f ^= LIBTRACE_PRIVATE_DATA;
    kern_return_t kr = _mutate_atm_diagnostic_flag(f);
    T_EXPECT_MACH_ERROR(KERN_INVALID_ARGUMENT, kr,
            "Deny change to atm_diagnostic_flag");
}
