#include <stdint.h>

extern "C" {
uintptr_t
pass_trivial(uintptr_t x)
{
	return x;
}
uintptr_t
pass_complex(uintptr_t x)
{
	return x;
}
uintptr_t
_Z14return_trivialm(uintptr_t x)
{
	return x;
}
uintptr_t
_Z14return_complexm(uintptr_t x)
{
	return x;
}
}
