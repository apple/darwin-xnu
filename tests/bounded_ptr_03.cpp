//
// Make sure that the forward declaration header can be included in C++03.
//

#include <libkern/c++/bounded_ptr_fwd.h>
#include <darwintest.h>

T_DECL(fwd_decl_cxx03, "bounded_ptr.fwd_decl.cxx03") {
	T_PASS("bounded_ptr.fwd_decl.cxx03 compiled successfully");
}
