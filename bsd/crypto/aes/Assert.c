/*	This module exists solely to check compile-time assertions.  It should be
	compiled when building the project, and building should be terminated if
	errors are encountered.  However, any object it produces need not be
	included in the build.
*/


#include <stddef.h>

#include "crypto/aes.h"
#include "Context.h"

/*	Declare CheckAssertion so that if any of the declarations below differ
	from it, the compiler will report an error.
*/
extern char CheckAssertion[1];

/*	Ensure that ContextKey is the offset of the ks member of the AES context
	structures.
*/
extern char CheckAssertion[ContextKey == offsetof(aes_encrypt_ctx, ks)];
extern char CheckAssertion[ContextKey == offsetof(aes_decrypt_ctx, ks)];
	/*	If these assertions fail, change the definition of ContextKey in
		Context.h to match the offset of the ks field.
	*/

/*	Ensure that ContextKeyLength is the offset of the inf member of the AES
	context structures.
*/
extern char CheckAssertion[ContextKeyLength == offsetof(aes_encrypt_ctx, inf)];
extern char CheckAssertion[ContextKeyLength == offsetof(aes_decrypt_ctx, inf)];
	/*	If these assertions fail, change the definition of ContextKeyLength in
		Context.h to match the offset of the inf field.
	*/
