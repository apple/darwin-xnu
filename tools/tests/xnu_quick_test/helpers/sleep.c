/* Helper binary for the execve tests. Added for PR-4607285 */
#include <unistd.h>
int main()
{
	sleep(120);
}
