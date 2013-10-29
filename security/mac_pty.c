#include <sys/vnode.h>
#include <sys/kauth.h>
#include <sys/param.h>
#include <sys/tty.h>
#include <security/mac_framework.h>
#include <security/mac_internal.h>

void
mac_pty_notify_grant(proc_t p, struct tty *tp, dev_t dev, struct label *label) {
	MAC_PERFORM(pty_notify_grant, p, tp, dev, label);
}

void
mac_pty_notify_close(proc_t p, struct tty *tp, dev_t dev, struct label *label) {
	MAC_PERFORM(pty_notify_close, p, tp, dev, label);
}
