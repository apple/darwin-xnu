#include <sys/kpi_mbuf.h>

struct inpcb;

// Tag an mbuf on the way out with the edge flags from the inpcb
extern void ip_edgehole_mbuf_tag(struct inpcb *inp, mbuf_t m);

// Attach the edge flags to the inpcb
extern void ip_edgehole_attach(struct inpcb *inp);

// Called by the edge interface to determine if the edge interface
// should drop the packet. Will return 0 if the packet should continue
// to be processed or EPERM if ip_edgehole_filter swallowed the packet.
// When ip_edgehole_filter swallows a packet, it frees it and sets your
// pointer to it to NULL. isVV should be set to zero unless the edge
// interface in question is the visual voicemail edge interface.
extern int ip_edgehole_filter(mbuf_t *m, int isVV);
