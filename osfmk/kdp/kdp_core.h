/* Various protocol definitions 
 *  for the core transfer protocol, which is a variant of TFTP 
 */

/*
 * Packet types.
 */
#define	KDP_RRQ	  1			/* read request */
#define	KDP_WRQ	  2			/* write request */
#define	KDP_DATA  3			/* data packet */
#define	KDP_ACK	  4			/* acknowledgement */
#define	KDP_ERROR 5			/* error code */
#define KDP_SEEK  6                     /* Seek to specified offset */
#define KDP_EOF   7                     /* signal end of file */
struct	corehdr {
	short	th_opcode;		/* packet type */
	union {
		unsigned int	tu_block;	/* block # */
		unsigned int	tu_code;	/* error code */
		char	tu_rpl[1];	/* request packet payload */
	} th_u;
	char	th_data[1];		/* data or error string */
}__attribute__((packed));

#define	th_block	th_u.tu_block
#define	th_code		th_u.tu_code
#define	th_stuff	th_u.tu_rpl
#define	th_msg		th_data

/*
 * Error codes.
 */
#define	EUNDEF		0		/* not defined */
#define	ENOTFOUND	1		/* file not found */
#define	EACCESS		2		/* access violation */
#define	ENOSPACE	3		/* disk full or allocation exceeded */
#define	EBADOP		4		/* illegal TFTP operation */
#define	EBADID		5		/* unknown transfer ID */
#define	EEXISTS		6		/* file already exists */
#define	ENOUSER		7		/* no such user */

#define CORE_REMOTE_PORT 1069 /* hardwired, we can't really query the services file */

void kdp_panic_dump (void);

void abort_panic_transfer (void);

struct corehdr *create_panic_header(unsigned int request, const char *corename, unsigned length, unsigned block);

int kdp_send_panic_pkt (unsigned int request, char *corename, unsigned int length, void *panic_data);
