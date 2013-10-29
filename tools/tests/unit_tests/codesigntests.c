#import <stdint.h>
#import <bsm/libbsm.h>
#import <System/sys/codesign.h>
#import <sys/errno.h>

#import <err.h>
#import <stdio.h>
#import <unistd.h>

int
get_blob(pid_t pid, int op)
{
    uint8_t header[8];
    unsigned int cnt;
    int rcent;

    for (cnt = 0; cnt < sizeof(header); cnt++) {
	rcent = csops(pid, op, header, 1);
	if (rcent != -1 && errno != ERANGE)
	    err(1, "errno != ERANGE for short header");
    }

    rcent = csops(pid, op, header, sizeof(header));
    if (rcent == -1 && errno == ERANGE) {
	uint32_t len, bufferlen, bufferlen2;
	    
	memcpy(&len, &header[4], 4);
	bufferlen = ntohl(len);
	if (bufferlen > 1024 * 1024)
	    errx(1, "invalid length on blob from kernel");
	else if (bufferlen == 0)
	    errx(1, "bufferlen == 0");
	else if (bufferlen < 8)
	    errx(1, "bufferlen <8 0");
	    
	uint8_t buffer[bufferlen + 1];
	    
	rcent = csops(pid, op, buffer, bufferlen - 1);
	if (rcent != -1 && errno != ERANGE)
	    errx(1, "csops with full buffer - 1 failed");

	rcent = csops(pid, op, buffer, bufferlen);
	if (rcent != 0)
	    errx(1, "csops with full buffer failed");
	    
	memcpy(&len, &buffer[4], 4);
	bufferlen2 = ntohl(len);

	if (op == CS_OPS_BLOB) {
		if (bufferlen2 > bufferlen)
			errx(1, "buffer larger on second try");
		if (bufferlen2 != bufferlen)
			warnx("buffer shrunk since codesign can't tell the right size to codesign_allocate");
	} else {
		if (bufferlen2 != bufferlen)
			errx(1, "buffer sizes different");
	}

	rcent = csops(pid, op, buffer, bufferlen + 1);
	if (rcent != 0)
	    errx(1, "csops with full buffer + 1 didn't pass");

	return 0;

    } else if (rcent == 0) {
        return 0;
    } else {
	return 1;
    }
}

int
main(int argc, const char * argv[])
{
    uint32_t status;
    int rcent;
    pid_t pid;
	
    pid = getpid();

    if (get_blob(pid, CS_OPS_ENTITLEMENTS_BLOB))
        errx(1, "failed to get entitlements");

    if (get_blob(0, CS_OPS_ENTITLEMENTS_BLOB))
        errx(1, "failed to get entitlements");

    if (get_blob(pid, CS_OPS_BLOB))
        errx(1, "failed to get blob");

    if (get_blob(0, CS_OPS_BLOB))
        errx(1, "failed to get blob");

    if (get_blob(pid, CS_OPS_IDENTITY))
        errx(1, "failed to get identity");

    if (get_blob(0, CS_OPS_IDENTITY))
        errx(1, "failed to get identity");

    rcent = csops(pid, CS_OPS_SET_STATUS, &status, sizeof(status) - 1);
    if (rcent == 0)
        err(1, "passed when passed in too short status buffer");

    status = htonl(CS_RESTRICT);
    rcent = csops(pid, CS_OPS_SET_STATUS, &status, sizeof(status));
    if (rcent != 0)
        errx(1, "failed to mark proc RESTRICTED");

    rcent = csops(pid, CS_OPS_MARKINVALID, NULL, 0);
    if (rcent != 0)
        errx(1, "failed to mark proc invalid");
    
    status = htonl(CS_VALID);
    rcent = csops(pid, CS_OPS_SET_STATUS, &status, sizeof(status));
    if (rcent == 0)
        errx(1, "managed set flags on an INVALID proc");

    if (!get_blob(pid, CS_OPS_ENTITLEMENTS_BLOB))
        errx(1, "got entitlements while invalid");

    if (!get_blob(pid, CS_OPS_IDENTITY))
        errx(1, "got identity");

    if (!get_blob(0, CS_OPS_IDENTITY))
        errx(1, "got identity");

    if (!get_blob(pid, CS_OPS_BLOB))
        errx(1, "got blob");

    return 0;
}
