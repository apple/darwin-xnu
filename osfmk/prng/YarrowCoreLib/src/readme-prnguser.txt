12345678901234567890123456789012345678901234567890123456789012345678901234567890

Description of User Routines in Prngcore
----------------------------------------------

This files describes routines in prngcore that are designed to be called by the
user (ie client apps). Those interested in the details of the library are 
directed to readme-prngcoder.

Files of interest in this directory
-----------------------------------

yarrow.h

Main header file (and the only one needed) for client apps.

userdefines.h

Header file with macros that can be defined to specify the system that this
code is being compiled on, as well as other details of the prng operation.

usersources.h

Header file containing the names of the various user sources of entropic data.
You can add/delete/rename sources by altering the entries in the enumeration.


PRNG Client Routines
--------------------

All major routines return the success/error value for their operation.

prngOutput(outbuf,outbuflen)

Writes outbuflen worth of "random" data to outbuf. This routine has
backtracking protection, but you should call prngAllowReseed whenever you can
spare the cycles to guarantee good output. 

prngStretch(inbuf,inbuflen,outbuf,outbuflen)

Takes inbuflen bytes of data from inbuf and turns it into outbuflen bytes of 
data stored in outbuf.

prngInput(inbuf,inbuflen,poolnum,estbits)

Takes inbuflen bytes of data from inbuf and places it in entropy pool poolnum.  
The user entropy pool names can be found in usersources.h (see above).

prngForceReseed(ticks)

Forces a reseed that lasts about ticks ticks long. Be very careful when using
this function to ensure that you do not produce a poor output state.  It is 
suggested that you instead use prngAllowReseed.

prngAllowReseed(ticks)

Will force a reseed if there is enough entropy. A reseed (of length ticks) 
will be done if the total entropy estimate, ignoring the K greatest sources,
is greater than THRESHOLD. Currently, K = 0 (a bad idea) and THRESHOLD = 100
(likely to remain so). These values can be found and edited in userdefines.h.
Will return PRNG_ERR_NOT_ENOUGH_ENTROPY if there is not enough entropy in the
pool at this time.

prngProcessSeedBuffer(buf,ticks)

Takes 20 bytes of data from buf and churns it into the entropy pool, and then
forces a reseed of length ticks. The first 20 bytes of output are then
returned in buf for future use with this function.  It is recommended that data
used with this function be stored very securely.

prngSlowPoll(pollsize)

Does a slow poll to collect a large amount of vaguely random data from the OS
itself.  The poll with collect at most pollsize bytes, and this parameter can
be used to control (approximately) the length of the poll. The collected data
is fed into the entropy pool.  After calling this function you may call either
allow (recommended) or force a reseed if desired.

--------

Any questions can be directed to the programmer (me), Ari Benbasat, at 
pigsfly@unixg.ubc.ca.  Comments would be greatly appreciated.  Please cc: all
e-mail to Bruce Schneier, John Kelsey and Chris Hall 
{schneier,kelsey,hall}@counterpane.com.  

Thank you.



i
