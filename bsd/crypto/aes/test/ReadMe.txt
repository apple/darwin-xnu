This directory contains file and shell scripts 

	tstaes.c
	makegenarm.sh
	makegenx86.sh
	makeoptx86.sh

that can be used to build executables. These executable are used to validate the implementation
and to benchmark the performance of the aes functions in the kernel. This directory also serves
as a development environment for porting of the aes functions to any new architectures.

On xnu-1699.20.6 (from which we add this work), the generic aes source code sits at bsd/crypto/aes/gen. The x86_64 
and i386 architectural optimization is given in bsd/crypto/aes/i386.

After making some code corrections (aes.h and most assembly code in i386), now you can build a test executable
that is functionally equivalent to aes in the kernel code.

To generate a test executable for the aes in x86_64/i386 kernel,

	$ makeoptx86.sh

This will build a test executable tstaesoptx86 (x86_64/i386). The executable will automatically detects the 
CPU clock rates. You specify the number of iterations and the number of 16-byte blocks for simulation. 
The executable generates (random number) the test data, and calls aes_encrypt_cbc to encrypt the plain data
into cipher data, and then calls aes_decrypt_cbc to decrypt cipher into decrypted data. Afterwards, it compares
the decrypted data against the plain data. Should there be a mismatch, the code breaks and exit. 
Otherwise, it measures the times the system spends on the 2 functions under test. Afterwards, it prints out
the performance profiling data.

On K5,

$ tstaesoptx86 1000 2560
device max CPU clock rate = 2659.00 MHz
40960 bytes per cbc call
 aes_encrypt_cbc : time elapsed =   220.24 usecs,  177.37 MBytes/sec,    14.30 cycles/byte
  best iteration : time elapsed =   218.30 usecs,  178.94 MBytes/sec,    14.17 cycles/byte
 worst iteration : time elapsed =   286.14 usecs,  136.51 MBytes/sec,    18.58 cycles/byte

 aes_decrypt_cbc : time elapsed =   199.85 usecs,  195.46 MBytes/sec,    12.97 cycles/byte
  best iteration : time elapsed =   198.17 usecs,  197.12 MBytes/sec,    12.86 cycles/byte
 worst iteration : time elapsed =   228.12 usecs,  171.23 MBytes/sec,    14.81 cycles/byte

On K5B (with aesni)

$ tstaesoptx86 1000 256    
device max CPU clock rate = 2400.00 MHz
4096 bytes per cbc call
 aes_encrypt_cbc : time elapsed =     6.69 usecs,  583.67 MBytes/sec,     3.92 cycles/byte
  best iteration : time elapsed =     6.38 usecs,  612.46 MBytes/sec,     3.74 cycles/byte
 worst iteration : time elapsed =     9.72 usecs,  401.96 MBytes/sec,     5.69 cycles/byte

 aes_decrypt_cbc : time elapsed =     2.05 usecs, 1902.65 MBytes/sec,     1.20 cycles/byte
  best iteration : time elapsed =     1.96 usecs, 1997.06 MBytes/sec,     1.15 cycles/byte
 worst iteration : time elapsed =     4.60 usecs,  849.00 MBytes/sec,     2.70 cycles/byte

You can also build a test executable using the generic source code for the i386/x86_64 architecture.

	$ makegenx86.sh

When run on K5,

$ tstaesgenx86 1000 2560   
device max CPU clock rate = 2659.00 MHz
40960 bytes per cbc call
 aes_encrypt_cbc : time elapsed =   278.05 usecs,  140.49 MBytes/sec,    18.05 cycles/byte
  best iteration : time elapsed =   274.63 usecs,  142.24 MBytes/sec,    17.83 cycles/byte
 worst iteration : time elapsed =   309.70 usecs,  126.13 MBytes/sec,    20.10 cycles/byte

 aes_decrypt_cbc : time elapsed =   265.43 usecs,  147.17 MBytes/sec,    17.23 cycles/byte
  best iteration : time elapsed =   262.20 usecs,  148.98 MBytes/sec,    17.02 cycles/byte
 worst iteration : time elapsed =   296.19 usecs,  131.88 MBytes/sec,    19.23 cycles/byte

We can see the current AES implementation in the x86_64 kernel has been improved from 17.83/17.02
down to 14.12/12.86 cycles/byte for aes_encrypt_cbc and aes_decrypt_cbc, respectively.


 --------- iOS ---------

Similarly, you can build a test executable for the aes in the armv7 kernel (which uses the generic source code)

	$ makegenarm.sh

Note that you need the iOS SDK installed. We can then copy this executable to iOS devices for simulation.

On N88,

iPhone:~ root# ./tstaesgenarm 1000 2560
device max CPU clock rate = 600.00 MHz
40960 bytes per cbc call
 aes_encrypt_cbc : time elapsed =  2890.18 usecs,   13.52 MBytes/sec,    42.34 cycles/byte
  best iteration : time elapsed =  2692.00 usecs,   14.51 MBytes/sec,    39.43 cycles/byte
 worst iteration : time elapsed = 18248.33 usecs,    2.14 MBytes/sec,   267.31 cycles/byte

 aes_decrypt_cbc : time elapsed =  3078.20 usecs,   12.69 MBytes/sec,    45.09 cycles/byte
  best iteration : time elapsed =  2873.33 usecs,   13.59 MBytes/sec,    42.09 cycles/byte
 worst iteration : time elapsed =  9664.79 usecs,    4.04 MBytes/sec,   141.57 cycles/byte

