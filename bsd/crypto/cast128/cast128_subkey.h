/*
 * heavily modified by Tomomi Suzuki <suzuki@grelot.elec.ryukoku.ac.jp>
 */
/*
 * The CAST-128 Encryption Algorithm (RFC 2144)
 *
 * original implementation <Hideo "Sir MaNMOS" Morisita>
 * 1997/08/21
 */
/*
 * Copyright (C) 1997 Hideo "Sir MANMOS" Morishita
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Hideo "Sir MaNMOS" Morishita ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Hideo "Sir MaNMOS" Morishita BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef RFC2144_CAST_128_SUBKEY_H
#define RFC2144_CAST_128_SUBKEY_H

#define x0x1x2x3 buf[0]
#define x4x5x6x7 buf[1]
#define x8x9xAxB buf[2]
#define xCxDxExF buf[3]
#define z0z1z2z3 buf[4]
#define z4z5z6z7 buf[5]
#define z8z9zAzB buf[6]
#define zCzDzEzF buf[7]

#define byte0(x) (((x) >> 24))
#define byte1(x) (((x) >> 16) & 0xff)
#define byte2(x) (((x) >> 8) & 0xff)
#define byte3(x) (((x)) & 0xff)

#define x0 byte0(buf[0])
#define x1 byte1(buf[0])
#define x2 byte2(buf[0])
#define x3 byte3(buf[0])
#define x4 byte0(buf[1])
#define x5 byte1(buf[1])
#define x6 byte2(buf[1])
#define x7 byte3(buf[1])
#define x8 byte0(buf[2])
#define x9 byte1(buf[2])
#define xA byte2(buf[2])
#define xB byte3(buf[2])
#define xC byte0(buf[3])
#define xD byte1(buf[3])
#define xE byte2(buf[3])
#define xF byte3(buf[3])
#define z0 byte0(buf[4])
#define z1 byte1(buf[4])
#define z2 byte2(buf[4])
#define z3 byte3(buf[4])
#define z4 byte0(buf[5])
#define z5 byte1(buf[5])
#define z6 byte2(buf[5])
#define z7 byte3(buf[5])
#define z8 byte0(buf[6])
#define z9 byte1(buf[6])
#define zA byte2(buf[6])
#define zB byte3(buf[6])
#define zC byte0(buf[7])
#define zD byte1(buf[7])
#define zE byte2(buf[7])
#define zF byte3(buf[7])

#define circular_leftshift(x, y) ( ((x) << (y)) | ((x) >> (32-(y))) )

#endif

