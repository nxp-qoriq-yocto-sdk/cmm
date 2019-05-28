/*
*   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
*   Copyright 2016 NXP
*
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/

/*
--------------------------------------------------------------------
lookup2.c, by Bob Jenkins, December 1996, Public Domain.
hash(), hash2(), hash3, and mix() are externally useful functions.
Routines to test the hash are included if SELF_TEST is defined.
You can use this free for any purpose.  It has no warranty.

Obsolete.  Use lookup3.c instead, it is faster and more thorough.
--------------------------------------------------------------------
*/
/*
* source of the below macro and function defintion from the below link
* http://burtleburtle.net/bob/c/lookup2.c
*/

#ifndef __JHASH_H
#define __JHASH_H

#define __jhash_mix(a, b, c) \
{ \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12);  \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3);  \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
}


/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO      0x9e3779b9

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
static inline u_int32_t jhash(const void *key, u_int32_t length, u_int32_t initval)
{
        u_int32_t a, b, c, len;
        const u_int8_t *k = key;

        len = length;
        a = b = JHASH_GOLDEN_RATIO;
        c = initval;

        while (len >= 12) {
                a += (k[0] +((u_int32_t)k[1]<<8) +((u_int32_t)k[2]<<16) +((u_int32_t)k[3]<<24));
                b += (k[4] +((u_int32_t)k[5]<<8) +((u_int32_t)k[6]<<16) +((u_int32_t)k[7]<<24));
                c += (k[8] +((u_int32_t)k[9]<<8) +((u_int32_t)k[10]<<16)+((u_int32_t)k[11]<<24));

                __jhash_mix(a,b,c);

                k += 12;
                len -= 12;
        }

        c += length;
        switch (len) {
        case 11: c += ((u_int32_t)k[10]<<24);
        case 10: c += ((u_int32_t)k[9]<<16);
        case 9 : c += ((u_int32_t)k[8]<<8);
        case 8 : b += ((u_int32_t)k[7]<<24);
        case 7 : b += ((u_int32_t)k[6]<<16);
        case 6 : b += ((u_int32_t)k[5]<<8);
        case 5 : b += k[4];
        case 4 : a += ((u_int32_t)k[3]<<24);
        case 3 : a += ((u_int32_t)k[2]<<16);
        case 2 : a += ((u_int32_t)k[1]<<8);
        case 1 : a += k[0];
        };

        __jhash_mix(a,b,c);

        return c;
}

static inline u_int32_t jhash_3words(u_int32_t a, u_int32_t b, u_int32_t c, u_int32_t initval)
{
        a += JHASH_GOLDEN_RATIO;
        b += JHASH_GOLDEN_RATIO;
        c += initval;

        __jhash_mix(a, b, c);

        return c;
}

static inline u_int32_t jhash_2words(u_int32_t a, u_int32_t b, u_int32_t initval)
{
        return jhash_3words(a, b, 0, initval);
}

static inline u_int32_t jhash_1word(u_int32_t a, u_int32_t initval)
{
        return jhash_3words(a, 0, 0, initval);
}

#endif
