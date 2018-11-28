/*
 * Gatekeeper - DoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* 
 * Implementation of RHHH algorithm in Gatekeeper. 
 * 
 * The script is based on reserch paper on Randomized Hierarchical Heavy Hitters 
 * algorithm by Ran Ben Basat, Gil Einziger, Roy Friedman, Marcelo C. Luizelli 
 * and Erez Waisbard. https://arxiv.org/pdf/1707.06778.pdf.
 */

#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <math.h>

#include <rte_ring.h>

#include "gatekeeper_rhhh.h"
#include "space_saving.h"

#if NUM_V4_COUNTERS == 5 /* IPv4 byte heirarchies. */
/* Masks for IPv4 byte heirarchies. */
uint32_t mask_v4[NUM_V4_COUNTERS] = {
        0xFFFFFFFFu, 0xFFFFFF00u, 0xFFFF0000u, 0xFF000000u, 0x00000000u
};

uint8_t leveleps_v4[NUM_V4_COUNTERS] = { 32, 24, 16, 8, 0 };

#elif NUM_V4_COUNTERS == 33 /* IPv4 bit heirarchies. */
/* Mask for IPv4 bit heirarchies. */ 
uint32_t mask_v4[NUM_V4_COUNTERS] = { 
        0xFFFFFFFFu << 0, 0xFFFFFFFFu << 1, 0xFFFFFFFFu << 2,
        0xFFFFFFFFu << 3, 0xFFFFFFFFu << 4, 0xFFFFFFFFu << 5,
        0xFFFFFFFFu << 6, 0xFFFFFFFFu << 7, 0xFFFFFFFFu << 8,
        0xFFFFFFFFu << 9, 0xFFFFFFFFu << 10, 0xFFFFFFFFu << 11,
        0xFFFFFFFFu << 12, 0xFFFFFFFFu << 13, 0xFFFFFFFFu << 14,
        0xFFFFFFFFu << 15, 0xFFFFFFFFu << 16, 0xFFFFFFFFu << 17, 
        0xFFFFFFFFu << 18, 0xFFFFFFFFu << 19, 0xFFFFFFFFu << 20,
        0xFFFFFFFFu << 21, 0xFFFFFFFFu << 22, 0xFFFFFFFFu << 23,
        0xFFFFFFFFu << 24, 0xFFFFFFFFu << 25, 0xFFFFFFFFu << 26,
        0xFFFFFFFFu << 27, 0xFFFFFFFFu << 28, 0xFFFFFFFFu << 29,
        0xFFFFFFFFu << 30, 0xFFFFFFFFu << 31, 0x00000000u
};

uint8_t leveleps_v4[NUM_V4_COUNTERS] = {
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
        16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};
#endif /* IPv4 heirarchies. */

#if NUM_V6_COUNTERS == 17 /* IPv6 byte heirarchies. */
/* Mask for IPv6 byte heirarchies. */
uint8_t mask_v6[NUM_V6_COUNTERS][16] = {
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u}
};

uint8_t leveleps_v6[NUM_V6_COUNTERS] = { 64, 56, 48, 40, 32, 24, 16, 8, 0 };

#elif NUM_V6_COUNTERS == 129 /* IPv6 bit heirarchies. */
/* Mask for IPv6 bit heirarchies. */
uint8_t mask_v6[NUM_V6_COUNTERS][16] = {
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFEu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xFCu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xF8u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xF0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xE0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFEu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xFCu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xF8u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xF0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xE0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFEu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xFCu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xF8u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xF0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xE0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u},
        {0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u}
};

uint8_t leveleps_v6[NUM_V6_COUNTERS] = {
        64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 
        46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 
        28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 
        10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
};
#endif /* IPv6 heirarchies. */

/* TODO: Test the code for correctness. */

#ifndef VMULT
#define VMULT 1
#endif

#if VMULT>1
#define PROB
#endif

struct rte_ring *ip4_hhh;
struct rte_ring *ip6_hhh;

HeavyHitter *output_v4;
HeavyHitter *output_v6;
Descendant *Hp_table_v4;
Descendant *Hp_table_v6;

int ss_epsilon = 512;
int opspace;
int hpspace;
int numhit;
int numdesc;

#ifdef PROB
double ignoreProb;
double logIgnoreProb;
double minusQuantity;
int nrIgnore;
#endif

double dblmax(double a, double b) 
{
        return (a >= b ? a : b);
}

double two_to_the_k(int k) 
{
	k = k % 9;
        double ans = 1;        
	while (k > 0) 
        {
                ans *= 2; 
                k--;
        }
        return ans ;
}

int
rhhh_init(unsigned int socket_id, uint16_t proto, double prob) 
{
        int ret;
        int i;
        srand(time(0));

        #ifdef PROB
        ignoreProb = 1.0 - prob;
        logIgnoreProb = log(ignoreProb);
        minusQuantity = log(RAND_MAX) / logIgnoreProb;
        nrIgnore = log((double)rand()) / logIgnoreProb - minusQuantity;
        #endif
        if (proto == ETHER_TYPE_IPv4) {
                for(i = 0; i < NUM_V4_COUNTERS; i++) {
                        counter_ip4[i] = create_counter_table(socket_id, 
                                proto, i, max(ss_epsilon, 
                                two_to_the_k(leveleps_v4[i])));
                        if (counter_ip4[i] == NULL) {
                                ret = -1;
                                goto out;
                        }
                }
        } else if (proto == ETHER_TYPE_IPv6) {
                for(i = 0; i < NUM_V6_COUNTERS; i++) {
                        counter_ip6[i] = create_counter_table(socket_id, 
                                proto, i, max(ss_epsilon, 
                                two_to_the_k(leveleps_v6[i])));
                        if (counter_ip6[i] == NULL) {
                                ret = -1;
                                goto out;
                        }
                }
        } else {
                ret = -1;
                goto out;
        }

out:
        return ret;
}

void
rhhh_deinit(uint16_t proto) 
{
        int i;
        if (proto == ETHER_TYPE_IPv4) {
                for(i = 0; i < NUM_V4_COUNTERS; i++)
                        rte_hash_free(counter_ip4[i]);
        } else if (proto == ETHER_TYPE_IPv6) {
                for(i = 0; i < NUM_V6_COUNTERS; i++)
                        rte_hash_free(counter_ip6[i]);
        }
}

int
rhhh_update(unsigned int socket_id, struct ip_key *key) 
{
        int ret;
        
        #ifdef PROB
                if (nrIgnore--) return;
                nrIgnore = log((double)rand()) / logIgnoreProb - minusQuantity;
        #endif
        if (key->proto == ETHER_TYPE_IPv4) {
                short i = rand() % NUM_V4_COUNTERS;
		//printf("MASK = %d\n", i);
                #if DIMENSION == 1
                        key->k.v4.src.s_addr = key->k.v4.src.s_addr & 
                                mask_v4[i];
                #else
                        int src_ptr = 0, dst_ptr = 0;
                        src_ptr = i % NUM_V4_COUNTERS;
                        dst_ptr = i / NUM_V4_COUNTERS;
                        key->k.v4.src.s_addr = key->k.v4.src.s_addr & 
                                mask_v4[src_ptr];
                        key->k.v4.src.s_addr = key->k.v4.src.s_addr & 
                                mask_v4[dst_ptr];
                #endif
                ret = space_saving(socket_id, key->proto, 
                        key, counter_ip4[i]);
		//printf("Iterating\n");
		//SSiterate(counter_ip4[i], key->proto, 1);

        } else if (key->proto == ETHER_TYPE_IPv6) {
                short i = rand() % NUM_V6_COUNTERS;
                #if DIMENSION == 1
                        int j;
                        for(j = 0; j < 16; j++) {
                                uint8_t src_bits = key->k.v6.src.s6_addr[j];
                                src_bits = src_bits & mask_v6[i][j];
                                key->k.v6.src.s6_addr[j] = src_bits;
                        }
                #else
                        int src_ptr = 0, dst_ptr = 0, j;
                        src_ptr = i % NUM_V6_COUNTERS;
                        dst_ptr = i / NUM_V6_COUNTERS;
                        for(j = 0; j < 16; j++) {
                                uint8_t src_bits = key->k.v6.src.s6_addr[j];
                                uint8_t dst_bits = key->k.v6.dst.s6_addr[j]; 
                                src_bits = src_bits & mask_v6[src_ptr][j];
                                dst_bits = dst_bits & mask_v6[dst_ptr][j];
                                key->k.v6.src.s6_addr[j] = src_bits;
                                key->k.v6.dst.s6_addr[j] = dst_bits;
                        }
                #endif
                ret = space_saving(socket_id, key->proto, 
                        key, counter_ip6[i]);
        } else
                ret = -1;
        
        return ret;
}

static
struct rte_hash *
create_dblcounter(unsigned int socket_id, uint16_t proto, int dblcounter_id,
        int dblcounter_size)
{
        int ret;

	int key_len = proto == ETHER_TYPE_IPv4 ?
                2 * sizeof(struct in_addr) : 2 * sizeof(struct in6_addr);

	char dblcounter_name[64];
        ret = snprintf(dblcounter_name, sizeof(dblcounter_name), 
               "Double_Counter_%d_%d", proto, dblcounter_id);
        RTE_VERIFY(ret > 0 && ret < (int)sizeof(dblcounter_name));
        
	struct rte_hash_parameters dblcounter_params = {
		.name = dblcounter_name,
		.entries = dblcounter_size,
		.key_len = key_len,
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
		.reserved = 0,
		.socket_id = socket_id,
	};
        
        if (proto == ETHER_TYPE_IPv4) {
                struct rte_hash *dblcounter = rte_hash_create(
                                &dblcounter_params);
                if (dblcounter == NULL) {
                        RTE_LOG(ERR, HASH, "Double_counter_%d_%d cannot "
                                "be created!\n", proto, dblcounter_id);
                        ret = -1;
                }
                return dblcounter;
        }
        
        if (proto == ETHER_TYPE_IPv6) {
                struct rte_hash *dblcounter = rte_hash_create(
                                &dblcounter_params);
                if (dblcounter == NULL) {
                        RTE_LOG(ERR, HASH, "Double_Counter_%d_%d cannot "
                                "be created!\n", proto, dblcounter_id);
                        ret = -1;
                }
                return dblcounter;
        }

        return NULL;
}

extern int 
rhhh1D_v4_output(double threshold, unsigned int socket_id)
{
        int iter_ret, ret;
        struct ip_key *key;
        struct ip_data *element;
        uint32_t next = 0;
        int src_ptr;
	
        int htsize = 2048;
        struct rte_hash *dbl_counter = create_dblcounter(socket_id, 
                ETHER_TYPE_IPv4, 0, htsize);
        
#ifdef PROB
        double adjustedThreshold = 
                (1 - ignoreProb) * (threshold / ((double)NUM_V4_COUNTERS));
#else
        double adjustedThreshold = threshold / ((double) NUM_V4_COUNTERS);
#endif
     
	printf("Adjusted threshold = %f\n", adjustedThreshold);
        numhit = 0; 
        int output_space = 2;

        int level, j;
        unsigned long long * tmp;
        
        int dbl_cnt;
        int z = 4;

        output_v4 = (HeavyHitter *) calloc(sizeof(HeavyHitter), output_space);

        //struct rte_hash *ct_table[NUM_V4_COUNTERS];
        for (level = 0; level < NUM_V4_COUNTERS; level++) {
		printf("Iterating Counter #%d\n", level);		
		char ct_name[64];
		ret = snprintf(ct_name, sizeof(ct_name), "counter_hash_%d_%d",
			ETHER_TYPE_IPv4, level);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(ct_name));	

		//ct_table[level] = rte_hash_find_existing(ct_name);        	
		iter_ret = rte_hash_iterate(counter_ip4[level], (
                                const void **)&key, 
			(void **)&element, &next);
		while (iter_ret >= 0) {
			src_ptr = level;
		        printf("Src = %u Dst = %u\n", key->k.v4.src.s_addr, 
                                key->k.v4.dst.s_addr);
			int cnt = element->bkt_id;
		        if (cnt < adjustedThreshold) {
				iter_ret = rte_hash_iterate(counter_ip4[level], 
                                        (const void **)&key, (void **)&element, 
                                        &next);		        	
				continue;
			}
	   
                        uint64_t src = (key->k.v4.src.s_addr);
                        uint64_t src_key = (src << 32)|((uint64_t)level);
                        
                        ret = rte_hash_lookup_data(dbl_counter, 
                                (const void *)&src_key, (void **)&dbl_cnt);
                        if (ret < 0) {
				iter_ret = rte_hash_iterate(counter_ip4[level], 
                                        (const void **)&key, (void **)&element, 
                                        &next);
                                continue;
			}
                        
                        ret = rte_hash_del_key(dbl_counter, &src_key);
                        if (ret < 0) {
				RTE_LOG(ERR, HASH, "IP not found\n");
                                continue;
			}
                       
                        int freq;
#ifdef PROB
                        freq = (j-dbl_cnt)+(2*z*sqrt((1-ignoreProb)*2*j);
#else
                        freq = (j-dbl_cnt)+(2*z*sqrt(2*j));
#endif
                        if (freq >= adjustedThreshold) {
                                while (output_space <= numhit)
                                        output_space *= 2;
                                output_v4 = (HeavyHitter *)
                                        realloc (output_v4, 
					output_space*sizeof(HeavyHitter));
                                output_v4[numhit].key = *key;
                                output_v4[numhit].msk.v4.src_mask = level;
                                output_v4[numhit].upr_bnd = j;
                                output_v4[numhit].lwr_bnd = 
                                                        j-element->err;
				dbl_cnt = output_v4[numhit].lwr_bnd;
				numhit++;
                        }
                        
                        if (dbl_cnt > 0 && level+1 < NUM_V4_COUNTERS) {
                                uint64_t pkey = ((src&mask_v4[level+1]) <<32)|
                                                (level+1);
                                ret = rte_hash_add_key_data(dbl_counter,
                                        &pkey, (void **)&dbl_cnt);
                                if (ret < 0) {
					RTE_LOG(ERR, HASH, "IP not addeed\n"); 
                                        continue;
				}
                        }
			iter_ret = rte_hash_iterate(counter_ip4[level], 
                                (const void **)&key, (void **)&element, &next);
                }
		//free(ct_table[level]);
        }
	
        rte_hash_free(dbl_counter);
        output_v4 = (HeavyHitter *)realloc(output_v4, 
                (numhit)*sizeof(HeavyHitter));
        
	printf("\nNum of IPv4 heavy hitters = %d.\n", numhit);
	
        return ret;
out:
        RTE_LOG(ERR, HASH, "Heavy Hitter output could not be generated!\n");
        ret = -1;
        
}

extern int
calcPred2D_v4(struct ip_key *key, uint32_t src_mask, uint32_t dst_mask)
{
        int ret;
        int i, j, k, dblcount, src_msk_ptr, dst_msk_ptr, cntr;
        numdesc = 0;
        struct ip_key newIP;
        
        for(i = 0; i < numhit; i++) {
                uint32_t src = key->k.v4.src.s_addr;
                uint32_t dst = key->k.v4.dst.s_addr;
                uint32_t hhh_src = output_v4[i].key.k.v4.src.s_addr;
                uint32_t hhh_dst = output_v4[i].key.k.v4.dst.s_addr;
                uint32_t hhh_src_mask = mask_v4[output_v4[i].msk.v4.src_mask];
                uint32_t hhh_dst_mask = mask_v4[output_v4[i].msk.v4.dst_mask];
                
                if (
                        (src_mask & hhh_src_mask) == src_mask && 
                        (dst_mask & hhh_dst_mask) == dst_mask && 
                        (src & src_mask) == (hhh_src & src_mask) && 
                        (dst & dst_mask) == (hhh_dst & dst_mask)
                ) {
                        j = 0;
                        for(k = 0; k < numdesc; k++) {
                                uint32_t Hp_src = 
                                        Hp_table_v4[k].key.k.v4.src.s_addr;
                                uint32_t Hp_dst = 
                                        Hp_table_v4[k].key.k.v4.dst.s_addr;
                                uint32_t Hp_src_mask = 
                                        mask_v4[Hp_table_v4[k].msk.v4.src_mask];
                                uint32_t Hp_dst_mask = 
                                        mask_v4[Hp_table_v4[k].msk.v4.dst_mask];
                                hhh_src = output_v4[k].key.k.v4.src.s_addr;
                                hhh_dst = output_v4[k].key.k.v4.dst.s_addr;
                                hhh_src_mask = 
                                        mask_v4[output_v4[k].msk.v4.src_mask];
                                hhh_dst_mask = 
                                        mask_v4[output_v4[k].msk.v4.dst_mask];
                                
                                Hp_table_v4[j] = Hp_table_v4[k];
                                if (
                                        (src_mask&Hp_src_mask != src_mask) ||
                                        (dst_mask&Hp_dst_mask != dst_mask) ||
                                        (Hp_src&hhh_src_mask != 
                                                hhh_src&hhh_src_mask) ||
                                        (Hp_dst & hhh_dst_mask != 
                                                hhh_dst & hhh_dst_mask)
                                ) 
                                        j++;
                        }
                        numdesc = j;
                        Hp_table_v4[numdesc].msk.v4.src_mask = 
                                output_v4[i].msk.v4.src_mask;
                        Hp_table_v4[numdesc].msk.v4.dst_mask = 
                                output_v4[i].msk.v4.dst_mask;
                        Hp_table_v4[numdesc].key = output_v4[i].key;
                        numdesc++;
                        while (numdesc >= hpspace)
                                hpspace *= 2;
                        Hp_table_v4 = (Descendant *) realloc(
                                Hp_table_v4, sizeof(Descendant) * hpspace);
                }
        }

        dblcount = 0;
        for(i = 0; i < numdesc; i++) {
                dblcount += SSEstLow(counter_ip4[i], &Hp_table_v4[i].key);
        }

        for(i = 0; i < numdesc; i++) {
                uint32_t Hp_src1 = Hp_table_v4[i].key.k.v4.src.s_addr;
                uint32_t Hp_dst1 = Hp_table_v4[i].key.k.v4.dst.s_addr;
                uint32_t Hp_src_mask1 = mask_v4[Hp_table_v4[i].msk.v4.src_mask];
                uint32_t Hp_dst_mask1 = mask_v4[Hp_table_v4[i].msk.v4.dst_mask];
                for(j = i + 1; j < numdesc; j++) {
                        uint32_t Hp_src2 = Hp_table_v4[j].key.k.v4.src.s_addr;
                        uint32_t Hp_dst2 = Hp_table_v4[j].key.k.v4.dst.s_addr;
                        uint32_t Hp_src_mask2 = 
                                mask_v4[Hp_table_v4[j].msk.v4.src_mask];
                        uint32_t Hp_dst_mask2 = 
                                mask_v4[Hp_table_v4[j].msk.v4.dst_mask];
                        uint32_t src_msk = Hp_src_mask1 & Hp_src_mask2;
                        uint32_t dst_msk = Hp_dst_mask1 & Hp_dst_mask2;
                        uint32_t src_or = Hp_src1 | Hp_src2;
                        uint32_t dst_or = Hp_dst1 | Hp_dst2;
                        uint32_t src_msk_or = Hp_src_mask1 | Hp_src_mask2;
                        uint32_t dst_msk_or = Hp_dst_mask1 | Hp_dst_mask2;
                        
                        if (
                                (Hp_src1 & src_msk) != (Hp_src2 & src_msk) || 
                                (Hp_dst1 & dst_msk) != (Hp_dst2 & dst_msk)
                        ) {
                                /* There is no IP common to subnets i and j. */
                                continue;
                        }

			newIP.proto = ETHER_TYPE_IPv4;
                        newIP.k.v4.src.s_addr = src_or;
                        newIP.k.v4.dst.s_addr = dst_or;

			/* Compute the right mask for new IP. */
			src_msk_ptr = 0;
                        while (mask_v4[src_msk_ptr] != src_msk_or) {
                                dst_msk_ptr = 0; 
                                while (mask_v4[dst_msk_ptr] != dst_msk_or)
                                        dst_msk_ptr++;
                                src_msk_ptr++;
                        }
                        assert( (mask_v4[src_msk_ptr] == src_msk_or) && 
                                (mask_v4[dst_msk_ptr] == dst_msk_or));
                        
                        cntr = (src_msk_ptr * NUM_V4_COUNTERS) + dst_msk_ptr;
			dblcount -= SSEstUpp(counter_ip4[cntr], &newIP);
                }
        }
        return dblcount;
}

extern int
rhhh2D_v4_output(double threshold, unsigned int socket_id)
{
        int ret;
        int i, bkt_ptr, element_ptr, dblcount, src_ptr, dst_ptr;
        int z = 4; 
        numhit = 0;;

	struct counter_bucket* min_bkt = list_first_entry(&bkt_head_ip4, 
		struct counter_bucket, list);
        int min_bkt_id = min_bkt->bkt_id;

#ifdef PROB
        double adjustedThreshold = 
                (1 - ignoreProb) * (threshold / ((double)NUM_V4_COUNTERS));
#else
        double adjustedThreshold = threshold / ((double) NUM_V4_COUNTERS);
#endif

        output_v4 = (HeavyHitter *) calloc(opspace, sizeof(HeavyHitter));
        Hp_table_v4 = (Descendant *) calloc(hpspace, sizeof(Descendant));

        for(i = 0; i < NUM_V4_COUNTERS; i++) {
                struct counter_bucket *entry, *next;
                src_ptr = i / 5;
                dst_ptr = i % 5;
                list_for_each_entry_safe(entry, next, &bkt_head_ip4, list) {
                        struct rte_hash *bkt_ip4 = entry->bkt.bkt_ip4;
                        struct ip_key * key;
                        struct ip_data *element;
                        uint32_t next = 0;
                        while (1) {
                                ret = rte_hash_iterate(bkt_ip4, (const void **)
                                        &key, (void **)&element, &next);
                                if (ret < 0)
                                        break;
                                
                                int cnt = element->bkt_id;
                                if (cnt < adjustedThreshold)
                                        continue;
                                
                                dblcount = calcPred2D_v4(key, mask_v4[src_ptr], 
                                        mask_v4[dst_ptr]);

                                double freq;
#ifdef PROB
                                freq = (cnt - dblcount) + (2 * z * sqrt(
                                        (1 - ignoreProb) * 2 * dblcount);
#else
                                freq = (cnt - dblcount) + 
                                        (2 * z * sqrt(2 * dblcount));
#endif
                                if (freq >= adjustedThreshold) {
                                        while (opspace <= numhit)
                                                opspace *= 2;
                                        output_v4 = (HeavyHitter *)realloc(
                                                output_v4, 
                                                opspace*sizeof(HeavyHitter));
                                        output_v4[numhit].key = *key;
                                        output_v4[numhit].msk.v4.src_mask = i;
                                        output_v4[numhit].upr_bnd = cnt;
                                        output_v4[numhit].lwr_bnd = 
                                                cnt - element->err;
                                        numhit++;
                                }
                                
                        }
                }
        }

        free(Hp_table_v4);
        return ret;
}

extern int
rhhh1D_v6_output(double threshold, unsigned int socket_id)
{
        /* TODO : Implement 1D RHHH output function for IPV6. */
	int ret;
        //struct counter_bucket ct_bkt;
        //struct ip_key key;
        //struct ip_data element;
        //uint32_t next = 0;
        int src_ptr;
	double SSepsval = 0.001;
        
        int htsize = (((int)(1.0/SSepsval)) + 1) | 1;
        struct rte_hash *hashtable = create_dblcounter(socket_id, 
                ETHER_TYPE_IPv6, 0, htsize);
        
#ifdef PROB
        double adjustedThreshold = 
                (1 - ignoreProb) * (threshold / ((double)NUM_V6_COUNTERS));
#else
        double adjustedThreshold = threshold / ((double) NUM_V6_COUNTERS);
#endif
     
        numhit = 0; 
        int output_space = 2;

        int i, j, k;

        unsigned long long * tmp;
        
        int d_cnt;
        int z = 4;

        output_v6 = (HeavyHitter *) calloc(sizeof(HeavyHitter), output_space);
        
        for (i = 0; i < NUM_V6_COUNTERS; i++) {
                for (j = (int)adjustedThreshold; j < streamlen; j++) {
                        
                        struct counter_bucket *entry, *next;
		        src_ptr = i;
		        //dst_ptr = i % 5;
		        list_for_each_entry_safe(entry, next, &bkt_head_ip4, 
                                list) {
		                struct rte_hash *bkt_ip4 = entry->bkt.bkt_ip4;
		                struct ip_key *key;
		                struct ip_data *element;
		                uint32_t next = 0;
		                while (1) {
		                        ret = rte_hash_iterate(bkt_ip4, 
                                                (const void **)&key, 
                                                (void **)&element, &next);
		                        if (ret < 0)
		                                break;
		                        
					int cnt = element->bkt_id;
		                        if (cnt < adjustedThreshold)
		                                continue;
		                        
		                        //dblcount = calcPred1D(key, 
                                                //mask_v6[src_ptr], 
                                                //mask_v6[dst_ptr]);
	   				
					uint16_t src[16], src_key[16];

					for (k = 0; k < 16; k++) {
		                       		src[k] = 
                                                       (key->k.v6.src.s6_addr[k]);
		                        	src_key[k] = 
                                                        (src[k] << 8)|((uint16_t)i);
					}
		                        
		                        ret = rte_hash_lookup_data(hashtable, 
		                                (const void *)&src_key, 
                                                (void **)&d_cnt);
		                        if (ret < 0)
		                                continue;
		                        
		                        ret = rte_hash_del_key(hashtable, 
                                                &src_key);
		                        if (ret < 0)
		                                goto out;
		                       
		                        int freq;
	#ifdef PROB
		                        freq = (j - d_cnt) + (2 * z * 
                                                sqrt((1 - ignoreProb) * 2 * j));
	#else
		                        freq = (j - d_cnt) + (2 * z * 
                                                sqrt(2 * j));
	#endif
		                        if (freq >= adjustedThreshold) {
		                                while (output_space <= numhit)
		                                        output_space *= 2;
		                                output_v6 = (HeavyHitter *)
		                                        realloc (output_v6, 
							output_space * 
                                                        sizeof(HeavyHitter));
		                                output_v6[numhit].key = *key;
						int l;
						for(l = 0; l < 16; l++)		                                
							output_v6[numhit].
                                                        msk.v6.src_mask[l] = 
                                                        mask_v6[i][l];
		                                output_v6[numhit].upr_bnd = j;
		                                output_v6[numhit].lwr_bnd = 
		                                        j-element->err;
						d_cnt = output_v6[numhit].lwr_bnd;
						numhit++;
		                        }
		                        
		                        if (d_cnt > 0 && i+1 < NUM_V6_COUNTERS) 
                                        {
						uint16_t pkey[NUM_V6_COUNTERS];
						for(k = 0; k < 16; k++)
				                        pkey[k] = ((src[k] & 
                                                                (uint16_t)
                                                                mask_v6[i+1][k]) 
                                                                << 8)|(i+1);
		                                ret = rte_hash_add_key_data(
                                                        hashtable, &pkey, 
                                                        (void **)&d_cnt);
		                                if (ret < 0)
		                                        goto out;
		                        }
		                }
			}
                }
        }
	
        rte_hash_free(hashtable);
        output_v6 = (HeavyHitter *)realloc(output_v6, 
                (numhit) * sizeof(HeavyHitter));
        
        return ret;
out:
        RTE_LOG(ERR, HASH, "Heavy Hitter output could not be generated!\n");
        ret = -1;
}