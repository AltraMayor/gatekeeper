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

#ifndef _GATEKEEPER_RHHH_H_
#define _GATEKEEPER_RHHH_H_

#include "space_saving.h"

#ifndef DIMENSION
#define DIMENSION 1
#endif

#ifndef NUM_V4_COUNTERS
#define NUM_V4_COUNTERS 5
#endif

#ifndef NUM_V6_COUNTERS
#define NUM_V6_COUNTERS 17
#endif

extern struct rte_hash *counter_ip4[NUM_V4_COUNTERS];
extern struct rte_hash *counter_ip6[NUM_V6_COUNTERS];

typedef struct heavyhitter {
        struct ip_key key;
        
        union {
                /* Mask for IPv4 packets */
                struct {
                        uint32_t src_mask;
                        uint32_t dst_mask;
                } v4;

                /* Mask for IPv6 packets */
                struct {
                        uint8_t src_mask[16];
                        uint8_t dst_mask[16];
                } v6;
        } msk;

        uint32_t upr_bnd;
        uint32_t lwr_bnd;
} HeavyHitter;

typedef struct descendant {
        struct ip_key key;
        union {
                /* Mask for IPv4 packet. */ 
                struct {
                        uint32_t src_mask;
                        uint32_t dst_mask;
                } v4;

                /* Mask for IPv6 packet. */
                struct {
                        uint8_t src_mask[16];
                        uint8_t dst_mask[16];
                } v6;
        } msk;
} Descendant;

double dblmax(double a, double b);

double two_to_the_k(int k);

extern int
rhhh_init(unsigned int socket_id, uint16_t proto, double prob);

void
rhhh_deinit(uint16_t proto);

extern int
rhhh_update(unsigned int socket_id, struct ip_key *key);

static
struct rte_hash *
create_dblcounter(unsigned int socket_id, uint16_t proto, int dblcounter_id,
        int dblcounter_size);

extern int 
rhhh1D_v4_output(double threshold, unsigned int socket_id);           
      
extern int
calcPred2D_v4(struct ip_key *key, uint32_t src_mask, uint32_t dst_mask);

extern int
rhhh2D_v4_output(double threshold, unsigned int socket_id);
 
extern int
rhhh1D_v6_output(double threshold, unsigned int socket_id);

#endif /* _GATEKEEPER_RHHH_H_ */ 
