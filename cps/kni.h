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

#ifndef _GATEKEEPER_CPS_KNI_H_
#define _GATEKEEPER_CPS_KNI_H_

int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
int kni_change_if(uint8_t port_id, uint8_t if_up);
int init_kni(const char *kni_kmod_path, unsigned int num_kni);
void rm_kni(void);

#endif /* _GATEKEEPER_CPS_KNI_H_ */
