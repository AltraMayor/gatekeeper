/*
 * Gatekeeper - DDoS protection system.
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

#ifndef _GATEKEEPER_QID_H_
#define _GATEKEEPER_QID_H_

struct qid {
	/* The LIFO stack of IDs (indexes) available for use. */
	uint32_t *ids;

	/* The length of @ids. */
	uint32_t len;

	/*
	 * The index of the top of the stack.
	 * If the stack is empty, @top is @len.
	 */
	uint32_t top;
};

int qid_init(struct qid *qid, uint32_t len, const char *name, int socket);
void qid_free(struct qid *qid);
int qid_push(struct qid *qid, uint32_t id);
int qid_pop(struct qid *qid, uint32_t *p_id);

#endif /* _GATEKEEPER_QID_H_ */
