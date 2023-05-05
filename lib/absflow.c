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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

#include "memblock.h"
#include "gatekeeper_main.h"
#include "gatekeeper_lls.h" /* Needed for struct icmpv6_hdr. */
#include "gatekeeper_absflow.h"

struct buf_str {
	char   *buf;
	size_t size;
};

static int
bstr_append(struct buf_str *bstr, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static int
bstr_append(struct buf_str *bstr, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vsnprintf(bstr->buf, bstr->size, format, ap);
	va_end(ap);

	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(): errno=%i: %s\n",
			__func__, -ret, strerror(-ret));
		return ret;
	}

	if (likely(ret < (int)bstr->size)) {
		bstr->buf = RTE_PTR_ADD(bstr->buf, ret);
		bstr->size -= ret;
		return 0;
	}

	G_LOG(ERR, "%s(): buffer size (= %zu) is less than %i bytes\n",
		__func__, bstr->size, ret);
	return -EINVAL;
}

typedef int (*check_flow_item_spec_func)(const void *item_spec,
	const void *item_mask);
typedef int (*check_flow_item_mask_func)(const void *item_mask);

static int
check_flow_item(const struct rte_flow_item *item, const char *name,
	check_flow_item_spec_func spec_f, check_flow_item_mask_func mask_f)
{
	int ret;

	if (unlikely(item->spec == NULL)) {
		G_LOG(ERR, "%s(%s): .spec cannot be NULL\n",
			__func__, name);
		return -EINVAL;
	}

	if (unlikely(item->last != NULL)) {
		G_LOG(ERR, "%s(%s): .last is not implemented\n",
			__func__, name);
		return -ENOTSUP;
	}

	if (unlikely(item->mask == NULL)) {
		G_LOG(ERR, "%s(%s): .mask cannot be NULL\n",
			__func__, name);
		return -EINVAL;
	}

	ret = mask_f(item->mask);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): .mask is not valid (errno=%i): %s\n",
			__func__, name, -ret, strerror(-ret));
		return ret;
	}

	ret = spec_f(item->spec, item->mask);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): .spec is not valid (errno=%i): %s\n",
			__func__, name, -ret, strerror(-ret));
		return ret;
	}

	return 0;
}

static bool
is_ether_addr_zero(const struct rte_ether_addr *addr)
{
	const struct rte_ether_addr zero = {};
	return memcmp(addr->addr_bytes, zero.addr_bytes,
		sizeof(addr->addr_bytes)) == 0;
}

static int
check_eth_zeros(const struct rte_flow_item_eth *eth)
{
	if (unlikely(is_ether_addr_zero(&eth->dst))) {
		G_LOG(ERR, "%s(): .dst must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(is_ether_addr_zero(&eth->src))) {
		G_LOG(ERR, "%s(): .src must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(eth->has_vlan)) {
		G_LOG(ERR, "%s(): .has_vlan must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(eth->reserved != 0)) {
		G_LOG(ERR, "%s(): .reserved must be zero\n", __func__);
		return -ENOTSUP;
	}
	return 0;
}

static int
check_eth_item_spec(const void *item_spec, const void *item_mask)
{
	const struct rte_flow_item_eth *eth_spec = item_spec;
	const struct rte_flow_item_eth *eth_mask = item_mask;

	int ret = check_eth_zeros(eth_spec);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely((eth_spec->type & ~eth_mask->type) != 0)) {
		G_LOG(ERR, "%s(): .type=0x%x/0x%x has at least an invalid bit: 0x%x\n",
			__func__, rte_be_to_cpu_16(eth_spec->type),
			rte_be_to_cpu_16(eth_mask->type),
			rte_be_to_cpu_16(eth_spec->type & ~eth_mask->type));
		return -EINVAL;
	}
	return 0;
}

static int
check_eth_item_mask(const void *item_mask)
{
	const struct rte_flow_item_eth *eth_mask = item_mask;

	int ret = check_eth_zeros(item_mask);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely(eth_mask->type == 0)) {
		G_LOG(ERR, "%s(): .type is zero; the Ethernet item has no function\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

static inline int
check_eth_item(const struct rte_flow_item *item)
{
	return check_flow_item(item, __func__,
		check_eth_item_spec, check_eth_item_mask);
}

static int
ethertype_str(struct buf_str *bstr, uint16_t ether_type)
{
	const char *str;

	switch (ether_type) {
	case RTE_ETHER_TYPE_IPV4:
		str = "IPv4";
		break;
	case RTE_ETHER_TYPE_IPV6:
		str = "IPv6";
		break;
	case RTE_ETHER_TYPE_ARP:
		str = "ARP";
		break;
	default:
		return bstr_append(bstr, "EtherType=0x%x", ether_type);
	}

	return bstr_append(bstr, "%s", str);
}

static int
pattern_eth(struct buf_str *bstr, const struct rte_flow_item *item)
{
	const struct rte_flow_item_eth *eth_spec;
	const struct rte_flow_item_eth *eth_mask;

	int ret = check_eth_item(item);
	if (unlikely(ret < 0))
		return ret;

	eth_spec = item->spec;
	eth_mask = item->mask;
	if (eth_mask->type == 0xFFFF)
		return ethertype_str(bstr, rte_be_to_cpu_16(eth_spec->type));
	return bstr_append(bstr, "EtherType=0x%x/0x%x",
		rte_be_to_cpu_16(eth_spec->type),
		rte_be_to_cpu_16(eth_mask->type));
}

static int
check_ipv4_zeros(const struct rte_flow_item_ipv4 *ipv4_item)
{
	const struct rte_ipv4_hdr *ipv4_hdr = &ipv4_item->hdr;

	if (unlikely(ipv4_hdr->version_ihl != 0)) {
		G_LOG(ERR, "%s(): .hdr.version_ihl must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv4_hdr->type_of_service != 0)) {
		G_LOG(ERR, "%s(): .hdr.type_of_service must be zero\n",
			__func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv4_hdr->total_length != 0)) {
		G_LOG(ERR, "%s(): .hdr.total_length must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv4_hdr->packet_id != 0)) {
		G_LOG(ERR, "%s(): .hdr.packet_id must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv4_hdr->fragment_offset != 0)) {
		G_LOG(ERR, "%s(): .hdr.fragment_offset must be zero\n",
			__func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv4_hdr->time_to_live != 0)) {
		G_LOG(ERR, "%s(): .hdr.time_to_live must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv4_hdr->hdr_checksum != 0)) {
		G_LOG(ERR, "%s(): .hdr.hdr_checksum must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv4_hdr->src_addr != 0)) {
		G_LOG(ERR, "%s(): .hdr.src_addr must be zero\n", __func__);
		return -ENOTSUP;
	}
	return 0;
}

/*
 * ATTENTION
 * If this function is updated, also update the following functions:
 * next_proto_id_str() and eval_l4_proto().
 */
static int
l4_min_header_length(uint8_t next_proto_id)
{
	switch (next_proto_id) {
	case IPPROTO_ICMP:
		/*
		 * The minimum ICMPv4 header size is the 8 bytes
		 * defined in struct rte_icmp_hdr (RFC 792).
		 */
		return sizeof(struct rte_icmp_hdr);
	case IPPROTO_IPIP:
		return sizeof(struct rte_ipv4_hdr);
	case IPPROTO_TCP:
		return sizeof(struct rte_tcp_hdr);
	case IPPROTO_UDP:
		return sizeof(struct rte_udp_hdr);
	case IPPROTO_IPV6:
		return sizeof(struct rte_ipv6_hdr);
	case IPPROTO_ICMPV6:
		/*
		 * The minimum ICMPv6 header size is the 4 bytes
		 * defined in struct icmpv6_hdr (RFC 4443).
		 */
		return sizeof(struct icmpv6_hdr);

	default:
		return -ENOTSUP;
	}
}

static int
check_ipv4_item_spec(const void *item_spec, const void *item_mask)
{
	const struct rte_flow_item_ipv4 *ipv4_spec = item_spec;
	const struct rte_flow_item_ipv4 *ipv4_mask = item_mask;

	int ret = check_ipv4_zeros(ipv4_spec);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely((ipv4_spec->hdr.next_proto_id &
			~ipv4_mask->hdr.next_proto_id) != 0)) {
		G_LOG(ERR, "%s(): .hdr.next_proto_id=0x%x/0x%x has at least an invalid bit: 0x%x\n",
			__func__, ipv4_spec->hdr.next_proto_id,
			ipv4_mask->hdr.next_proto_id,
			ipv4_spec->hdr.next_proto_id &
				~ipv4_mask->hdr.next_proto_id);
		return -EINVAL;
	}

	if (unlikely(ipv4_mask->hdr.next_proto_id != 0 &&
			l4_min_header_length(ipv4_spec->hdr.next_proto_id)
				< 0)) {
		G_LOG(ERR, "%s(): .hdr.next_proto_id=%i is not supported\n",
			__func__, ipv4_spec->hdr.next_proto_id);
		return -ENOTSUP;
	}

	if (unlikely((ipv4_spec->hdr.dst_addr & ~ipv4_mask->hdr.dst_addr)
			!= 0)) {
		G_LOG(ERR, "%s(): .hdr.dst_addr has at least an invalid bit\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

static int
check_ipv4_item_mask(const void *item_mask)
{
	const struct rte_flow_item_ipv4 *ipv4_mask = item_mask;

	int ret = check_ipv4_zeros(ipv4_mask);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely(ipv4_mask->hdr.next_proto_id != 0 &&
			ipv4_mask->hdr.next_proto_id != 0xFF)) {
		/* l4_min_header_length() requires full mask. */
		G_LOG(ERR, "%s(): .hdr.next_proto_id must be either zero or full mask\n",
			__func__);
		return -EINVAL;
	}

	if (unlikely(ipv4_mask->hdr.next_proto_id == 0 &&
			ipv4_mask->hdr.dst_addr == 0)) {
		G_LOG(ERR, "%s(): .hdr.next_proto_id and .hdr.dst_addr are zeros; the IPv4 item has no function\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

static inline int
check_ipv4_item(const struct rte_flow_item *item)
{
	return check_flow_item(item, __func__,
		check_ipv4_item_spec, check_ipv4_item_mask);
}

static int
next_proto_id_str(struct buf_str *bstr, uint8_t next_proto_id)
{
	const char *str;

	switch (next_proto_id) {
	case IPPROTO_ICMP:
		str = "ICMPv4";
		break;
	case IPPROTO_IPIP:
		str = "IPv4";
		break;
	case IPPROTO_TCP:
		str = "TCP";
		break;
	case IPPROTO_UDP:
		str = "UDP";
		break;
	case IPPROTO_IPV6:
		str = "IPv6";
		break;
	case IPPROTO_ICMPV6:
		str = "ICMPv6";
		break;

	default:
		return bstr_append(bstr, "IPProto=0x%x", next_proto_id);
	}

	return bstr_append(bstr, "%s", str);
}

static int
bstr_inet_ntop(struct buf_str *bstr, int af, const void *src)
{
	size_t addr_len;

	if (unlikely(inet_ntop(af, src, bstr->buf, bstr->size)
			== NULL)) {
		int saved_errno = errno;
		G_LOG(ERR, "%s(): inet_ntop(%i) failed (errno=%i): %s\n",
			__func__, af, saved_errno, strerror(saved_errno));
		bstr->buf[0] = '\0';
		return -saved_errno;
	}

	addr_len = strlen(bstr->buf);
	bstr->buf = RTE_PTR_ADD(bstr->buf, addr_len);
	bstr->size -= addr_len;
	return 0;
}

static inline int
ipv4_str(struct buf_str *bstr, rte_be32_t dst_addr)
{
	return bstr_inet_ntop(bstr, AF_INET, &dst_addr);
}

static int
pattern_ipv4(struct buf_str *bstr, const struct rte_flow_item *item)
{
	const struct rte_flow_item_ipv4 *ipv4_spec;
	const struct rte_flow_item_ipv4 *ipv4_mask;

	int ret = check_ipv4_item(item);
	if (unlikely(ret < 0))
		return ret;

	ipv4_spec = item->spec;
	ipv4_mask = item->mask;

	/* Destination address and mask. */
	ret = bstr_append(bstr, "dst=");
	if (unlikely(ret < 0))
		return ret;
	ret = ipv4_str(bstr, ipv4_spec->hdr.dst_addr);
	if (unlikely(ret < 0))
		return ret;
	if (ipv4_mask->hdr.dst_addr != 0xFFFFFFFF) {
		ret = bstr_append(bstr, "/");
		if (unlikely(ret < 0))
			return ret;
		ret = ipv4_str(bstr, ipv4_mask->hdr.dst_addr);
		if (unlikely(ret < 0))
			return ret;
	}

	/* Next protocol. */
	ret = bstr_append(bstr, " ");
	if (unlikely(ret < 0))
		return ret;
	if (ipv4_mask->hdr.next_proto_id == 0xFF)
		return next_proto_id_str(bstr, ipv4_spec->hdr.next_proto_id);
	return bstr_append(bstr, "IPProto=0x%x/0x%x",
		ipv4_spec->hdr.next_proto_id, ipv4_mask->hdr.next_proto_id);
}

static bool
is_ipv6_addr_zero(const uint8_t *addr)
{
	const struct in6_addr zero = {};
	return memcmp(addr, zero.s6_addr, sizeof(zero)) == 0;
}

static int
check_ipv6_zeros(const struct rte_flow_item_ipv6 *ipv6_item)
{
	const struct rte_ipv6_hdr *ipv6_hdr;

	if (unlikely(ipv6_item->has_hop_ext)) {
		G_LOG(ERR, "%s(): .has_hop_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_route_ext)) {
		G_LOG(ERR, "%s(): .has_route_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_frag_ext)) {
		G_LOG(ERR, "%s(): .has_frag_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_auth_ext)) {
		G_LOG(ERR, "%s(): .has_auth_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_esp_ext)) {
		G_LOG(ERR, "%s(): .has_esp_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_dest_ext)) {
		G_LOG(ERR, "%s(): .has_dest_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_mobil_ext)) {
		G_LOG(ERR, "%s(): .has_mobil_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_hip_ext)) {
		G_LOG(ERR, "%s(): .has_hip_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->has_shim6_ext)) {
		G_LOG(ERR, "%s(): .has_shim6_ext must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_item->reserved)) {
		G_LOG(ERR, "%s(): .reserved must be zero\n", __func__);
		return -ENOTSUP;
	}

	ipv6_hdr = &ipv6_item->hdr;
	if (unlikely(ipv6_hdr->vtc_flow)) {
		G_LOG(ERR, "%s(): .hdr.vtc_flow must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_hdr->payload_len)) {
		G_LOG(ERR, "%s(): .hdr.payload_len must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(ipv6_hdr->hop_limits)) {
		G_LOG(ERR, "%s(): .hdr.hop_limits must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(is_ipv6_addr_zero(ipv6_hdr->src_addr))) {
		G_LOG(ERR, "%s(): .hdr.src_addr must be zero\n", __func__);
		return -ENOTSUP;
	}
	return 0;
}

static int
check_ipv6_item_spec(const void *item_spec, const void *item_mask)
{
	const struct rte_flow_item_ipv6 *ipv6_spec = item_spec;
	const struct rte_flow_item_ipv6 *ipv6_mask = item_mask;
	unsigned int i;

	int ret = check_ipv6_zeros(ipv6_spec);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely((ipv6_spec->hdr.proto & ~ipv6_mask->hdr.proto) != 0)) {
		G_LOG(ERR, "%s(): .hdr.proto=0x%x/0x%x has at least an invalid bit: 0x%x\n",
			__func__, ipv6_spec->hdr.proto, ipv6_mask->hdr.proto,
			ipv6_spec->hdr.proto & ~ipv6_mask->hdr.proto);
		return -EINVAL;
	}

	if (unlikely(ipv6_mask->hdr.proto != 0 &&
			l4_min_header_length(ipv6_spec->hdr.proto) < 0)) {
		G_LOG(ERR, "%s(): .hdr.proto=%i is not supported\n",
			__func__, ipv6_spec->hdr.proto);
		return -ENOTSUP;
	}

	for (i = 0; i < RTE_DIM(ipv6_spec->hdr.dst_addr); i++) {
		if (unlikely((ipv6_spec->hdr.dst_addr[i] &
				~ipv6_mask->hdr.dst_addr[i]) != 0)) {
			G_LOG(ERR, "%s(): .hdr.dst_addr has at least an invalid bit\n",
				__func__);
			return -EINVAL;
		}
	}

	return 0;
}

static int
check_ipv6_item_mask(const void *item_mask)
{
	const struct rte_flow_item_ipv6 *ipv6_mask = item_mask;

	int ret = check_ipv6_zeros(ipv6_mask);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely(ipv6_mask->hdr.proto != 0 &&
			ipv6_mask->hdr.proto != 0xFF)) {
		/* l4_min_header_length() requires full mask. */
		G_LOG(ERR, "%s(): .hdr.proto must be either zero or full mask\n",
			__func__);
		return -EINVAL;
	}

	if (unlikely(ipv6_mask->hdr.proto == 0 &&
			is_ipv6_addr_zero(ipv6_mask->hdr.dst_addr))) {
		G_LOG(ERR, "%s(): .hdr.proto and .hdr.dst_addr are zeros; the IPv6 item has no function\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

static inline int
check_ipv6_item(const struct rte_flow_item *item)
{
	return check_flow_item(item, __func__,
		check_ipv6_item_spec, check_ipv6_item_mask);
}

static inline int
ipv6_str(struct buf_str *bstr, const uint8_t *dst_addr)
{
	return bstr_inet_ntop(bstr, AF_INET6, dst_addr);
}

static bool
is_ipv6_addr_ones(const uint8_t *addr)
{
	const struct in6_addr ones = {
		.s6_addr32[0] = 0xFFFFFFFF,
		.s6_addr32[1] = 0xFFFFFFFF,
		.s6_addr32[2] = 0xFFFFFFFF,
		.s6_addr32[3] = 0xFFFFFFFF,
	};
	return memcmp(addr, ones.s6_addr, sizeof(ones)) == 0;
}

static int
pattern_ipv6(struct buf_str *bstr, const struct rte_flow_item *item)
{
	const struct rte_flow_item_ipv6 *ipv6_spec;
	const struct rte_flow_item_ipv6 *ipv6_mask;

	int ret = check_ipv6_item(item);
	if (unlikely(ret < 0))
		return ret;

	ipv6_spec = item->spec;
	ipv6_mask = item->mask;

	/* Destination address and mask. */
	ret = bstr_append(bstr, "dst=");
	if (unlikely(ret < 0))
		return ret;
	ret = ipv6_str(bstr, ipv6_spec->hdr.dst_addr);
	if (unlikely(ret < 0))
		return ret;
	if (!is_ipv6_addr_ones(ipv6_mask->hdr.dst_addr)) {
		ret = bstr_append(bstr, "/");
		if (unlikely(ret < 0))
			return ret;
		ret = ipv6_str(bstr, ipv6_mask->hdr.dst_addr);
		if (unlikely(ret < 0))
			return ret;
	}

	/* Next protocol. */
	ret = bstr_append(bstr, " ");
	if (unlikely(ret < 0))
		return ret;
	if (ipv6_mask->hdr.proto == 0xFF)
		return next_proto_id_str(bstr, ipv6_spec->hdr.proto);
	return bstr_append(bstr, "IPProto=0x%x/0x%x",
		ipv6_spec->hdr.proto, ipv6_mask->hdr.proto);
}

static int
check_tcp_zeros(const struct rte_flow_item_tcp *tcp_item)
{
	const struct rte_tcp_hdr *tcp_hdr = &tcp_item->hdr;

	if (unlikely(tcp_hdr->sent_seq != 0)) {
		G_LOG(ERR, "%s(): .hdr.sent_seq must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(tcp_hdr->recv_ack != 0)) {
		G_LOG(ERR, "%s(): .hdr.recv_ack must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(tcp_hdr->data_off != 0)) {
		G_LOG(ERR, "%s(): .hdr.data_off must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(tcp_hdr->tcp_flags != 0)) {
		G_LOG(ERR, "%s(): .hdr.tcp_flags must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(tcp_hdr->rx_win != 0)) {
		G_LOG(ERR, "%s(): .hdr.rx_win must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(tcp_hdr->cksum != 0)) {
		G_LOG(ERR, "%s(): .hdr.cksum must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(tcp_hdr->tcp_urp != 0)) {
		G_LOG(ERR, "%s(): .hdr.tcp_urp must be zero\n", __func__);
		return -ENOTSUP;
	}
	return 0;
}

static int
check_tcp_item_spec(const void *item_spec, const void *item_mask)
{
	const struct rte_flow_item_tcp *tcp_spec = item_spec;
	const struct rte_flow_item_tcp *tcp_mask = item_mask;

	int ret = check_tcp_zeros(tcp_spec);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely((tcp_spec->hdr.src_port & ~tcp_mask->hdr.src_port) != 0)) {
		G_LOG(ERR, "%s(): .hdr.src_port=0x%x/0x%x has at least an invalid bit: 0x%x\n",
			__func__, rte_be_to_cpu_16(tcp_spec->hdr.src_port),
			rte_be_to_cpu_16(tcp_mask->hdr.src_port),
			rte_be_to_cpu_16(tcp_spec->hdr.src_port &
				~tcp_mask->hdr.src_port));
		return -EINVAL;
	}

	if (unlikely((tcp_spec->hdr.dst_port & ~tcp_mask->hdr.dst_port) != 0)) {
		G_LOG(ERR, "%s(): .hdr.dst_port=0x%x/0x%x has at least an invalid bit: 0x%x\n",
			__func__, rte_be_to_cpu_16(tcp_spec->hdr.dst_port),
			rte_be_to_cpu_16(tcp_mask->hdr.dst_port),
			rte_be_to_cpu_16(tcp_spec->hdr.dst_port &
				~tcp_mask->hdr.dst_port));
		return -EINVAL;
	}

	return 0;
}

static int
check_tcp_item_mask(const void *item_mask)
{
	const struct rte_flow_item_tcp *tcp_mask = item_mask;
	const struct rte_tcp_hdr *tcp_hdr;

	int ret = check_tcp_zeros(tcp_mask);
	if (unlikely(ret < 0))
		return ret;

	tcp_hdr = &tcp_mask->hdr;
	if (unlikely(tcp_hdr->src_port == 0 && tcp_hdr->dst_port == 0)) {
		G_LOG(ERR, "%s(): .hdr.src_port and .hdr.dst_port are zeros; the TCP item has no function\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

static inline int
check_tcp_item(const struct rte_flow_item *item)
{
	return check_flow_item(item, __func__,
		check_tcp_item_spec, check_tcp_item_mask);
}

static int
port_str(struct buf_str *bstr, const char *port_name,
	rte_be16_t port, rte_be16_t mask)
{
	if (mask == 0)
		return 0;

	if (mask == 0xFFFF)
		return bstr_append(bstr, "%s=%i", port_name,
			rte_be_to_cpu_16(port));

	return bstr_append(bstr, "%s=0x%x/0x%x", port_name,
			rte_be_to_cpu_16(port), rte_be_to_cpu_16(mask));

}

static int
pattern_tcp(struct buf_str *bstr, const struct rte_flow_item *item)
{
	const struct rte_flow_item_tcp *tcp_spec;
	const struct rte_flow_item_tcp *tcp_mask;

	int ret = check_tcp_item(item);
	if (unlikely(ret < 0))
		return ret;

	tcp_spec = item->spec;
	tcp_mask = item->mask;

	ret = port_str(bstr, "src",
		tcp_spec->hdr.src_port, tcp_mask->hdr.src_port);
	if (unlikely(ret < 0))
		return ret;

	if (tcp_mask->hdr.src_port != 0 && tcp_mask->hdr.dst_port != 0) {
		ret = bstr_append(bstr, " ");
		if (unlikely(ret < 0))
			return ret;
	}

	return port_str(bstr, "dst",
		tcp_spec->hdr.dst_port, tcp_mask->hdr.dst_port);
}

static int
check_udp_zeros(const struct rte_flow_item_udp *udp_item)
{
	const struct rte_udp_hdr *udp_hdr = &udp_item->hdr;

	if (unlikely(udp_hdr->dgram_len != 0)) {
		G_LOG(ERR, "%s(): .hdr.dgram_len must be zero\n", __func__);
		return -ENOTSUP;
	}
	if (unlikely(udp_hdr->dgram_cksum != 0)) {
		G_LOG(ERR, "%s(): .hdr.dgram_cksum must be zero\n", __func__);
		return -ENOTSUP;
	}
	return 0;
}

static int
check_udp_item_spec(const void *item_spec, const void *item_mask)
{
	const struct rte_flow_item_udp *udp_spec = item_spec;
	const struct rte_flow_item_udp *udp_mask = item_mask;

	int ret = check_udp_zeros(udp_spec);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely((udp_spec->hdr.src_port & ~udp_mask->hdr.src_port) != 0)) {
		G_LOG(ERR, "%s(): .hdr.src_port=0x%x/0x%x has at least an invalid bit: 0x%x\n",
			__func__, rte_be_to_cpu_16(udp_spec->hdr.src_port),
			rte_be_to_cpu_16(udp_mask->hdr.src_port),
			rte_be_to_cpu_16(udp_spec->hdr.src_port &
				~udp_mask->hdr.src_port));
		return -EINVAL;
	}

	if (unlikely((udp_spec->hdr.dst_port & ~udp_mask->hdr.dst_port) != 0)) {
		G_LOG(ERR, "%s(): .hdr.dst_port=0x%x/0x%x has at least an invalid bit: 0x%x\n",
			__func__, rte_be_to_cpu_16(udp_spec->hdr.dst_port),
			rte_be_to_cpu_16(udp_mask->hdr.dst_port),
			rte_be_to_cpu_16(udp_spec->hdr.dst_port &
				~udp_mask->hdr.dst_port));
		return -EINVAL;
	}

	return 0;
}

static int
check_udp_item_mask(const void *item_mask)
{
	const struct rte_flow_item_udp *udp_mask = item_mask;
	const struct rte_udp_hdr *udp_hdr;

	int ret = check_udp_zeros(udp_mask);
	if (unlikely(ret < 0))
		return ret;

	udp_hdr = &udp_mask->hdr;
	if (unlikely(udp_hdr->src_port == 0 && udp_hdr->dst_port == 0)) {
		G_LOG(ERR, "%s(): .hdr.src_port and .hdr.dst_port are zeros; the UDP item has no function\n",
			__func__);
		return -EINVAL;
	}

	return 0;
}

static inline int
check_udp_item(const struct rte_flow_item *item)
{
	return check_flow_item(item, __func__,
		check_udp_item_spec, check_udp_item_mask);
}

static int
pattern_udp(struct buf_str *bstr, const struct rte_flow_item *item)
{
	const struct rte_flow_item_udp *udp_spec;
	const struct rte_flow_item_udp *udp_mask;

	int ret = check_udp_item(item);
	if (unlikely(ret < 0))
		return ret;

	udp_spec = item->spec;
	udp_mask = item->mask;

	ret = port_str(bstr, "src",
		udp_spec->hdr.src_port, udp_mask->hdr.src_port);
	if (unlikely(ret < 0))
		return ret;

	if (udp_mask->hdr.src_port != 0 && udp_mask->hdr.dst_port != 0) {
		ret = bstr_append(bstr, " ");
		if (unlikely(ret < 0))
			return ret;
	}

	return port_str(bstr, "dst",
		udp_spec->hdr.dst_port, udp_mask->hdr.dst_port);
}

static int
pattern_str(struct buf_str *bstr, const struct rte_flow_item *item)
{
	switch (item->type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
		return pattern_eth(bstr, item);
	case RTE_FLOW_ITEM_TYPE_IPV4:
		return pattern_ipv4(bstr, item);
	case RTE_FLOW_ITEM_TYPE_IPV6:
		return pattern_ipv6(bstr, item);
	case RTE_FLOW_ITEM_TYPE_TCP:
		return pattern_tcp(bstr, item);
	case RTE_FLOW_ITEM_TYPE_UDP:
		return pattern_udp(bstr, item);

	default:
		G_LOG(ERR, "%s(): rte_flow_item_type=%i is not implemented\n",
			__func__, item->type);
		return -ENOTSUP;
	}
}

static int
bstr_flow_human_str(struct buf_str *bstr, const struct absflow_desc *desc)
{
	const struct rte_flow_item *pattern = desc->pattern;
	int ret = -1;

	while (pattern->type != RTE_FLOW_ITEM_TYPE_END) {
		if (unlikely(ret >= 0)) {
			/* This is NOT the first time of the loop. */
			ret = bstr_append(bstr, " ");
			if (unlikely(ret < 0))
				return ret;
		}
		ret = pattern_str(bstr, pattern++);
		if (unlikely(ret < 0))
			return ret;
	}
	return 0;
}

void
flow_human_str(char *buf, size_t size, const struct absflow_desc *desc)
{
	struct buf_str bstr = {.buf = buf, .size = size};
	int ret;

	if (unlikely(size == 0)) {
		G_LOG(ERR, "%s(): buffer size is zero\n", __func__);
		return;
	}

	ret = bstr_flow_human_str(&bstr, desc);
	if (likely(ret == 0))
		return;

	bstr.buf = buf;
	bstr.size = size;
	bstr_append(&bstr, "%s(): failed (errno=%i): %s",
		__func__, -ret, strerror(-ret));
	buf[size - 1] = '\0';
}

static struct flow_tree_node *
new_tree_node(struct memblock_head *mb_flow_tree, enum ft_source source)
{
	struct flow_tree_node *node = memblock_calloc(mb_flow_tree, 1,
		sizeof(struct flow_tree_node));
	if (unlikely(node == NULL))
		return NULL;
	node->source = source;
	return node;
}

static inline void
chain_node(struct flow_tree_node ***ppnext_node, struct flow_tree_node *node)
{
	**ppnext_node = node;
	*ppnext_node = &node->and_branch;
}

/*
 * The maximum mask of the input may not match the maximum mask of
 * the type of struct flow_tree_node. For example, type FTS_L4_PROTO has
 * 16 bits in BPF, but the field in IPv4 and IPv6 headers has only 8 bits.
 * While mismatches are not bugs, having full mask avoids the need for
 * BPF instructions to mask input; i.e. quicker BPFs.
 */
static uint64_t
expand_mask(uint64_t original_mask, uint8_t max_size_byte)
{
	uint64_t max_mask = max_size_byte < 8
		? (1ULL << (max_size_byte * 8)) - 1
		: (typeof(max_mask))-1;

	if (likely(original_mask == max_mask))
		return -1; /* Full mask. */

	return original_mask;
}

static int
build_eth_tree(struct memblock_head *mb_flow_tree,
	struct flow_tree_node ***ppnext_node, const struct rte_flow_item *item)
{
	const struct rte_flow_item_eth *eth_spec;
	const struct rte_flow_item_eth *eth_mask;
	struct flow_tree_node *node;

	int ret = check_eth_item(item);
	if (unlikely(ret < 0))
		return ret;

	eth_spec = item->spec;
	eth_mask = item->mask;

	if (unlikely(eth_mask->type != 0)) {
		node = new_tree_node(mb_flow_tree, FTS_L3_PROTO);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->mask = expand_mask(rte_be_to_cpu_16(eth_mask->type),
			sizeof(eth_mask->type));
		node->value = rte_be_to_cpu_16(eth_spec->type);
		chain_node(ppnext_node, node);
	}

	return 0;
}

static int
build_l4_proto(struct memblock_head *mb_flow_tree,
	struct flow_tree_node ***ppnext_node, uint8_t proto, uint8_t mask)
{
	int l4_len;

	struct flow_tree_node *node = new_tree_node(mb_flow_tree, FTS_L4_PROTO);
	if (unlikely(node == NULL))
		return -ENOENT;
	node->mask = expand_mask(mask, sizeof(mask));
	node->value = proto;
	chain_node(ppnext_node, node);

	l4_len = l4_min_header_length(proto);
	if (unlikely(l4_len < 0)) {
		/* Do not enforce any property for unknown level-4 headers. */
		return 0;
	}

	node = new_tree_node(mb_flow_tree, FTS_L4_FRAGMENTED);
	if (unlikely(node == NULL))
		return -ENOENT;
	node->mask = -1;
	node->value = false;
	chain_node(ppnext_node, node);

	node = new_tree_node(mb_flow_tree, FTS_L4_LEN);
	if (unlikely(node == NULL))
		return -ENOENT;
	node->mask = -1;
	node->value = l4_len;
	chain_node(ppnext_node, node);

	return 0;
}

static int
build_ipv4_tree(struct memblock_head *mb_flow_tree,
	struct flow_tree_node ***ppnext_node, const struct rte_flow_item *item)
{
	const struct rte_flow_item_ipv4 *ipv4_spec;
	const struct rte_flow_item_ipv4 *ipv4_mask;
	struct flow_tree_node *node;

	int ret = check_ipv4_item(item);
	if (unlikely(ret < 0))
		return ret;

	ipv4_spec = item->spec;
	ipv4_mask = item->mask;

	if (ipv4_mask->hdr.next_proto_id != 0) {
		ret = build_l4_proto(mb_flow_tree, ppnext_node,
			ipv4_spec->hdr.next_proto_id,
			ipv4_mask->hdr.next_proto_id);
		if (unlikely(ret < 0))
			return ret;
	}

	if (ipv4_mask->hdr.dst_addr != 0) {
		node = new_tree_node(mb_flow_tree, FTS_L3_HEADER);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->hdr_offset = offsetof(struct rte_ipv4_hdr, dst_addr);
		node->hdr_length = sizeof(ipv4_spec->hdr.dst_addr);
		node->mask = rte_be_to_cpu_32(ipv4_mask->hdr.dst_addr);
		node->value = rte_be_to_cpu_32(ipv4_spec->hdr.dst_addr);
		chain_node(ppnext_node, node);
	}

	return 0;
}

static inline uint64_t
read_64bits(const uint8_t *pbe8)
{
	const rte_be64_t *pbe64 = (const rte_be64_t *)pbe8;
	return rte_be_to_cpu_64(*pbe64);
}

static int
build_ipv6_tree(struct memblock_head *mb_flow_tree,
	struct flow_tree_node ***ppnext_node, const struct rte_flow_item *item)
{
	const struct rte_flow_item_ipv6 *ipv6_spec;
	const struct rte_flow_item_ipv6 *ipv6_mask;
	struct flow_tree_node *node;

	int ret = check_ipv6_item(item);
	if (unlikely(ret < 0))
		return ret;

	ipv6_spec = item->spec;
	ipv6_mask = item->mask;

	if (ipv6_mask->hdr.proto != 0) {
		ret = build_l4_proto(mb_flow_tree, ppnext_node,
			ipv6_spec->hdr.proto, ipv6_mask->hdr.proto);
		if (unlikely(ret < 0))
			return ret;
	}

	if (read_64bits(&ipv6_mask->hdr.dst_addr[0]) != 0) {
		node = new_tree_node(mb_flow_tree, FTS_L3_HEADER);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->hdr_offset = offsetof(struct rte_ipv6_hdr, dst_addr[0]);
		node->hdr_length = sizeof(uint64_t);
		node->mask = read_64bits(&ipv6_mask->hdr.dst_addr[0]);
		node->value = read_64bits(&ipv6_spec->hdr.dst_addr[0]);
		chain_node(ppnext_node, node);
	}

	if (read_64bits(&ipv6_mask->hdr.dst_addr[8]) != 0) {
		node = new_tree_node(mb_flow_tree, FTS_L3_HEADER);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->hdr_offset = offsetof(struct rte_ipv6_hdr, dst_addr[8]);
		node->hdr_length = sizeof(uint64_t);
		node->mask = read_64bits(&ipv6_mask->hdr.dst_addr[8]);
		node->value = read_64bits(&ipv6_spec->hdr.dst_addr[8]);
		chain_node(ppnext_node, node);
	}

	return -ENOTSUP;
}

static int
build_tcp_tree(struct memblock_head *mb_flow_tree,
	struct flow_tree_node ***ppnext_node, const struct rte_flow_item *item)
{
	const struct rte_flow_item_tcp *tcp_spec;
	const struct rte_flow_item_tcp *tcp_mask;
	struct flow_tree_node *node;

	int ret = check_tcp_item(item);
	if (unlikely(ret < 0))
		return ret;

	tcp_spec = item->spec;
	tcp_mask = item->mask;

	if (tcp_mask->hdr.src_port != 0) {
		node = new_tree_node(mb_flow_tree, FTS_L4_HEADER);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->hdr_offset = offsetof(struct rte_tcp_hdr, src_port);
		node->hdr_length = sizeof(tcp_spec->hdr.src_port);
		node->mask = rte_be_to_cpu_16(tcp_mask->hdr.src_port);
		node->value = rte_be_to_cpu_16(tcp_spec->hdr.src_port);
		chain_node(ppnext_node, node);
	}

	if (tcp_mask->hdr.dst_port != 0) {
		node = new_tree_node(mb_flow_tree, FTS_L4_HEADER);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->hdr_offset = offsetof(struct rte_tcp_hdr, dst_port);
		node->hdr_length = sizeof(tcp_spec->hdr.dst_port);
		node->mask = rte_be_to_cpu_16(tcp_mask->hdr.dst_port);
		node->value = rte_be_to_cpu_16(tcp_spec->hdr.dst_port);
		chain_node(ppnext_node, node);
	}

	return 0;
}

static int
build_udp_tree(struct memblock_head *mb_flow_tree,
	struct flow_tree_node ***ppnext_node, const struct rte_flow_item *item)
{
	const struct rte_flow_item_udp *udp_spec;
	const struct rte_flow_item_udp *udp_mask;
	struct flow_tree_node *node;

	int ret = check_udp_item(item);
	if (unlikely(ret < 0))
		return ret;

	udp_spec = item->spec;
	udp_mask = item->mask;

	if (udp_mask->hdr.src_port != 0) {
		node = new_tree_node(mb_flow_tree, FTS_L4_HEADER);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->hdr_offset = offsetof(struct rte_udp_hdr, src_port);
		node->hdr_length = sizeof(udp_spec->hdr.src_port);
		node->mask = rte_be_to_cpu_16(udp_mask->hdr.src_port);
		node->value = rte_be_to_cpu_16(udp_spec->hdr.src_port);
		chain_node(ppnext_node, node);
	}

	if (udp_mask->hdr.dst_port != 0) {
		node = new_tree_node(mb_flow_tree, FTS_L4_HEADER);
		if (unlikely(node == NULL))
			return -ENOENT;
		node->hdr_offset = offsetof(struct rte_udp_hdr, dst_port);
		node->hdr_length = sizeof(udp_spec->hdr.dst_port);
		node->mask = rte_be_to_cpu_16(udp_mask->hdr.dst_port);
		node->value = rte_be_to_cpu_16(udp_spec->hdr.dst_port);
		chain_node(ppnext_node, node);
	}

	return 0;
}

static int
build_pattern_tree(struct memblock_head *mb_flow_tree,
	struct flow_tree_node ***ppnext_node, const struct rte_flow_item *item)
{
	switch (item->type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
		return build_eth_tree(mb_flow_tree, ppnext_node, item);
	case RTE_FLOW_ITEM_TYPE_IPV4:
		return build_ipv4_tree(mb_flow_tree, ppnext_node, item);
	case RTE_FLOW_ITEM_TYPE_IPV6:
		return build_ipv6_tree(mb_flow_tree, ppnext_node, item);
	case RTE_FLOW_ITEM_TYPE_TCP:
		return build_tcp_tree(mb_flow_tree, ppnext_node, item);
	case RTE_FLOW_ITEM_TYPE_UDP:
		return build_udp_tree(mb_flow_tree, ppnext_node, item);

	default:
		G_LOG(ERR, "%s(): rte_flow_item_type=%i is not implemented\n",
			__func__, item->type);
		return -ENOTSUP;
	}
}

static inline struct flow_tree_node **
pnext_on_branch(struct flow_tree_node *node, bool and_branch)
{
	return and_branch ? &node->and_branch : &node->or_branch;
}

static inline struct flow_tree_node * const *
const_pnext_on_branch(const struct flow_tree_node *node, bool and_branch)
{
	return and_branch ? &node->and_branch : &node->or_branch;
}

static unsigned int
depth_by_branch(const struct flow_tree_node *next_node, bool and_branch)
{
	unsigned int count = 0;
	while (next_node != NULL) {
		count++;
		next_node = *const_pnext_on_branch(next_node, and_branch);
	}
	return count;
}

static inline unsigned int
depth_of_desc_tree(const struct flow_tree_node *next_node)
{
	return depth_by_branch(next_node, true);
}

static inline uint64_t
comb64(uint8_t msb, uint64_t lsb)
{
	return (((uint64_t)msb) << 56) | lsb;
}

static inline uint64_t
eval_meta(const struct flow_tree_node *node)
{
	uint64_t mask_length = __builtin_popcountll(node->mask);
	/*
	 * The longer the mask, the smaller the result of (255 - mask_length).
	 * This property is needed since the intention is to prioritize longer
	 * masks, and the smaller the number, the higher the priority.
	 */
	return ((255 - mask_length) << 48) |
		(node->value & node->mask);
}

static uint64_t
eval_l3_proto(const struct flow_tree_node *node)
{
	/* Prioritize longer masks. */
	if (node->mask != 0xFFFF)
		return eval_meta(node);

	/* Prioritize protocol polularity. */
	switch (node->value) {
	case RTE_ETHER_TYPE_IPV4:
		return 0;
	case RTE_ETHER_TYPE_IPV6:
		return 1;
	case RTE_ETHER_TYPE_ARP:
		return 2;
	default:
		return (node->value & node->mask) << 16;
	}
}

static uint64_t
eval_l4_proto(const struct flow_tree_node *node)
{
	/* Prioritize longer masks. */
	if (node->mask != 0xFF)
		return eval_meta(node);

	/* Prioritize protocol polularity. */
	switch (node->value) {
	case IPPROTO_TCP:
		return 0;
	case IPPROTO_UDP:
		return 1;
	case IPPROTO_ICMP:
		return 2;
	case IPPROTO_ICMPV6:
		return 3;
	case IPPROTO_IP:
		return 4;
	case IPPROTO_IPIP:
		return 5;
	case IPPROTO_GRE:
		return 6;
	case IPPROTO_IPV6:
		return 7;
	case IPPROTO_FRAGMENT:
		return 8;
	default:
		return (node->value & node->mask) << 8;
	}
}

static inline uint64_t
comb_off_len(const struct flow_tree_node *node)
{
	/* Byte order and length. */
	return (node->hdr_offset << 16) | node->hdr_length;
}

static uint64_t
eval_node(const struct flow_tree_node *node)
{
	switch (node->source) {
	case FTS_L2_HEADER:
		return comb64(0, comb_off_len(node));
	case FTS_L3_PROTO:
		return comb64(1, eval_l3_proto(node));
	case FTS_L3_HEADER:
		return comb64(2, comb_off_len(node));
	case FTS_L4_PROTO:
		return comb64(3, eval_l4_proto(node));
	case FTS_L4_FRAGMENTED:
		return comb64(4, node->value);
	case FTS_L4_LEN:
		return comb64(5, node->value);
	case FTS_L4_HEADER:
		return comb64(6, comb_off_len(node));
	}

	return UINT64_MAX;
}

static int
cmp_node(const void *pa, const void *pb)
{
	const struct flow_tree_node * const *pnode_a = pa;
	const struct flow_tree_node * const *pnode_b = pb;
	return eval_node(*pnode_a) - eval_node(*pnode_b);
}

static int
list_all_nodes_and_sort(struct flow_tree_node **proot,
	struct flow_tree_node **nodes, unsigned int max_depth, bool and_branch)
{
	struct flow_tree_node *next_node = *proot;
	struct flow_tree_node **pnext_node;
	unsigned int i, count = 0;

	/* List all nodes. */
	while (next_node != NULL) {
		if (unlikely(count >= max_depth)) {
			G_LOG(CRIT, "%s(and_branch=%i): bug: count=%u >= max_depth=%u\n",
				__func__, and_branch, count, max_depth);
			return -EFAULT;
		}
		nodes[count++] = next_node;
		next_node = *pnext_on_branch(next_node, and_branch);
	}

	if (count <= 1)
		return count;

	qsort(nodes, count, sizeof(nodes[0]), cmp_node);

	/* Update the X_branch fields. */
	pnext_node = proot;
	for (i = 0; i < count; i++) {
		*pnext_node = nodes[i];
		pnext_node = pnext_on_branch(nodes[i], and_branch);
	}
	*pnext_node = NULL;

	return count;
}

static int
sort_desc_tree(struct flow_tree_node **pdesc_root, unsigned int max_depth,
	uint32_t flow_id)
{
	struct flow_tree_node *nodes[max_depth];
	struct flow_tree_node *last_node;

	int count = list_all_nodes_and_sort(pdesc_root, nodes, max_depth, true);
	if (unlikely(count < 0))
		return count;

	/* Add @flow_id to the last node. */
	if (unlikely(count == 0)) {
		G_LOG(CRIT, "%s(): bug: there is no node\n", __func__);
		return -EFAULT;
	}
	last_node = nodes[count - 1];
	last_node->has_flow_id = true;
	last_node->flow_id = flow_id;
	return 0;
}

static int
build_desc_tree(struct memblock_head *mb_flow_tree,
	const struct absflow_desc *desc, uint32_t flow_id,
	struct flow_tree_node **pdesc_root)
{
	const struct rte_flow_item *pattern = desc->pattern;
	struct flow_tree_node *desc_root = NULL;
	struct flow_tree_node **pnext_node = &desc_root;
	int ret;

	while (pattern->type != RTE_FLOW_ITEM_TYPE_END) {
		ret = build_pattern_tree(mb_flow_tree, &pnext_node, pattern++);
		if (unlikely(ret < 0))
			return ret;
	}

	ret = sort_desc_tree(&desc_root, depth_of_desc_tree(desc_root),
		flow_id);
	if (unlikely(ret < 0))
		return ret;

	*pdesc_root = desc_root;
	return 0;
}

static bool
nodes_have_same_match(const struct flow_tree_node *a,
	const struct flow_tree_node *b)
{
	if (a->source != b->source)
		return false;

	switch (a->source) {
	case FTS_L2_HEADER:
	case FTS_L3_HEADER:
	case FTS_L4_HEADER:
		return a->hdr_offset == b->hdr_offset &&
			a->hdr_length == b->hdr_length &&
			a->mask == b->mask && a->value == b->value;

	case FTS_L3_PROTO:
	case FTS_L4_PROTO:
	case FTS_L4_LEN:
	case FTS_L4_FRAGMENTED:
		return a->mask == b->mask && a->value == b->value;
	}

	return false;
}

static int
merge_trees(const struct absflow_director *dir, struct flow_tree_node **proot,
	struct flow_tree_node *desc_root)
{
	struct flow_tree_node **pnext_node, *next_desc_node;

	if (unlikely(desc_root == NULL)) {
		/* There's nothing to do. */
		return 0;
	}

	pnext_node = proot;
	next_desc_node = desc_root;
	while (*pnext_node != NULL) {
		struct flow_tree_node *next_node = *pnext_node;
		if (!nodes_have_same_match(next_node, desc_root))
			goto next_or;

		if (next_node->has_flow_id) {
			if (next_desc_node->has_flow_id) {
				char flow_str[FLOW_HUMAN_STR_SIZE];
				flow_human_str(flow_str, sizeof(flow_str),
					&dir->flow_descs[next_node->flow_id]);
				if (next_node->flow_id ==
						next_desc_node->flow_id) {
					G_LOG(CRIT, "%s(%s): bug: flow_id=%u was inserted twice\n",
						__func__, flow_str,
						next_node->flow_id);
					return -EFAULT;
				}
				G_LOG(ERR, "%s(%s): flow is duplicated at flow_id=%u and flow_id=%u\n",
					__func__, flow_str, next_node->flow_id,
					next_desc_node->flow_id);
				return -EEXIST;
			}
			goto next_and;
		}

		if (next_desc_node->has_flow_id) {
			next_node->has_flow_id = true;
			next_node->flow_id = next_desc_node->flow_id;
		}

next_and:
		pnext_node = &next_node->and_branch;
		/*
		 * It is okay to "memory leak" @next_desc_node because all
		 * nodes are in the same struct memblock_head.
		 */
		next_desc_node = next_desc_node->and_branch;
		if (next_desc_node == NULL) {
			/* Done. */
			return 0;
		}
		continue;
next_or:
		pnext_node = &next_node->or_branch;
	}

	*pnext_node = next_desc_node;
	return 0;
}

static inline unsigned int
depth_of_tree(const struct flow_tree_node *next_node)
{
	return depth_by_branch(next_node, false);
}

static int
sort_tree(struct flow_tree_node **proot, unsigned int max_depth)
{
	struct flow_tree_node *nodes[max_depth];
	int i;

	int count = list_all_nodes_and_sort(proot, nodes, max_depth, false);
	if (unlikely(count <= 0)) {
		/*
		 * if (count <  0) => Error.
		 * if (count == 0) => There's nothing to do.
		 */
		return count;
	}

	/* Recursively sort the other *OR* branches. */
	for (i = 0; i < count; i++) {
		struct flow_tree_node **pnode = &nodes[i]->and_branch;
		int ret = sort_tree(pnode, depth_of_tree(*pnode));
		if (unlikely(ret < 0))
			return ret;
	}
	return 0;
}

static int
build_flow_tree(struct memblock_head *mb_flow_tree,
	const struct absflow_director *dir, struct flow_tree_node **proot)
{
	unsigned int i;

	for (i = 0; i < dir->flow_descs_count; i++) {
		struct flow_tree_node *desc_root;
		int ret = build_desc_tree(mb_flow_tree, &dir->flow_descs[i], i,
			&desc_root);
		if (unlikely(ret < 0))
			return ret;
		merge_trees(dir, proot, desc_root);
	}

	return sort_tree(proot, depth_of_tree(*proot));
}

static int
offload_flow(struct gatekeeper_if *iface, uint32_t flow_id)
{
	struct absflow_director *dir = &iface->absflow_dir;
	struct absflow_desc *desc;
	char flow_str[FLOW_HUMAN_STR_SIZE];
	struct rte_flow_error error;
	struct rte_flow *flow;

	if (unlikely(flow_id >= dir->flow_descs_count)) {
		G_LOG(CRIT, "%s(%s): bug: invalid flow descriptor index %i; there are only %i descriptors\n",
			__func__, iface->name, flow_id, dir->flow_descs_count);
		return -EINVAL;
	}
	desc = &dir->flow_descs[flow_id];

	flow_human_str(flow_str, sizeof(flow_str), desc);
	flow = rte_flow_create(iface->id, desc->attr, desc->pattern,
		desc->action, &error);
	if (flow == NULL) {
		G_LOG(ERR, "%s(%s): cannot offload flow %s, (errno=%i: %s), rte_flow_error_type=%i: %s\n",
		__func__, iface->name, flow_str,
		rte_errno, rte_strerror(rte_errno),
		error.type, error.message);
		return -rte_errno;
	}

	desc->hw_offloaded = true;
	G_LOG(NOTICE, "%s(%s): flow %s is offloaded to hardware\n",
		__func__, iface->name, flow_str);
	return 0;
}

static int
__offload_flows(struct gatekeeper_if *iface,
	const struct flow_tree_node *node)
{
	bool keep_offloading = true;
	const struct flow_tree_node *next_node = node;

	while (next_node != NULL) {
		const struct absflow_desc *desc;
		int ret = __offload_flows(iface, next_node->and_branch);
		if (unlikely(ret < 0))
			return ret;

		keep_offloading = keep_offloading && ret;
		if (!ret || !next_node->has_flow_id)
			goto next;

		if (unlikely(next_node->flow_id >=
				iface->absflow_dir.flow_descs_count)) {
			G_LOG(CRIT, "%s(%s): bug: invalid flow descriptor index %i; there are only %i descriptors\n",
				__func__, iface->name, next_node->flow_id,
				iface->absflow_dir.flow_descs_count);
			return -EINVAL;
		}

		desc = &iface->absflow_dir.flow_descs[node->has_flow_id];
		if (desc->hw_supported) {
			ret = offload_flow(iface, node->flow_id);
			if (unlikely(ret < 0))
				return ret;
		} else
			keep_offloading = false;

next:
		next_node = next_node->or_branch;
	}
	return keep_offloading;
}

/*
 * Offload flows to the hardware.
 *
 * In order for a flow X to be offloaded,
 *	(1) the hardware supports it, and
 *	(2) there is no flow Y such that
 *		(a) the flow Y is more specific that the flow X and
 *		(b) the hardware cannot offload the flow Y.
 *
 * As this function identifies and offloads the flow that can be offloaded,
 * it updates the field @iface->absflow_dir.flow_descs[i].hw_offloaded.
 */
static int
offload_flows(struct gatekeeper_if *iface, const struct flow_tree_node *root)
{
	int ret = __offload_flows(iface, root);
	if (likely(ret >= 0))
		return 0;
	return ret;
}

static int
bstr_indent(struct buf_str *bstr, unsigned int indent)
{
	while (indent > 0) {
		int ret = bstr_append(bstr, "  ");
		if (unlikely(ret < 0))
			return ret;
		indent--;
	}
	return 0;
}

static int
bstr_flow_return(struct buf_str *bstr, const struct absflow_director *dir,
	const struct absflow_execution *exec,
	const struct flow_tree_node *node, unsigned int indent)
{
	const struct absflow_desc *desc;

	/* First comment line. */
	int ret = bstr_indent(bstr, indent);
	if (unlikely(ret < 0))
		return ret;
	ret = bstr_append(bstr, "# FlowID: %u", node->flow_id);
	if (unlikely(ret < 0))
		return ret;
	if (unlikely(node->flow_id >= dir->flow_descs_count)) {
		ret = bstr_append(bstr, "; bug: invalid flow descriptor index %i; there are only %i descriptors\n",
			node->flow_id, dir->flow_descs_count);
		return -EINVAL;
	}
	desc = &dir->flow_descs[node->flow_id];
	if (desc->hw_offloaded) {
		ret = bstr_append(bstr, "; Hardware offloaded\n");
	} else if (desc->hw_supported) {
		ret = bstr_append(bstr, "; Hardware supported\n");
	} else {
		ret = bstr_append(bstr, "\n");
	}
	if (unlikely(ret < 0))
		return ret;

	/* Second comment line. */
	ret = bstr_indent(bstr, indent);
	if (unlikely(ret < 0))
		return ret;
	ret = bstr_append(bstr, "# Submit ID: %u\n",
		exec->flow_id_to_submit[node->flow_id]);
	if (unlikely(ret < 0))
		return ret;

	/* Third comment line. */
	ret = bstr_indent(bstr, indent);
	if (unlikely(ret < 0))
		return ret;
	ret = bstr_append(bstr, "# ");
	if (unlikely(ret < 0))
		return ret;
	ret = bstr_flow_human_str(bstr, desc);
	if (unlikely(ret < 0))
		return ret;
	ret = bstr_append(bstr, "\n");
	if (unlikely(ret < 0))
		return ret;

	/* Return line. */
	ret = bstr_indent(bstr, indent);
	if (unlikely(ret < 0))
		return ret;
	ret = bstr_append(bstr, "return %u;", node->flow_id);
	if (unlikely(ret < 0))
		return ret;

	return 0;
}

static int
__log_flow_tree(struct buf_str *bstr, const struct absflow_director *dir,
	const struct absflow_execution *exec,
	const struct flow_tree_node *node, unsigned int indent)
{
	int ret;

	if (unlikely(node == NULL)) {
		if (unlikely(indent == 0)) {
			ret = bstr_indent(bstr, indent);
			if (unlikely(ret < 0))
				return ret;
			ret = bstr_append(bstr,
				"return %u; # Unclassified packet",
				GATEKEEPER_ABSFLOW_INVALID_FLOWID);
			if (unlikely(ret < 0))
				return ret;
		}
		return 0;
	}

	ret = bstr_indent(bstr, indent);
	if (unlikely(ret < 0))
		return ret;

	switch (node->source) {
	case FTS_L2_HEADER:
		ret = bstr_append(bstr, "if L2_HEADER(off=%u, len=%u, val=0x%"
			PRIx64 "/0x%" PRIx64 ") {\n",
			node->hdr_offset, node->hdr_length,
			node->value, node->mask);
		break;

	case FTS_L3_HEADER:
		ret = bstr_append(bstr, "if L3_HEADER(off=%u, len=%u, val=0x%"
			PRIx64 "/0x%" PRIx64 ") {\n",
			node->hdr_offset, node->hdr_length,
			node->value, node->mask);
		break;

	case FTS_L4_HEADER:
		ret = bstr_append(bstr, "if L4_HEADER(off=%u, len=%u, val=0x%"
			PRIx64 "/0x%" PRIx64 ") {\n",
			node->hdr_offset, node->hdr_length,
			node->value, node->mask);
		break;

	case FTS_L3_PROTO:
		ret = bstr_append(bstr, "if (L3_PROTO & 0x%" PRIx64 ") == 0x%"
			PRIx64 " {\n", node->mask, node->value);
		break;

	case FTS_L4_PROTO:
		ret = bstr_append(bstr, "if (L4_PROTO & 0x%" PRIx64 ") == 0x%"
			PRIx64 " {\n", node->mask, node->value);
		break;

	case FTS_L4_LEN:
		ret = bstr_append(bstr, "if (L4_LEN >= %" PRIu64 ") {\n",
			node->value);
		break;

	case FTS_L4_FRAGMENTED:
		ret = bstr_append(bstr, "if (%sL4_FRAGMENTED) {\n",
			node->value ? "" : "!");
		break;
	}
	if (unlikely(ret < 0))
		return ret;

	ret = __log_flow_tree(bstr, dir, exec, node->and_branch, indent + 1);
	if (unlikely(ret < 0))
		return ret;

	if (node->has_flow_id) {
		/*
		 * Add an empty line if there's an if-statement immediately
		 * above.
		 */
		if (node->and_branch != NULL) {
			ret = bstr_append(bstr, "\n");
			if (unlikely(ret < 0))
				return ret;
		}

		ret = bstr_flow_return(bstr, dir, exec, node, indent + 1);
		if (unlikely(ret < 0))
			return ret;
	}

	ret = bstr_indent(bstr, indent);
	if (unlikely(ret < 0))
		return ret;
	ret = bstr_append(bstr, "}\n");
	if (unlikely(ret < 0))
		return ret;

	return __log_flow_tree(bstr, dir, exec, node->or_branch, indent);
}

static void
log_flow_tree(const struct gatekeeper_if *iface,
	const struct flow_tree_node *root)
{
	const struct absflow_director *dir = &iface->absflow_dir;
	char log_entry[dir->flow_descs_count * (1024 + FLOW_HUMAN_STR_SIZE)];
	size_t size = sizeof(log_entry);
	struct buf_str bstr = {.buf = log_entry, .size = size};

	int ret = bstr_append(&bstr, "%s(%s): BEGINNING of the flow tree\n",
		__func__, iface->name);
	if (unlikely(ret < 0))
		goto error;

	ret = __log_flow_tree(&bstr, dir, &dir->dir_exec, root, 0);
	if (unlikely(ret < 0))
		goto error;

	ret = bstr_append(&bstr, "END of the flow tree\n");
	if (unlikely(ret < 0))
		goto error;

	G_LOG(INFO, "%s", log_entry);
	return;

error:
	G_LOG(ERR, "%s(%s): failed (errno=%i): %s",
		__func__, iface->name, -ret, strerror(-ret));
}

static int
__prune_hw_offload(const struct gatekeeper_if *iface,
	struct flow_tree_node **pnode)
{
	bool may_discard = true;
	struct flow_tree_node **pnext_node;

	pnext_node = pnode;
	while (*pnext_node != NULL) {
		const struct absflow_desc *desc;
		int ret = __prune_hw_offload(iface, &(*pnext_node)->and_branch);
		if (unlikely(ret < 0))
			return ret;

		may_discard = may_discard && ret;
		if (!ret)
		       goto next;

		if (!(*pnext_node)->has_flow_id)
			goto drop;

		if (unlikely((*pnext_node)->flow_id >=
				iface->absflow_dir.flow_descs_count)) {
			G_LOG(CRIT, "%s(%s): bug: invalid flow descriptor index %i; there are only %i descriptors\n",
				__func__, iface->name, (*pnext_node)->flow_id,
				iface->absflow_dir.flow_descs_count);
			return -EINVAL;
		}

		desc = &iface->absflow_dir.flow_descs[(*pnext_node)->flow_id];
		if (!desc->hw_offloaded) {
			may_discard = false;
			goto next;
		}

drop:
		/*
		 * This node is not needed.
		 *
		 * It's okay to leak this node because all tree nodes are
		 * allocated in a memblock.
		 */
		*pnext_node = (*pnext_node)->or_branch;
		continue;
next:
		pnext_node = &(*pnext_node)->or_branch;
	}

	return may_discard;
}

static int
prune_hw_offload(const struct gatekeeper_if *iface,
	struct flow_tree_node **proot)
{
	int ret = __prune_hw_offload(iface, proot);
	if (likely(ret >= 0))
		return 0;
	G_LOG(CRIT, "%s(%s): bug (errno=%i): %s\n",
		__func__, iface->name, -ret, strerror(-ret));
	return ret;
}

int
absflow_deploy_flows(struct gatekeeper_if *iface)
{
	struct absflow_director *dir = &iface->absflow_dir;
	MEMBLOCK_DEF(mb_flow_tree, dir->flow_descs_count * 1024);
	struct flow_tree_node *root;
	int ret;

	memblock_sinit(&mb_flow_tree);
	ret = build_flow_tree(memblock_from_stack(mb_flow_tree), dir, &root);
	if (unlikely(ret < 0))
		return ret;
	log_flow_tree(iface, root);

	ret = offload_flows(iface, root);
	if (unlikely(ret < 0))
		return ret;
	log_flow_tree(iface, root);

	ret = prune_hw_offload(iface, &root);
	if (unlikely(ret < 0))
		return ret;
	log_flow_tree(iface, root);

	return absflow_enable_exec(&dir->dir_exec, root);
}
