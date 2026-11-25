// SPDX-License-Identifier: GPL-2.0-only
/*
 * Octeon packet forwarding offload.
 *
 * Gets its flows from nf_flowtable hardware offload (fw4's flow_offloading_hw)
 * through the indirect flow block API, and sees received packets through the
 * Octeon ethernet driver's offload hook (asm/octeon/octeon-ethernet-offload.h).
 * A packet that matches a flow has its headers rewritten in its receive buffer
 * and goes straight back out through PKO, without an skb going through the
 * stack: the same fast path as Cavium's ipfwd offload, fed by nf_flowtable
 * instead of its own flow learning.
 *
 * Offloaded: IPv4 and IPv6 TCP/UDP flows between Octeon ports, with IPv4 NAT,
 * untagged or with one 802.1Q tag on either side (VLAN subinterfaces, VLAN
 * filtering bridges). Refused, so they stay in the software flowtable: PPPoE,
 * stacked VLANs, tunnels, IPv6 NAT, flows out of other devices.
 *
 * The driver hook comes from OpenWrt's octeon patch 703; a stock kernel without
 * it has the same vermagic, so this package installs there too. The hook is
 * therefore looked up at load time: without it the module still loads, says
 * so, and offloads nothing.
 *
 * Counters are in /proc/octeon_offload.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/rhashtable.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/unaligned.h>
#include <net/flow_offload.h>
#include <net/ip.h>
#include <net/pkt_cls.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-wqe.h>
#include <asm/octeon/octeon-ethernet-offload.h>

static unsigned int max_flows = 16384;
module_param(max_flows, uint, 0644);
MODULE_PARM_DESC(max_flows, "Most flows (one per direction) offloaded at once");

/* The driver's offload hook (patch 703), looked up at load time */
static struct {
	typeof(cvm_oct_offload_register) *reg;
	typeof(cvm_oct_offload_unregister) *unreg;
	typeof(cvm_oct_is_offload_port) *is_port;
	typeof(cvm_oct_offload_xmit) *xmit;
} oo_drv;
static bool oo_active;

static void oo_put_driver(void)
{
	if (oo_drv.reg)
		symbol_put(cvm_oct_offload_register);
	if (oo_drv.unreg)
		symbol_put(cvm_oct_offload_unregister);
	if (oo_drv.is_port)
		symbol_put(cvm_oct_is_offload_port);
	if (oo_drv.xmit)
		symbol_put(cvm_oct_offload_xmit);
	memset(&oo_drv, 0, sizeof(oo_drv));
}

static bool oo_get_driver(void)
{
	oo_drv.reg = symbol_get(cvm_oct_offload_register);
	oo_drv.unreg = symbol_get(cvm_oct_offload_unregister);
	oo_drv.is_port = symbol_get(cvm_oct_is_offload_port);
	oo_drv.xmit = symbol_get(cvm_oct_offload_xmit);
	if (oo_drv.reg && oo_drv.unreg && oo_drv.is_port && oo_drv.xmit)
		return true;
	oo_put_driver();
	return false;
}

/* --- counters --- */

struct oo_pcpu_stats {
	u64 rx_seen;		/* packets the driver showed us */
	u64 hits;		/* forwarded here */
	u64 misses;		/* candidates with no flow */
	u64 bypassed;		/* flow found, but sent to the stack (MTU) */
	u64 tx_errors;		/* forwarded here, but PKO refused them */
};
static DEFINE_PER_CPU(struct oo_pcpu_stats, oo_pcpu);

static atomic64_t oo_binds = ATOMIC64_INIT(0);
static atomic64_t oo_unbinds = ATOMIC64_INIT(0);
static atomic64_t oo_offered = ATOMIC64_INIT(0);
static atomic64_t oo_added = ATOMIC64_INIT(0);
static atomic64_t oo_refused = ATOMIC64_INIT(0);
static atomic64_t oo_removed = ATOMIC64_INIT(0);
/*
 * nf_flowtable offers a flow again whenever one of its packets takes the
 * software path (flow_offload_refresh(), at most once a second per flow):
 * not a new flow, and not refused either.
 */
static atomic64_t oo_reoffered = ATOMIC64_INIT(0);

/* Why a flow was refused: one counter each, in /proc/octeon_offload */
enum oo_refusal {
	OO_OK,
	OO_R_FULL,		/* max_flows reached */
	OO_R_NOMEM,
	OO_R_MATCH,		/* matches on more than we handle: stacked VLAN, tunnel */
	OO_R_PROTO,		/* not TCP or UDP */
	OO_R_L3,		/* neither IPv4 nor IPv6 */
	OO_R_VLAN,		/* not a single 802.1Q tag, or popped/pushed oddly */
	OO_R_ETH,		/* MAC address rewrite we can't read */
	OO_R_NAT,		/* IPv4 NAT rewrite we can't read */
	OO_R_IPV6_NAT,
	OO_R_OUT_DEV,		/* leaves through something other than an Octeon port */
	OO_R_ACTION,		/* other actions: PPPoE, tunnels */
	OO_R_INCOMPLETE,	/* no way out, or not both MAC addresses */
	OO_R_DUP_KEY,		/* another flow already has the same match */
	OO_R_MAX
};

static const char * const oo_refusal_names[OO_R_MAX] = {
	[OO_R_FULL] = "full",
	[OO_R_NOMEM] = "nomem",
	[OO_R_MATCH] = "match",
	[OO_R_PROTO] = "proto",
	[OO_R_L3] = "l3",
	[OO_R_VLAN] = "vlan",
	[OO_R_ETH] = "eth",
	[OO_R_NAT] = "nat",
	[OO_R_IPV6_NAT] = "ipv6_nat",
	[OO_R_OUT_DEV] = "out_dev",
	[OO_R_ACTION] = "action",
	[OO_R_INCOMPLETE] = "incomplete",
	[OO_R_DUP_KEY] = "dup_key",
};

static atomic64_t oo_refused_by[OO_R_MAX];

/* --- flows --- */

/*
 * What a received packet is matched on. IPv4 addresses go in src[0] and
 * dst[0]; the rest stays zero. A multiple of 4 bytes, for jhash2.
 */
struct oo_key {
	__be32 src[4];
	__be32 dst[4];
	__be16 sport;
	__be16 dport;
	int iif;
	u8 l3;			/* 4 or 6 */
	u8 proto;		/* IPPROTO_TCP or IPPROTO_UDP */
	u16 vlan;		/* OO_TAGGED | VLAN ID, or 0 if untagged */
};

#define OO_TAGGED	0x8000

/* One direction of an nf_flowtable flow */
struct oo_flow {
	struct rhash_head node;		/* oo_flows, by key */
	struct rhash_head cookie_node;	/* oo_cookies, by cookie */
	unsigned long cookie;		/* nf_flowtable's tuple */
	struct oo_block_priv *owner;	/* the flowtable binding that added it */
	struct oo_key key;

	/* What the packet leaves with */
	u8 eth[2 * ETH_ALEN];		/* destination and source MAC */
	__be32 src;			/* IPv4 NAT: addresses and ports after it */
	__be32 dst;
	__be16 sport;
	__be16 dport;
	bool nat;
	u16 out_vlan;			/* OO_TAGGED | VLAN ID, or 0 */
	u16 out_tci;			/* the tag it leaves with */
	struct net_device *out;
	netdevice_tracker out_tracker;

	/* Counted in the receive path, reported to nf_flowtable as deltas */
	atomic64_t packets;
	atomic64_t bytes;
	unsigned long lastused;
	u64 reported_packets;
	u64 reported_bytes;

	struct rcu_head rcu;
};

static const struct rhashtable_params oo_flow_params = {
	.head_offset = offsetof(struct oo_flow, node),
	.key_offset = offsetof(struct oo_flow, key),
	.key_len = sizeof(struct oo_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params oo_cookie_params = {
	.head_offset = offsetof(struct oo_flow, cookie_node),
	.key_offset = offsetof(struct oo_flow, cookie),
	.key_len = sizeof(unsigned long),
	.automatic_shrinking = true,
};

static struct rhashtable oo_flows;	/* receive path, under RCU */
static struct rhashtable oo_cookies;	/* control path, under oo_lock */
static DEFINE_MUTEX(oo_lock);		/* adding and removing flows */
static atomic_t oo_nflows = ATOMIC_INIT(0);

/* --- receive path --- */

static enum cvm_oct_rx_result oo_rx(struct net_device *dev,
				    struct cvmx_wqe *work, struct sk_buff *skb)
{
	struct oo_pcpu_stats *st = this_cpu_ptr(&oo_pcpu);
	struct oo_key key = {};
	struct oo_flow *flow;
	unsigned int len, l3_offset = 0;
	__be16 *ports, proto = skb->protocol;
	u8 *l3 = skb->data, *l4, *mac, *new_mac;
	u64 addr;
	int err;

	st->rx_seen++;
	if (!atomic_read(&oo_nflows))
		return CVM_OCT_RX_PASS;

	/*
	 * PIP has parsed the packet: only unfragmented TCP/UDP with good
	 * checksums and at most one VLAN tag, in one buffer (the skb is that
	 * buffer, so rewriting it rewrites what PKO sends), addressed to us.
	 */
	if (work->word2.s.bufs != 1 || work->word2.s.not_IP ||
	    work->word2.s.IP_exc || work->word2.s.L4_error ||
	    work->word2.s.is_frag || !work->word2.s.tcp_or_udp ||
	    work->word2.s.vlan_stacked || skb->pkt_type != PACKET_HOST)
		return CVM_OCT_RX_PASS;

	key.iif = dev->ifindex;
	if (work->word2.s.vlan_valid) {
		/* The driver leaves the tag in: skb->data is at the TCI */
		if (proto != htons(ETH_P_8021Q))
			return CVM_OCT_RX_PASS;
		key.vlan = OO_TAGGED | (get_unaligned_be16(l3) & VLAN_VID_MASK);
		proto = get_unaligned((__be16 *)(l3 + 2));
		l3 += VLAN_HLEN;
	}
	if (proto == htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)l3;

		if (iph->ihl != 5 || iph->ttl <= 1 || ip_is_fragment(iph))
			return CVM_OCT_RX_PASS;
		key.l3 = 4;
		key.proto = iph->protocol;
		key.src[0] = iph->saddr;
		key.dst[0] = iph->daddr;
		len = ntohs(iph->tot_len);
		l4 = (u8 *)(iph + 1);
	} else if (proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)l3;

		if (ip6h->hop_limit <= 1)
			return CVM_OCT_RX_PASS;
		key.l3 = 6;
		key.proto = ip6h->nexthdr;	/* no extension headers */
		memcpy(key.src, &ip6h->saddr, sizeof(key.src));
		memcpy(key.dst, &ip6h->daddr, sizeof(key.dst));
		len = ntohs(ip6h->payload_len) + sizeof(*ip6h);
		l4 = (u8 *)(ip6h + 1);
	} else {
		return CVM_OCT_RX_PASS;
	}

	if (key.proto == IPPROTO_TCP) {
		struct tcphdr *th = (struct tcphdr *)l4;

		/* Connection tracking sees connections start and end */
		if (th->syn || th->fin || th->rst)
			return CVM_OCT_RX_PASS;
	} else if (key.proto != IPPROTO_UDP) {
		return CVM_OCT_RX_PASS;
	}
	ports = (__be16 *)l4;
	key.sport = ports[0];
	key.dport = ports[1];

	/* The driver calls us under rcu_read_lock() */
	flow = rhashtable_lookup(&oo_flows, &key, oo_flow_params);
	if (!flow) {
		st->misses++;
		return CVM_OCT_RX_PASS;
	}
	/* Too big for the way out: the stack fragments or sends the ICMP */
	if (unlikely(len > READ_ONCE(flow->out->mtu))) {
		st->bypassed++;
		return CVM_OCT_RX_PASS;
	}

	/*
	 * The frame now starts where its new Ethernet header (and tag) end at
	 * the IP header: 4 bytes later for a tag taken off, 4 earlier (into
	 * the buffer's headroom, CVMX_HELPER_FIRST_MBUFF_SKIP) for one put on.
	 */
	mac = skb_mac_header(skb);
	new_mac = l3 - ETH_HLEN - (flow->out_vlan ? VLAN_HLEN : 0);
	addr = work->packet_ptr.s.addr + (new_mac - mac);
	/* back counts the 128-byte lines from addr to the buffer's start */
	if (unlikely((addr >> 7) <
		     (work->packet_ptr.s.addr >> 7) - work->packet_ptr.s.back)) {
		st->bypassed++;
		return CVM_OCT_RX_PASS;
	}
	memcpy(new_mac, flow->eth, sizeof(flow->eth));
	if (flow->out_vlan) {
		put_unaligned(htons(ETH_P_8021Q), (__be16 *)(new_mac + 12));
		put_unaligned_be16(flow->out_tci, new_mac + 14);
	}
	put_unaligned(proto, (__be16 *)(l3 - 2));
	if (new_mac != mac) {
		work->packet_ptr.s.back += (addr >> 7) -
					   (work->packet_ptr.s.addr >> 7);
		work->packet_ptr.s.addr = addr;
		work->word1.len -= new_mac - mac;
	}

	if (key.l3 == 4) {
		struct iphdr *iph = (struct iphdr *)l3;

		iph->ttl--;
		if (flow->nat) {
			iph->saddr = flow->src;
			iph->daddr = flow->dst;
			ports[0] = flow->sport;
			ports[1] = flow->dport;
			/* PKO fills in the TCP/UDP checksum */
			l3_offset = l3 - new_mac;
		}
		ip_send_check(iph);
	} else {
		/* The hop limit isn't in any checksum */
		((struct ipv6hdr *)l3)->hop_limit--;
	}

	atomic64_inc(&flow->packets);
	atomic64_add(len, &flow->bytes);
	if (READ_ONCE(flow->lastused) != jiffies)
		WRITE_ONCE(flow->lastused, jiffies);

	/* Frees the work and its buffers if it can't send them */
	err = oo_drv.xmit(flow->out, work, 0, l3_offset);
	if (unlikely(err))
		st->tx_errors++;
	else
		st->hits++;
	return CVM_OCT_RX_TAKEN_WORK;
}

static const struct cvm_oct_offload_ops oo_ops = {
	.owner = THIS_MODULE,
	.rx = oo_rx,
};

/* --- flows from nf_flowtable --- */

/*
 * One per port and flowtable. A port can be bound to two flowtables at once:
 * when fw4 reloads, nftables binds the new flowtable before it unbinds the
 * old one.
 *
 * Keyed on the flowtable (the setup call's data), not bo->block: when this
 * module registers while a flowtable exists, the kernel replays its binding
 * with a zeroed bo (existing_qdiscs_register()), so bo->block is NULL then.
 * Keyed on the block, that binding never matched the flowtable's unbind,
 * outlived the flowtable, and module unload ran nf_flowtable's cleanup on
 * the freed flowtable.
 */
struct oo_block_priv {
	struct list_head list;
	struct net_device *dev;
	void *flowtable;
};

static LIST_HEAD(oo_block_priv_list);
static LIST_HEAD(oo_block_cb_list);

#define OO_ETH_DST_HI	BIT(0)
#define OO_ETH_DST_LO	BIT(1)
#define OO_ETH_SRC_HI	BIT(2)
#define OO_ETH_SRC_LO	BIT(3)
#define OO_ETH_ALL	(OO_ETH_DST_HI | OO_ETH_DST_LO | OO_ETH_SRC_HI | \
			 OO_ETH_SRC_LO)

/*
 * nf_flowtable sets the MAC addresses with four 32-bit mangles built from
 * memcpy()s and shifts in CPU byte order (flow_offload_eth_src() and
 * _dst()), which only lay the bytes out in place on a little-endian CPU.
 * Octeon is big-endian, so undo that construction instead of applying the
 * mangles as masks: this gives the right bytes either way.
 */
static int oo_parse_eth(const struct flow_action_entry *act, u8 *eth,
			unsigned int *seen)
{
	u32 val = act->mangle.val;
	u16 v16;

	switch (act->mangle.offset) {
	case 0:			/* destination bytes 0-3 */
		if (act->mangle.mask)
			return -EOPNOTSUPP;
		memcpy(eth, &val, 4);
		*seen |= OO_ETH_DST_HI;
		return 0;
	case 4:
		if (act->mangle.mask == ~0x0000ffffU) {
			/* destination bytes 4-5 */
			v16 = val;
			memcpy(eth + 4, &v16, 2);
			*seen |= OO_ETH_DST_LO;
			return 0;
		}
		if (act->mangle.mask == ~0xffff0000U) {
			/* source bytes 0-1 */
			v16 = val >> 16;
			memcpy(eth + ETH_ALEN, &v16, 2);
			*seen |= OO_ETH_SRC_HI;
			return 0;
		}
		return -EOPNOTSUPP;
	case 8:			/* source bytes 2-5 */
		if (act->mangle.mask)
			return -EOPNOTSUPP;
		memcpy(eth + ETH_ALEN + 2, &val, 4);
		*seen |= OO_ETH_SRC_LO;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/* IPv4 address and port mangles are in network byte order */
static int oo_parse_nat(const struct flow_action_entry *act,
			struct oo_flow *flow)
{
	u32 mask = ntohl((__force __be32)act->mangle.mask);
	u32 val = ntohl((__force __be32)act->mangle.val);

	switch (act->mangle.htype) {
	case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
		if (mask)
			return -EOPNOTSUPP;
		if (act->mangle.offset == offsetof(struct iphdr, saddr))
			flow->src = htonl(val);
		else if (act->mangle.offset == offsetof(struct iphdr, daddr))
			flow->dst = htonl(val);
		else
			return -EOPNOTSUPP;
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
	case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
		if (act->mangle.offset)
			return -EOPNOTSUPP;
		if (mask == 0x0000ffff)
			flow->sport = htons(val >> 16);
		else if (mask == 0xffff0000)
			flow->dport = htons(val & 0xffff);
		else
			return -EOPNOTSUPP;
		break;
	default:
		return -EOPNOTSUPP;
	}
	flow->nat = true;
	return 0;
}

#define OO_KEYS (BIT_ULL(FLOW_DISSECTOR_KEY_META) |		\
		 BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |		\
		 BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |		\
		 BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |	\
		 BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |	\
		 BIT_ULL(FLOW_DISSECTOR_KEY_TCP) |		\
		 BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |		\
		 BIT_ULL(FLOW_DISSECTOR_KEY_VLAN))

/* The port a rule's packets come in on, or 0 */
static int oo_rule_iif(struct flow_rule *rule)
{
	struct flow_match_meta meta;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return 0;
	flow_rule_match_meta(rule, &meta);
	return meta.key->ingress_ifindex;
}

/*
 * Fill @flow from an nf_flowtable rule for a flow received on @in.
 * Returns OO_OK, or why the flow can't be offloaded.
 */
static enum oo_refusal oo_flow_parse(struct flow_rule *rule,
				     struct net_device *in,
				     struct oo_flow *flow)
{
	struct flow_dissector *dissector = rule->match.dissector;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ports ports;
	struct flow_action_entry *act;
	unsigned int eth_seen = 0;
	bool popped = false;
	int i;

	/* Not stacked VLAN or tunnel matches */
	if (dissector->used_keys & ~OO_KEYS)
		return OO_R_MATCH;
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS))
		return OO_R_MATCH;
	flow->key.iif = in->ifindex;

	flow_rule_match_basic(rule, &basic);
	if (basic.key->ip_proto != IPPROTO_TCP &&
	    basic.key->ip_proto != IPPROTO_UDP)
		return OO_R_PROTO;
	flow->key.proto = basic.key->ip_proto;

	flow_rule_match_control(rule, &control);
	if (control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs addrs;

		flow_rule_match_ipv4_addrs(rule, &addrs);
		flow->key.l3 = 4;
		flow->key.src[0] = addrs.key->src;
		flow->key.dst[0] = addrs.key->dst;
	} else if (control.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs addrs;

		flow_rule_match_ipv6_addrs(rule, &addrs);
		flow->key.l3 = 6;
		memcpy(flow->key.src, &addrs.key->src, sizeof(flow->key.src));
		memcpy(flow->key.dst, &addrs.key->dst, sizeof(flow->key.dst));
	} else {
		return OO_R_L3;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan vlan;

		flow_rule_match_vlan(rule, &vlan);
		if (vlan.key->vlan_tpid != htons(ETH_P_8021Q) ||
		    vlan.mask->vlan_id != VLAN_VID_MASK)
			return OO_R_VLAN;
		flow->key.vlan = OO_TAGGED | vlan.key->vlan_id;
	}

	flow_rule_match_ports(rule, &ports);
	flow->key.sport = ports.key->src;
	flow->key.dport = ports.key->dst;

	/* Without NAT, the packet leaves with what it came in with */
	flow->src = flow->key.src[0];
	flow->dst = flow->key.dst[0];
	flow->sport = flow->key.sport;
	flow->dport = flow->key.dport;

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			if (act->mangle.htype == FLOW_ACT_MANGLE_HDR_TYPE_ETH) {
				if (oo_parse_eth(act, flow->eth, &eth_seen))
					return OO_R_ETH;
			} else if (flow->key.l3 == 4) {
				if (oo_parse_nat(act, flow))
					return OO_R_NAT;
			} else {
				return OO_R_IPV6_NAT;
			}
			break;
		case FLOW_ACTION_CSUM:
			/* The receive path fixes the checksums */
			break;
		case FLOW_ACTION_REDIRECT:
			if (flow->out)
				return OO_R_ACTION;
			if (!act->dev || !oo_drv.is_port(act->dev))
				return OO_R_OUT_DEV;
			flow->out = act->dev;
			break;
		case FLOW_ACTION_VLAN_POP:
			/* The tag it was matched on */
			if (!flow->key.vlan || popped)
				return OO_R_VLAN;
			popped = true;
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (flow->out_vlan || act->vlan.proto != htons(ETH_P_8021Q))
				return OO_R_VLAN;
			flow->out_vlan = OO_TAGGED | act->vlan.vid;
			flow->out_tci = act->vlan.vid |
					(act->vlan.prio << VLAN_PRIO_SHIFT);
			break;
		default:
			/* PPPoE, tunnels */
			return OO_R_ACTION;
		}
	}

	if (popped != !!flow->key.vlan)
		return OO_R_VLAN;
	if (!flow->out || eth_seen != OO_ETH_ALL)
		return OO_R_INCOMPLETE;
	return OO_OK;
}

/* Under oo_lock */
static void oo_flow_remove(struct oo_flow *flow)
{
	rhashtable_remove_fast(&oo_flows, &flow->node, oo_flow_params);
	rhashtable_remove_fast(&oo_cookies, &flow->cookie_node,
			       oo_cookie_params);
	atomic_dec(&oo_nflows);
	atomic64_inc(&oo_removed);
	netdev_put(flow->out, &flow->out_tracker);
	/* The receive path may still be forwarding with it */
	kfree_rcu(flow, rcu);
}

/* Module exit: the receive path is gone, no RCU grace period needed */
static void oo_flow_free(void *ptr, void *arg)
{
	struct oo_flow *flow = ptr;

	netdev_put(flow->out, &flow->out_tracker);
	kfree(flow);
}

static bool oo_have_cookie(unsigned long cookie)
{
	bool have;

	mutex_lock(&oo_lock);
	have = rhashtable_lookup_fast(&oo_cookies, &cookie, oo_cookie_params);
	mutex_unlock(&oo_lock);
	return have;
}

static int oo_flow_refuse(enum oo_refusal why, int err)
{
	atomic64_inc(&oo_refused);
	atomic64_inc(&oo_refused_by[why]);
	return err;
}

static int oo_flow_add(struct oo_block_priv *priv, struct flow_cls_offload *f)
{
	enum oo_refusal why;
	struct oo_flow *flow;
	int err;

	/*
	 * Offered again (see oo_reoffered): already offloaded, keep it.
	 * nf_flowtable tears a flow down and offers a new one when its way
	 * out changes, so a flow it offers again is the same flow.
	 */
	if (oo_have_cookie(f->cookie)) {
		atomic64_inc(&oo_reoffered);
		return 0;
	}

	atomic64_inc(&oo_offered);
	if (atomic_read(&oo_nflows) >= READ_ONCE(max_flows))
		return oo_flow_refuse(OO_R_FULL, -ENOSPC);

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	if (!flow)
		return oo_flow_refuse(OO_R_NOMEM, -ENOMEM);
	flow->cookie = f->cookie;
	flow->owner = priv;
	flow->lastused = jiffies;

	why = oo_flow_parse(flow_cls_offload_flow_rule(f), priv->dev, flow);
	if (why != OO_OK) {
		kfree(flow);
		return oo_flow_refuse(why, -EOPNOTSUPP);
	}

	mutex_lock(&oo_lock);
	err = rhashtable_lookup_insert_fast(&oo_cookies, &flow->cookie_node,
					    oo_cookie_params);
	if (err == -EEXIST) {
		/* Offered again while we were parsing it */
		mutex_unlock(&oo_lock);
		kfree(flow);
		atomic64_dec(&oo_offered);
		atomic64_inc(&oo_reoffered);
		return 0;
	}
	if (err) {
		why = OO_R_NOMEM;
		goto err_unlock;
	}
	err = rhashtable_lookup_insert_fast(&oo_flows, &flow->node,
					    oo_flow_params);
	if (err) {
		rhashtable_remove_fast(&oo_cookies, &flow->cookie_node,
				       oo_cookie_params);
		why = err == -EEXIST ? OO_R_DUP_KEY : OO_R_NOMEM;
		goto err_unlock;
	}
	netdev_hold(flow->out, &flow->out_tracker, GFP_KERNEL);
	atomic_inc(&oo_nflows);
	mutex_unlock(&oo_lock);

	atomic64_inc(&oo_added);
	return 0;

err_unlock:
	mutex_unlock(&oo_lock);
	kfree(flow);
	return oo_flow_refuse(why, err);
}

/*
 * nf_flowtable calls every port's callback for every flow, so each flow is
 * handled only by the callback of the port it is received on.
 */
static struct oo_flow *oo_flow_find(struct oo_block_priv *priv,
				    unsigned long cookie)
{
	struct oo_flow *flow;

	flow = rhashtable_lookup_fast(&oo_cookies, &cookie, oo_cookie_params);
	if (flow && flow->owner != priv)
		return NULL;
	return flow;
}

static void oo_flow_destroy(struct oo_block_priv *priv,
			    struct flow_cls_offload *f)
{
	struct oo_flow *flow;

	mutex_lock(&oo_lock);
	flow = oo_flow_find(priv, f->cookie);
	if (flow)
		oo_flow_remove(flow);
	mutex_unlock(&oo_lock);
}

static void oo_flow_stats(struct oo_block_priv *priv,
			  struct flow_cls_offload *f)
{
	struct oo_flow *flow;
	u64 packets, bytes;

	mutex_lock(&oo_lock);
	flow = oo_flow_find(priv, f->cookie);
	if (flow) {
		packets = atomic64_read(&flow->packets);
		bytes = atomic64_read(&flow->bytes);
		flow_stats_update(&f->stats, bytes - flow->reported_bytes,
				  packets - flow->reported_packets, 0,
				  READ_ONCE(flow->lastused),
				  FLOW_ACTION_HW_STATS_IMMEDIATE);
		flow->reported_packets = packets;
		flow->reported_bytes = bytes;
	}
	mutex_unlock(&oo_lock);
}

static int oo_flow_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct oo_block_priv *priv = cb_priv;
	struct flow_cls_offload *f = type_data;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	switch (f->command) {
	case FLOW_CLS_REPLACE:
		/* Another port's flow (see oo_flow_find()) */
		if (oo_rule_iif(flow_cls_offload_flow_rule(f)) !=
		    priv->dev->ifindex)
			return -EOPNOTSUPP;
		return oo_flow_add(priv, f);
	case FLOW_CLS_DESTROY:
		oo_flow_destroy(priv, f);
		return 0;
	case FLOW_CLS_STATS:
		oo_flow_stats(priv, f);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Remove the flows into or out of port @dev, or only its VLAN @vlan if set;
 * or, with @owner, the flows one flowtable binding added.
 */
static void oo_flows_purge(const struct net_device *dev, u16 vlan,
			   const struct oo_block_priv *owner)
{
	struct rhashtable_iter iter;
	struct oo_flow *flow;
	bool resized;

	mutex_lock(&oo_lock);
	do {
		/* Removing flows can shrink the table, and a walk across a
		 * resize may miss some: walk again until one doesn't cross one.
		 */
		resized = false;
		rhashtable_walk_enter(&oo_cookies, &iter);
		rhashtable_walk_start(&iter);
		while ((flow = rhashtable_walk_next(&iter))) {
			if (IS_ERR(flow)) {
				resized = true;		/* -EAGAIN */
				continue;
			}
			if (owner ? flow->owner == owner :
			    (flow->out == dev &&
			     (!vlan || flow->out_vlan == vlan)) ||
			    (flow->key.iif == dev->ifindex &&
			     (!vlan || flow->key.vlan == vlan)))
				oo_flow_remove(flow);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
	} while (resized);
	mutex_unlock(&oo_lock);
}

static struct oo_block_priv *oo_block_priv_lookup(struct net_device *dev,
						  void *flowtable)
{
	struct oo_block_priv *priv;

	list_for_each_entry(priv, &oo_block_priv_list, list)
		if (priv->dev == dev && priv->flowtable == flowtable)
			return priv;
	return NULL;
}

static void oo_block_release(void *cb_priv)
{
	struct oo_block_priv *priv = cb_priv;

	list_del(&priv->list);
	kfree(priv);
}

static int oo_setup_block(struct net_device *dev, struct Qdisc *sch,
			  struct flow_block_offload *bo, void *data,
			  void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct oo_block_priv *priv;
	struct flow_block_cb *block_cb;

	if (bo->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	switch (bo->command) {
	case FLOW_BLOCK_BIND:
		if (oo_block_priv_lookup(dev, data))
			return -EBUSY;
		priv = kzalloc(sizeof(*priv), GFP_KERNEL);
		if (!priv)
			return -ENOMEM;
		priv->dev = dev;
		priv->flowtable = data;
		list_add(&priv->list, &oo_block_priv_list);

		block_cb = flow_indr_block_cb_alloc(oo_flow_cb, priv, priv,
						    oo_block_release, bo, dev,
						    sch, data, NULL, cleanup);
		if (IS_ERR(block_cb)) {
			list_del(&priv->list);
			kfree(priv);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, bo);
		list_add_tail(&block_cb->driver_list, &oo_block_cb_list);
		atomic64_inc(&oo_binds);
		pr_info("%s: bound to a flowtable\n", dev->name);
		return 0;
	case FLOW_BLOCK_UNBIND:
		priv = oo_block_priv_lookup(dev, data);
		if (!priv)
			return -ENOENT;
		block_cb = flow_block_cb_lookup(bo->block, oo_flow_cb, priv);
		if (!block_cb)
			return -ENOENT;
		/* Only this flowtable's flows: another may be bound already */
		oo_flows_purge(dev, 0, priv);
		flow_indr_block_cb_remove(block_cb, bo);
		list_del(&block_cb->driver_list);
		atomic64_inc(&oo_unbinds);
		pr_info("%s: unbound from a flowtable\n", dev->name);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/* Called for every device a flowtable (or tc block) is offloaded on */
static int oo_indr_setup(struct net_device *dev, struct Qdisc *sch,
			 void *cb_priv, enum tc_setup_type type,
			 void *type_data, void *data,
			 void (*cleanup)(struct flow_block_cb *block_cb))
{
	if (!dev || !oo_drv.is_port(dev))
		return -EOPNOTSUPP;
	if (type != TC_SETUP_FT)
		return -EOPNOTSUPP;
	return oo_setup_block(dev, sch, type_data, data, cleanup);
}

/*
 * A flow holds its way out (and the MAC address it leaves with): drop the
 * flows through a port or VLAN subinterface that goes down, changes address
 * or goes away. Their packets then take the software flowtable.
 */
static int oo_netdev_event(struct notifier_block *nb, unsigned long event,
			   void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_DOWN:
	case NETDEV_CHANGEADDR:
	case NETDEV_UNREGISTER:
		if (oo_drv.is_port(dev))
			oo_flows_purge(dev, 0, NULL);
		else if (is_vlan_dev(dev) &&
			 oo_drv.is_port(vlan_dev_priv(dev)->real_dev))
			oo_flows_purge(vlan_dev_priv(dev)->real_dev,
				       OO_TAGGED | vlan_dev_priv(dev)->vlan_id, NULL);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block oo_netdev_nb = {
	.notifier_call = oo_netdev_event,
};

/* --- /proc/octeon_offload --- */

static int oo_proc_show(struct seq_file *m, void *v)
{
	struct oo_pcpu_stats sum = {};
	int cpu, i;

	for_each_possible_cpu(cpu) {
		const struct oo_pcpu_stats *st = per_cpu_ptr(&oo_pcpu, cpu);

		sum.rx_seen += READ_ONCE(st->rx_seen);
		sum.hits += READ_ONCE(st->hits);
		sum.misses += READ_ONCE(st->misses);
		sum.bypassed += READ_ONCE(st->bypassed);
		sum.tx_errors += READ_ONCE(st->tx_errors);
	}

	seq_printf(m, "driver_hooks %s\n", oo_active ? "yes" :
		   "no (kernel lacks the octeon offload patch, nothing offloaded)");
	seq_printf(m, "flows %d\n", atomic_read(&oo_nflows));
	seq_printf(m, "max_flows %u\n", READ_ONCE(max_flows));
	seq_printf(m, "rx_packets_seen %llu\n", sum.rx_seen);
	seq_printf(m, "forwarded %llu\n", sum.hits);
	seq_printf(m, "no_flow %llu\n", sum.misses);
	seq_printf(m, "to_stack_mtu %llu\n", sum.bypassed);
	seq_printf(m, "tx_errors %llu\n", sum.tx_errors);
	seq_printf(m, "flowtable_binds %lld\n", atomic64_read(&oo_binds));
	seq_printf(m, "flowtable_unbinds %lld\n", atomic64_read(&oo_unbinds));
	seq_printf(m, "flows_offered %lld\n", atomic64_read(&oo_offered));
	seq_printf(m, "flows_added %lld\n", atomic64_read(&oo_added));
	seq_printf(m, "flows_refused %lld\n", atomic64_read(&oo_refused));
	seq_printf(m, "flows_reoffered %lld\n", atomic64_read(&oo_reoffered));
	seq_printf(m, "flows_removed %lld\n", atomic64_read(&oo_removed));
	for (i = OO_OK + 1; i < OO_R_MAX; i++)
		seq_printf(m, "refused_%s %lld\n", oo_refusal_names[i],
			   atomic64_read(&oo_refused_by[i]));
	return 0;
}

static struct proc_dir_entry *oo_proc;

static int __init oo_init(void)
{
	int err;

	oo_proc = proc_create_single("octeon_offload", 0444, NULL, oo_proc_show);
	if (!oo_proc)
		return -ENOMEM;

	if (!oo_get_driver()) {
		pr_warn("kernel has no Octeon offload hooks (OpenWrt octeon patch 703); not offloading\n");
		return 0;
	}

	err = rhashtable_init(&oo_flows, &oo_flow_params);
	if (err)
		goto err_driver;
	err = rhashtable_init(&oo_cookies, &oo_cookie_params);
	if (err)
		goto err_flows;

	err = register_netdevice_notifier(&oo_netdev_nb);
	if (err)
		goto err_cookies;

	err = flow_indr_dev_register(oo_indr_setup, NULL);
	if (err)
		goto err_notifier;

	err = oo_drv.reg(&oo_ops);
	if (err)
		goto err_indr;

	oo_active = true;
	pr_info("loaded\n");
	return 0;

err_indr:
	flow_indr_dev_unregister(oo_indr_setup, NULL, oo_block_release);
err_notifier:
	unregister_netdevice_notifier(&oo_netdev_nb);
err_cookies:
	rhashtable_destroy(&oo_cookies);
err_flows:
	rhashtable_destroy(&oo_flows);
err_driver:
	oo_put_driver();
	proc_remove(oo_proc);
	return err;
}

static void __exit oo_exit(void)
{
	if (oo_active) {
		/* No receive callback runs after this */
		oo_drv.unreg(&oo_ops);
		flow_indr_dev_unregister(oo_indr_setup, NULL, oo_block_release);
		unregister_netdevice_notifier(&oo_netdev_nb);
		/* Nothing adds or looks up flows any more */
		rhashtable_destroy(&oo_flows);
		rhashtable_free_and_destroy(&oo_cookies, oo_flow_free, NULL);
		rcu_barrier();	/* kfree_rcu() of flows removed before */
		oo_put_driver();
	}
	proc_remove(oo_proc);
}

module_init(oo_init);
module_exit(oo_exit);
MODULE_DESCRIPTION("Octeon packet forwarding offload");
MODULE_LICENSE("GPL");
