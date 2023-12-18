/* Kernel PSP transmit path
 *
 */
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <net/protocol.h>
#include <net/psp_defs.h>
#include <net/psp.h>
#include <net/udp.h>

static void __psp_write_headers(struct net *net, struct sk_buff *skb,
				unsigned int udp_len, int port_min,
				int port_max)
{
	struct udphdr *uh = udp_hdr(skb);
	struct psphdr *psph = (struct psphdr *)(uh + 1);

	uh->dest = htons(PSP_UDP_DPORT);
	uh->source = udp_flow_src_port(net,
				       skb,
				       port_min,
				       port_max,
				       /*use_eth=*/ false);
	uh->check = 0;
	uh->len = htons(udp_len);

	psph->nh = IPPROTO_TCP;
	psph->extlen = 1;
	/* expose TCP ports but not the rest of the TCP header */
	psph->cryptoff = offsetof(struct tcphdr, seq) / sizeof(__be32);
	psph->flags = 1;        /* reserved 0, version 0, V = 0 */
	psph->spi = skb->psp.spi;
	memset(&psph->iv, 0, sizeof(psph->iv));

	skb_shinfo(skb)->gso_type |= SKB_GSO_PSP;
}

/* Encapsulate a TCP packet with PSP by adding the UDP+PSP headers and filling
 * them in.
 */
void psp_encapsulate(struct net *net, struct sk_buff *skb,
		     const struct psp_key_spi *key_spi)
{
	skb_set_inner_ipproto(skb, IPPROTO_TCP);
	skb_reset_inner_headers(skb);
	skb->encapsulation = 1;
	psp_set_psp_skb(skb, key_spi);

	skb_push(skb, PSP_ENCAP_HLEN);
	skb_reset_transport_header(skb);

	__psp_write_headers(net, skb, skb->len, 0, 0);

	skb->psp.spi = PSP_SKB_SPI_SPECIAL;
}

int __psp_dev_encapsulate(struct sk_buff *skb)
{
	u32 ip_payload_len;
	unsigned int udp_len;

	/* Only valid for PSP socket and packets without PSP encap yet */
	if (!SKB_PSP_SPI(skb))
		return 0;
	/* skb with PSP metadata but transport header was not set */
	if (unlikely(!skb_transport_header_was_set(skb))) {
		WARN_ON(1);
		return -1;
	}
	/* Ensure we have enough headroom to encapsulate */
	if (unlikely(skb_headroom(skb) < PSP_ENCAP_HLEN)) {
		WARN_ON(1);
		return -1;
	}
	/* Consume more headroom */
	skb_push(skb, PSP_ENCAP_HLEN);
	/* Shift headers to make room for PSP [MAC][IP][...][PSP][TCP] */
	memmove(skb->data,
		skb->data + PSP_ENCAP_HLEN,
		skb->transport_header - skb->mac_header);
	skb->transport_header -= PSP_ENCAP_HLEN;
	skb->network_header -= PSP_ENCAP_HLEN;
	skb->mac_header -= PSP_ENCAP_HLEN;
	/* Update inner transport header */
	skb_set_inner_ipproto(skb, IPPROTO_TCP);
	skb->inner_transport_header = skb->transport_header + PSP_ENCAP_HLEN;
	skb->encapsulation = 1;
	/* Fill in PSP header */
	udp_len = skb->len - skb_transport_offset(skb),
	__psp_write_headers(&init_net, skb, udp_len,
			    PSP_SRC_PORT_MIN, PSP_SRC_PORT_MAX);
	/* Update IP header and extension*/
	if (ip_hdr(skb)->version == 4) {
		ip_hdr(skb)->protocol = IPPROTO_UDP;
		ip_payload_len = ntohs(ip_hdr(skb)->tot_len);
		ip_payload_len += PSP_ENCAP_HLEN;
		ip_hdr(skb)->tot_len = htons(ip_payload_len);
	} else {
		ipv6_hdr(skb)->nexthdr = IPPROTO_UDP;
		ip_payload_len = ntohs(ipv6_hdr(skb)->payload_len);
		ip_payload_len += PSP_ENCAP_HLEN;
		ipv6_hdr(skb)->payload_len = htons(ip_payload_len);
	}
	/* Mark SKB_GSO_PSP */
	skb_shinfo(skb)->gso_type |= SKB_GSO_PSP;
	return 0;
}
EXPORT_SYMBOL(__psp_dev_encapsulate);

/* Similar to psp_encapsulate() but for an skb built from an ip_reply_arg.
 * The PSP/UDP headers already exist, we need to fill them in.
 */
void psp_finish_encap(struct net *net, struct sk_buff *skb,
		      const struct psp_key_spi *key_spi)
{
	skb_set_inner_ipproto(skb, IPPROTO_TCP);
	skb->inner_transport_header = skb->transport_header + PSP_ENCAP_HLEN;
	skb->encapsulation = 1;
	psp_set_psp_skb(skb, key_spi);

	__psp_write_headers(net, skb, skb->len - skb_transport_offset(skb), 0, 0);

	skb->psp.spi = PSP_SKB_SPI_SPECIAL;
}

struct sk_buff *psp_segment(struct sk_buff *skb, netdev_features_t features,
			    const struct net_offload __rcu **offloads)
{
	const unsigned int psp_udp_hlen = PSP_ENCAP_HLEN;
	const struct net_offload *ops;
	struct sk_buff *segs;
	int udp_offset;

	ops = rcu_dereference(offloads[skb->inner_ipproto]);
	if (unlikely(!ops || !ops->callbacks.gso_segment)) {
		segs = ERR_PTR(-EPROTONOSUPPORT);
		goto out;
	}

	if (unlikely(!pskb_may_pull(skb, psp_udp_hlen))) {
		segs = ERR_PTR(-EINVAL);
		goto out;
	}

	udp_offset = skb_transport_header(skb) - skb_mac_header(skb);
	__skb_pull(skb, psp_udp_hlen);
	skb_reset_transport_header(skb);
	skb->encapsulation = 0;

	features &= skb->dev->hw_enc_features;
	segs = ops->callbacks.gso_segment(skb, features);
	if (unlikely(IS_ERR_OR_NULL(segs))) {
		skb_push(skb, psp_udp_hlen);
		skb_reset_transport_header(skb);
		skb->encapsulation = 1;
		goto out;
	}

	for (skb = segs; skb; skb = skb->next) {
		skb->transport_header -= psp_udp_hlen;
		skb->encapsulation = 1;

		/* transport-mode PSP requires this to be 0 */
		skb->inner_network_header = 0;

		udp_hdr(skb)->len = htons(skb->len - udp_offset);
	}
out:
	return segs;
}
EXPORT_SYMBOL(psp_segment);
