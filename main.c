#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/ip.h>

#include<linux/kthread.h>
#include<linux/sched.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("caydyn <caydyn@icloud.com>");
MODULE_DESCRIPTION("send a pkt in kernel");


inline struct sk_buff * 
create_skb(struct net_device *dev, uint16_t size)
{
	uint16_t skb_size = size + LL_RESERVED_SPACE(dev);
	struct sk_buff *skb = alloc_skb(skb_size, GFP_ATOMIC);
	if(skb)
	{		
		skb_reserve(skb, LL_RESERVED_SPACE(dev));

		skb->dev = dev;
		skb->pkt_type = PACKET_OTHERHOST;
    	skb->protocol = htons(ETH_P_IP);
    	skb->ip_summed = CHECKSUM_NONE;
    	skb->priority = 0;
		skb->next = skb->prev = NULL;

		return skb;
	}
	
	return NULL;
}

inline void put_L2hdr(struct sk_buff *pkt)
{
	struct ethhdr *eth = NULL;
	uint8_t src[ETH_ALEN] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
	uint8_t dst[ETH_ALEN] = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};

	skb_set_mac_header(pkt, 0);
	
	eth = (struct ethhdr *) skb_put(pkt, ETH_HLEN);
	if(eth)
	{
		eth->h_proto = htons(ETH_P_IP);
		memcpy(eth->h_source, src, ETH_ALEN);
		memcpy(eth->h_dest, dst, ETH_ALEN);
	}
}

inline void put_L3hdr(struct sk_buff *pkt)
{	
	struct iphdr *ipv4 = NULL;
	struct ipv6hdr *ipv6 = NULL;
	
	skb_set_network_header(pkt, sizeof(struct ethhdr));

	ipv4 = (struct iphdr *)skb_put(pkt, sizeof(struct iphdr));
	if(ipv4)
	{
		ipv4->version = IPVERSION;
		ipv4->ihl = sizeof(struct iphdr) >> 2;
		ipv4->tos = 0;
		ipv4->id = 0;
		ipv4->ttl = 0x40;
		ipv4->frag_off = 0;
		ipv4->protocol = IPPROTO_UDP;
		ipv4->saddr = htonl(0xC0A802C8);
		ipv4->daddr = htonl(0xC0A80264);
		ipv4->tot_len = htons(50);
		ipv4->check = 0;
		
		skb_set_transport_header(pkt, 
			sizeof(struct ethhdr) + sizeof(struct iphdr));
	}
}

inline void put_L4hdr(struct sk_buff *pkt)
{
	struct udphdr *udp = NULL;
	struct tcphdr *tcp = NULL;

	udp = (struct udphdr *)skb_put(pkt, sizeof(struct udphdr));
	if(udp)
	{
		udp->source = htons(0x1234);
		udp->dest = htons(0x1235);
		udp->len = htons(22);
		udp->check = 0;
	}
}

inline void put_data(struct sk_buff *pkt)
{
	void *data = (void *)skb_put(pkt, 22);
	if(data)
		get_random_bytes(data, 22);
}

inline void insert_l3_l4_checksum(struct sk_buff *pkt)
{
	struct ethhdr *eth = NULL;
	struct iphdr *ipv4 = NULL;
	struct udphdr *udp = NULL;
	struct tcphdr *tcp = NULL;
	__wsum partial;

	eth = eth_hdr(pkt);
	
	if(eth->h_proto == htons(ETH_P_IP))
	{		
		ipv4 = ip_hdr(pkt);
		ipv4->check = ip_fast_csum((unsigned char *)ipv4, 5);
		if(ipv4->protocol == IPPROTO_UDP)
		{
			udp = udp_hdr(pkt);
			partial = 
				csum_partial((unsigned char *)udp, 22, 0);
			udp->check = 
				csum_tcpudp_magic(ipv4->saddr, ipv4->daddr, 22, 
				IPPROTO_UDP, partial);
		}
		else if(ipv4->protocol == IPPROTO_TCP)
		{
			tcp = tcp_hdr(pkt);
			partial = 
				csum_partial((unsigned char *)tcp, 22, 0);
			tcp->check = 
				csum_tcpudp_magic(ipv4->saddr, ipv4->daddr, 22, 
				IPPROTO_TCP, partial);
		}
	}	
}

inline struct sk_buff * 
create_a_pkt(struct net_device *send)
{
	struct sk_buff *pkt = NULL;
	
	pkt = create_skb(send, 64);

	if(!pkt)
		goto ERROR_RETURN;
	
	put_L2hdr(pkt);
	put_L3hdr(pkt);
	put_L4hdr(pkt);
	put_data(pkt);
	insert_l3_l4_checksum(pkt);

ERROR_RETURN:
	return pkt;
}

inline int 
send_A_pkt(struct net_device *send)
{
	int err = 0;
	struct sk_buff *pkt = create_a_pkt(send);
	if(!pkt)
		return (-1);
	
 	err = dev_queue_xmit(pkt);
	
	if (err != NET_XMIT_SUCCESS)
	{
		kfree_skb(pkt);
		return (-2);
	}
	
	return err;
}

struct net_device *get_send_dev(char *device_name)
{
	struct net_device *dev;
	dev = first_net_device(&init_net);
	while (dev) {
		if (!strcmp(dev->name, device_name))
			return dev;
		dev = next_net_device(dev);
	}
	return NULL;
}

static int __int send_module_init(void)
{
	struct net_device *send_dev = NULL;

	send_dev = get_send_dev("eth0");

	if(send_dev)
		send_A_pkt(send_dev);

	return 0;
}

static void __exit send_module_exit(void)
{
	return;
}

module_init(send_module_init);
module_exit(send_module_exit);
