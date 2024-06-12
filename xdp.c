#include "/home/katana/c/headers/vmlinux.h"  // Include the vmlinux.h header for kernel structures.
#include <bpf/bpf_helpers.h>  // Include the BPF helper functions.
#include <bpf/bpf_endian.h>   // Include the BPF endian conversion functions.

#define MAX_MAP_ENTRIES 100  // Define the maximum number of entries for the map.

/*
 * Define an LRU hash map for storing packet counts by source IP and port.
 * BPF_MAP_TYPE_LRU_HASH: This type of map lets us store a (key, value) pair as a hashmap with LRU variant.
 * __uint: Macro to define a map attribute.
 * max_entries: The maximum number of entries the map can hold.
 * key: The type of the map key (u64 in this case, representing IP:port).
 * value: The type of the map value (u32 in this case, representing packet count).
 */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Specify the map type.
    __uint(max_entries, MAX_MAP_ENTRIES);  // Specify the maximum number of entries.
    __type(key, u64);   // Specify the key type.
    __type(value, u32); // Specify the value type.
} xdp_stats_map SEC(".maps");  // Define the map in the BPF program.

/* Define some constants for protocol parsing and packet processing */
#define ETH_P_IP 0x0800     // Internet Protocol Packet (IPv4).
#define PARSE_SKIP 0        // Code to indicate packet parsing should be skipped.
#define PARSED_TCP_PACKET 1 // Code to indicate a successfully parsed TCP packet.
#define PARSED_UDP_PACKET 2 // Code to indicate a successfully parsed UDP packet.

/*
 * Function to parse the IP packet and extract metadata (source IP, source port, destination port).
 * - ctx: The XDP context containing packet data.
 * - ip_metadata: Pointer to store the extracted IP metadata.
 * Returns a code indicating the packet type or whether to skip processing.
 */
static __always_inline int parse_ip_packet(struct xdp_md *ctx, u64 *ip_metadata)
{
    // Pointers to the start and end of the packet data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // First, parse the Ethernet header.
    struct ethhdr *eth = data;

    // Ensure the Ethernet header is within packet bounds.
    if ((void *)(eth + 1) > data_end)
    {
        return PARSE_SKIP;  // Skip packet parsing if Ethernet header is out of bounds.
    }

    // Check if the Ethernet frame contains an IPv4 packet.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return PARSE_SKIP;  // Skip packet if not an IPv4 packet.
    }

    // Then parse the IP header.
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Ensure the IP header is within packet bounds.
    if ((void *)(ip + 1) > data_end)
    {
        return PARSE_SKIP;  // Skip packet parsing if IP header is out of bounds.
    }

    u16 src_port, dest_port; // Variables to hold source and destination ports.
    int retval;              // Variable to hold the return value.

    // Check if the protocol is TCP.
    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));

        // Ensure the TCP header is within packet bounds.
        if ((void *)(tcp + 1) > data_end)
        {
            return PARSE_SKIP;  // Skip packet parsing if TCP header is out of bounds.
        }

        // Retrieve source and destination ports.
        src_port = bpf_ntohs(tcp->source);
        dest_port = bpf_ntohs(tcp->dest);
        retval = PARSED_TCP_PACKET;  // Indicate that a TCP packet was parsed.
    }
    // Check if the protocol is UDP.
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(*ip));

        // Ensure the UDP header is within packet bounds.
        if ((void *)(udp + 1) > data_end)
        {
            return PARSE_SKIP;  // Skip packet parsing if UDP header is out of bounds.
        }

        // Retrieve source and destination ports.
        src_port = bpf_ntohs(udp->source);
        dest_port = bpf_ntohs(udp->dest);
        retval = PARSED_UDP_PACKET;  // Indicate that a UDP packet was parsed.
    }
    else
    {
        return PARSE_SKIP;  // Skip packet if not TCP or UDP.
    }

    // Construct the (source IP, source port, destination port) tuple.
    *ip_metadata = ((u64)(ip->saddr) << 32) | ((u64)src_port << 16) | (u64)dest_port;
    return retval;  // Return the packet type code.
}

/*
 * XDP program to process incoming packets.
 * - ctx: The XDP context containing packet data.
 * Returns XDP_PASS to pass the packet to the next processing stage.
 */
SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{
    u64 ip_meta;  // Variable to store IP metadata.
    int retval = parse_ip_packet(ctx, &ip_meta);  // Parse the IP packet.

    if (retval != PARSED_TCP_PACKET)
    {
        return XDP_PASS;  // Pass non-TCP packets.
    }

    // Lookup the packet count for the IP tuple in the map.
    u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip_meta);

    if (!pkt_count)
    {
        // No entry in the map for this IP tuple, so set the initial value to 1.
        u32 init_pkt_count = 1;
        bpf_map_update_elem(&xdp_stats_map, &ip_meta, &init_pkt_count, BPF_ANY);
    }
    else
    {
        // Entry already exists for this IP tuple, so increment it atomically.
        __sync_fetch_and_add(pkt_count, 1);
    }

    return XDP_PASS;  // Pass the packet to the next processing stage.
}

// Define the license for the BPF program.
char _license[] SEC("license") = "GPL";
