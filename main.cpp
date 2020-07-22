#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h> // ntohs, ntohl.

#include <libnet.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

/*
 * print functions.
 * codes written at the bottom.
 */
void print_ether_addresses(struct libnet_ethernet_hdr *eth_hdr);
void print_ip4_addresses(struct libnet_ipv4_hdr *ip4_hdr);
void print_tcp_ports(struct libnet_tcp_hdr *tcp_hdr);
void print_payload(void *payload, int payload_len);



int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./%s <interface>\n", argv[0]);
        return 1;
    }

    /*
     * get a handle that can capture packets on live.
     */
    char *interface = argv[1];
    char error_message[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_message); // capture packets on live interface.
    if (handle == nullptr) {
        fprintf(stderr, "Error occurred at pcap_open_live(%s)\n", interface);
        fprintf(stderr, "Error Message: %s\n", error_message);
        return 1;
    }

    /*
     * start to capture.
     */
    while (1) {
        struct pcap_pkthdr *header;
        const u_char *frame;

        int result_capturing = pcap_next_ex(handle, &header, &frame);

        // error occurred.
        if(result_capturing == -1 || result_capturing == -2)
        {
            fprintf(stderr, "Error occurred at pcap_next_ex\n");
            fprintf(stderr, "Error Message: %s\n", pcap_geterr(handle));
            break;
        }

        // timeout.
        else if(result_capturing == 0)
        {
            continue;
        }

        // success to capture a packet without problems.
        else
        {
            /*
             * parse frame as ethernet.
             */
            struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)(&frame[0]);
            int eth_hdr_size = sizeof(struct libnet_ethernet_hdr);

            if(ntohs(eth_hdr->ether_type) != (u_int16_t)0x0800) continue; // check that 3 layer protocol is ip.

            /*
             * parse packet as ipv4.
             */
            struct libnet_ipv4_hdr *ip4_hdr = (struct libnet_ipv4_hdr *)(&frame[eth_hdr_size]);
            int ip4_hdr_size = ip4_hdr->ip_hl << 2; // '<< 2' same as '* 4'

            if(ip4_hdr->ip_p != 6) continue; // check that 4 layer protocol is tcp.

            /*
             * parse segment as tcp.
             */
            struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(&frame[eth_hdr_size+ip4_hdr_size]);
            int tcp_hdr_size = tcp_hdr->th_off << 2; // '<< 2' same as '* 4'

            /*
             * extract a payload data and calculate a payload size.
             */
            const u_char *payload = &frame[eth_hdr_size + ip4_hdr_size + tcp_hdr_size];
            int payload_len = ntohs(ip4_hdr->ip_len) - (ip4_hdr_size + tcp_hdr_size);

            /*
             * print
             */
            print_ether_addresses(eth_hdr);
            print_ip4_addresses(ip4_hdr);
            print_tcp_ports(tcp_hdr);
            print_payload((void *)payload, payload_len);
            printf("\n");
        }
    }

    pcap_close(handle);
}

/*
 * print source and destination mac addresses.
 * ex) AA-AA-AA-AA-AA-AA -> BB-BB-BB-BB-BB-BB
 */
void print_ether_addresses(struct libnet_ethernet_hdr *eth_hdr)
{
    printf("Ethernet: %02x-%02x-%02x-%02x-%02x-%02x -> %02x-%02x-%02x-%02x-%02x-%02x\n",
        eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
        eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5],
        eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
        eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]
    );
}

/*
 * print source and destination ip addresses.
 * ex) 1.1.1.1 -> 2.2.2.2
 */
void print_ip4_addresses(struct libnet_ipv4_hdr *ip4_hdr) {
    u_int32_t s_addr = ntohl(ip4_hdr->ip_src.s_addr);
    u_int32_t d_addr = ntohl(ip4_hdr->ip_dst.s_addr);

    printf("IP: %d.%d.%d.%d -> %d.%d.%d.%d\n",
       (s_addr >> 24) & 0xFF, (s_addr >> 16) & 0xFF,
       (s_addr >> 8) & 0xFF, s_addr & 0xFF,
       (d_addr >> 24) & 0xFF, (d_addr >> 16) & 0xFF,
       (d_addr >> 8) & 0xFF, d_addr & 0xFF
    );
}

/*
 * print source and destination tcp ports.
 * ex) 1234 -> 5678
 */
void print_tcp_ports(struct libnet_tcp_hdr *tcp_hdr) {
    printf("TCP: %d -> %d\n",
       ntohs(tcp_hdr->th_sport),
       ntohs(tcp_hdr->th_dport)
    );
}

/*
 * print payload data(maximum 16 bytes).
 * ex) 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
 */
void print_payload(void *payload, int payload_len) {
    int print_len = min(payload_len, 16);

    printf("Data: ");
    for(int i = 0; i < print_len; i++) {
        printf("%02x ", ((u_int8_t *)payload)[i]);
    }
    printf("\n");
}
