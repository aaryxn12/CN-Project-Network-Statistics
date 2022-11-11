#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <assert.h>
#include <string.h>
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

struct sniff_udp
{
    u_short sport; //source port
    u_short dport; //destination port
    u_short len;   //datagram length
    u_short crc;   //checksum
};

/* This function can be used as a callback for pcap_loop() */
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
    struct ether_header *eth_header;
    struct sniff_tcp *t_header;
    struct sniff_ip *ip_header;
    struct sniff_udp *udp_header;
    eth_header = (struct ether_header *)packet;
    ip_header = (struct ip *)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip_header) * 4;

    printf("\n---------PACKET---------\n");
    if (ip_header->ip_p == 6)
        printf("PROTOCOL:TCP\n");
    if (ip_header->ip_p == 17)
    {
        printf("PROTOCOL:UDP\n");
    }
    printf("Packet length:%d\n", header->len);
    printf("IP Length:%d\n", ip_header->ip_len / 256);
    printf("IP header length:%d\n", size_ip);
    //TCP PACKET
    if (ip_header->ip_p == 6)
    {
        t_header = (struct tcp_hdr *)(packet + SIZE_ETHERNET + size_ip);
        u_int size_tcp = TH_OFF(t_header) * 4;
        const char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        printf("TCP header length:%d\n", size_tcp);
        printf("TCP segment length:%d\n", ip_header->ip_len / 256 - (size_ip + size_tcp));
        printf("Source port:%u\nDestination port:%u\n", t_header->th_sport, t_header->th_dport);
        printf("FLAGS:0x%x\n", t_header->th_flags);
        printf("Sequence number:%u\n", t_header->th_seq);
        printf("Acknowledgement number:%u\n\n\n", t_header->th_ack);
    }
    //UDP PACKET
    else if (ip_header->ip_p == 17)
    {
        udp_header = (struct udp_hdr *)(packet + SIZE_ETHERNET + size_ip);
        printf("Source port:%u\nDestination port:%u\n", udp_header->sport, udp_header->dport);
        printf("UDP datagram length:%u\n", udp_header->len / 256);
    }
}

void fileParser()
{
    FILE *f;
    f = fopen("output.txt", "r");
    char buf[256];
    char temp[256];
    int count = 0;
    int i = 0, j = 0;
    float size, speed, Mbps, prate;
    for (int count = 0; fgets(buf, sizeof(buf), f) != NULL && count < 15; count++)
    {
        if (count < 11)
        {
            continue;
        }
        i = 0, j = 0;
        while (!isdigit(buf[i]))
            i++;
        while (buf[i] != ' ')
        {
            if (buf[i] != ',')
            {
                temp[j++] = buf[i];
            }
            i++;
        }
        temp[j++] = 0;

        if (count == 11)
        {
            speed = atof(temp);

            while (buf[i++] != ' ')
                ;
            char type[10];
            int k = 0;
            while (isalpha(buf[i]) || buf[i] == '/')
            {
                type[k++] = buf[i++];
            }
            type[k++] = 0;
            if (strcmp(type, "kBps") == 0)
                speed /= 1024.0f;
            else if (strcmp(type, "bytes/s") == 0)
                speed /= 1024.0f * 1024.0f;
            else if (strcmp(type, "MBps") != 0)
                puts(type), assert(0);

            printf("**\t\tAVERAGE SPEED(MBps)   : %4.2f MBps\n", speed);
        }
        else if (count == 12)
        {
            Mbps = atof(temp);

            while (buf[i++] != ' ')
                ;
            char type[10];
            int k = 0;
            while (isalpha(buf[i]))
            {
                type[k++] = buf[i++];
            }
            type[k++] = 0;
            if (strcmp(type, "kbps") == 0)
                Mbps /= 1024.0f;
            else if (strcmp(type, "Mbps") != 0)
                assert(0);

            printf("**\t\tAVERAGE SPEED(Mbps)   : %4.2f Mbps\n", Mbps);
        }
        else if (count == 13)
        {
            size = atof(temp);
            printf("**\t\tAVERAGE PACKET SIZE   : %4.2f bytes\n", size);
        }
        else if (count == 14)
        {
            prate = atof(temp);
            printf("**\t\tAVERAGE PACKET RATE/s : %4.2f kpackets/s\n", prate);
        }
    }
    printf("**\t\tAVERAGE RTT           : %f seconds\n", size * 2 / (speed * (1 << 20)));
}

int main(int argc, char **argv)
{
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];

    char fileName[100];
    printf("******************MENU******************\n");
    printf("Enter pcap file name to analyze:");
    scanf("%s", fileName);
    int f = fopen(fileName, "r");
    if (fopen(fileName, "r") == 0)
    {
        printf("FILE NOT FOUND\nEXITING\n");
        exit(0);
    }
    printf("Analyzing network packets in the given file...\n");
    char command[100];
    sprintf(command, "./shell.sh %s", fileName);
    system(command);
    handle = pcap_open_offline(fileName, error_buffer);

    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);
    fileParser();
    return 0;
}