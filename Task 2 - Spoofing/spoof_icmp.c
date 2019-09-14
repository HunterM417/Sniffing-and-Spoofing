#define __USE_BSD   /* use bsd'ish ip header */
#include <sys/socket.h> /* these headers are for a Linux system, but */
#include <netinet/in.h> /* the names on other systems are easy to guess.. */
#include <netinet/ip.h>
#define __FAVOR_BSD /* use bsd'ish tcp header */
#include <netinet/ip_icmp.h>
#include <unistd.h>

#define IP_SIZE 20
#define ICMP_SIZE 20

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int main(int argc, char **argv)
{
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_ICMP);  /* open raw socket */

    struct ip iph;
    struct icmp icmp;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr ("10.0.1.13");

    // Construct IP Header
    u_char* datagram = (u_char *)malloc(60);
    iph.ip_hl = 0x5;
    iph.ip_v = 0x4;
    iph.ip_tos = 0x0;
    iph.ip_len = 60;
    iph.ip_id = 0;
    iph.ip_off = 0x0;
    iph.ip_ttl = 64;
    iph.ip_p = IPPROTO_ICMP;
    iph.ip_sum = 0x0;
    iph.ip_src.s_addr = inet_addr("101.101.101.101");
    iph.ip_dst.s_addr = inet_addr("10.0.1.13");
    iph.ip_sum = 0;
    memcpy(datagram, &iph, sizeof(iph));

    // Construct ICMP Header
    icmp.icmp_type = 8;
    icmp.icmp_code = 0;
    icmp.icmp_id = htons(0);
    icmp.icmp_seq = htons(0x1);
    icmp.icmp_cksum = 0;
    icmp.icmp_cksum = csum ((unsigned short *) datagram + sizeof(iph), sizeof(icmp));
    memcpy(datagram + IP_SIZE, &icmp, 8);
    
    const int val = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) 
    {
        perror("Failure on IP_HDRINCL");
        exit(1);    
    }
    
    // Send the datagram
    if (sendto(s, datagram, iph.ip_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) 
    {
        perror("Failure on Send");
        exit(1);
    }
    
    return 0;
}
