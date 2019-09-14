#define __USE_BSD   /* use bsd'ish ip header */
#include <sys/socket.h> /* these headers are for a Linux system, but */
#include <netinet/in.h> /* the names on other systems are easy to guess.. */
#include <netinet/ip.h>
#define __FAVOR_BSD /* use bsd'ish tcp header */
#include <netinet/tcp.h>
#include <unistd.h>

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int main (void)
{
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);  /* open raw socket */
  u_char* datagram = (u_char *)malloc(60);
  struct ip iph;
  struct tcphdr tcph;
  struct sockaddr_in sin;

  sin.sin_family = AF_INET;
  sin.sin_port = htons (7);
  sin.sin_addr.s_addr = inet_addr ("10.0.1.13");

  iph.ip_hl = 5;
  iph.ip_v = 4;
  iph.ip_tos = 0;
  iph.ip_len = sizeof (struct ip) + sizeof (struct tcphdr);    /* no payload */
  iph.ip_id = htonl (54321);   /* the value doesn't matter here */
  iph.ip_off = 0;
  iph.ip_ttl = 255;
  iph.ip_p = 6;
  iph.ip_sum = 0;      /* set it to 0 before computing the actual checksum later */
  iph.ip_src.s_addr = inet_addr ("101.101.101.101");/* SYN's can be blindly spoofed */
  iph.ip_dst.s_addr = sin.sin_addr.s_addr;
  tcph.th_sport = htons (1234);    /* arbitrary port */
  tcph.th_dport = htons (7);
  tcph.th_seq = random ();/* in a SYN packet, the sequence is a random */
  tcph.th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
  tcph.th_x2 = 0;
  tcph.th_off = 5;     /* first and only tcp segment */
  tcph.th_flags = TH_SYN;  /* initial connection request */
  tcph.th_win = htonl (65535); /* maximum allowed window size */
  tcph.th_sum = 0;/* if you set a checksum to zero, your kernel's IP stack
              should fill in the correct checksum during transmission */
  tcph.th_urp = 0;

  iph.ip_sum = csum ((unsigned short *) datagram, iph.ip_len >> 1);
  memcpy(datagram, &iph, sizeof(iph));
  memcpy(datagram + 20, &tcph, sizeof(tcph));

  int one = 1;
  const int *val = &one;
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
  {
    perror("Warning: Cannot set HDRINCL!\n");
    exit(1);
  }

  if (sendto(s, datagram, iph.ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
  {
    perror("Error on send.\n");
    exit(1);
  }

  return 0;
}