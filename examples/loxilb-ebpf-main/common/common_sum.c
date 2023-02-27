#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <assert.h>

static unsigned short
calc_csum(unsigned short *addr, unsigned int count)
{
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }

  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }

  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }

  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

void
calc_tcp6_checksum(struct ip6_hdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->ip6_plen);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

    //add the pseudo header 
    //the source ip
    sum += (pIph->ip6_src.s6_addr32[0]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[0])&0xFFFF;

    sum += (pIph->ip6_src.s6_addr32[1]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[1])&0xFFFF;

    sum += (pIph->ip6_src.s6_addr32[2]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[2])&0xFFFF;

    sum += (pIph->ip6_src.s6_addr32[3]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[3])&0xFFFF;

    //the dest ip
    sum += (pIph->ip6_dst.s6_addr32[0]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[0])&0xFFFF;

    sum += (pIph->ip6_dst.s6_addr32[1]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[1])&0xFFFF;

    sum += (pIph->ip6_dst.s6_addr32[2]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[2])&0xFFFF;

    sum += (pIph->ip6_dst.s6_addr32[3]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[3])&0xFFFF;

    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);

    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

void
calc_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

void
calc_ip_csum(struct iphdr *iph)
{
  iph->check = 0;
  iph->check = calc_csum((unsigned short*)iph, (iph->ihl) <<2);
}
