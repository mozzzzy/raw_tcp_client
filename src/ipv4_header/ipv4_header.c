#include <arpa/inet.h>    // inet_pton
#include <netinet/ip.h>   // iphdr
#include <stddef.h>       // size_t
#include <stdlib.h>       // srandom, random
#include <time.h>         // time
#include "ipv4_header.h"

uint16_t calc_iphdr_checksum(struct iphdr *ip) {
  uint32_t sum = 0;
  uint16_t *iphdr_hextets = (uint16_t *)ip;
  size_t iphdr_size = sizeof(struct iphdr);

  while (iphdr_size > 1) {
    sum += *iphdr_hextets;
    iphdr_hextets++;
    iphdr_size -= 2;
  }

  // if last octet exists
  if (iphdr_size == 1) {
    sum += *(uint8_t *)ip;
  }

  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

/*
 * IPv4 Header Format
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version|  IHL  |Type of Service|          Total Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Identification        |Flags|      Fragment Offset    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Time to Live |    Protocol   |         Header Checksum       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Source Address                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Destination Address                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Options                    |    Padding    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void build_ipv4_hdr(
    struct iphdr *ip, uint16_t protocol, char *src_addr, char *dst_addr,
    void *data, size_t data_size) {
  ip->version = 4;
  ip->ihl = sizeof(struct iphdr) * 8 / 32;  // ip header length is 32bit unit.
  ip->tos = 0;  // TODO
  ip->tot_len = htons(sizeof(struct iphdr) + data_size);

  srandom(time(0));
  ip->id = random();

  ip->frag_off = 0; // TODO
  ip->ttl = 32;
  ip->protocol = protocol;
  inet_pton(AF_INET, src_addr, &ip->saddr);
  inet_pton(AF_INET, dst_addr, &ip->daddr);
  ip->check = calc_iphdr_checksum(ip);
}
