#include <arpa/inet.h>  // inet_addr
#include <stddef.h>     // size_t
#include <stdint.h>     // uintX_t
#include <stdio.h>      // perror
#include <stdlib.h>     // calloc

#include "../hextet/hextet.h"
#include "tcp_header.h"
/*
 * TCP Pseudo Header Format
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Source Address                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Destination Address                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Reserved    |    Protocol   |          TCP Length           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct tcp_pseudo_hdr {
  uint32_t source;
  uint32_t dest;
  uint8_t  reserved;
  uint8_t  protocol;
  uint16_t tcp_len;
} tcp_pseudo_hdr;

void build_tcp_pseudo_hdr(
    tcp_pseudo_hdr *pseudo, char *src_addr, char *dst_addr, uint16_t tcp_len) {
  pseudo->source = inet_addr(src_addr);
  pseudo->dest = inet_addr(dst_addr);
  pseudo->reserved = 0;
  pseudo->protocol = 6;
  pseudo->tcp_len = htons(tcp_len);
}

uint16_t calc_tcphdr_checksum(tcp_pseudo_hdr pseudo, struct tcphdr tcp) {
  // NOTE:
  // checksum field is not used to calculate itself.
  tcp.check = 0;

  // parse pseudo header data into hextets.
  // Note: data in uint16_t is held in host byte order.
  // e.g.
  // 7f 00 00 01 is held in order 01 00 00 7f
  size_t pseudo_hextets_size = sizeof(tcp_pseudo_hdr)/2;
  uint16_t pseudo_hdr_hextets[pseudo_hextets_size];
  parse_to_hextets(pseudo_hdr_hextets, &pseudo, sizeof(tcp_pseudo_hdr));

  // parse tcp header data into hextets.
  size_t tcp_hdr_hextets_size = sizeof(struct tcphdr)/2;
  uint16_t tcp_hdr_hextets[tcp_hdr_hextets_size];
  parse_to_hextets(tcp_hdr_hextets, &tcp, sizeof(struct tcphdr));

  // get sum of all hextets
  uint32_t hextet_sum = 0;
  hextet_sum += calc_hextet_sum(pseudo_hdr_hextets, pseudo_hextets_size);
  hextet_sum += calc_hextet_sum(tcp_hdr_hextets, tcp_hdr_hextets_size);

  // get the highest place hextet of hextet_sum
  uint32_t hextet_sum_hst_byte_odr = htonl(hextet_sum);
  size_t hextet_sum_hextets_max_size = sizeof(uint32_t)/2;
  uint16_t hextet_sum_hextets[hextet_sum_hextets_max_size];
  size_t hextet_sum_hextets_size =
    parse_to_hextets(hextet_sum_hextets, &hextet_sum_hst_byte_odr, sizeof(uint32_t));
  uint8_t highest_place_hextet =
    hextet_sum_hextets[hextet_sum_hextets_max_size - hextet_sum_hextets_size];

  hextet_sum -= highest_place_hextet << (8 * hextet_sum_hextets_size);
  hextet_sum += highest_place_hextet;

  // flip bits
  hextet_sum = ~hextet_sum;

  return hextet_sum;
}

/*
 * TCP Header Format
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Source Port          |       Destination Port        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Sequence Number                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Acknowledgment Number                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Data |           |U|A|P|R|S|F|                               |
 *  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 *  |       |           |G|K|H|T|N|N|                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Checksum            |         Urgent Pointer        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Options                    |    Padding    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             data                              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void build_tcp_syn_hdr(
    struct tcphdr *tcp, char *src_addr, uint16_t src_port,
    char *dst_addr, uint16_t dst_port, uint32_t init_seq) {
  /*
   * NOTE:
   * htons and htonl convert multi-byte integer data from host byte order
   * to network byte order.
   * e.g.
   *   80 is
   *   host byte order:    00000000 01010000
   *   network byte order: 01010000 00000000
   */
  tcp->source  = htons(src_port);
  tcp->dest    = htons(dst_port);
  tcp->seq     = htonl(init_seq);
  tcp->ack_seq = htonl(0);
  tcp->doff = sizeof(struct tcphdr)  * 8 / 32; // data offset is 32bit unit.
  tcp->urg = 0;
  tcp->ack = 0;
  tcp->psh = 0;
  tcp->rst = 0;
  tcp->syn = 1;
  tcp->fin = 0;
  tcp->window = htons(0);

  tcp_pseudo_hdr *pseudo = (tcp_pseudo_hdr*)calloc(1, sizeof(tcp_pseudo_hdr));
  build_tcp_pseudo_hdr(pseudo, src_addr, dst_addr, sizeof(struct tcphdr));

  uint16_t checksum = calc_tcphdr_checksum(*pseudo, *tcp);
  free(pseudo);
  tcp->check = htons(checksum);
}
