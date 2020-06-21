#include <arpa/inet.h>  // inet_addr
#include <stdint.h>     // uintX_t
#include <stdio.h>      // perror
#include <stdlib.h>     // calloc
#include <sys/socket.h> // socket
#include <sys/types.h>  // NOTE: This header file is not needed for linux.
                        //       But some implementations (like BSD) need this.

#include "tcp.h"

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

uint8_t tcphdr_size = sizeof(tcphdr)  * 8 / 32;  // NOTE: data offset is 32bit unit.

int parse_to_hextets(uint16_t *hextets, void *data, size_t data_size) {
  // parse data into hextets
  uint8_t *data_octets = (uint8_t *)data;
  int octet_cnt = 0;
  int hextet_cnt = 0;
  for (octet_cnt = 0; octet_cnt+1 < data_size; octet_cnt += 2) {
    uint8_t big_octet   = data_octets[octet_cnt];
    uint8_t small_octet = data_octets[octet_cnt+1];

    uint16_t hextet = big_octet;
    hextet = hextet << 8;
    hextet += small_octet;

    hextets[hextet_cnt++] = hextet;
  }

  // parse the highest place octet if exists
  if (octet_cnt == data_size - 3) {
    uint8_t small_octet = data_octets[octet_cnt];
    hextets[hextet_cnt++] = small_octet;
  }

  for (; hextet_cnt >= 0; hextet_cnt--) {
    // decrement hextet_cnt if the highest place hextet is 0x00
    if (hextets[hextet_cnt-1] != 0) {
      break;
    }
  }
  return hextet_cnt;
}

uint32_t calc_hextet_sum(uint16_t *data_hextets, size_t data_size) {
  uint32_t hextet_sum = 0;
  int i;
  for (i = 0; i < data_size; i++) {
    hextet_sum += data_hextets[i];
  }
  return hextet_sum;
}

uint16_t calc_checksum(tcp_pseudo_hdr pseudo, tcphdr tcp) {
  // NOTE: checksum field is not used to calcurate itself.
  tcp.check = 0;

  // parse pseudo header data into hextets.
  // Note: data in uint16_t is held in host byte order.
  //       e.g.
  //       7f 00 00 01 is held in order 01 00 00 7f
  size_t pseudo_hextets_size = sizeof(tcp_pseudo_hdr)/2;
  uint16_t pseudo_hdr_hextets[pseudo_hextets_size];
  parse_to_hextets(pseudo_hdr_hextets, &pseudo, sizeof(tcp_pseudo_hdr));

  // parse tcp header data into hextets.
  size_t tcp_hdr_hextets_size = sizeof(tcphdr)/2;
  uint16_t tcp_hdr_hextets[tcp_hdr_hextets_size];
  parse_to_hextets(tcp_hdr_hextets, &tcp, sizeof(tcphdr));

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

void build_tcp_pseudo_hdr(
    tcp_pseudo_hdr *pseudo, char *src_addr, char *dst_addr, uint16_t tcp_len) {
  pseudo->source = inet_addr(src_addr);
  pseudo->dest = inet_addr(dst_addr);
  pseudo->reserved = 0;
  pseudo->protocol = 6;
  pseudo->tcp_len = htons(tcp_len);
}

void build_tcp_syn_hdr(
    tcphdr *tcp, char *src_addr, uint16_t src_port,
    char *dst_addr, uint16_t dst_port, uint32_t init_seq) {
  // NOTE:
  // htons and htonl convert multi-byte integer types from host byte order
  // to network byte order.
  // e.g. 80 is ...
  // host byte order:    00000000 01010000
  // network byte order: 01010000 00000000
  tcp->source  = htons(src_port);
  tcp->dest    = htons(dst_port);
  tcp->seq     = htonl(init_seq);
  tcp->ack_seq = htonl(0);
  tcp->doff = tcphdr_size;
  tcp->urg = 0;
  tcp->ack = 0;
  tcp->psh = 0;
  tcp->rst = 0;
  tcp->syn = 1;
  tcp->fin = 0;
  tcp->window = htons(0);

  tcp_pseudo_hdr *pseudo = (tcp_pseudo_hdr*)calloc(1, sizeof(tcp_pseudo_hdr));
  build_tcp_pseudo_hdr(pseudo, src_addr, dst_addr, sizeof(tcphdr));

  uint16_t checksum = calc_checksum(*pseudo, *tcp);
  free(pseudo);
  tcp->check = htons(checksum);
}

int send_tcp_syn(char* src_addr, uint16_t src_port, char* dst_addr, uint16_t dst_port, uint32_t init_seq) {
  tcphdr *tcp = (tcphdr*)calloc(1, sizeof(tcphdr));
  build_tcp_syn_hdr(tcp, src_addr, src_port, dst_addr, dst_port, init_seq);

  // socket to write data
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if(sock < 0) {
    return sock;
  }

  // remote info
  struct sockaddr_in remote;
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(dst_addr);
  remote.sin_port = dst_port;

  int send_result = sendto(
    sock, tcp, sizeof(struct tcphdr), 0, (struct sockaddr *)&remote, sizeof(struct sockaddr));
  if (send_result < 0) {
    return send_result;
  }
  return 0;
}
