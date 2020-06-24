#include <stdio.h>        // printf
#include <stdlib.h>       // calloc
#include <netinet/tcp.h>  // tcphdr
#include <netinet/in.h>   // IPPROTO_TCP
#include <netinet/ip.h>   // iphdr
#include <net/ethernet.h> // ETH_P_IP

#include "ipv4_header/ipv4_header.h"
#include "tcp_header/tcp_header.h"
#include "tcp_packet/tcp_packet.h"

int send_tcp_syn() {
  return 0;
}

int main() {
  char    *src_addr = "127.0.0.1";
  uint16_t src_port = 49152;
  char    *dst_addr = "127.0.0.1";
  uint16_t dst_port = 80;
  uint32_t tcp_initial_seq = 12345678;
  char *interface = "lo";

  // build tcp SYN header
  struct tcphdr *tcphdr_syn = calloc(1, sizeof(struct tcphdr));
  build_tcp_syn_hdr(tcphdr_syn, src_addr, src_port, dst_addr, dst_port, tcp_initial_seq);

  // build ip header
  struct iphdr *iphdr_tcp_syn = calloc(1, sizeof(struct iphdr));
  build_ipv4_hdr(
      iphdr_tcp_syn, IPPROTO_TCP, src_addr, dst_addr, tcphdr_syn, sizeof(struct tcphdr));

  // build tcp SYN packet
  struct tcp_packet packet;
  packet.ip  = *iphdr_tcp_syn;
  packet.tcp = *tcphdr_syn;

  // socket to write data
  int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
  if(sock < 0) {
    perror("failed to create socket: ");
    return 1;
  }

  // send tcp SYN packet
  int send_size = send_tcp_packet(sock, interface, &packet);
  if (send_size < 0) {
    perror("failed to send tcp packet: ");
    return 1;
  }

  free(tcphdr_syn);
  free(iphdr_tcp_syn);
  return 0;
}
