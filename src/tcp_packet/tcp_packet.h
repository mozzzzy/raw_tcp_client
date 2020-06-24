#ifndef TCP_PACKET_H_
#define TCP_PACKET_H_

#include <netinet/ip.h>   // iphdr
#include <netinet/tcp.h>  // tcphdr
#include <stdint.h>       // uintX_t

#define MAX_TCP_DATA_SIZE 65535

typedef struct tcp_packet {
  struct iphdr  ip;
  struct tcphdr tcp;
  uint8_t data[MAX_TCP_DATA_SIZE];
} tcp_packet;

int send_tcp_packet(int sock, char *ifname, tcp_packet *packet);

#endif // TCP_PACKET_H_
