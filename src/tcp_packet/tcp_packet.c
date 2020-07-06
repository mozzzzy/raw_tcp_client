#include <arpa/inet.h>        // inet_ntop
#include <net/ethernet.h>     // ETH_P_IP
#include <net/if.h>           // if_nametoindex
#include <netpacket/packet.h> // sockaddr_ll
#include <string.h>           // memset

#include "../arp/src/arp.h"
#include "../hextet/hextet.h"
#include "../tcp_header/tcp_header.h"
#include "../tcp_packet/tcp_packet.h"

int send_tcp_packet(int sock, char *ifname, tcp_packet *packet) {
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_IP);  // ipv4
  addr.sll_ifindex = if_nametoindex(ifname);
  addr.sll_halen = IFHWADDRLEN;

  // get source mac addr from interface name
  int ret = 0;
  uint8_t src_mac[6];
  ret = get_mac_from_ifname(ifname, src_mac);
  if (ret < 0) {
    return ret;
  }

  // convert source ip uint32_t to char ptr
  int addr_max_size = 15;
  char src_addr[addr_max_size];
  if (inet_ntop(AF_INET, &(packet->ip.saddr), src_addr, addr_max_size) == NULL) {
    return -1;
  }
  // convert destination ip uint32_t to char ptr
  char dst_addr[addr_max_size];
  if (inet_ntop(AF_INET, &(packet->ip.daddr), dst_addr, addr_max_size) == NULL) {
    return -1;
  }

  // get destination mac address
  ret = arp_request(ifname,
                    src_mac,
                    src_addr,
                    addr.sll_addr,
                    dst_addr);
  if (ret < 0) {
    return ret;
  }

  return sendto(
      sock, (char *)packet, sizeof(struct tcphdr)+sizeof(struct iphdr), 0,
      (struct sockaddr *)&addr, sizeof(addr));
}
