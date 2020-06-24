#include <net/ethernet.h>     // ETH_P_IP
#include <net/if.h>           // if_nametoindex
#include <netpacket/packet.h> // sockaddr_ll
#include <string.h>           // memset

#include "../hextet/hextet.h"
#include "../tcp_header/tcp_header.h"
#include "../tcp_packet/tcp_packet.h"

int send_tcp_packet(int sock, char *ifname, tcp_packet *packet) {
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_IP);  // ipv4. ipv6 is ETH_P_IPV6.
  addr.sll_ifindex = if_nametoindex(ifname);

  addr.sll_halen = IFHWADDRLEN;
  memset(&addr.sll_addr, 0xff, IFHWADDRLEN);  // TODO this is broadcast

  return sendto(
      sock, packet, sizeof(struct tcphdr)+sizeof(struct iphdr), 0,
      (struct sockaddr *)&addr, sizeof(addr));
}
