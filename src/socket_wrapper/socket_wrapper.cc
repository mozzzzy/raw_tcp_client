#include <algorithm>
#include <arpa/inet.h>        // for htons()
#include <cerrno>             // for errno
#include <cstring>            // for std::strerror()
#include <netpacket/packet.h> // for struct sockaddr_ll
#include <net/ethernet.h>     // for ETH_P_ALL
#include <net/if.h>           // for if_nametoindex
#include <stdexcept>
#include <string>
#include <sys/socket.h>       // for socket()
#include <unistd.h>           // for close()
#include <vector>
#include <iostream>           // XXX tmp

#include "socket_wrapper.h"

socket_wrapper::socket_wrapper(const unsigned short ether_prtcl_type)
  : ether_prtcl_type_(ether_prtcl_type) {
  sock_ = socket(AF_PACKET, SOCK_DGRAM, htons(ether_prtcl_type_));
  if (sock_ == -1) {
    std::string msg = "Failed to create socket: ";
    msg += std::strerror(errno);
    throw std::runtime_error(msg);
  }
}

void socket_wrapper::send(
    const std::string& ifname, const uint8_t *target_mac,
    const std::vector<uint8_t>& data) const {
  // The sockaddr_ll structure is a device-independent physical-layer address.
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(addr));
  // always AF_PACKET
  addr.sll_family   = AF_PACKET;
  // the standard ethernet protocol type in network byte order as defined in the <linux/if_ether.h>.
  addr.sll_protocol = htons(ether_prtcl_type_);
  // Interface number
  addr.sll_ifindex  = if_nametoindex(ifname.c_str());
  // Length of address
  addr.sll_halen    = IFHWADDRLEN;
  // Physical-layer address
  memcpy(&addr.sll_addr, target_mac, IFHWADDRLEN);

  int flags = 0;
  int send_size =
    sendto(sock_, data.data(), data.size(), flags, (struct sockaddr *)&addr, sizeof(addr));

  if (send_size < 0) {
    std::string msg = "Failed to sendto: ";
    msg += std::strerror(errno);
    throw std::runtime_error(msg);
  }
}

void socket_wrapper::recv(const size_t size, std::vector<uint8_t>& data) const {
  char buf[size];
  int flags = 0;
  size_t recv_size = ::recv(sock_, buf, size, flags);
  if (recv_size < 0) {
    std::string msg = "Failed to recv: ";
    msg += std::strerror(errno);
    throw std::runtime_error(msg);
  }
  std::copy(&buf[0], &buf[recv_size], back_inserter(data));
}

socket_wrapper::~socket_wrapper() {
  if (sock_ != -1) {
    close(sock_);
  }
}
