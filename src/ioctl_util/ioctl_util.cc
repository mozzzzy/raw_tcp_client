#include <cerrno>         // for errno
#include <cstring>        // for std::strncpy()
#include <netinet/in.h>   // for struct sockaddr_in
#include <net/if.h>       // for struct ifreq
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>    // for ioctl()
#include <sys/socket.h>   // for socket() and AF_INET
#include <unistd.h>       // for close()


#include "ioctl_util.h"
#include "ip_addr.h"
#include "mac_addr.h"

namespace {
void io_ctl_request(const std::string& ifname, unsigned long request, struct ifreq& ifr) {
  const auto sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    throw std::runtime_error("Failed to create socket");
  }
  // NOTE
  // struct ifreq is passed to ioctl system call to set or get network setting.
  ifr.ifr_addr.sa_family = AF_INET;
  std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

  int ret = ioctl(sock, request, &ifr);
  close(sock);
  if (ret == -1) {
    std::string msg = "Failed to ioctl(): ";
    msg += std::strerror(errno);
    throw std::runtime_error(msg);
  }
}
} // namespace

void get_ip_addr_from_ifname(const std::string& ifname, ip_addr& addr) {
  struct ifreq ifr;
  io_ctl_request(ifname, SIOCGIFADDR, ifr);
  uint32_t s_addr = (reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr))->sin_addr.s_addr;
  char *ip_addr_bytes = reinterpret_cast<char *>(&s_addr);
  addr.from_host_order(ip_addr_bytes);
}

void get_mac_addr_from_ifname(const std::string& ifname, mac_addr& addr) {
  struct ifreq ifr;
  io_ctl_request(ifname, SIOCGIFHWADDR, ifr);
  addr.from_host_order(ifr.ifr_hwaddr.sa_data);
}
