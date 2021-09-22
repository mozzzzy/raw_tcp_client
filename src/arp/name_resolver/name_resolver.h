#ifndef NAME_RESOLVER_H_
#define NAME_RESOLVER_H_

#include <string>

#include "ip_addr.h"
#include "mac_addr.h"

class name_resolver {
 private:
  ip_addr  src_ip_;
  mac_addr src_mac_;
  std::string src_ifname_;
 public:
  name_resolver(const std::string src_ifname, const mac_addr src_mac, const ip_addr src_ip);
  void resolve(const ip_addr remote_ip, mac_addr& remote_mac);
};

#endif  // NAME_RESOLVER_H_
