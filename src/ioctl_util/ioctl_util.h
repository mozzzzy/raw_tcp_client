#ifndef IOCTL_UTIL_H_
#define IOCTL_UTIL_H_

#include <string>

#include "ip_addr.h"
#include "mac_addr.h"

void get_ip_addr_from_ifname(const std::string& ifname, ip_addr& addr);
void get_mac_addr_from_ifname(const std::string& ifname, mac_addr& addr);

#endif  // IOCTL_UTIL_H
