#include <net/ethernet.h>     // for ETH_P_ARP
#include <string>

#include "arp_message.h"
#include "ip_addr.h"
#include "mac_addr.h"
#include "name_resolver.h"
#include "socket_wrapper.h"

name_resolver::name_resolver(const std::string src_ifname, const mac_addr src_mac, const ip_addr src_ip)
  : src_ifname_(src_ifname), src_ip_(src_ip), src_mac_(src_mac) {}

void name_resolver::resolve(const ip_addr remote_ip, mac_addr& remote_mac) {
  // src ip
  uint8_t src_ip_bytes[PROTOCOL_SIZE_IPV4];
  src_ip_.host_order(src_ip_bytes);

  // src mac
  uint8_t src_mac_bytes[HW_SIZE_MAC];
  src_mac_.host_order(src_mac_bytes);

  // remote ip
  uint8_t remote_ip_bytes[PROTOCOL_SIZE_IPV4];
  remote_ip.host_order(remote_ip_bytes);

  // remote mac
  uint8_t remote_mac_bytes_empty[HW_SIZE_MAC] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

  // Create arp request
  arp_message req(
    HW_TYPE_ETHERNET, PROTOCOL_TYPE_IPV4,
    HW_SIZE_MAC, PROTOCOL_SIZE_IPV4, OPERATION_CODE_ARP_REQUEST,
    src_mac_bytes, src_ip_bytes,
    remote_mac_bytes_empty, remote_ip_bytes);

  // Send arp request
  uint8_t dst_mac_bytes_broadcast[HW_SIZE_MAC] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  socket_wrapper sock_for_arp(ETH_P_ARP);
  sock_for_arp.send(src_ifname_, dst_mac_bytes_broadcast, req.data());

  // Receive arp response
  std::vector<uint8_t> arp_resp_data;
  sock_for_arp.recv(sizeof(arp_message), arp_resp_data);

  // Parse arp response
  arp_message resp(arp_resp_data);

  // Get remote mac address from arp response
  uint8_t remote_mac_bytes[HW_SIZE_MAC];
  resp.get_sender_mac(remote_mac_bytes);
  remote_mac.from_host_order(reinterpret_cast<const char *>(remote_mac_bytes));
}
