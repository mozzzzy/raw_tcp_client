#include <iostream>
#include <net/ethernet.h>     // for ETH_P_ARP

#include "ioctl_util.h"
#include "ip_addr.h"
#include "ip_packet.h"
#include "mac_addr.h"
#include "name_resolver.h"
#include "socket_wrapper.h"
#include "tcp_segment.h"
#include "transmission_control_block.h"

namespace {
void print_ip_header(const ip_packet& pkt) {
  std::cout << "version   : " << static_cast<unsigned>(pkt.get_version())  << std::endl;
  std::cout << "ihl       : " << static_cast<unsigned>(pkt.get_ihl())      << std::endl;
  std::cout << "tos       : " << static_cast<unsigned>(pkt.get_tos())      << std::endl;
  std::cout << "tot_len   : " << static_cast<unsigned>(pkt.get_tot_len())  << std::endl;
  std::cout << "id        : " << static_cast<unsigned>(pkt.get_id())       << std::endl;
  std::cout << "frag_off  : " << static_cast<unsigned>(pkt.get_frag_off()) << std::endl;
  std::cout << "ttl       : " << static_cast<unsigned>(pkt.get_ttl())      << std::endl;
  std::cout << "protocol  : " << static_cast<unsigned>(pkt.get_protocol()) << std::endl;
  std::cout << "check     : " << static_cast<unsigned>(pkt.get_check())    << std::endl;
  uint8_t saddr[4];
  pkt.get_saddr(saddr);
  std::cout << "src addr  : "
            << static_cast<unsigned>(saddr[0]) << "."
            << static_cast<unsigned>(saddr[1]) << "."
            << static_cast<unsigned>(saddr[2]) << "."
            << static_cast<unsigned>(saddr[3]) << std::endl;
  uint8_t daddr[4];
  pkt.get_daddr(daddr);
  std::cout << "dst addr  : "
            << static_cast<unsigned>(daddr[0]) << "."
            << static_cast<unsigned>(daddr[1]) << "."
            << static_cast<unsigned>(daddr[2]) << "."
            << static_cast<unsigned>(daddr[3]) << std::endl;
}

void print_tcp_header(const tcp_segment& segment) {
  std::cout << "src port    : " << static_cast<unsigned>(segment.get_src_port())    << std::endl;
  std::cout << "dst port    : " << static_cast<unsigned>(segment.get_dst_port())    << std::endl;
  std::cout << "seq         : " << static_cast<unsigned>(segment.get_seq())         << std::endl;
  std::cout << "ack seq     : " << static_cast<unsigned>(segment.get_ack_seq())     << std::endl;
  std::cout << "data offset : " << static_cast<unsigned>(segment.get_data_offset()) << std::endl;
  std::cout << "reserved    : " << static_cast<unsigned>(segment.get_reserved())    << std::endl;
  if (segment.get_ns()) {
    std::cout << "ns          : " << static_cast<unsigned>(segment.get_ns()) << std::endl;
  }
  if (segment.get_cwr()) {
    std::cout << "cwr         : " << static_cast<unsigned>(segment.get_cwr()) << std::endl;
  }
  if (segment.get_ece()) {
    std::cout << "ece         : " << static_cast<unsigned>(segment.get_ece()) << std::endl;
  }
  if (segment.get_urg()) {
    std::cout << "urg         : " << static_cast<unsigned>(segment.get_urg()) << std::endl;
  }
  if (segment.get_ack()) {
    std::cout << "ack         : " << static_cast<unsigned>(segment.get_ack()) << std::endl;
  }
  if (segment.get_psh()) {
    std::cout << "psh         : " << static_cast<unsigned>(segment.get_psh()) << std::endl;
  }
  if (segment.get_rst()) {
    std::cout << "rst         : " << static_cast<unsigned>(segment.get_rst()) << std::endl;
  }
  if (segment.get_syn()) {
    std::cout << "syn         : " << static_cast<unsigned>(segment.get_syn()) << std::endl;
  }
  if (segment.get_fin()) {
    std::cout << "fin         : " << static_cast<unsigned>(segment.get_fin()) << std::endl;
  }
  std::cout << "window      : " << static_cast<unsigned>(segment.get_window()) << std::endl;
  std::cout << "checksum    : " << static_cast<unsigned>(segment.get_checksum()) << std::endl;
  if (segment.get_urg()) {
    std::cout << "urg_pointer : " << static_cast<unsigned>(segment.get_urgent_pointer()) << std::endl;
  }
}

void send_tcp_segment(
    socket_wrapper &sock_wrapper,
    const char *src_ifname, const uint8_t *dst_mac_bytes,
    const uint8_t *src_ip_bytes, const uint8_t *dst_ip_bytes, const tcp_segment &seg) {
  // Create ip packet
  const ip_packet packet(
      PROTOCOL_TCP,
      src_ip_bytes,
      dst_ip_bytes,
      seg.marshal());

  std::cout << "======= sent ip packet ======" << std::endl;
  print_ip_header(packet);
  std::cout << "=============================" << std::endl;

  std::cout << "====== sent tcp segment =====" << std::endl;
  print_tcp_header(seg);
  std::cout << "=============================" << std::endl;

  // Send ip packet
  sock_wrapper.send(src_ifname, dst_mac_bytes, packet.marshal());
}

tcp_segment receive_tcp_segment(
    socket_wrapper &sock_wrapper,
    const uint8_t *local_ip_bytes, const uint16_t local_port,
    const uint8_t *remote_ip_bytes, const uint16_t remote_port) {
  std::vector<uint8_t> rcv_buf;

  while(true) {
    // Receive data from socket
    sock_wrapper.recv(1024, rcv_buf);

    // Parse ip packet
    ip_packet pkt(rcv_buf);
    // if packet is not from remote host, continue
    uint8_t pkt_saddr[4];
    pkt.get_saddr(pkt_saddr);
    if (pkt_saddr[0] != remote_ip_bytes[0] ||
        pkt_saddr[1] != remote_ip_bytes[1] ||
        pkt_saddr[2] != remote_ip_bytes[2] ||
        pkt_saddr[3] != remote_ip_bytes[3]) {
      rcv_buf.clear();
      continue;
    }
    // if packet is not for local host, continue
    uint8_t pkt_daddr[4];
    pkt.get_daddr(pkt_daddr);
    if (pkt_daddr[0] != local_ip_bytes[0] ||
        pkt_daddr[1] != local_ip_bytes[1] ||
        pkt_daddr[2] != local_ip_bytes[2] ||
        pkt_daddr[3] != local_ip_bytes[3]) {
      rcv_buf.clear();
      continue;
    }

    // Parse tcp segment
    tcp_segment seg(pkt.get_body());
    // if segment is not from remote port, continue
    const auto seg_src_port = seg.get_src_port();
    if (seg_src_port != remote_port) {
      rcv_buf.clear();
      continue;
    }
    // if segment is not for local port, continue
    const auto seg_dst_port = seg.get_dst_port();
    if (seg_dst_port != local_port) {
      rcv_buf.clear();
      continue;
    }

    std::cout << "===== received ip packet ====" << std::endl;
    print_ip_header(pkt);
    std::cout << "=============================" << std::endl;

    std::cout << "==== received tcp segment ===" << std::endl;
    print_tcp_header(seg);
    std::cout << "=============================" << std::endl;
    return seg;
  }
}
} // namespace

int main(int argc, const char **argv) {
  if (argc != 5) {
    std::cout << "Usage: " << argv[0] << " <src interface name> <src port> <dst ip address> <dst port>" << std::endl;
    return 1;
  }
  const char *src_ifname = argv[1];
  const uint16_t src_port = std::atoi(argv[2]);
  const char *dst_ip_str = argv[3];
  const uint16_t dst_port = std::atoi(argv[4]);

  // Get src mac address from interface name
  mac_addr src_mac;
  get_mac_addr_from_ifname(src_ifname, src_mac);
  std::cout << "mac address of " << src_ifname << " : " << src_mac << std::endl;
  uint8_t src_mac_bytes[MAC_ADDR_LEN];
  src_mac.host_order(src_mac_bytes);

  // Get src ip address from interface name
  ip_addr src_ip;
  get_ip_addr_from_ifname(src_ifname, src_ip);
  std::cout << "ip address of " << src_ifname << "  : " << src_ip << std::endl;
  uint8_t src_ip_bytes[IP_ADDR_LEN];
  src_ip.host_order(src_ip_bytes);

  // Create dst ip address
  ip_addr dst_ip;
  dst_ip.from_string(dst_ip_str);
  std::cout << "dst ip address : " << dst_ip << std::endl;
  uint8_t dst_ip_bytes[IP_ADDR_LEN];
  dst_ip.host_order(dst_ip_bytes);

  // Create dst mac address
  mac_addr dst_mac;
  name_resolver resolver(src_ifname, src_mac, src_ip);
  resolver.resolve(dst_ip, dst_mac);
  std::cout << "mac address of " << dst_ip << " : " << dst_mac << std::endl;
  uint8_t dst_mac_bytes[MAC_ADDR_LEN];
  dst_mac.host_order(dst_mac_bytes);

  // Create Transmission Control Block
  transmission_control_block tcb;

  // Create socket
  socket_wrapper sock_for_tcp(ETH_P_IP);

  // Create tcp segment (SYN = 1)
  const tcp_segment syn_seg = tcb.create_send_segment(
        src_ip_bytes,
        src_port,
        dst_ip_bytes,
        dst_port,
        false,  // ns
        false,  // cwr
        false,  // ece
        false,  // urg
        false,  // ack
        false,  // psh
        false,  // rst
        true,   // syn
        false,  // fin
        64240,  // window
        0,      // urgent pointer
        std::vector<uint8_t>(), // option
        std::vector<uint8_t>()  // body
      );

  send_tcp_segment(
      sock_for_tcp, src_ifname, dst_mac_bytes,
      src_ip_bytes, dst_ip_bytes, syn_seg);

  // Receive tcp segment (ACK = 1 and SYN = 1)
  tcp_segment ack_syn_seg = receive_tcp_segment(
      sock_for_tcp, src_ip_bytes, src_port, dst_ip_bytes, dst_port);
  tcb.apply_receive_segment(ack_syn_seg);

  // Create tcp segment (ACK = 1)
  const tcp_segment ack_for_syn_seg = tcb.create_send_segment(
        src_ip_bytes,
        src_port,
        dst_ip_bytes,
        dst_port,
        false,  // ns
        false,  // cwr
        false,  // ece
        false,  // urg
        true,   // ack
        false,  // psh
        false,  // rst
        false,  // syn
        false,  // fin
        64240,  // window
        0,      // urgent pointer
        std::vector<uint8_t>(), // option
        std::vector<uint8_t>()  // body
      );

  send_tcp_segment(
      sock_for_tcp, src_ifname, dst_mac_bytes,
      src_ip_bytes, dst_ip_bytes, ack_for_syn_seg);

  // Create tcp segment (body = HELLO TCP)
  const tcp_segment data_seg = tcb.create_send_segment(
        src_ip_bytes,
        src_port,
        dst_ip_bytes,
        dst_port,
        false,  // ns
        false,  // cwr
        false,  // ece
        false,  // urg
        true,   // ack
        true,   // psh
        false,  // rst
        false,  // syn
        false,  // fin
        64240,  // window
        0,      // urgent pointer
        std::vector<uint8_t>(), // option
        {'H', 'E', 'L', 'L', 'O', ' ', 'T', 'C', 'P'} // body
      );

  send_tcp_segment(
      sock_for_tcp, src_ifname, dst_mac_bytes,
      src_ip_bytes, dst_ip_bytes, data_seg);

  // Receive tcp segment (ACK = 1)
  tcp_segment ack_for_data_seg = receive_tcp_segment(
      sock_for_tcp, src_ip_bytes, src_port, dst_ip_bytes, dst_port);
  tcb.apply_receive_segment(ack_for_data_seg);

  // Create tcp segment (FIN = 1)
  const tcp_segment fin_seg = tcb.create_send_segment(
        src_ip_bytes,
        src_port,
        dst_ip_bytes,
        dst_port,
        false,  // ns
        false,  // cwr
        false,  // ece
        false,  // urg
        true,   // ack
        false,  // psh
        false,  // rst
        false,  // syn
        true,   // fin
        64240,  // window
        0,      // urgent pointer
        std::vector<uint8_t>(), // option
        std::vector<uint8_t>()  // body
      );

  send_tcp_segment(
      sock_for_tcp, src_ifname, dst_mac_bytes,
      src_ip_bytes, dst_ip_bytes, fin_seg);

  // Receive tcp segment (ACK = 1 and FIN = 1)
  tcp_segment ack_fin_seg = receive_tcp_segment(
      sock_for_tcp, src_ip_bytes, src_port, dst_ip_bytes, dst_port);
  tcb.apply_receive_segment(ack_fin_seg);

  // Create tcp segment (ACK = 1)
  const tcp_segment ack_for_fin_seg = tcb.create_send_segment(
        src_ip_bytes,
        src_port,
        dst_ip_bytes,
        dst_port,
        false,  // ns
        false,  // cwr
        false,  // ece
        false,  // urg
        true,   // ack
        false,  // psh
        false,  // rst
        false,  // syn
        false,   // fin
        64240,  // window
        0,      // urgent pointer
        std::vector<uint8_t>(), // option
        std::vector<uint8_t>()  // body
      );

  send_tcp_segment(
      sock_for_tcp, src_ifname, dst_mac_bytes,
      src_ip_bytes, dst_ip_bytes, ack_for_fin_seg);
}
