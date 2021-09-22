#ifndef IP_PACKET_H_
#define IP_PACKET_H_

#include <cstdint>        // for uint8_t
#include <netinet/ip.h>   // for struct iphdr
#include <vector>

const uint8_t PROTOCOL_TCP = 6;
const uint8_t PROTOCOL_UDP = 17;

/*
 * IPv4 Header Format
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version|  IHL  |Type of Service|          Total Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Identification        |Flags|      Fragment Offset    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Time to Live |    Protocol   |         Header Checksum       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Source Address                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Destination Address                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Options                    |    Padding    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

class ip_packet {
 private:
  struct iphdr header_;
  std::vector<uint8_t> options_;
  std::vector<uint8_t> padding_;
  std::vector<uint8_t> body_;
 public:
  ip_packet(
      const uint16_t protocol,
      const uint8_t *src_addr,
      const uint8_t *dst_addr,
      const std::vector<uint8_t> body);
  ip_packet(const std::vector<uint8_t>marshaled);
  std::vector<uint8_t> marshal() const;
  uint8_t  get_version() const;
  uint8_t  get_ihl() const;
  uint8_t  get_tos() const;
  uint16_t get_tot_len() const;
  uint16_t get_id() const;
  uint16_t get_frag_off() const;
  uint8_t  get_ttl() const;
  uint8_t  get_protocol() const;
  uint16_t get_check() const;
  void     get_saddr(uint8_t *dst) const;
  void     get_daddr(uint8_t *dst) const;
  std::vector<uint8_t> get_body() const;
};

#endif  // IP_PACKET_H_
