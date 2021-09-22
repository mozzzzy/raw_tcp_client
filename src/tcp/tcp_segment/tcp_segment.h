#ifndef TCP_SEGMENT_H_
#define TCP_SEGMENT_H_

#include <cstdint>        // for uint8_t
#include <netinet/tcp.h>  // for struct tcphdr
#include <vector>

/*
 * TCP Header Format
 * (see: https://datatracker.ietf.org/doc/html/rfc793)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |Reser|N|C|E|U|A|P|R|S|F|                               |
 * | Offset|ved  |S|W|C|R|C|S|S|Y|I|            Window             |
 * |       |     | |R|E|G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

class tcp_segment {
 private:
  struct tcphdr header_;
  std::vector<uint8_t> options_;
  std::vector<uint8_t> body_;
 public:
  tcp_segment(
      const uint16_t src_port,
      const uint16_t dest_port,
      const uint32_t seq,
      const uint32_t ack_seq,
      const uint8_t data_offset,
      const uint8_t reserved,
      const bool ns,
      const bool cwr,
      const bool ece,
      const bool urg,
      const bool ack,
      const bool psh,
      const bool rst,
      const bool syn,
      const bool fin,
      const uint16_t window,
      const uint16_t checksum,
      const uint16_t urgent_pointer,
      const std::vector<uint8_t> options,
      const std::vector<uint8_t> body);
  // Following constructor calcurate data_offset, reserved and checksum automatically.
  tcp_segment(
      const uint8_t *src_addr,
      const uint8_t *dest_addr,
      const uint16_t src_port,
      const uint16_t dest_port,
      const uint32_t seq,
      const uint32_t ack_seq,
      const bool ns,
      const bool cwr,
      const bool ece,
      const bool urg,
      const bool ack,
      const bool psh,
      const bool rst,
      const bool syn,
      const bool fin,
      const uint16_t window,
      const uint16_t urgent_pointer,
      const std::vector<uint8_t> options,
      const std::vector<uint8_t> body);
  tcp_segment(const std::vector<uint8_t>marshaled);
  std::vector<uint8_t> marshal() const;
  uint16_t get_src_port() const;
  uint16_t get_dst_port() const;
  uint32_t get_seq() const;
  uint32_t get_ack_seq() const;
  uint8_t  get_data_offset() const;
  uint8_t  get_reserved() const;
  bool     get_ns() const;
  bool     get_cwr() const;
  bool     get_ece() const;
  bool     get_urg() const;
  bool     get_ack() const;
  bool     get_psh() const;
  bool     get_rst() const;
  bool     get_syn() const;
  bool     get_fin() const;
  uint16_t get_window() const;
  uint16_t get_checksum() const;
  uint16_t get_urgent_pointer() const;
  std::vector<uint8_t> get_options() const;
  std::vector<uint8_t> get_body() const;
};

#endif  // TCP_SEGMENT_H_
