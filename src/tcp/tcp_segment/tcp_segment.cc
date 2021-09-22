#include <arpa/inet.h>    // for htons() htonl()
#include <cstdint>        // for uint8_t
#include <cstring>        // for std::memcpy(), std::memset()
#include <iostream>       // XXX tmp
#include <bitset>         // XXX tmp
#include <netinet/tcp.h>  // for struct tcphdr
#include <stdexcept>
#include <vector>

#include "tcp_segment.h"

namespace {
/*
 * TCP Pseudo Header Format
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Source Address                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Destination Address                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Reserved    |    Protocol   |          TCP Length           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class tcp_pseudo_header {
 public:
  tcp_pseudo_header(
      const uint8_t *src_addr, const uint8_t *dst_addr,
      const uint8_t reserved_, const uint8_t protocol_, const uint16_t tcp_length);
  std::vector<uint8_t> marshal() const;
 private:
  uint8_t src_addr_[4];
  uint8_t dst_addr_[4];
  uint8_t reserved_;
  uint8_t protocol_;
  uint16_t tcp_length_;
};

tcp_pseudo_header::tcp_pseudo_header(
    const uint8_t *src_addr, const uint8_t *dst_addr,
    const uint8_t reserved, const uint8_t protocol, const uint16_t tcp_length)
  : reserved_(reserved), protocol_(protocol), tcp_length_(tcp_length) {
  std::memcpy(src_addr_, src_addr, 4);
  std::memcpy(dst_addr_, dst_addr, 4);
}

std::vector<uint8_t> tcp_pseudo_header::marshal() const {
  std::vector<uint8_t> marshaled;
  for (int i = 0; i < 4; ++i) {
    marshaled.push_back(src_addr_[i]);
  }
  for (int i = 0; i < 4; ++i) {
    marshaled.push_back(dst_addr_[i]);
  }
  marshaled.push_back(reserved_);
  marshaled.push_back(protocol_);
  uint16_t tcp_length_copy = tcp_length_;
  marshaled.push_back(reinterpret_cast<uint8_t *>(&tcp_length_copy)[1]);
  marshaled.push_back(reinterpret_cast<uint8_t *>(&tcp_length_copy)[0]);
  return marshaled;
}

uint16_t calc_checksum(const std::vector<uint8_t> segment) {
  uint32_t sum = 0;
  const size_t segment_size = segment.size();

  // Add each 16 bits
  for (int i = 0; i + 1 < segment_size; i += 2) {
    uint16_t hextet = (segment[i] << 8) + segment[i + 1];
    sum += hextet;
  }
  // Add last 8 bit
  if (segment_size % 2 != 0) {
    sum += (segment[segment_size - 1] << 8);
  }

  // Add lower 16 bits and upper bits
  sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}
} // namespace


tcp_segment::tcp_segment(
    const uint16_t src_port, const uint16_t dst_port,
    const uint32_t seq, const uint32_t ack_seq,
    const uint8_t data_offset, const uint8_t reserved,
    const bool ns,  const bool cwr, const bool ece,
    const bool urg, const bool ack, const bool psh,
    const bool rst, const bool syn, const bool fin,
    const uint16_t window,
    const uint16_t checksum, const uint16_t urgent_pointer,
    const std::vector<uint8_t> options,
    const std::vector<uint8_t> body)
  : body_(body), options_(options) {
  std::memset(&header_, 0, sizeof(header_));
  header_.source  = htons(src_port);
  header_.dest    = htons(dst_port);
  header_.seq     = htonl(seq);
  header_.ack_seq = htonl(ack_seq);
  header_.doff    = data_offset;
  header_.res1    = (reserved << 5) + ns;
  header_.res2    = (cwr << 1) + ece;
  header_.urg     = urg;
  header_.ack     = ack;
  header_.psh     = psh;
  header_.rst     = rst;
  header_.syn     = syn;
  header_.fin     = fin;
  header_.window  = htons(window);
  header_.check   = htons(checksum);
  header_.urg_ptr = htons(urgent_pointer);
}

tcp_segment::tcp_segment(
    const uint8_t *src_addr,
    const uint8_t *dst_addr,
    const uint16_t src_port,
    const uint16_t dst_port,
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
    const std::vector<uint8_t> body)
  : body_(body), options_(options) {
  const auto header_size_byte = 20;
  std::memset(&header_, 0, sizeof(header_));
  header_.source  = htons(src_port);
  header_.dest    = htons(dst_port);
  header_.seq     = htonl(seq);
  header_.ack_seq = htonl(ack_seq);
  header_.doff    = header_size_byte + options_.size() + 1;
  header_.res1    = ns;
  header_.res2    = (cwr << 1) + ece;
  header_.urg     = urg;
  header_.ack     = ack;
  header_.psh     = psh;
  header_.rst     = rst;
  header_.syn     = syn;
  header_.fin     = fin;
  header_.window  = htons(window);
  header_.urg_ptr = htons(urgent_pointer);
  const uint8_t reserved = 0;
  const uint8_t protocol_tcp = 6;
  tcp_pseudo_header pseudo_hdr(
      src_addr, dst_addr, reserved, protocol_tcp,
      header_size_byte + options_.size() + body_.size());

  const std::vector<uint8_t> marshaled_pseudo_hdr = pseudo_hdr.marshal();
  const std::vector<uint8_t> marshaled_segment = marshal();
  std::vector<uint8_t> checksum_calc_src;
  std::copy(marshaled_pseudo_hdr.begin(), marshaled_pseudo_hdr.end(),
            std::back_inserter(checksum_calc_src));
  std::copy(marshaled_segment.begin(), marshaled_segment.end(),
            std::back_inserter(checksum_calc_src));
  const uint16_t checksum = calc_checksum(checksum_calc_src);
  header_.check   = htons(checksum);
}

tcp_segment::tcp_segment(const std::vector<uint8_t>marshaled) {
  const size_t min_hdr_size = 20;
  if (marshaled.size() < min_hdr_size) {
    std::string msg = "Invalid data size: " + std::to_string(marshaled.size());
    throw std::invalid_argument(msg);
  }
  std::memset(&header_, 0, sizeof(struct tcphdr));
  // parse tcp header
  header_.source  = (marshaled[1] << 8) + marshaled[0];
  header_.dest    = (marshaled[3] << 8) + marshaled[2];

  header_.seq     = (marshaled[7] << 24) +
                    (marshaled[6] << 16) +
                    (marshaled[5] << 8)  +
                     marshaled[4];

  header_.ack_seq = (marshaled[11] << 24) +
                    (marshaled[10] << 16) +
                    (marshaled[9] << 8) +
                     marshaled[8];

  header_.doff    = marshaled[12] >> 4;
  header_.res1    = marshaled[12] & 0xf;
  header_.res2    = marshaled[13] >> 6;
  header_.urg     = (marshaled[13] & 0x20) >> 5;
  header_.ack     = (marshaled[13] & 0x10) >> 4;
  header_.psh     = (marshaled[13] & 0x8)  >> 3;
  header_.rst     = (marshaled[13] & 0x4)  >> 2;
  header_.syn     = (marshaled[13] & 0x2)  >> 1;
  header_.fin     = (marshaled[13] & 0x1);
  header_.window  = (marshaled[15] << 8) + marshaled[14];
  header_.check   = (marshaled[17] << 8) + marshaled[16];
  header_.urg_ptr = (marshaled[19] << 8) + marshaled[18];
}

std::vector<uint8_t> tcp_segment::marshal() const {
  std::vector<uint8_t> marshaled;
  struct tcphdr hdr_copy;
  std::memcpy(&hdr_copy, &header_, sizeof(header_));
  for (int i = 0; i < sizeof(hdr_copy); ++i) {
    marshaled.push_back((reinterpret_cast<uint8_t *>(&hdr_copy))[i]);
  }
  std::copy(options_.begin(), options_.end(), std::back_inserter(marshaled));
  std::copy(body_.begin(), body_.end(), std::back_inserter(marshaled));
  return marshaled;
}

uint16_t tcp_segment::get_src_port() const {
  return ntohs(header_.source);
}

uint16_t tcp_segment::get_dst_port() const {
  return ntohs(header_.dest);
}

uint32_t tcp_segment::get_seq() const {
  return ntohl(header_.seq);
}

uint32_t tcp_segment::get_ack_seq() const {
  return ntohl(header_.ack_seq);
}

uint8_t tcp_segment::get_data_offset() const {
  return header_.doff;
}

uint8_t tcp_segment::get_reserved() const {
  return header_.res1 >> 1;
}

bool tcp_segment::get_ns() const {
  return header_.res1 & 0x1;
}

bool tcp_segment::get_cwr() const {
  return header_.res2 >> 7;
}

bool tcp_segment::get_ece() const {
  return (header_.res2 >> 6) & 0x1;
}

bool tcp_segment::get_urg() const {
  return header_.urg;
}

bool tcp_segment::get_ack() const {
  return header_.ack;
}

bool tcp_segment::get_psh() const {
  return header_.psh;
}

bool tcp_segment::get_rst() const {
  return header_.rst;
}

bool tcp_segment::get_syn() const {
  return header_.syn;
}

bool tcp_segment::get_fin() const {
  return header_.fin;
}

uint16_t tcp_segment::get_window() const {
  return ntohs(header_.window);
}

uint16_t tcp_segment::get_checksum() const {
  return ntohs(header_.check);
}

uint16_t tcp_segment::get_urgent_pointer() const {
  return ntohs(header_.urg_ptr);
}

std::vector<uint8_t> tcp_segment::get_options() const {
  std::vector<uint8_t> options;
  std::copy(options_.begin(), options_.end(), std::back_inserter(options));
  return options;
}

std::vector<uint8_t> tcp_segment::get_body() const {
  std::vector<uint8_t> body;
  std::copy(body_.begin(), body_.end(), std::back_inserter(body));
  return body;
}
