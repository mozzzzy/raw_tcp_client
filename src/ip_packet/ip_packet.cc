#include <iostream>     // XXX tmp
#include <arpa/inet.h>  // for inet_pton()
#include <cstring>      // for std::memcpy()
#include <stdexcept>
#include <stdlib.h> // for srandom() TODO cpp style
#include <string>
#include <time.h>   // for time()    TODO cpp style
#include <vector>

#include "ip_packet.h"

namespace {
uint16_t calc_checksum(struct iphdr *header) {
  uint32_t sum = 0;
  uint8_t *octets = (uint8_t *)header;
  size_t hdr_size = sizeof(struct iphdr);

  // Add each 16 bits
  while (hdr_size > 0) {
    uint16_t hextet = (*octets << 8) + *(octets + 1);
    sum += hextet;
    octets += 2;
    hdr_size -= 2;
  }

  // add lower 16 bits and upper bits
  sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}
} // namespace

ip_packet::ip_packet(
      const uint16_t protocol,
      const uint8_t *src_addr,
      const uint8_t *dst_addr,
      const std::vector<uint8_t> body) : body_(body) {
  std::memset(&header_, 0, sizeof(struct iphdr));
  header_.version = 4;
  header_.ihl = sizeof(struct iphdr) * 8 / 32;  // ip header length is 32bit unit.
  header_.tos = 0;  // TODO
  header_.tot_len = htons(sizeof(struct iphdr) + body.size());

  // TODO cpp style
  srandom(time(0));
  //header_.id = random();
  header_.id = htons(0xa78b);

  header_.frag_off = 0; // TODO
  header_.ttl = 32;
  header_.protocol = protocol;

  std::memcpy(&(header_.saddr), src_addr, 4);
  std::memcpy(&(header_.daddr), dst_addr, 4);

  header_.check = htons(calc_checksum(&header_));
}

ip_packet::ip_packet(const std::vector<uint8_t> marshaled) {
  const size_t min_hdr_size = 20;
  if (marshaled.size() < min_hdr_size) {
    std::string msg = "Invalid data size: " + std::to_string(marshaled.size());
    throw std::invalid_argument(msg);
  }
  std::memset(&header_, 0, sizeof(struct iphdr));
  // parse ip header
  header_.version  = marshaled[0] >> 4;
  header_.ihl      = marshaled[0] & 0xf;
  header_.tos      = marshaled[1];
  header_.tot_len  = (marshaled[3] << 8) + marshaled[2];
  header_.id       = (marshaled[5] << 8) + marshaled[4];
  header_.frag_off = (marshaled[7] << 8) + marshaled[6];
  header_.ttl      = marshaled[8];
  header_.protocol = marshaled[9];
  header_.check    = (marshaled[10] << 8) + marshaled[11];
  std::memcpy(&(header_.saddr), &(marshaled[12]), 4);
  std::memcpy(&(header_.daddr), &(marshaled[16]), 4);

  const auto hdr_len  = header_.ihl * 4;  // NOTE ihl is in 4 bytes (= 32 bit) increments
  const auto body_len = header_.tot_len - hdr_len;
  if (body_len <= 0) {
    return;
  }
  std::copy(&marshaled[hdr_len], &marshaled[header_.tot_len], std::back_inserter(body_));
}

std::vector<uint8_t> ip_packet::marshal() const {
  std::vector<uint8_t> marshaled;
  struct iphdr hdr_copy;
  std::memcpy(&hdr_copy, &header_, sizeof(header_));
  for (int i = 0; i < sizeof(hdr_copy); ++i) {
    marshaled.push_back((reinterpret_cast<uint8_t *>(&hdr_copy))[i]);
  }
  std::copy(body_.begin(), body_.end(), std::back_inserter(marshaled));
  return marshaled;
}

uint8_t ip_packet::get_version() const {
  return header_.version;
}

uint8_t ip_packet::get_ihl() const {
  return header_.ihl;
}

uint8_t ip_packet::get_tos() const {
  return header_.tos;
}

uint16_t ip_packet::get_tot_len() const {
  return ntohs(header_.tot_len);
}

uint16_t ip_packet::get_id() const {
  return ntohs(header_.id);
}

uint16_t ip_packet::get_frag_off() const {
  return ntohs(header_.frag_off);
}

uint8_t ip_packet::get_ttl() const {
  return header_.ttl;
}

uint8_t ip_packet::get_protocol() const {
  return header_.protocol;
}

uint16_t ip_packet::get_check() const {
  return ntohs(header_.check);
}

void ip_packet::get_saddr(uint8_t *dst) const {
  std::memcpy(dst, &(header_.saddr), 4);
}

void ip_packet::get_daddr(uint8_t *dst) const {
  std::memcpy(dst, &(header_.daddr), 4);
}

std::vector<uint8_t> ip_packet::get_body() const {
  std::vector<uint8_t> body;
  std::copy(body_.begin(), body_.end(), std::back_inserter(body));
  return body;
}
