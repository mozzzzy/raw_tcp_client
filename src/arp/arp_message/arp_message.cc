#include <cstring>  // for std::memcpy()
#include <vector>

#include "arp_message.h"

namespace {
void push_back_uint16_t_to_uint8_t(std::vector<uint8_t> &dest, uint16_t src) {
  auto first_byte  = static_cast<uint8_t>((src & 0xFF00) >> 8);
  auto second_byte = static_cast<uint8_t>(src & 0x00FF);
  dest.push_back(first_byte);
  dest.push_back(second_byte);
}

void push_back_uint32_t_to_uint8_t(std::vector<uint8_t> &dest, uint32_t src) {
  auto first_byte  = static_cast<uint8_t>((src & 0xFF000000) >> 24);
  auto second_byte = static_cast<uint8_t>((src & 0x00FF0000) >> 16);
  auto third_byte  = static_cast<uint8_t>((src & 0x0000FF00) >> 8);
  auto fourth_byte = static_cast<uint8_t>(src & 0x000000FF);
  dest.push_back(first_byte);
  dest.push_back(second_byte);
  dest.push_back(third_byte);
  dest.push_back(fourth_byte);
}
} // namespace

arp_message::arp_message(
    const uint16_t hw_type, const uint16_t prtcl_type,
    const uint8_t hw_size, const uint8_t prtcl_size, const uint16_t operation,
    const uint8_t *sender_mac, const uint8_t *sender_ip,
    const uint8_t *target_mac, const uint8_t *target_ip)
  : hw_type_(hw_type), prtcl_type_(prtcl_type),
    hw_size_(hw_size), prtcl_size_(prtcl_size), operation_(operation) {
  std::memcpy(sender_mac_, sender_mac, HW_SIZE_MAC);
  std::memcpy(target_mac_, target_mac, HW_SIZE_MAC);
  std::memcpy(sender_ip_, sender_ip, PROTOCOL_SIZE_IPV4);
  std::memcpy(target_ip_, target_ip, PROTOCOL_SIZE_IPV4);
}

arp_message::arp_message(const std::vector<uint8_t> data) {
  hw_type_    = (static_cast<uint16_t>(data[0]) << 8) + data[1];
  prtcl_type_ = (static_cast<uint16_t>(data[2]) << 8) + data[3];
  hw_size_    = data[4];
  prtcl_size_ = data[5];
  operation_  = (static_cast<uint16_t>(data[6]) << 8) + data[7];
  for (int i = 0; i < HW_SIZE_MAC; ++i) {
    sender_mac_[i] = data[8 + i];
  }
  for (int i = 0; i < PROTOCOL_SIZE_IPV4; ++i) {
    sender_ip_[i] = data[14 + i];
  }
  for (int i = 0; i < HW_SIZE_MAC; ++i) {
    target_mac_[i] = data[18 + i];
  }
  for (int i = 0; i < PROTOCOL_SIZE_IPV4; ++i) {
    target_ip_[i] = data[24 + i];
  }
}

std::vector<uint8_t> arp_message::data() {
  std::vector<uint8_t> data;
  push_back_uint16_t_to_uint8_t(data, hw_type_);
  push_back_uint16_t_to_uint8_t(data, prtcl_type_);
  data.push_back(hw_size_);
  data.push_back(prtcl_size_);
  push_back_uint16_t_to_uint8_t(data, operation_);
  for (int i = 0; i < HW_SIZE_MAC; ++i) {
    data.push_back(sender_mac_[i]);
  }
  for (int i = 0; i < PROTOCOL_SIZE_IPV4; ++i) {
    data.push_back(sender_ip_[i]);
  }
  for (int i = 0; i < HW_SIZE_MAC; ++i) {
    data.push_back(target_mac_[i]);
  }
  for (int i = 0; i < PROTOCOL_SIZE_IPV4; ++i) {
    data.push_back(target_ip_[i]);
  }
  return data;
}

void arp_message::get_sender_ip(uint8_t *sender_ip) {
  std::memcpy(sender_ip, sender_ip_, PROTOCOL_SIZE_IPV4);
}

void arp_message::get_target_ip(uint8_t *target_ip) {
  std::memcpy(target_ip, target_ip_, PROTOCOL_SIZE_IPV4);
}

void arp_message::get_sender_mac(uint8_t *sender_mac) {
  std::memcpy(sender_mac, sender_mac_, HW_SIZE_MAC);
}

void arp_message::get_target_mac(uint8_t *target_mac) {
  std::memcpy(target_mac, target_mac_, HW_SIZE_MAC);
}
