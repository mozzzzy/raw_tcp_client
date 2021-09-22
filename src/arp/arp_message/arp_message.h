#ifndef ARP_H_
#define ARP_H_

#include <string>
#include <vector>

const uint16_t HW_TYPE_ETHERNET            = 0x0001;
const uint16_t PROTOCOL_TYPE_IPV4          = 0x0800;
const uint8_t  HW_SIZE_MAC                 = 0x06;
const uint8_t  PROTOCOL_SIZE_IPV4          = 0x04;
const uint16_t OPERATION_CODE_ARP_REQUEST  = 0x0001;
const uint16_t OPERATION_CODE_ARP_RESPONSE = 0x0002;

/*
 * Format of ARP message.
 *
 * +-----------------+-----------------+-----+
 * | Ethernet Header |   ARP message   | FCS |
 * +-----------------+-----------------+-----+
 *
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Hardware Type         |         Protocol Type         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Hardware Size | Protocol Size |       Operation Code          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Sender Mac Address                      |
 * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |       Sender IP Address       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       Sender IP Address       |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 * |                       Target Mac Address                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Target IP Address                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
class arp_message {
 private:
  uint16_t hw_type_;
  uint16_t prtcl_type_;
  uint8_t  hw_size_;
  uint8_t  prtcl_size_;
  uint16_t operation_;
  uint8_t  sender_mac_[HW_SIZE_MAC];
  uint8_t  sender_ip_[PROTOCOL_SIZE_IPV4];
  uint8_t  target_mac_[HW_SIZE_MAC];
  uint8_t  target_ip_[PROTOCOL_SIZE_IPV4];
 public:
  arp_message(
      const uint16_t hw_type, const uint16_t prtcl_type,
      const uint8_t hw_size, const uint8_t prtcl_size, const uint16_t operation,
      const uint8_t *sender_mac, const uint8_t *sender_ip,
      const uint8_t *target_mac, const uint8_t *target_ip);
  arp_message(const std::vector<uint8_t> data);
  std::vector<uint8_t> data();
  void get_sender_ip(uint8_t *sender_ip);
  void get_target_ip(uint8_t *target_ip);
  void get_sender_mac(uint8_t *sender_mac);
  void get_target_mac(uint8_t *target_mac);
};

#endif  // ARP_H_
