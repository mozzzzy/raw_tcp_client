#ifndef TRANSMISSION_CONTROL_BLOCK_H_
#define TRANSMISSION_CONTROL_BLOCK_H_

#include "tcp_segment.h"

// NOTE
// (rfc 793 - 2.7. Connection Establishment and Clearing)
//   There are several things that must be remembered
//   about a connection. To store this information we imagine that there
//   is a data structure called a Transmission Control Block (TCB).
class transmission_control_block {
 private:
  // NOTE
  // (rfc 793 - 3.2. Terminology and 3.3. Sequence Numbers)
  //
  //   SND.UNA : unacknowledged sequence number
  //   SND.NXT : next sequence number to be sent
  //   SND.UP  : send urgent pointer
  //   SND.WL1 : segment sequence number used for last window update
  //   SND.WL2 : segment acknowledgment number used for last window update
  //   ISS     : initial send sequence number
  //
  uint32_t snd_una_;
  uint32_t snd_nxt_;
  uint32_t snd_up_;
  uint32_t snd_wl1_;
  uint32_t snd_wl2_;
  uint32_t iss_;
  // NOTE
  // (rfc 793 - 3.2. Terminology and 3.3. Sequence Numbers)
  //
  //   RCV.NXT : next sequence number expected on an incoming segments, and
  //             is the left or lower edge of the receive window
  //   RCV.WND : receive window
  //   RCV,UP  : receive urgent pointer
  //   IRS     : initial receive sequence number
  //
  uint32_t rcv_nxt_;
  uint32_t rcv_wnd_;
  uint32_t rcv_up_;
  uint32_t irs_;
 public:
  transmission_control_block();
  tcp_segment create_send_segment(
      const uint8_t *src_ip_bytes,
      const uint16_t src_port,
      const uint8_t *dst_ip_bytes,
      const uint16_t dst_port,
      const bool ns_flag,
      const bool cwr_flag,
      const bool ece_flag,
      const bool urg_flag,
      const bool ack_flag,
      const bool psh_flag,
      const bool rst_flag,
      const bool syn_flag,
      const bool fin_flag,
      const uint16_t window,
      const uint16_t urg_ptr,
      const std::vector<uint8_t> options,
      const std::vector<uint8_t> body);
  void apply_receive_segment(const tcp_segment& segment);
};

#endif  // TRANSMISSION_CONTROL_BLOCK_H_
