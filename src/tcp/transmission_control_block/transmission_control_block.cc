#include <chrono>
#include <chrono>
#include <stdexcept>

#include "tcp_segment.h"
#include "transmission_control_block.h"

namespace {
namespace chrono = std::chrono;

unsigned long long get_current_time_microsec_from_midnight() {
  std::timespec ts;
  if (std::timespec_get(&ts, TIME_UTC) == 0) {
    throw std::runtime_error("Failed to get current time.");
  }
  auto current_unixtime_sec = ts.tv_sec;
  auto one_day_sec = 86400;   // 60 * 60 * 24
  auto current_sec_from_midnight = current_unixtime_sec % one_day_sec;

  auto current_nsec_part = ts.tv_nsec;
  auto current_microsec_part =
    chrono::duration_cast<chrono::microseconds>(chrono::nanoseconds{current_nsec_part});

  // current_microsec_from_midnight is
  //   0 < now_msec_from_midnight < 86400000000
  unsigned long long current_microsec_from_midnight =
    current_sec_from_midnight * 1000000 + current_microsec_part.count();
  return current_microsec_from_midnight;
}

uint32_t generate_initial_send_seq_number() {
  // NOTE
  // (rfc 793 - 3.3. Sequence Numbers - Initial Sequence Number Selection)
  //   When new connections are created,
  //   an initial sequence number (ISN) generator is employed which selects a
  //   new 32 bit ISN.  The generator is bound to a (possibly fictitious) 32
  //   bit clock whose low order bit is incremented roughly every 4
  //   microseconds.  Thus, the ISN cycles approximately every 4.55 hours.
  //   Since we assume that segments will stay in the network no more than
  //   the Maximum Segment Lifetime (MSL) and that the MSL is less than 4.55
  //   hours we can reasonably assume that ISN's will be unique.
  const auto current_time_from_midnight = get_current_time_microsec_from_midnight();
  const uint32_t iss = (current_time_from_midnight / 4) % UINT32_MAX;
  return iss;
}
} // namespace

transmission_control_block::transmission_control_block() {
  const auto isn = generate_initial_send_seq_number();
  snd_nxt_ = isn;
  iss_     = isn;
}

tcp_segment transmission_control_block::create_send_segment(
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
    const std::vector<uint8_t> body) {
  tcp_segment seg(
      src_ip_bytes,
      dst_ip_bytes,
      src_port,
      dst_port,
      snd_nxt_,
      rcv_nxt_,
      ns_flag,
      cwr_flag,
      ece_flag,
      urg_flag,
      ack_flag,
      psh_flag,
      rst_flag,
      syn_flag,
      fin_flag,
      window,
      urg_ptr,
      options,
      body);
  // update snd_una_
  snd_una_ = snd_nxt_;
  // update snd_nxt_
  if (syn_flag || fin_flag) {
    snd_nxt_++;
  } else {
    snd_nxt_ += body.size();
  }
  // update snd_up_
  if (urg_flag) {
    snd_up_ = urg_ptr;
  }
  // update snd_wl1_
  snd_wl1_ = window;
  // update snd_wl2_
  snd_wl2_ = rcv_nxt_;
  return seg;
}

void transmission_control_block::apply_receive_segment(const tcp_segment& segment) {
  // update snd_una_
  if (segment.get_ack()) {
    snd_una_ = segment.get_ack_seq() + 1;
  }
  // update rcv_nxt_
  if (segment.get_syn() || segment.get_fin()) {
    rcv_nxt_ = segment.get_seq() + 1;
  } else if (!segment.get_ack() && segment.get_body().size() == 0) {
    rcv_nxt_ = segment.get_seq() + 1;
  } else if (segment.get_body().size() != 0) {
    rcv_nxt_ = segment.get_seq() + segment.get_body().size();
  }
  // update rcv_wnd_
  rcv_wnd_ = segment.get_window();
  // update rcv_up_
  if (segment.get_urg()) {
    rcv_up_ = segment.get_urgent_pointer();
  }
  // update irs_
  if (segment.get_syn()) {
    irs_ = segment.get_seq();
  }
}
