#include <iomanip>  // for std::setw() and std::setfill()
#include <iostream> // for std::ostream
#include <sstream>  // for std::stringstream
#include <stdexcept>
#include <string>

#include "ip_addr.h"

ip_addr::ip_addr() : addr(IP_ADDR_LEN) {}

void ip_addr::from_string(const std::string& addr) {
  char addr_host_bytes[addr_len_];
  std::string::size_type pos_dot = 0;
  std::string::size_type prev_pos_dot = -1;
  for (int i = 0; i < addr_len_; ++i) {
    std::string::size_type pos_start = prev_pos_dot + 1;
    pos_dot = addr.find_first_of(".", pos_start);
    if (i < addr_len_ - 1 &&  pos_dot == std::string::npos) {
      throw std::invalid_argument("Failed to parse ip address string. \".\" is missing");
    }
    if (i == addr_len_ - 1 && pos_dot != std::string::npos) {
      throw std::invalid_argument("Failed to parse ip address string. Extra \".\" is found");
    }
    if (i == addr_len_ - 1 && pos_dot == std::string::npos) {
      pos_dot = addr.length();
    }
    std::string::size_type part_size = pos_dot - pos_start;
    const auto base = 10;
    addr_host_bytes[i] = std::stoi(addr.substr(pos_start, part_size), nullptr, base);
    prev_pos_dot = pos_dot;
  }
  from_host_order(addr_host_bytes);
}

std::string ip_addr::to_string() const {
  std::stringstream ss;
  for (int i = 0; i < addr_len_; ++i) {
    ss << static_cast<unsigned int>(addr_[i]);
    if (i != addr_len_ - 1) {
      ss << ".";
    }
  }
  return ss.str();
}

std::ostream& operator<<(std::ostream& os, const ip_addr& addr) {
  os << addr.to_string();
  return os;
}
