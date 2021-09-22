#include <iomanip>  // for std::setw() and std::setfill()
#include <iostream> // for std::ostream
#include <sstream>  // for std::stringstream
#include <stdexcept>
#include <string>

#include "mac_addr.h"

mac_addr::mac_addr() : addr(MAC_ADDR_LEN) {}

void mac_addr::from_string(const std::string& addr) {
  char addr_host_bytes[addr_len_];
  std::string::size_type pos_colon = 0;
  std::string::size_type prev_pos_colon = -1;
  for (int i = 0; i < addr_len_; ++i) {
    std::string::size_type pos_start = prev_pos_colon + 1;
    pos_colon = addr.find_first_of(":", pos_start);
    if (i < addr_len_ - 1 &&  pos_colon == std::string::npos) {
      throw std::invalid_argument("Failed to parse mac address string. \":\" is missing");
    }
    if (i == addr_len_ - 1 && pos_colon != std::string::npos) {
      throw std::invalid_argument("Failed to parse mac address string. Extra \":\" is found");
    }
    if (i == addr_len_ - 1 && pos_colon == std::string::npos) {
      pos_colon = addr.length();
    }
    std::string::size_type part_size = pos_colon - pos_start;
    const auto base = 16;
    addr_host_bytes[i] = std::stoi(addr.substr(pos_start, part_size), nullptr, base);
    prev_pos_colon = pos_colon;
  }
  from_host_order(addr_host_bytes);
}

std::string mac_addr::to_string() const {
  std::stringstream ss;
  for (int i = 0; i < addr_len_; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<unsigned int>(addr_[i]);
    if (i != addr_len_ - 1) {
      ss << ":";
    }
  }
  return ss.str();
}

std::ostream& operator<<(std::ostream& os, const mac_addr& addr) {
  os << addr.to_string();
  return os;
}
