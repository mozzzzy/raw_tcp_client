#include <cstdint>  // for uint8_t

#include "addr.h"

addr::addr(size_t addr_len) : addr_len_(addr_len) {}

void addr::from_host_order(const char *addr) {
  for (int i = 0; i < addr_len_; ++i) {
    addr_.push_back(addr[i]);
  }
}

void addr::from_network_order(const char *addr) {
  for (int i = 0; i < addr_len_; ++i) {
    addr_.push_back(addr[addr_len_ - 1 - i]);
  }
}

void addr::host_order(uint8_t *addr) const {
  for (int i = 0; i < addr_len_; ++i) {
    addr[i] = addr_[i];
  }
}

void addr::network_order(uint8_t *addr) const {
  for (int i = 0; i < addr_len_; ++i) {
    addr[i] = addr_[addr_len_ - 1 - i];
  }
}
