#ifndef ADDR_H_
#define ADDR_H_

#include <cstdint>  // for uint8_t
#include <vector>

class addr {
 protected:
  std::vector<uint8_t> addr_;
  size_t addr_len_;
 public:
  addr(size_t addr_len);
  void from_host_order(const char *addr);
  void from_network_order(const char *addr);
  void host_order(uint8_t *addr) const;
  void network_order(uint8_t *addr) const;
};

#endif  // ADDR_H_
