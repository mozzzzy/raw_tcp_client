#ifndef IP_ADDR_H_
#define IP_ADDR_H_

#include <iostream>
#include <string>

#include "addr.h"

const int IP_ADDR_LEN = 4; // 4 bytes

class ip_addr : public addr {
 public:
  ip_addr();
  void from_string(const std::string& addr);
  std::string to_string() const;
  friend std::ostream& operator<<(std::ostream& os, const ip_addr& addr);
};

#endif  // IP_ADDR_H_
