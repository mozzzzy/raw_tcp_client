#ifndef MAC_ADDR_H_
#define MAC_ADDR_H_

#include <iostream>
#include <string>
#include <vector>

#include "addr.h"

const int MAC_ADDR_LEN = 6; // 6 bytes

class mac_addr : public addr {
 public:
  mac_addr();
  void from_string(const std::string& addr);
  std::string to_string() const;
  friend std::ostream& operator<<(std::ostream& os, const mac_addr& addr);
};

#endif  // MAC_ADDR_H_
