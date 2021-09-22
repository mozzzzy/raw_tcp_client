#ifndef SOCKET_WRAPPER_H_
#define SOCKET_WRAPPER_H_

#include <string>
#include <vector>

class socket_wrapper {
 private:
  int sock_;
  unsigned short ether_prtcl_type_;
 public:
  socket_wrapper(const unsigned short ether_prtcl_type);
  void send(
    const std::string& ifname,
    const uint8_t *target_mac,
    const std::vector<uint8_t>& data) const;
  void recv(const size_t size, std::vector<uint8_t>& data) const;
  ~socket_wrapper();
};

#endif  // SOCKET_WRAPPER_H_
