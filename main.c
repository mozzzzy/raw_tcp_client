#include <stdint.h> // uintX_t
#include <stdio.h>

#include "tcp.h"

int main() {
  char *src_addr = "127.0.0.1";
  uint16_t src_port = 49152;
  char *dest_addr = "127.0.0.1";
  uint16_t dest_port = 80;
  uint32_t init_seq = 12345678;

  int ret = 0;
  // send tcp syn
  ret = send_tcp_syn(src_addr, src_port, dest_addr, dest_port, init_seq);
  if (ret < 0) {
    perror("failed to send tcp syn packet: ");
  }

  // receive tcp syn ack

  // send tcp ack

  // send tcp rst

  // send tcp fin

  // receive tcp fin ack


  return 0;
}
