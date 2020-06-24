#ifndef TCP_HEADER_H_
#define TCP_HEADER_H_

#include <netinet/tcp.h>  // tcphdr
#include <stddef.h>       // size_t
#include <stdint.h>       // uintX_t

void build_tcp_syn_hdr(
    struct tcphdr *tcp, char *src_addr, uint16_t src_port,
    char *dst_addr, uint16_t dst_port, uint32_t init_seq);

#endif // TCP_HEADER_H_
