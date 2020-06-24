#ifndef IPV4_HEADER_H_
#define IPV4_HEADER_H_

#include <netinet/ip.h>  // iphdr
#include <stddef.h>      // size_t

void build_ipv4_hdr(
    struct iphdr *ip, uint16_t protocol, char *src_addr, char *dst_addr,
    void *data, size_t data_size);

#endif  // IPV4_HEADER_H_
