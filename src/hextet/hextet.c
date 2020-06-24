#include <stddef.h>     // size_t
#include <stdint.h>     // uintX_t
#include "./hextet.h"

int parse_to_hextets(uint16_t *hextets, void *data, size_t data_size) {
  // Parse data into octets
  uint8_t *data_octets = (uint8_t *)data;

  // Build hextet by two octets.
  int octet_cnt = 0;
  int hextet_cnt = 0;
  for (octet_cnt = 0; octet_cnt+1 < data_size; octet_cnt += 2) {
    /*
     * NOTE
     * The original data is host byte order.
     * So first octet is 16th place and second octet is 0th place.
     *
     * memory address
     * 0                  1
     * +------------------+------------------+
     * | 16th place octet | 0th place octet  |
     * +------------------+------------------+
     */
    uint8_t big_octet   = data_octets[octet_cnt];
    uint8_t small_octet = data_octets[octet_cnt+1];

    uint16_t hextet = 0;
    hextet = big_octet << 8;
    hextet += small_octet;

    hextets[hextet_cnt++] = hextet;
  }

  if (octet_cnt == data_size - 3) {
    /*
     * Parse the last octet if exists.
     *
     * memory address
     * data_size - 1      data_size
     * +------------------+------------------+
     * | 16th place octet |       0x00       |
     * +------------------+------------------+
     */
    uint8_t big_octet   = data_octets[data_size-1];
    uint16_t hextet = 0;
    hextet = big_octet << 8;

    hextets[hextet_cnt++] = hextet;
  }

  for (; hextet_cnt >= 0; hextet_cnt--) {
    // Decrement hextet_cnt if the highest place hextet is 0x00
    if (hextets[hextet_cnt-1] != 0) {
      break;
    }
  }
  return hextet_cnt;
}

int calc_hextet_sum(uint16_t *data_hextets, size_t data_size) {
  int hextet_sum = 0;
  int i;
  for (i = 0; i < data_size; i++) {
    hextet_sum += data_hextets[i];
  }
  return hextet_sum;
}
