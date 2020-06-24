#ifndef HEXTET_H_
#define HEXTET_H_

#include <stddef.h>     // size_t
#include <stdint.h>     // uintX_t

int parse_to_hextets(uint16_t *hextets, void *data, size_t data_size);

int calc_hextet_sum(uint16_t *data_hextets, size_t data_size);

#endif  // HEXTET_H_
