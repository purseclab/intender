#ifndef _BLOOM_H
#define _BLOOM_H
#include <stdint.h>

void bloom_free(uint32_t filter);
void bloom_add_32bit(uint32_t *filter, uint32_t item);
void bloom_add_port(uint32_t *filter, uint64_t dpid, uint32_t port);

#endif /* _BLOOM_H */
