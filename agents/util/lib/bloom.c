#include "bloom.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <string.h>
#include <arpa/inet.h>
/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */

struct bloom_port {
    uint64_t dpid;
    uint32_t port;
};

static inline uint32_t get_unaligned_u32(const uint32_t *p_)
{
    const uint8_t *p = (const uint8_t *) p_;
    return ntohl((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline uint32_t
jhash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

static inline void
jhash_mix(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *a -= *c; *a ^= jhash_rot(*c,  4); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a,  6); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  8); *b += *a;
      *a -= *c; *a ^= jhash_rot(*c, 16); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a, 19); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  4); *b += *a;
}

static inline void
jhash_final(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *c ^= *b; *c -= jhash_rot(*b, 14);
      *a ^= *c; *a -= jhash_rot(*c, 11);
      *b ^= *a; *b -= jhash_rot(*a, 25);
      *c ^= *b; *c -= jhash_rot(*b, 16);
      *a ^= *c; *a -= jhash_rot(*c,  4);
      *b ^= *a; *b -= jhash_rot(*a, 14);
      *c ^= *b; *c -= jhash_rot(*b, 24);
}

/* Returns the Jenkins hash of the 'n' 32-bit words at 'p', starting from
 * 'basis'.  'p' must be properly aligned.
 *
 * Use hash_words() instead, unless you're computing a hash function whose
 * value is exposed "on the wire" so we don't want to change it. */
uint32_t
jhash_words(const uint32_t *p, size_t n, uint32_t basis)
{
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + (((uint32_t) n) << 2) + basis;

    while (n > 3) {
        a += p[0];
        b += p[1];
        c += p[2];
        jhash_mix(&a, &b, &c);
        n -= 3;
        p += 3;
    }

    switch (n) {
    case 3:
        c += p[2];
        /* fall through */
    case 2:
        b += p[1];
        /* fall through */
    case 1:
        a += p[0];
        jhash_final(&a, &b, &c);
        /* fall through */
    case 0:
        break;
    }
    return c;
}

/* Returns the Jenkins hash of the 'n' bytes at 'p', starting from 'basis'.
 *
 * Use hash_bytes() instead, unless you're computing a hash function whose
 * value is exposed "on the wire" so we don't want to change it. */
uint32_t
jhash_bytes(const void *p_, size_t n, uint32_t basis)
{
    const uint32_t *p = p_;
    uint32_t a, b, c;

    a = b = c = 0xdeadbeef + n + basis;

    while (n >= 12) {
        a += get_unaligned_u32(p);
        b += get_unaligned_u32(p + 1);
        c += get_unaligned_u32(p + 2);
        jhash_mix(&a, &b, &c);
        n -= 12;
        p += 3;
    }

    if (n) {
        uint32_t tmp[3];

        tmp[0] = tmp[1] = tmp[2] = 0;
        memcpy(tmp, p, n);
        a += tmp[0];
        b += tmp[1];
        c += tmp[2];
        jhash_final(&a, &b, &c);
    }

    return c;
}

static void
bloom_add(uint32_t *filter, const void *p, size_t n) {
    // filter should have memory

    uint8_t *bits = (uint8_t *)filter;
    uint32_t hash = jhash_bytes(p, n, 0);
    uint16_t *first_half = (uint16_t *)&hash;
    uint16_t *second_half = &first_half[1];
    uint32_t gi[] = {*first_half, (*first_half + *second_half),(*first_half + 2 * (*second_half)) };
    int i;

    for (i = 0; i < 3; i++){
        gi[i] %= 32;
        bits[gi[i]/8] |= (1 << (gi[i]%8));
    }
}

void
bloom_add_32bit(uint32_t *filter, uint32_t item) {
    // filter should have memory

    uint8_t *bits = (uint8_t *)filter;
    const uint32_t *it = &item;
    uint32_t hash = jhash_words(it, 1, 0);
    uint16_t *first_half = (uint16_t *)&hash;
    uint16_t *second_half = &first_half[1];
    uint32_t gi[] = {*first_half, (*first_half + *second_half),(*first_half + 2 * (*second_half)) };
    int i;

    for (i = 0; i < 3; i++){
        gi[i] %= 32;
        bits[gi[i]/8] |= (1 << (gi[i]%8));
    }
}

void
bloom_add_port(uint32_t *filter, uint64_t dpid, uint32_t port) {
    struct bloom_port bp;

    bp.dpid = dpid;
    bp.port = port;

    bloom_add(filter, &bp, sizeof(uint64_t) + sizeof(uint32_t));
}
