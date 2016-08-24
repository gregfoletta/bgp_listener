/* byte_conv.h - this file contains functions used for translating arrays of unsigned chars into
 * types of uint8_t, uint16_t, uint32_t and uint64_t. It also contains the reverse, functions 
 * which convert those types into arrays of chars.
 */

#include <stdint.h>

/* Takes a pointer to uchars in network byte order */
static inline uint8_t uchar_to_uint8(const unsigned char *bytes) {
    return (uint8_t) bytes[0];
}

static inline uint8_t uchar_to_uint8_inc(const unsigned char **byte) {
    uint8_t x = uchar_to_uint8(*byte);
    (*byte)++;
    return x;
}

static inline uint16_t uchar_be_to_uint16(const unsigned char *bytes) {
    uint16_t x;
    x =  (uint16_t) bytes[0] << 8; 
    x |= (uint16_t) bytes[1]; 
    return x;
}

static inline uint16_t uchar_be_to_uint16_inc(const unsigned char **bytes) {
    uint16_t x = uchar_be_to_uint16(*bytes);
    *bytes += 2;
    return x;
}

static inline uint32_t uchar_be_to_uint32(const unsigned char *bytes) {
    uint32_t x;
    x =  (uint32_t) bytes[0]; 
    x |= (uint32_t) bytes[1] << 8; 
    x |= (uint32_t) bytes[2] << 16; 
    x |= (uint32_t) bytes[3] << 24; 
    return x;
}

static inline uint32_t uchar_be_to_uint32_inc(const unsigned char **bytes) {
    uint32_t x = uchar_be_to_uint32(*bytes);
    *bytes += 4;
    return x;
}

static inline uint64_t uchar_be_to_uint64(const unsigned char *bytes) {
    uint64_t x;
    x =  (uint64_t) bytes[0]; 
    x |= (uint64_t) bytes[1] << 8; 
    x |= (uint64_t) bytes[2] << 16; 
    x |= (uint64_t) bytes[3] << 24; 
    x |= (uint64_t) bytes[1] << 32; 
    x |= (uint64_t) bytes[1] << 40; 
    x |= (uint64_t) bytes[2] << 48; 
    x |= (uint64_t) bytes[2] << 56; 
    return x;
}

static inline void uint8_to_uchar(unsigned char *bytes, uint8_t i) {
    bytes[0] = i;
}


static inline void uint8_to_uchar_inc(unsigned char **bytes, uint8_t i) {
    uint8_to_uchar(*bytes, i);
    (*bytes)++;
}

static inline void uint16_to_uchar_be(unsigned char *bytes, uint16_t i) {
    bytes[0] = (i >> 8);
    bytes[1] = i;
}

static inline void uint16_to_uchar_be_inc(unsigned char **bytes, uint16_t i) {
    uint16_to_uchar_be(*bytes, i);
    *bytes += 2;
}

static inline void uint32_to_uchar_be(unsigned char *bytes, uint32_t i) {
    bytes[0] = (i >> 24);
    bytes[1] = (i >> 16);
    bytes[2] = (i >> 8);
    bytes[3] = i;
}

static inline void uint32_to_uchar_be_inc(unsigned char **bytes, uint32_t i) {
    uint32_to_uchar_be(*bytes, i);
    *bytes += 4;
}

static inline void uint64_to_uchar_be(unsigned char *bytes, uint64_t i) {
    bytes[0] = (i >> 56);
    bytes[1] = (i >> 48);
    bytes[2] = (i >> 40);
    bytes[3] = (i >> 32);
    bytes[4] = (i >> 24);
    bytes[5] = (i >> 16);
    bytes[6] = (i >> 8);
    bytes[7] = i;
}

static inline void uint64_to_uchar_be_inc(unsigned char *bytes, uint64_t i) {
    uint64_to_uchar_be(bytes, i);
    bytes += 8;
}
