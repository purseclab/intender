#include "crc16.h"
#include <stdio.h>

struct verify_rule {
    unsigned long long dpid;
    unsigned short rule;
};

int main(int argc, char *argv[]){

    struct verify_rule vr;
    unsigned short basis;
    sscanf(argv[1], "%llu", &vr.dpid);
    sscanf(argv[2], "%hu", &vr.rule);
    sscanf(argv[3], "%hu", &basis);

    const void *buf = &vr;
#ifdef DEBUG
    int i;
    for (i = 0; i < 10; i++) {
        printf("%02x", ((char*)buf)[i]);
    }
    printf("\n");
#endif
    const unsigned short crc = crc16(buf, 10, basis);

    printf("%u", crc);

    return 0;
}

