#include <stdio.h>
#include <string.h>

#include "libsha1.h"

static void print_hex(const char* data, size_t size)
{
    int i;
    printf("0x");
    for(i = 0; i < size; ++i)
        printf("%x%x", ((unsigned char)data[i])/16, ((unsigned char)data[i])%16);
}

static int num_test;

static int do_test(const char* data, size_t size, const char* expected_dgst)
{
    sha1_ctx ctx;
    int i;
    char dgst[SHA1_DIGEST_SIZE];

    printf("Test %d. [%d] ", num_test++, size);
    print_hex(data, size);
    printf("\nExpected        : ");
    print_hex(expected_dgst, SHA1_DIGEST_SIZE);
    printf("\n");

    sha1_begin(&ctx);
    for(i = 0; i < size; ++i)
        sha1_hash(data+i, 1, &ctx);
    sha1_end(dgst, &ctx);

    printf("Actual (1-byte) : ");
    print_hex(dgst, SHA1_DIGEST_SIZE);
    if(!memcmp(dgst, expected_dgst, SHA1_DIGEST_SIZE))
        printf(" - ok\n");
    else
    {
        printf(" - ERR\n");
        return 0;
    }

    sha1_begin(&ctx);
    sha1_hash(data, size, &ctx);
    sha1_end(dgst, &ctx);
    printf("Actual (1 block): ");
    print_hex(dgst, SHA1_DIGEST_SIZE);
    if(!memcmp(dgst, expected_dgst, SHA1_DIGEST_SIZE))
        printf(" - ok\n");
    else
    {
        printf(" - ERR\n");
        return 0;
    }

    return 1;
}

char t1[] = "";
char t1_output[] = "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09";

char t2[] = "1234567890";
char t2_output[] = "\x01\xb3\x07\xac\xba\x4f\x54\xf5\x5a\xaf\xc3\x3b\xb0\x6b\xbb\xf6\xca\x80\x3e\x9a";

int main()
{
    do_test(t1, sizeof(t1) - 1, t1_output);
    do_test(t2, sizeof(t2) - 1, t2_output);
}
