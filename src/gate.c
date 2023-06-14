#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __MSVCRT_VERSION__ 0x0700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include "utils.c"

/**
 * Name........: gate
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define MOD_VALUE 3  // Modify the default MOD value here
#define OFFSET_VALUE 1  // Modify the default OFFSET value here

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s mod offset < infile > outfile\n", argv[0]);
        return -1;
    }

    const int mod = atoi(argv[1]);
    const int offset = atoi(argv[2]);

    if (mod <= 0)
    {
        fprintf(stderr, "mod must be a positive integer\n");
        return -1;
    }

    if (offset < 0 || offset >= mod)
    {
        fprintf(stderr, "offset must be between 0 and mod-1\n");
        return -1;
    }

    int pos = 0;
    char line_buf[BUFSIZ];

    while (fgets(line_buf, sizeof(line_buf), stdin) != NULL)
    {
        const size_t line_len = strlen(line_buf);

        if (line_len == 0 || line_buf[line_len - 1] != '\n')
        {
            // Line too long, skip it or handle the error accordingly
            continue;
        }

        if ((pos++ % mod) != offset)
        {
            // Line doesn't match the modulo and offset criteria, skip it
            continue;
        }

        // Print the line to stdout
        fputs(line_buf, stdout);
    }

    return 0;
}
