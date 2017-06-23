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
#include <search.h>
#include "utils.c"

/**
 * Name........: hcstatgen
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define CHARSIZ 0x100

#define PW_MAX 64

#define ROOT_CNT   (PW_MAX * CHARSIZ)
#define MARKOV_CNT (PW_MAX * CHARSIZ * CHARSIZ)

#define FGETSBUFSZ 0x100000

#define HEX 0

/**
 * Outfile structure:
 *
 * - PW_MAX pw_pos
 *   - CHARSIZ root
 * - PW_MAX pw_pos
 *   - CHARSIZ key0
 *     - CHARSIZ key1
 */

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

#if HEX
static u8 hex_convert (const u8 c)
{
  return ((c & 15) + (c >> 6) * 9);
}
#endif

int main (int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "usage: %s outfile < dictionary\n", argv[0]);

    return (-1);
  }

  char *outfile = argv[1];

  /* allocate memory */

  u64 *root_stats_buf = (u64 *) calloc (ROOT_CNT, sizeof (u64));

  u64 *markov_stats_buf = (u64 *) calloc (MARKOV_CNT, sizeof (u64));

  char *buf = (char *) calloc (FGETSBUFSZ, sizeof (char));

  /* init pointer */

  u64 *root_stats_ptr = root_stats_buf;

  u64 *root_stats_buf_by_pos[PW_MAX];

  for (int i = 0; i < PW_MAX; i++)
  {
    root_stats_buf_by_pos[i] = root_stats_ptr;

    root_stats_ptr += CHARSIZ;
  }

  u64 *markov_stats_ptr = markov_stats_buf;

  u64 *markov_stats_buf_by_key[PW_MAX][CHARSIZ];

  for (int i = 0; i < PW_MAX; i++)
  {
    for (int j = 0; j < CHARSIZ; j++)
    {
      markov_stats_buf_by_key[i][j] = markov_stats_ptr;

      markov_stats_ptr += CHARSIZ;
    }
  }

  /* parse dictionary */

  printf ("Reading input...\n");

  #if HEX
  while (!feof (stdin))
  {
    const int len = fgetl (stdin, FGETSBUFSZ, buf);

    if (len == -1) continue;

    const int max = (len > PW_MAX * 2) ? PW_MAX * 2 : len;

    for (int pos = 0; pos < len; pos += 2)
    {
      const u8 c0 = (hex_convert ((const u8) buf[pos + 0]) << 4)
                  | (hex_convert ((const u8) buf[pos + 1]) << 0);

      root_stats_buf_by_pos[pos / 2][c0]++;
    }

    for (int pos = 0; pos < len - 2; pos += 2)
    {
      const u8 c0 = (hex_convert ((const u8) buf[pos + 0]) << 4)
                  | (hex_convert ((const u8) buf[pos + 1]) << 0);

      const u8 c1 = (hex_convert ((const u8) buf[pos + 2]) << 4)
                  | (hex_convert ((const u8) buf[pos + 3]) << 0);

      markov_stats_buf_by_key[pos / 2][c0][c1]++;
    }
  }
  #else
  while (!feof (stdin))
  {
    const int len = fgetl (stdin, FGETSBUFSZ, buf);

    if (len == -1) continue;

    const int max = (len > PW_MAX) ? PW_MAX : len;

    for (int pos = 0; pos < max; pos++)
    {
      const u8 c0 = (const u8) buf[pos];

      root_stats_buf_by_pos[pos][c0]++;
    }

    for (int pos = 0; pos < max - 1; pos++)
    {
      const u8 c0 = (const u8) buf[pos + 0];
      const u8 c1 = (const u8) buf[pos + 1];

      markov_stats_buf_by_key[pos][c0][c1]++;
    }
  }
  #endif

  /* write results */

  printf ("Writing stats...\n");

  FILE *fd = fopen (outfile, "wb");

  if (fd == NULL)
  {
    fprintf (stderr, "%s: %s", outfile, strerror (errno));

    return (-1);
  }

  fwrite (root_stats_buf,   sizeof (u64), ROOT_CNT,   fd);
  fwrite (markov_stats_buf, sizeof (u64), MARKOV_CNT, fd);

  fclose (fd);

  free (root_stats_buf);
  free (markov_stats_buf);
  free (buf);

  return 0;
}
