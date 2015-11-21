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
 * Name........: permute_exist
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

typedef struct
{
  char chr;
  int  occ;

} db_t;

int scan_word (char *line_buf, int line_len, db_t db_buf[256])
{
  int db_cnt = 0;

  int i;

  for (i = 0; i < line_len; i++)
  {
    const char chr = line_buf[i];

    int j;

    for (j = 0; j < db_cnt; j++)
    {
      if (db_buf[j].chr == chr)
      {
        db_buf[j].occ++;

        break;
      }
    }

    if (j == db_cnt)
    {
      db_buf[j].chr = chr;
      db_buf[j].occ = 0;

      db_cnt++;
    }
  }

  return db_cnt;
}

int sort_by_key (const void *p1, const void *p2)
{
  const db_t *db1 = (db_t *) p1;
  const db_t *db2 = (db_t *) p2;

  return db1->chr - db2->chr;
}

int main (int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "usage: %s word < infile > outfile\n", argv[0]);

    return (-1);
  }

  char *word_buf = argv[1];

  #ifdef _WINDOWS
  _setmode (_fileno (stdin), _O_BINARY);
  #endif

  db_t db1_buf[256];

  memset (db1_buf, 0, sizeof (db1_buf));

  int db1_cnt = scan_word (word_buf, strlen (word_buf), db1_buf);

  qsort (db1_buf, db1_cnt, sizeof (db_t), sort_by_key);

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    if (line_len == 0) continue;

    db_t db2_buf[256];

    memset (db2_buf, 0, sizeof (db2_buf));

    int db2_cnt = scan_word (line_buf, line_len, db2_buf);

    if (db1_cnt != db2_cnt) continue;

    qsort (db2_buf, db2_cnt, sizeof (db_t), sort_by_key);

    int i;

    for (i = 0; i < db1_cnt; i++)
    {
      if (db1_buf[i].chr != db2_buf[i].chr) break;
      if (db1_buf[i].occ != db2_buf[i].occ) break;
    }

    if (i < db1_cnt) continue;

    puts (line_buf);
  }

  return (0);
}
