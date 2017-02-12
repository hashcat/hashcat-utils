#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __MSVCRT_VERSION__ 0x0700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "utils.c"
#include "rp_cpu.h"

/**
 * Name........: generate-rules
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define RP_GEN_FUNC_MIN 1
#define RP_GEN_FUNC_MAX 4

static void generate_random_rule (char rule_buf[BUFSIZ], const uint32_t rp_gen_func_min, const uint32_t rp_gen_func_max)
{
  const uint32_t rp_gen_num = get_random_num (rp_gen_func_min, rp_gen_func_max);

  uint32_t j;

  uint32_t rule_pos = 0;

  for (j = 0; j < rp_gen_num; j++)
  {
    uint32_t r  = 0;
    uint32_t p1 = 0;
    uint32_t p2 = 0;
    uint32_t p3 = 0;

    switch ((char) get_random_num (0, 9))
    {
      case 0:
        r = get_random_num (0, sizeof (grp_op_nop));
        rule_buf[rule_pos++] = grp_op_nop[r];
        break;

      case 1:
        r = get_random_num (0, sizeof (grp_op_pos_p0));
        rule_buf[rule_pos++] = grp_op_pos_p0[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        break;

      case 2:
        r = get_random_num (0, sizeof (grp_op_pos_p1));
        rule_buf[rule_pos++] = grp_op_pos_p1[r];
        p1 = get_random_num (1, 6);
        rule_buf[rule_pos++] = grp_pos[p1];
        break;

      case 3:
        r = get_random_num (0, sizeof (grp_op_chr));
        rule_buf[rule_pos++] = grp_op_chr[r];
        p1 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p1;
        break;

      case 4:
        r = get_random_num (0, sizeof (grp_op_chr_chr));
        rule_buf[rule_pos++] = grp_op_chr_chr[r];
        p1 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p1;
        p2 = get_random_num (0x20, 0x7e);
        while (p1 == p2)
        p2 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p2;
        break;

      case 5:
        r = get_random_num (0, sizeof (grp_op_pos_chr));
        rule_buf[rule_pos++] = grp_op_pos_chr[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (0x20, 0x7e);
        rule_buf[rule_pos++] = (char) p2;
        break;

      case 6:
        r = get_random_num (0, sizeof (grp_op_pos_pos0));
        rule_buf[rule_pos++] = grp_op_pos_pos0[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (0, sizeof (grp_pos));
        while (p1 == p2)
        p2 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p2];
        break;

      case 7:
        r = get_random_num (0, sizeof (grp_op_pos_pos1));
        rule_buf[rule_pos++] = grp_op_pos_pos1[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (1, sizeof (grp_pos));
        while (p1 == p2)
        p2 = get_random_num (1, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p2];
        break;

      case 8:
        r = get_random_num (0, sizeof (grp_op_pos1_pos2_pos3));
        rule_buf[rule_pos++] = grp_op_pos1_pos2_pos3[r];
        p1 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p2 = get_random_num (1, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p1];
        p3 = get_random_num (0, sizeof (grp_pos));
        rule_buf[rule_pos++] = grp_pos[p3];
        break;
    }

    rule_buf[rule_pos++] = ' ';
  }
}

int main (int argc, char *argv[])
{
  if ((argc != 2) && (argc != 3))
  {
    fprintf (stderr, "usage: %s number [seed]\n", argv[0]);

    return (-1);
  }

  const int num = atoi (argv[1]);

  if ((num < 1) || (num > 1000000000))
  {
    fprintf (stderr, "invalid rule count\n");

    return (-1);
  }

  time_t seed;

  if (argc == 3)
  {
    seed = atoi (argv[2]);
  }
  else
  {
    time (&seed);
  }

  srand (seed);

  int i;

  for (i = 0; i < num; i++)
  {
    char rule_buf[BUFSIZ];

    memset (rule_buf, 0, sizeof (rule_buf));

    generate_random_rule (rule_buf, RP_GEN_FUNC_MIN, RP_GEN_FUNC_MAX);

    puts (rule_buf);
  }

  return 0;
}
