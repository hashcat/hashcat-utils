#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __MSVCRT_VERSION__ 0x0700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "utils.c"

/**
 * Name........: generate-rules
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define RP_GEN_FUNC_MIN 1
#define RP_GEN_FUNC_MAX 4

#define RULE_OP_MANGLE_NOOP             ':'
#define RULE_OP_MANGLE_LREST            'l'
#define RULE_OP_MANGLE_UREST            'u'
#define RULE_OP_MANGLE_LREST_UFIRST     'c'
#define RULE_OP_MANGLE_UREST_LFIRST     'C'
#define RULE_OP_MANGLE_TREST            't'
#define RULE_OP_MANGLE_TOGGLE_AT        'T'
#define RULE_OP_MANGLE_REVERSE          'r'
#define RULE_OP_MANGLE_DUPEWORD         'd'
#define RULE_OP_MANGLE_DUPEWORD_TIMES   'p'
#define RULE_OP_MANGLE_REFLECT          'f'
#define RULE_OP_MANGLE_ROTATE_LEFT      '{'
#define RULE_OP_MANGLE_ROTATE_RIGHT     '}'
#define RULE_OP_MANGLE_APPEND           '$'
#define RULE_OP_MANGLE_PREPEND          '^'
#define RULE_OP_MANGLE_DELETE_FIRST     '['
#define RULE_OP_MANGLE_DELETE_LAST      ']'
#define RULE_OP_MANGLE_DELETE_AT        'D'
#define RULE_OP_MANGLE_EXTRACT          'x'
#define RULE_OP_MANGLE_INSERT           'i'
#define RULE_OP_MANGLE_OVERSTRIKE       'o'
#define RULE_OP_MANGLE_TRUNCATE_AT      '\''
#define RULE_OP_MANGLE_REPLACE          's'
#define RULE_OP_MANGLE_PURGECHAR        '@'
#define RULE_OP_MANGLE_TOGGLECASE_REC   'a'
#define RULE_OP_MANGLE_DUPECHAR_FIRST   'z'
#define RULE_OP_MANGLE_DUPECHAR_LAST    'Z'
#define RULE_OP_MANGLE_DUPECHAR_ALL     'q'
#define RULE_OP_MANGLE_EXTRACT_MEMORY   'X'
#define RULE_OP_MANGLE_APPEND_MEMORY    '4'
#define RULE_OP_MANGLE_PREPEND_MEMORY   '6'

#define RULE_OP_MEMORIZE_WORD           'M'

#define RULE_OP_REJECT_LESS             '<'
#define RULE_OP_REJECT_GREATER          '>'
#define RULE_OP_REJECT_CONTAIN          '!'
#define RULE_OP_REJECT_NOT_CONTAIN      '/'
#define RULE_OP_REJECT_EQUAL_FIRST      '('
#define RULE_OP_REJECT_EQUAL_LAST       ')'
#define RULE_OP_REJECT_EQUAL_AT         '='
#define RULE_OP_REJECT_CONTAINS         '%'
#define RULE_OP_REJECT_MEMORY           'Q'

/* hashcat only */
#define RULE_OP_MANGLE_SWITCH_FIRST     'k'
#define RULE_OP_MANGLE_SWITCH_LAST      'K'
#define RULE_OP_MANGLE_SWITCH_AT        '*'
#define RULE_OP_MANGLE_CHR_SHIFTL       'L'
#define RULE_OP_MANGLE_CHR_SHIFTR       'R'
#define RULE_OP_MANGLE_CHR_INCR         '+'
#define RULE_OP_MANGLE_CHR_DECR         '-'
#define RULE_OP_MANGLE_REPLACE_NP1      '.'
#define RULE_OP_MANGLE_REPLACE_NM1      ','
#define RULE_OP_MANGLE_DUPEBLOCK_FIRST  'y'
#define RULE_OP_MANGLE_DUPEBLOCK_LAST   'Y'
#define RULE_OP_MANGLE_TITLE            'E'

static const char grp_op_nop[] =
{
  RULE_OP_MANGLE_LREST,
  RULE_OP_MANGLE_UREST,
  RULE_OP_MANGLE_LREST_UFIRST,
  RULE_OP_MANGLE_UREST_LFIRST,
  RULE_OP_MANGLE_TREST,
  RULE_OP_MANGLE_REVERSE,
  RULE_OP_MANGLE_DUPEWORD,
  RULE_OP_MANGLE_REFLECT,
  RULE_OP_MANGLE_DELETE_FIRST,
  RULE_OP_MANGLE_DELETE_LAST,
  RULE_OP_MANGLE_ROTATE_LEFT,
  RULE_OP_MANGLE_ROTATE_RIGHT,
  RULE_OP_MANGLE_SWITCH_FIRST,
  RULE_OP_MANGLE_SWITCH_LAST,
  RULE_OP_MANGLE_DUPECHAR_ALL,
  RULE_OP_MANGLE_TITLE,
  RULE_OP_MANGLE_APPEND_MEMORY,
  RULE_OP_MANGLE_PREPEND_MEMORY,
};

static const char grp_op_pos_p0[] =
{
  RULE_OP_MANGLE_TOGGLE_AT,
  RULE_OP_MANGLE_DELETE_AT,
  RULE_OP_MANGLE_TRUNCATE_AT,
  RULE_OP_MANGLE_CHR_INCR,
  RULE_OP_MANGLE_CHR_DECR,
  RULE_OP_MANGLE_CHR_SHIFTL,
  RULE_OP_MANGLE_CHR_SHIFTR,
  RULE_OP_MANGLE_REPLACE_NP1,
  RULE_OP_MANGLE_REPLACE_NM1
};

static const char grp_op_pos_p1[] =
{
  RULE_OP_MANGLE_DUPEWORD_TIMES,
  RULE_OP_MANGLE_DUPECHAR_FIRST,
  RULE_OP_MANGLE_DUPECHAR_LAST,
  RULE_OP_MANGLE_DUPEBLOCK_FIRST,
  RULE_OP_MANGLE_DUPEBLOCK_LAST
};

static const char grp_op_chr[] =
{
  RULE_OP_MANGLE_APPEND,
  RULE_OP_MANGLE_PREPEND,
  RULE_OP_MANGLE_PURGECHAR
};

static const char grp_op_chr_chr[] =
{
  RULE_OP_MANGLE_REPLACE
};

static const char grp_op_pos_chr[] =
{
  RULE_OP_MANGLE_INSERT,
  RULE_OP_MANGLE_OVERSTRIKE
};

static const char grp_op_pos_pos0[] =
{
  RULE_OP_MANGLE_SWITCH_AT
};

static const char grp_op_pos_pos1[] =
{
  RULE_OP_MANGLE_EXTRACT
};

static const char grp_op_pos1_pos2_pos3[] =
{
  RULE_OP_MANGLE_EXTRACT_MEMORY
};

static const char grp_pos[] =
{
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B'
};

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

  int num = atoi (argv[1]);

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
