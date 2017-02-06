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
 * Name........: cleanup-rules
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

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

#define ATTACK_EXEC_ON_CPU 1
#define ATTACK_EXEC_ON_GPU 2

#define MAX_CPU_RULES 255 // this is defined in include/types.h (hashcat)
#define MAX_GPU_RULES 255

static int class_num (const char c)
{
  return ((c >= '0') && (c <= '9'));
}

static int class_upper (const char c)
{
  return ((c >= 'A') && (c <= 'Z'));
}

static char conv_ctoi (const char c)
{
  if (class_num (c))
  {
    return (char)(c - '0');
  }
  else if (class_upper (c))
  {
    return (char)(c - 'A' + 10);
  }

  return -1;
}

int main (int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "usage: %s mode\n", argv[0]);

    return (-1);
  }

  int num = atoi (argv[1]);

  if ((num != ATTACK_EXEC_ON_CPU) && (num != ATTACK_EXEC_ON_GPU))
  {
    fprintf (stderr, "mode: 1 = CPU, 2 = GPU\n");

    return (-1);
  }

  #ifdef _WINDOWS
  _setmode (_fileno (stdin), _O_BINARY);
  #endif

  char line_buf[BUFSIZ];

  int line_len;

  #define NEXT_RULEPOS  if (++pos == line_len)                rc = -1;
  #define NEXT_RPTOI    if (conv_ctoi (line_buf[pos]) == -1)  rc = -1;
  #define DENY_GPU      if (num == ATTACK_EXEC_ON_GPU)        rc = -1;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    int rc = 0;

    int cnt = 0;

    int pos;

    for (pos = 0; pos < line_len; pos++)
    {
      switch (line_buf[pos])
      {
        case ' ':
          continue; // just skip all spaces around rules

        case RULE_OP_MANGLE_NOOP:
          break;

        case RULE_OP_MANGLE_LREST:
          break;

        case RULE_OP_MANGLE_UREST:
          break;

        case RULE_OP_MANGLE_LREST_UFIRST:
          break;

        case RULE_OP_MANGLE_UREST_LFIRST:
          break;

        case RULE_OP_MANGLE_TREST:
          break;

        case RULE_OP_MANGLE_TOGGLE_AT:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_REVERSE:
          break;

        case RULE_OP_MANGLE_DUPEWORD:
          break;

        case RULE_OP_MANGLE_DUPEWORD_TIMES:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_REFLECT:
          break;

        case RULE_OP_MANGLE_ROTATE_LEFT:
          break;

        case RULE_OP_MANGLE_ROTATE_RIGHT:
          break;

        case RULE_OP_MANGLE_APPEND:
          NEXT_RULEPOS;
          break;

        case RULE_OP_MANGLE_PREPEND:
          NEXT_RULEPOS;
          break;

        case RULE_OP_MANGLE_DELETE_FIRST:
          break;

        case RULE_OP_MANGLE_DELETE_LAST:
          break;

        case RULE_OP_MANGLE_DELETE_AT:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_EXTRACT:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_INSERT:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          break;

        case RULE_OP_MANGLE_OVERSTRIKE:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          break;

        case RULE_OP_MANGLE_TRUNCATE_AT:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_REPLACE:
          NEXT_RULEPOS;
          NEXT_RULEPOS;
          break;

        case RULE_OP_MANGLE_PURGECHAR:
          NEXT_RULEPOS;
          break;

        case RULE_OP_MANGLE_TOGGLECASE_REC:
          break;

        case RULE_OP_MANGLE_DUPECHAR_FIRST:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_DUPECHAR_LAST:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_DUPECHAR_ALL:
          break;

        case RULE_OP_MANGLE_DUPEBLOCK_FIRST:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_DUPEBLOCK_LAST:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_SWITCH_FIRST:
          break;

        case RULE_OP_MANGLE_SWITCH_LAST:
          break;

        case RULE_OP_MANGLE_SWITCH_AT:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_CHR_SHIFTL:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_CHR_SHIFTR:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_CHR_INCR:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_CHR_DECR:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_REPLACE_NP1:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_REPLACE_NM1:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          break;

        case RULE_OP_MANGLE_TITLE:
          break;

        case RULE_OP_MANGLE_EXTRACT_MEMORY:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          NEXT_RPTOI;
          DENY_GPU;
          break;

        case RULE_OP_MANGLE_APPEND_MEMORY:
          DENY_GPU;
          break;

        case RULE_OP_MANGLE_PREPEND_MEMORY:
          DENY_GPU;
          break;

        case RULE_OP_MEMORIZE_WORD:
          DENY_GPU;
          break;

        case RULE_OP_REJECT_LESS:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_GREATER:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_CONTAIN:
          NEXT_RULEPOS;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_NOT_CONTAIN:
          NEXT_RULEPOS;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_EQUAL_FIRST:
          NEXT_RULEPOS;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_EQUAL_LAST:
          NEXT_RULEPOS;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_EQUAL_AT:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_CONTAINS:
          NEXT_RULEPOS;
          NEXT_RPTOI;
          NEXT_RULEPOS;
          DENY_GPU;
          break;

        case RULE_OP_REJECT_MEMORY:
          DENY_GPU;
          break;

        default:
          rc = -1;
          break;
      }

      if (rc == -1) break;

      cnt++;

      if ((num == ATTACK_EXEC_ON_CPU) && (cnt > MAX_CPU_RULES))
      {
        rc = -1;

        break;
      }

      if ((num == ATTACK_EXEC_ON_GPU) && (cnt > MAX_GPU_RULES))
      {
        rc = -1;

        break;
      }
    }

    if (rc == -1) continue;

    puts (line_buf);
  }

  return 0;
}
