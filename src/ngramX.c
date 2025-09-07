/**
 * Name........: ngramX
 * Author......: Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
 * Version.....: 1.0
 * Date........: Sun Sep  7 18:48:41 CEST 2025
 * License.....: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LINE_BUFFER 4096

// Print all possible n-grams of size groupSize
void printGroups (char **words, size_t wordCount, int groupSize)
{
  for (size_t i = 0; i + groupSize <= wordCount; i++)
  {
    for (int j = 0; j < groupSize; j++)
    {
      fprintf (stdout, "%s", words[i + j]);
      if (j < groupSize - 1) fprintf (stdout, " ");
    }
    fprintf (stdout, "\n");
  }
}

// Add a word to dynamic array
void addWord (char ***words, size_t *count, size_t *capacity, const char *word)
{
  if (*count >= *capacity)
  {
    *capacity = (*capacity == 0) ? 1024 : (*capacity * 2);
    *words = realloc (*words, (*capacity) * sizeof (char *));
    if (!*words)
    {
      fprintf (stderr, "! Memory allocation failed\n");

      exit (1);
    }
  }

  (*words)[(*count)++] = strdup (word); // duplicate token so it persists
}

int main (int argc, char *argv[])
{
  if (argc != 3)
  {
    fprintf (stdout, "> Usage: %s <filename> <groupSize>\n", argv[0]);

    return 1;
  }

  char *filename = argv[1];

  int groupSize = atoi (argv[2]);
  if (groupSize <= 0)
  {
    fprintf (stderr, "! groupSize must be > 0\n");

    return 1;
  }

  FILE *file = fopen (filename, "r");
  if (!file)
  {
    fprintf (stderr, "! fopen() failed: %s\n", strerror (errno));

    return 1;
  }

  char line[LINE_BUFFER];
  char **words = NULL;
  size_t wordCount = 0, wordCapacity = 0;

  while (fgets (line, sizeof (line), file))
  {
    line[strcspn (line, "\r\n")] = '\0';  // strip newlines only

    // Tokenize line on spaces/tabs
    char *token = strtok (line, " \t");
    while (token)
    {
      addWord (&words, &wordCount, &wordCapacity, token);

      token = strtok (NULL, " \t");
    }
  }

  fclose (file);

  // Print n-grams
  printGroups (words, wordCount, groupSize);

  // Free allocated memory
  for (size_t i = 0; i < wordCount; i++) free (words[i]);
  free (words);

  return 0;
}
