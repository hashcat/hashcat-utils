#!/usr/bin/env python

import sys
import re


for line in sys.stdin:
  if ':' in line:
    passw = line.split(':')[1].rstrip()
    if passw.startswith('$HEX['):
      hexpassw = re.search('\$HEX\[([a-zA-Z0-9]+)\]', passw).group(1)
      passw = bytearray.fromhex(hexpassw).decode('latin-1')
    if rep.startswith('u'):
      print(rep[2:][:-1])
    else:
      print(rep[1:][:-1])

