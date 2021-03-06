#!/usr/bin/python3
# You may redistribute this program and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import print_function
import sys
import os
from cjdnsadmin import cjdnsadmin
import json
import getopt
import string

def usage():
  """ print usage information """

  print("""
Cjdns admin command line interface.
Usage: [OPTION]... RPC
  RPC              the function name w/ arguments of the RPC you want to make.

options:
  -c  --config=    the cjdnsadmin file to use.  Defaults to ~/.cjdnsadmin
  -h, --help       display this help and exit
  -p, --pretty     format the output of the RPC as formatted JSON

Example:
  'functions()'    Prints the list of functions available.
""")


def parse(args):
  """ parse the command line arguments """

  try:
    return getopt.getopt(args, 'phc:', ['pretty','help','config='])
  except getopt.GetoptError:
    usage()
    sys.exit(2)

def main(argv):
  options, remainder = parse(argv)
  transform = lambda s: s
  connect = lambda : cjdnsadmin.connectWithAdminInfo()

  for opt, arg in options:
    if opt in ('-c', '--config'):
      connect = lambda :  cjdnsadmin.connectWithAdminInfo(arg)
    elif opt in ('-h', '--help'):
      usage()
      sys.exit(0)
    elif opt in ('-p', '--pretty'):
      transform = lambda s: json.dumps(s, sort_keys=True, indent=4, separators=(',', ': '))

  if remainder:
    try:
      s = connect()
    except FileNotFoundError: sys.exit(1)
    result = eval('s.' + ''.join(remainder))
    if result:
      print(transform(result))
  else:
    usage()
  return 0

if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
