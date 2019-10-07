#!/usr/bin/python

from distutils.core import setup
import sys

DESC = """Cjdns admin tools implemented in Python."""
with open("README.md", "r") as fh:
    LONG_DESC = fh.read()

setup(name='python-cjdns',
      version='0.1',
      description=DESC,
      long_description=LONG_DESC,
      long_description_content_type="text/markdown",
      author='Ilia Sidorenko',
      maintainer="Stuart D. Gathman",
      maintainer_email="stuart@gathman.org",
      url='https://github.com/cjdelisle/cjdns/',
      license='GPL3',
      packages=['cjdnsadmin'],
      keywords = ['cjdns','tools'],
      #scripts = [ 'pingAll.py', 'trashroutes', 'getLinks', 'ip6topk',
      #            'pktoip6', 'cjdnsa', 'searches', 'findnodes',
      #            'graphStats', 'drawgraph', 'dumpgraph'
      #            ],
      scripts = [ 'cexec', 'cjdnsa', 'cjdnsadminmaker.py', 'cjdnslog',
                  'drawgraph', 'dumpgraph', 'dumptable', 'dynamicEndpoints.py',
                  'findnodes', 'getLinks', 'graphStats', 'ip6topk', 'peerStats',
                  'pingAll.py', 'pktoip6', 'searches', 'sessionStats',
                  'trashroutes' ],
      classifiers = [
	'Development Status :: 4 - Production/Stable',
	'Environment :: Console',
	'Intended Audience :: Developers',
	'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
	'Natural Language :: English',
	'Operating System :: OS Independent',
	'Programming Language :: Python',
	'Programming Language :: Python :: 3',
	'Topic :: Communications',
	'Topic :: Internet',
	'Topic :: Software Development :: Libraries :: Python Modules'
      ]
)
