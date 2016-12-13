# -*- coding: utf-8 -*-
# @Author: detailyang
# @Date:   2016-12-13 17:47:41
# @Last Modified by:   detailyang
# @Last Modified time: 2016-12-13 17:54:10


import sys

from readelf import readelf

def entry():
	if len(sys.argv) != 2:
		print("Usage: readelf /path/to/file")
		sys.exit(1)

	with open(sys.argv[1], 'r') as elf:
		readelf(elf)
