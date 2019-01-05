# Author: Xueyuan Han <hanx@g.harvard.edu>
# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

import sqlite3
import sys

def getID(name, cursor):
	'''
	This function gets the ID of the give function `name` in system call database.

	@param name The name of the function
	@param cursor The cursor that traverses through the SQLite database
	@return None or the ID (as a one-element list) of the system call in the database
	'''
	cursor.execute('SELECT f.Id FROM functions AS f WHERE Name = ?', (name,))
	ids = []
	for fid in cursor.fetchall():
		ids.append(fid[0])
	if len(ids) != 1:
		print "Error in function name: " + name
		return None
	else:
		return ids

if __name__ == "__main__":
	if len(sys.argv) < 4:
		print '''
			usage: python syscall.py <database_file_path> <syscall_list_file_path> <output_file_path>
			'''
		exit(1)
	output = open(sys.argv[3], "w+")
	conn = sqlite3.connect(sys.argv[1])
	c = conn.cursor()
	with open(sys.argv[2], 'r') as f:
		for line in f:
			funcname = line.strip()
			print "FuncName: " + funcname
			id = str(getID(funcname, c)[0])
			print "ID: " + id
			outline = funcname + '\t' + id + '\n'
			output.write(outline)
	f.close()
	output.close()
	conn.close()
