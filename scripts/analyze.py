import sqlite3
import sys
import logging
from collections import deque
import re

def getCallee(cursor, caller, callmap):
	'''
	This function gets all the functions called by the caller, and record the level of the functions
	'''
	cursor.execute('SELECT c.Caller, c.Callee, f.File FROM functions AS f INNER JOIN calls AS c ON f.Id = c.Caller WHERE Caller = ?', (caller,))
	calleelist = []
	for callee in cursor.fetchall():	# all the functions called by the caller
		calleelist.append(callee[1])	# callee[1] is the function ID of the callee function
	if caller not in callmap:
		callmap[caller] = calleelist
	return calleelist

def check_callmap(cursor, callmap, to_print):
	"""
	If to_print, we print the callmap
	"""
	pattern = re.compile("security_")	# All LSM hooks must start with "security_"
	hooks = []
	for caller in callmap:
		callername = cursor.execute('SELECT f.Name FROM functions AS f WHERE Id = ?', (str(caller),)).fetchone()[0]	# ID should be unique
		if pattern.match(callername) is not None:
			hooks.append(callername)
		for callee in callmap[caller]:
			calleename = cursor.execute('SELECT f.Name FROM functions AS f WHERE Id = ?', (str(callee),)).fetchone()[0]
			if pattern.match(calleename) is not None:
				hooks.append(calleename)
			if to_print:
				callees += str(calleename) + ', '
		if to_print:
			print(callername + ": " + callees)
	return hooks

if __name__ == "__main__":
	if len(sys.argv) < 4:
		print(
			"""
			Usage: python analyze.py <database_file_path> <root_caller_ID_file_path> <output_file_path>
			"""
		)
		exit(1)

	logging.basicConfig(filename='error.log',level=logging.DEBUG)

	# Connect to the database and get a cursor.
	conn = sqlite3.connect(sys.argv[1])
	c = conn.cursor()
	output = open(sys.argv[3], "w+")

	with open(sys.argv[2]) as f:
		for line in f:	# Each line should contain a system call name and the entry point ID.
			fields = line.split()
			syscallname = fields[0]
			callerID = fields[1]
			caller2callee = {}	# Maps a caller function (ID) to its callee functions (IDs).

			queue = deque([callerID])	# starting from the root caller

			while len(queue) > 0:
				caller = queue.popleft()
				callees = getCallee(c, caller, caller2callee)
				for callee in callees:
					if callee not in caller2callee and callee not in queue:	# We have not checked this function as a caller yet nor will check later
						queue.append(callee)

			security_hooks = check_callmap(c, caller2callee, False)	# LSM hooks called by the system call
			security_hooks = set(security_hooks)
			output.write(syscallname + "\t" + str(security_hooks) + "\n")

	f.close()
	output.close()
	conn.close()	# Done. Close the database
