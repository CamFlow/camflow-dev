import sys

no_lsm_syscalls = []	# syscalls with no LSM hooks
syscall_num_lsm_map = {}	# syscalls -> number of LSM hooks
lsm_stats = {}	# number of LSM hooks -> number of syscalls with that number of LSM hooks
weightedAPI = []	# the order of the system calls signifies the weighted importance of the system calls
unweightedAPI = []	# the order of the system calls signifies the unweighted importance of the system calls

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print '''
			usage: python stats.py <syshooks_file_path> <output_file_path>
			'''
		exit(1)

	with open(sys.argv[1], 'r') as f:
		for line in f:
			fields = line.split('\t')
			syscall = fields[0]
			lsm_list = fields[1]
			lsm_list = lsm_list.translate(None, '[]')
			lsm_list = lsm_list.translate(None, ' ')
			hooks = lsm_list.strip().split(',')
			if '' in hooks:
				hooks.remove('')
			hooks = list(set(hooks))
			print hooks
			if len(hooks) == 0:
				no_lsm_syscalls.append(syscall)
			else:
				syscall_num_lsm_map[syscall] = len(hooks)
				if len(hooks) not in lsm_stats:
					lsm_stats[len(hooks)] = 1
				else:
					lsm_stats[len(hooks)] = lsm_stats[len(hooks)] + 1
	f.close()

	skip_first_line = 0
	with open("weightAPI.txt", "r") as f:
		for line in f:
			if skip_first_line == 0:
				skip_first_line += 1
			else:
				fields = line.split("(")
				weightedAPI.append(fields[0])
	f.close()

	skip_first_line = 0
	with open("unweightAPI.txt", "r") as f:
		for line in f:
			if skip_first_line == 0:
				skip_first_line += 1
			else:
				fields = line.split("(")
				unweightedAPI.append(fields[0])
	f.close()

	with open(sys.argv[2], "w+") as f:
		f.write("# LSM statistics\n")
		f.write("Total number of system calls that trigger no LSM hooks: " + str(len(no_lsm_syscalls)) + "\n\n")
		f.write("Those system calls are:\n\n")
		for syscall in no_lsm_syscalls:
			f.write("\t" + syscall + "\n\n")
		f.write("## Statistics of System Calls That Trigger LSM Hooks\n")
		f.write("SYSTEM CALL NAME | NUMBER OF HOOKS CALLED |\n")
		f.write("-----------------|------------------------|\n")
		for syscall in syscall_num_lsm_map:
			f.write(syscall + '|' + str(syscall_num_lsm_map[syscall]) + '|\n')
		f.write("\n\n")
		f.write("## Statistics of Number of LSM Hooks Triggered by System Calls\n")
		f.write("NUMBER OF HOOKS CALLED | NUMBER OF SYSTEM CALLS |\n")
		f.write("-----------------------|------------------------|\n")
		for num in lsm_stats:
			f.write(str(num) + '|' + str(lsm_stats[num]) + '|\n')
		f.write("\n\n")
		f.write("## Statistics of System Calls Arranged by Weighted API Importance\n")
		f.write("WEIGHTED API CALL (MOST TO LEAST IMPORTANT) | NUMBER OF HOOKS CALLED |\n")
		f.write("--------------------------------------------|------------------------|\n")
		for wsyscall in weightedAPI:
			sys_syscall = "__x64_sys_" + wsyscall
			print sys_syscall
			if sys_syscall in syscall_num_lsm_map:
				f.write(wsyscall + '|' + str(syscall_num_lsm_map[sys_syscall]) + '|\n')
			else:
				f.write(wsyscall + '|' + "N/A" + '|\n')
		f.write("\n\n")
		f.write("## Statistics of System Calls Arranged by Unweighted API Importance\n")
		f.write("UNWEIGHTED API CALL (MOST TO LEAST IMPORTANT) | NUMBER OF HOOKS CALLED |\n")
		f.write("----------------------------------------------|------------------------|\n")
		for wsyscall in unweightedAPI:
			sys_syscall = "__x64_sys_" + wsyscall
			if sys_syscall in syscall_num_lsm_map:
				f.write(wsyscall + '|' + str(syscall_num_lsm_map[sys_syscall]) + '|\n')
			else:
				f.write(wsyscall + '|' + "N/A" + '|\n')
	f.close()
