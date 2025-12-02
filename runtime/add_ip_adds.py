import sys
import glob

# This script edits all main_party_numxx.sh and main_worker_numxx.sh scripts
# setting the ip addresses to the input list

ip_addresses 	= sys.argv[1]
shell_scripts 	= glob.glob("./*.sh")
detect_str 		= 'main_'
# man_str 		= 'run_manager'

for script in shell_scripts:
	if detect_str in script:
		with open(script) as f:
			lines = f.readlines()
			line_ind = 0
			for line in lines:
				if 'secure' in line:
					secure_ind 	= line.index('secure')
					replacement_str = line[:secure_ind+9] + " '" + ip_addresses + "'\n"#+ line[secure_ind+9:]
					if 'nonsecure' in line:
						replacement_str = replacement_str.replace("nonsecure", "secure")
					lines[line_ind] = replacement_str
					print(replacement_str)
				# elif 'nonsecure' in line:
				# 	line.replace("nonsecure", "secure")
				line_ind += 1
			f.close()

		with open(script, 'w') as f:
			f.writelines(lines)
			f.close()


