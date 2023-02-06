import subprocess

BASE_CONFIGS = [
	"CONFIG_BPF=y",
	"CONFIG_BPF_SYSCALL=y",
	"CONFIG_NET_CLS_BPF=m",
	"CONFIG_NET_ACT_BPF=m",
	"CONFIG_BPF_JIT=y",		
	#"CONFIG_HAVE_BPF_JIT=y",	# For Linux kernel versions 4.1 through 4.6
	"CONFIG_HAVE_EBPF_JIT=y",	# For Linux kernel versions 4.7 and later
	"CONFIG_BPF_EVENTS=y" 
]

ADDITIONAL_CONFIGS = [
	"CONFIG_NET_SCH_SFQ=m",
	"CONFIG_NET_ACT_POLICE=m",
	"CONFIG_NET_ACT_GACT=m",
	"CONFIG_DUMMY=m",
	"CONFIG_VXLAN=m"
]

def get_kernel_config_path():
	uname = subprocess.check_output(['uname', '-r'])[:-1] # last character of output is \n
	print('detected kernel release version '+uname)
	config_path = '/boot/config-' + uname
	return config_path

if __name__ == "__main__":
	config_path = get_kernel_config_path()
	print("kernel config path " + config_path)
	print("*******************************************")
	with open(config_path, 'r') as kernel_config:
		config_map = {}
		print("Will check for configs - ")
		for config in BASE_CONFIGS + ADDITIONAL_CONFIGS:
			config_map[config]=False
			print(config)
		print("*******************************************")

		for line in kernel_config.readlines():
			conf_string = line[:-1]	
			if conf_string in config_map:
				config_map[conf_string] = True

		count_not_found=0
		for config in config_map:
			if config_map[config] == True:
				print("FOUND " + config)
			else:
				print("NOT FOUND " + config)
				count_not_found = count_not_found + 1
		
		print("*******************************************")
		if count_not_found == 0:
			print("Found all configs")
		else:
			print("Not Found %d configs" % count_not_found)
