#!/usr/bin/python3

from shared import *
import sys, os, argparse
from subprocess import check_output

# ASCII art from: http://www.patorjk.com/software/taag/#p=display&f=Big&t=OpenVPN-Review
title="\n\
   ____               __      _______  _   _        _____            _               \n\
  / __ \              \ \    / /  __ \| \ | |      |  __ \          (_)              \n\
 | |  | |_ __   ___ _ _\ \  / /| |__) |  \| |______| |__) |_____   ___  _____      __\n\
 | |  | | '_ \ / _ \ '_ \ \/ / |  ___/| . ` |______|  _  // _ \ \ / / |/ _ \ \ /\ / /\n\
 | |__| | |_) |  __/ | | \  /  | |    | |\  |      | | \ \  __/\ V /| |  __/\ V  V / \n\
  \____/| .__/ \___|_| |_|\/   |_|    |_| \_|      |_|  \_\___| \_/ |_|\___| \_/\_/  \n\
        | |                                                                          \n\
        |_|                                                                          \n\
\n\
OpenVPN-Review v0.1\t\t\t\tsecurai.de"

github="https://github.com/securai/openvpn-review"

desc="\n\n\
This is a tool to evaluate the security of an OpenVPN Community configuration file.\n\
It is mainly intended for server configuration files, but client configuration files may also be evaluated.\n\
\n\
The grade(s) should not be interpreted as an absolute proof for security, more as a guideline for possible improvement.\n\
Please report any encountered bugs, suggestions or critique by opening an issue on "+str(github)+".\
\n\
If you come across any unknown data- and/or control-channel cipher(suites) or hashing functions, file an issue on "+str(github)+" for them to be implemented in near future.\n\
\n\
"

def main():

	default_config= "/etc/openvpn/server/server.conf"

	parser = argparse.ArgumentParser(description=title+desc,formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-c", "--config", help="The OpenVPN configuration file (default "+str(default_config)+")", default=default_config, type=check_file_arg)
	parser.add_argument("-s", "--server", help="Flag to define that the script is running on the OpenVPN server. The default tls-cipher for the server can only be identified on the server itself.\nIf the script is executed on a differnt system and this flag is set, the results may be distorted.\nIf the default tls-cipher is configured and the script is not executed on the server, the results will be incomplete.", action='store_true')
	parser.add_argument("-m", "--mbedtls", help="Flag to define that mbedTLS is used for OpenVPN.", action='store_true')
	parser.add_argument("-v", "--verbose", help="Verbose mode", action='store_true')
	parser.add_argument("-vv", "--veryverbose", help="Very verbose mode", action='store_true')

	args = parser.parse_args()
	c = args.config
	s = args.server
	m = args.mbedtls
	v = args.verbose
	vv = args.veryverbose

	# approach to get the default tls-cipher
	if s:
		if not m:
			try:
				openssl_out = check_output(['openssl', 'ciphers', 'DEFAULT:!EXP:!LOW:!MEDIUM:!kDH:!kECDH:!DSS:!PSK:!SRP:!kRSA'])
				default_tls_cipher = openssl_out.decode("utf-8").rstrip()
			except FileNotFoundError:
				printRed("OpenSSL not found on this system.")
				default_tls_cipher = "DEFAULT_UNKNOWN"
		else:
			printYellow("mbedTLS not supported yet.")
			default_tls_cipher = "DEFAULT_UNKNOWN"
	else:
		default_tls_cipher = "DEFAULT_UNKNOWN"


	# options with their defaults
	security_options={"secret":False,
					"auth":"SHA1",
					"cipher":"BF-CBC",
					"tls-cipher":default_tls_cipher,
					"prng":"SHA1",
					"tls-auth":False,
					"tls-version-min":"1.0",
					"tls-version-max":"1.2",
					"no-replay":False,
					"no-iv":False,
					"key-method":"2",
					"ncp-ciphers":False,
					"ncp-disable":False,
					"tls-crypt":False,
					"key-direction":False}
	other_options={"script-security":False,
					"up":False,
					"tls-verify":False,
					"ipchange":False,
					"client-connect":False,
					"route-up":False,
					"route-pre-down":False,
					"client-disconnect":False,
					"down":False,
					"learn-address":False,
					"auth-user-pass-verify":False,
					"plugin":False,
					"push":False,
					"client-to-client":False,
					"pull-filter":False,
					"push-remove":False,
					"push-reset":False}

	# option descriptions
	options_info={
				"secret":"Enables the static key encryption mode (non-TLS), for the data channel encryption, with the use of pre-shared secret keys.",
				"auth":"Authenticate data channel packets and (if enabled) tls-auth control channel packets with HMAC using the configured message digest algorithm. Note: This is ignored for the data channel with an AEAD cipher mode (e.g. GCM).",
				"prng":"For PRNG (Pseudo-random number generator), use the configured digest algorithm.",
				"cipher":"Encrypt data channel packets with the configured cipher algorithm",
				"tls-cipher":"A list of allowable TLS ciphers delimited by a colon (\":\"), used to encrypt the control channel.",
				"tls-auth":"Adds an additional layer of HMAC authentication on top of the TLS control channel to mitigate DoS attacks and attacks on the TLS stack.",
				"tls-version-min":"Sets the minimum TLS version we will accept from the peer.",
				"tls-version-max":"Set the maximum TLS version we will use.",
				"no-replay":"Disables OpenVPN's protection against replay attacks. Don't use this option unless you are prepared to make a tradeoff of greater efficiency in exchange for less security.",
				"no-iv":"Disable OpenVPN's use of IV (cipher initialization vector)",
				"key-method":"Use data channel key negotiation method m. The key method must match on both sides of the connection.",
				"client-to-client":"Internally route client-to-client traffic rather than pushing all client-originating traffic to the TUN/TAP interface, allowing clients see the other clients which are currently connected",
				"script-security":"This directive offers policy-level control over OpenVPN's usage of external programs and scripts.\n\t  0 -- Strictly no calling of external programs.\n\t  1 -- (Default) Only call built-in executables such as ifconfig, ip, route, or netsh.\n\t  2 -- Allow calling of built-in executables and user-defined scripts.\n\t  3 -- Allow passwords to be passed to scripts via environmental variables (potentially unsafe).",
				"up":"Executes a script after TCP/UDP socket bind and TUN/TAP open.",
				"tls-verify":"Executes a script when we have a still untrusted remote peer.",
				"ipchange":"Executes a script after connection authentication, or remote IP address change.",
				"client-connect":"Executes a script in --mode server mode immediately after client authentication.",
				"route-up":"Executes a script after connection authentication, either immediately after, or some number of seconds after as defined by the --route-delay option.",
				"route-pre-down":"Executes a script right before the routes are removed.",
			 	"client-disconnect":"Executes a script in --mode server mode on client instance shutdown.",
				"down":"Executes a script after TCP/UDP and TUN/TAP close.",
				"key-direction":"The optional direction parameter for the --tls-auth and --secret options.",
				"learn-address":"Executes a script in --mode server mode whenever an IPv4 address/route or MAC address is added to OpenVPN's internal routing table.",
				"auth-user-pass-verify":"Executes a script in --mode server mode on new client connections, when the client is still untrusted.",
				"plugin":"Loads one or multiple third-party plug-in module(s) in OpenVPN.",
				"push":"Push a config file option back to the client for remote execution. The client must specify --pull in its config file.",
				"pull-filter":"Filter options received from the server if the option starts with text. Runs on client. The action flag accept allows the option, ignore removes it and reject flags an error and triggers a SIGUSR1 restart.",
				"push-remove":"selectively remove all --push options matching \"opt\" from the option list for a client. \"opt\" is matched as a substring against the whole option string to-be-pushed to the client",
				"push-reset":"Don't inherit the global push list for a specific client instance. Specify this option in a client-specific context such as with a --client-config-dir configuration file. This option will ignore --push options at the global config file level.",
				"ncp-ciphers":"Restrict the allowed ciphers to be negotiated to the ciphers in cipher_list. cipher_list is a colon-separated list of ciphers, and defaults to \"AES-256-GCM:AES-128-GCM\"",
				"tls-crypt":"Encrypt and authenticate all control channel packets with the key from keyfile. (See --tls-auth for more background.)"}


	# options that should be set in tls mode
	opts_should_use=["tls-auth","tls-crypt"]

	# options and suggestions for improvement
	options_suggest={
				"secret":"Disable static key mode and enable TLS mode.",
				"auth":"Use a stronger digest algorithm for the data channel packet authentication (e.g. SHA512)",
				"prng":"Use a stronger digest algorithm for the PRNG (e.g. SHA512)",
				"cipher":"Use a strong data channel encryption  cipher/mode (e.g. AES-256-GCM)",
				"tls-cipher":"Use a stronger control channel encryption ciphersuite (e.g. TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384)",
				"tls-version-min":"Set the min TLS version to 1.2 or \'or-highest\' if possible",
				"tls-version-max":"Set the max TLS version to 1.2 if possible or omit the option, as the default option is the highest version supported",
				"no-replay":"Do not configure this option, to OpenVPN's protection against replay attacks.",
				"no-iv":"Do not configure this option, to enable OpenVPN's use of IV (cipher initialization vector)",
				"key-method":"Use key method 2, the default starting with OpenVPN 2.0",
				"tls-crypt":"Enable tls-crypt for additional security and privacy.",
				"tls-auth":"Enable tls-auth for an additional layer of HMAC authentication on top of the TLS control channel to mitigate DoS attacks and attacks on the TLS stack"}
	
	# options specific to the tls mode - redundant in static key mode
	tls_options = ["tls-cipher", "tls-auth", "tls-version-min", "tls-version-max", "tls-crypt"]
	alt_keydir_opt = False

	deprecated_opts = ["key-method","no-iv"]

	# possible inline options are:
	# --ca, --cert, --dh, --extra-certs, --key, --pkcs12, --secret, --crl-verify, --http-proxy-user-pass, --tls-auth and --tls-crypt
	inline_opts = ["secret", "tls-auth", "tls-crypt"]

	grades={
	"secret":{
		"1":0,
		"0":0,
		True:3},
	"tls-auth":{
		"1":0,
		"0":0,
		True:1,
		False:3},
	"tls-version-min":{
		"or-highest":0,
		"1.2":0,
		"1.1":1,
		"1.0":2},
	"tls-version-max":{
		"1.2":0,
		"1.1":2,
		"1.0":3},
	"no-replay":{
		False:0,
		True:3},
	"no-iv":{
		False:0,
		True:3},
	"key-method":{
		"2":0,
		"1":3},
	"client-to-client":{
		False:0,
		True:3},
	"tls-crypt":{
		True:0,
		False:3},
	"key-direction":{
		"0":0,
		"1":0,
		False:3}
	}

	try:
		if v or vv:
			print("\nParsing configuration file:\n\
  s = (security) relevant option\n\
  i = possibly interesting option\n\
  . = ingored option/line in the configuration file\n")

		# Open config file and parse each line
		with open(c, "r") as fo:
			for line in fo:

				# line clean-up
				if line.startswith("#") or line.startswith(";") or len(line.rstrip()) == 0:
					continue
				clear_line = line.lstrip().rstrip('\n')
				clear_line = clear_line.split("#",1)[0].rstrip()
				clear_line = clear_line.split(";",1)[0].rstrip()

				# Define the current option
				cur_opt=clear_line.split(' ', 1)[0].lower()

				# Check if the line has a value, or if it is just a flag-like option
				# if it has a parameter assign the current value to it, else define it as true
				try:
					cur_val = clear_line.split(' ', 1)[1]
				except IndexError:
					cur_val = True

				if cur_opt in security_options.keys():

					# secret and tls-auth key direction can be 0, 1 or omitted
					# 0 or 1 define a unidirectional key usage, whereas none defined a bidirectional key usage
					if cur_opt == "secret":
						try:
							print(clear_line.split(' ', 2)[2])
							cur_val=clear_line.split(' ', 2)[2]
						except IndexError:
							cur_val=True

						# if secret is provided, static key mode is used.
						# options tls-server, server, tls-cipher, tls-auth, tls-version-min, tls-version-max
						# are theroretically not possible
						for rem_opt in tls_options:
							del security_options[rem_opt]
					
					elif cur_opt == "tls-auth":				
						try:
							cur_val=clear_line.split(' ', 2)[2]
						except IndexError:
							cur_val=True

					elif cur_opt == "key-direction":
						# alternative way of specifying the key direction for secret/tls-auth
						# may be falsely set in the security_options for secret/tls-auth
						# thus a bool is set here to make sure key direction is correctly registered
						alt_keydir_opt = True
						alt_keydir = cur_val

					elif cur_opt == "tls-crypt":
						try:
							clear_line.split(' ', 2)[1]							
						except IndexError:
							printRed("Missing keyfile for tls-crypt.")
							exit(1)
						else:
							cur_val = True

					# Add the option and value pair to the security options dictionary
					if type(cur_val) != False:
						if not type(cur_val) == bool:
							security_options[cur_opt]=str(cur_val)
						else:
							security_options[cur_opt]=cur_val
					if v or vv:
						sys.stdout.write('s')
						sys.stdout.flush()

				# ["secret", "tls-auth", "tls-crypt"]
				elif cur_opt.strip('<>') in inline_opts:

					cur_opt = cur_opt.strip('<>')
					security_options[cur_opt]=True
					
					if v or vv:
						sys.stdout.write('s')
						sys.stdout.flush()

				elif cur_opt in other_options.keys():
					other_options[cur_opt]=cur_val
					if v or vv:
						sys.stdout.write('i')
						sys.stdout.flush()
				elif v or vv:
					# Verbose mode: print omitted options with a dot
					sys.stdout.write('.')
					sys.stdout.flush()

			# if static key mode is not enabled, remove it from the dict
			if not security_options["secret"]:
				del security_options["secret"]
				if alt_keydir_opt:
					security_options["tls-auth"] = alt_keydir
			elif alt_keydir_opt:
				security_options["secret"] = alt_keydir

			if security_options["ncp-ciphers"] and not security_options["ncp-disable"]:
				del security_options["cipher"]
			elif  security_options["ncp-ciphers"] and security_options["ncp-disable"]:
				printRed("Both ncp-ciphers and ncp-disable options are enabled. This is invalid.")
				exit(1)
			else:
				del security_options["ncp-ciphers"]

			if v or vv:
				print('\nDone.\n')

		# GRADING:		
		total_secg = 0
		total_allg = 0

		rating_msg = ""

		cur_grade = 0

		sec_opts_rated = 0

		final_sec_grade = 0

		is_sec_cap = False
		sec_cap = 0
		sec_cap_culprit = ""
		
		suggest=""

		print()
		

		for cur_opt in sorted(security_options.keys()):
			#tls-cipher gets special treatment here, because it could be configured as a list of ciphers.
			if cur_opt == "tls-cipher":
				cur_grade =	rate_tls_cipher(security_options[cur_opt],v,vv)
			
				if vv:
					print("\t  "+options_info[cur_opt])
				# dont consider default false options (e.g. no-iv)
			elif cur_opt == "cipher" or cur_opt == "ncp-ciphers":
				cur_grade =	rate_cipher(security_options[cur_opt],cur_opt,v,vv)
				if vv:
					print("\t  "+options_info[cur_opt])
			elif cur_opt == "auth":
				cur_grade = rate_digest(security_options[cur_opt],cur_opt,"auth",v,vv)
				if vv:
					print("\t  "+options_info[cur_opt])
			elif cur_opt == "prng":
				cur_grade = rate_digest(security_options[cur_opt],cur_opt,"prng",v,vv)
				if vv:
					print("\t  "+options_info[cur_opt])
			elif cur_opt == "ncp-disable":
				continue
			elif security_options[cur_opt]:
				try:
					cur_grade = grades[cur_opt][security_options[cur_opt]]
				except KeyError as e:
						printRed("\nERROR: Unrecognised parameter "+str(e)+" for option \'"+str(cur_opt)+"\'")
						exit(1)
				rating_msg = "\t"+get_letter_grade(cur_grade)+"\t"+cur_opt + ": " + str(security_options[cur_opt])
				printGraded(rating_msg, cur_grade)
				if cur_opt == "secret":
					printRed("\t\t! Static key encryption mode is not recommended. Please consider the TLS mode.")
				if vv:
					print("\t  "+str(options_info[cur_opt]))		
			elif cur_opt in opts_should_use and (v or vv) and not options_suggest[cur_opt] in suggest:
				suggest+="\n\t"+str(options_suggest[cur_opt])
			else:
				continue

			if cur_opt in deprecated_opts:
				printYellow("\t\tThis option is marked as deprecated and will be removed in future releases of OpenVPN.")
			if cur_grade >= sec_cap and cur_opt != "tls-crypt":
				sec_cap = cur_grade
				sec_cap_culprit = cur_opt+": "+str(security_options[cur_opt])
			if (v or vv) and cur_opt in options_suggest.keys() and cur_grade > 1 and not options_suggest[cur_opt] in suggest:
				suggest+="\n\t"+str(options_suggest[cur_opt])

			sec_opts_rated += 1
			total_secg += cur_grade

		final_sec_grade = total_secg/(sec_opts_rated*3)

		capped_final_sec_grade = final_sec_grade

		if final_sec_grade < sec_cap:
			capped_final_sec_grade = sec_cap
			is_sec_cap = True

		printGraded("\n\tRating:\t"+get_letter_grade(capped_final_sec_grade),capped_final_sec_grade)
		
		if v  or vv:
			printGraded("\n\tGrade capped to \'"+get_letter_grade(sec_cap)+"\' by "+str(sec_cap_culprit), sec_cap)

		info_banner_printed = False
		for cur_opt in other_options.keys():
			if other_options[cur_opt]:
				if not info_banner_printed:
					print("\n\t______________________\n\tAdditional information\n")
					info_banner_printed = True

					# inform the user if tls-auth and tls-crypt are both enabled
					if not security_options["tls-auth"] and not security_options["tls-crypt"]:
						rating_msg = "\tI\ttls-auth and tls-crypt are mutually exclusive"
						printGraded(rating_msg, "info")	

				rating_msg = "\tI\t"+cur_opt + ": " + str(other_options[cur_opt])
				printGraded(rating_msg, "info")
				if vv:
					print("\t  "+str(options_info[cur_opt]))

		if suggest:
			printBlue("\n\tRefer to the OpenVPN manual for further details: https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage")
			printBlue(suggest)

		exit(0)

	# Expect the user to interrupt the program with the keyboard (CTRL+c) and try to exit gracefully
	except KeyboardInterrupt:
		print("\nRegistered user interrupt//CTRL+c\nbye.")
		exit(0)

if __name__ == "__main__":
	main()