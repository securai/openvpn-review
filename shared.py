import os, argparse

# TODO: Support for --keysize n

# Check if the given file is a file and is readable
def check_file_arg(s):
	msg=""
	if os.path.isfile(s):
		if os.access(s, os.R_OK):
			return s
		else:
			msg = "\'"+s+"\' is not readable."
			# Let the user know who owns the file, if it's not readable
			owner = getpwuid(os.stat(s).st_uid).pw_name
			msg += "\nHint: The file is owned by \""+str(owner)+"\"."
			raise argparse.ArgumentTypeError(msg)
	else:
		msg = "\'"+s+"\' doesn\'t exist"
		raise argparse.ArgumentTypeError(msg)

# Colored printing
def printGreen(prt): print("\033[92m{}\033[00m" .format(prt))
def printBoldGreen(prt): print("\033[1m\033[92m{}\033[00m" .format(prt))
def printBoldGreenwUnderline(prt): print("\033[1m\033[4m\033[92m{}\033[00m" .format(prt))
def printYellow(prt): print("\033[93m{}\033[00m" .format(prt))
def printRed(prt): print("\033[91m{}\033[00m" .format(prt))
def printBoldRed(prt): print("\033[1m\033[91m{}\033[00m" .format(prt))
def printBoldRedwUnderline(prt): print("\033[1m\033[4m\033[91m{}\033[00m" .format(prt))
def printBlue(prt): print("\033[94m{}\033[00m" .format(prt))
def printMagenta(prt): print("\033[95m{}\033[00m" .format(prt))

# Print colored according to grade
def printGraded(text, grade):

	t = type(grade)

	if t == str:
		if grade == "crit":
			printRed(text)
		elif grade == "info":
			printBlue(text)
		else:
			printMagenta(text)
	elif t == int or t == float:
		if grade <= 0.25:
			printBoldGreenwUnderline(text)
		elif grade <= 0.5:
			printBoldGreen(text)
		elif grade <= 1:
			printGreen(text)
		elif grade <= 1.5:
			printYellow(text)
		elif grade <= 2:
			printRed(text)
		elif grade <= 2.5:
			printBoldRed(text)
		elif grade <= 3:
			printBoldRedwUnderline(text)
		else:
			printMagenta(text)
	else:
		printMagenta(text)

# Get letter grade from numeric grade
def get_letter_grade(g):
	if g < 0.25:
		return "A+"
	elif g <= 0.5:
		return "A"
	elif g <= 1:
		return "B"
	elif g <= 1.5:
		return "C"
	elif g <= 2:
		return "D"
	elif g <= 2.5:
		return "E"
	elif g <= 3:
		return "F"
	else:
		# This should not happen, no matter what the user puts in the config file.
		printRed("ERROR: Internal error.")
		exit(2)

# --auth or --prng
def rate_digest(d,o,t,v,vv):
	# may be prepended by "RSA-", "DSA-" or "ecdsa-with-". Thanks OpenSSL

	# type may be auth or prng
	if t == "prng":
		ap_dig={"none":3,
			"MD4":3,
			"MD5":2.5,
			"RIPEMD160":2.5,
			"SHA":1,
			"SHA1":1,
			"SHA224":0.75,
			"SHA256":0.5,
			"SHA384":0.25,
			"SHA512":0,
			"whirlpool":0}
	else:
		ap_dig={"none":3,
			"MD4":3,
			"MD5":2.5,
			"RIPEMD160":2.5,
			"SHA":1.5,
			"SHA1":1.5,
			"SHA224":0.75,
			"SHA256":0.5,
			"SHA384":0.25,
			"SHA512":0,
			"whirlpool":0}

	try:
		if '-' in d:
			dig_grade = ap_dig[d.split('-')[-1]]
		else:
			dig_grade = ap_dig[d]
	except KeyError as ke:
		printGraded("\tUnknown digest: "+str(ke),3)
		return(3)

	rating_msg = "\t"+get_letter_grade(dig_grade)+"\t"+str(o)+": " + d

	printGraded(rating_msg,dig_grade)
	return(dig_grade)

# --tls-cipher (control channel)
def rate_tls_cipher(c,v,vv):


	if c == "DEFAULT_UNKNOWN":
		uknown_g = 3

		rating_msg = "\t"+get_letter_grade(uknown_g)+"\ttls-cipher: UNKNOWN"

		printGraded(rating_msg,uknown_g)
	
		return(uknown_g)

	# TLS-kex-sig-WITH-cipher-keysize-mode-digest
	# PSK https://tools.ietf.org/html/rfc4279
	tc_kex={"DHE":0.5,		# No EC
			"ECDH":1, 	# No PFS
			"ECDHE":0,		
			"RSA":1.5,		# No PFS
			"DH":1.5,
			# OPENVPN DOESN'T SUPPORT TLS PSK; But appears to be available with mbedTLS
				#"DHE-PSK":1,	# No EC 	
				#"ECDHE-PSK":0,  
				#"RSA-PSK":1.5, 	# No PFS
				#"PSK":3}		# No PFS && PSK only
			}
	tc_sig={"ECDSA":0,
			"RSA":0.5,
			"DSA":2,
			"DSS":2}
	tc_cip={"3DES-EDE":3,
			"AES128":1,
			"AES256":0,
			"CAMELLIA128":1,
			"CAMELLIA256":0}
	tc_mod={"GCM":0,
			"CCM":0.25,
			"CCM8":0.75,
			"CBC":0.5}
	nod_dig_mod = ["CCM", "CCM8"]
	tc_dig={"SHA":1.5,
			"SHA256":0.25,
			"SHA384":0}

	worst_grade = 0
	worst_element = ""
	worst_element_part = ""
	non_ec_dh = False

	for tls_cipher in c.split(':'):
		if "TLS" in tls_cipher or "WITH" in tls_cipher:
			tls_cipher = tls_cipher.replace('TLS-','').replace('WITH-','')

		tls_cipher_elements = tls_cipher.split('-')

		current_element = 0
		current_worst_grade = 0
		current_worst_part = ""

		# Defaults, mainly to handle implicit usage of KEX, SIG or MOD
		kex, kex_grade = ("RSA",tc_kex["RSA"])
		sig, sig_grade = ("RSA",tc_sig["RSA"])
		cip, cip_grade = ("UNKWON", 3)
		mod, mod_grade = ("CBC", tc_mod["CBC"])
		dig, dig_grade = ("UNKNWON", 3)

		try:
			# Key exchange
			no_kex = False
			if tls_cipher_elements[current_element] in tc_kex:
				kex=tls_cipher_elements[current_element]
				kex_grade=tc_kex[kex]
				current_element += 1
				if kex == "DH" or kex == "DHE":
					non_ec_dh = True
			else:
				no_kex=True

			# Signature
			no_sig = False
			if tls_cipher_elements[current_element] in tc_sig:
				sig=tls_cipher_elements[current_element]
				sig_grade=tc_sig[sig]
				current_element +=1
			else:
				no_sig = True

			# Cipher
			if tls_cipher_elements[current_element] in tc_cip:
				cip=tls_cipher_elements[current_element]
				cip_grade=tc_cip[cip]
				current_element +=1
			elif (len(tls_cipher_elements)-1) >= current_element+1 and tls_cipher_elements[current_element]+str(tls_cipher_elements[current_element+1]) in tc_cip:
				cip=tls_cipher_elements[current_element]+str(tls_cipher_elements[current_element+1])
				cip_grade=tc_cip[cip]
				current_element = current_element + 2
			else:
				if no_kex:
					printRed("\t  Unknown key exchange algorithm ("+str(tls_cipher)+")")
				if no_sig:
					printRed("\t  Unknown signature method ("+str(tls_cipher)+")")

				printRed("\t  Unknown cipher ("+str(tls_cipher)+")")
				cip_grade=3

			no_mod = False
			# Mode
			if tls_cipher_elements[current_element] in tc_mod:
				if (len(tls_cipher_elements)-1) >= current_element+1 and tls_cipher_elements[current_element+1].isdigit() and tls_cipher_elements[current_element]+tls_cipher_elements[current_element+1] in tc_mod:
					mod=tls_cipher_elements[current_element]+tls_cipher_elements[current_element+1]
					mod_grade=tc_mod[mod]
					current_element +=2
				else:
					mod=tls_cipher_elements[current_element]
					mod_grade=tc_mod[mod]
					current_element +=1
			else:
				no_mod = True

			# Digest and possibly an unknown mod or missing (ccm/ccm-8)
			if current_element >= len(tls_cipher_elements) and mod in nod_dig_mod:
				# With the TLS cipher suites, without hashing algorithm and ccm/ccm8, the TLS1.2 default hashing algorithm SHA256 is used.
				# https://tools.ietf.org/html/rfc6655
				dig = "SHA256"
				dig_grade = dig_grade=tc_dig[dig]
			elif tls_cipher_elements[current_element] in tc_dig:
				dig=tls_cipher_elements[current_element]
				dig_grade=tc_dig[dig]
				current_element +=1
			else:
				if no_mod:
					printRed("\t  Unknown mode of operation ("+str(tls_cipher)+")")
					mod = "UNKNOWN"
					mod_grade=3
					printRed("\t  Unknown digest algorithm ("+str(tls_cipher)+")")
					dig_grade=3
				else:
					printRed("\t  Unknown digest algorithm ("+str(tls_cipher)+")")
					dig_grade = 3

			if kex_grade >= current_worst_grade: current_worst_grade, current_worst_part = (kex_grade,kex) 
			if sig_grade >= current_worst_grade: current_worst_grade, current_worst_part = (sig_grade,sig)
			if cip_grade >= current_worst_grade: current_worst_grade, current_worst_part = (cip_grade,cip)
			if mod_grade >= current_worst_grade: current_worst_grade, current_worst_part = (mod_grade,mod)
			if dig_grade >= current_worst_grade: current_worst_grade, current_worst_part = (dig_grade,dig)

			current_grade = max(kex_grade,sig_grade,cip_grade,mod_grade,dig_grade)
			if current_grade >= worst_grade:
				worst_grade = current_grade
				worst_element = tls_cipher
				worst_element_part = current_worst_part

		except KeyError:
			printRed("\tUnknown TLS cipher suite: "+str(tls_cipher))
			exit(1)

		if v or vv:
			if current_worst_grade > 0:
				rating_msg = "\t"+get_letter_grade(current_worst_grade)+"\ttls-cipher: " + tls_cipher + " capped by "+current_worst_part
			else:
				rating_msg = "\t"+get_letter_grade(current_worst_grade)+"\ttls-cipher: " + tls_cipher
		else:
			rating_msg = "\t"+get_letter_grade(current_worst_grade)+"\ttls-cipher: " + tls_cipher

		if vv:
			rating_msg +="\n\t\tKey Exchange: "+str(kex)+", Signature: "+str(sig)+", Cipher: "+str(cip)+", Mode: "+str(mod)+", Hash: "+str(dig)
			
		if non_ec_dh:
			rating_msg += "\n\t\t  Verify that the DH parameter set is at least 2048 bit\n\t\t  (OpenVPN option --dh, file generated with `openssl dhparam -out dh2048.pem 2048`)"

		printGraded(rating_msg,current_worst_grade)
	
	return(worst_grade)

# --cipher (data channel)
def rate_cipher(c,o,v,vv):
	# cipher-keysize-mode
	c_cipher={"AES-128":1,
			"AES-192":0.5,
			"AES-256":0,
			"BF":2.5,
			"CAMELLIA-128":1,
			"CAMELLIA-192":0.5,
			"CAMELLIA-256":0,
			"CAST5":2.5,
			"DES":3,
			"DES-EDE":3,
			"DES-EDE3":3,
			"DESX":3,
			"RC2-40":3,
			"RC2-64":3,
			"RC2":3,
			"SEED":1.5,
			"none":3}

	c_mode={"CBC":0.5,
			"CFB":0.25,
			"CFB1":0.25,
			"CFB8":0.25,
			"GCM":0,
			"OFB":0.75,
			"none":3}

	# rate cipher-keysize-mode
	cs_cap_culprit=""
	cs_cap=0

	# for each ciphersuite in the (list)
	for cs in c.split(':'):
		cse = cs.split('-')

		
		# cipher-(keysize/ede)-mod
		try:
			if cse[0] == "none":
				cip="none"
				mod="none"
			elif len(cse) > 1 and (cse[1].isdigit() or cse[1].lower().startswith("ede")):
				cip=cse[0]+"-"+cse[1]
				mod=cse[2]
			else:
				cip=cse[0]
				mod=cse[1]
		except IndexError as ie:
			try:
				cip
			except NameError as ne:
				cip = "UNKNOWN"
			try:
				mod
			except NameError as ne:
				mod = "UNKNOWN"
			
			cip_g = 3

		try:
			cip_g = c_cipher[cip]
			if cip_g >= cs_cap: cs_cap,cs_cap_culprit = (cip_g,cs)
			mod_g = c_mode[mod]
			if mod_g >= cs_cap: cs_cap,cs_cap_culprit = (mod_g,cs)
		except KeyError as ke:
			print("\t  ",end='')
			printGraded("Unknown cipher: "+str(cs),3)
			cip_g = mod_g = cs_cap = 3
			cs_cap_culprit = cs

		cur_cs_grade = max(cip_g,mod_g)
		rating_msg = "\t"+get_letter_grade(cur_cs_grade)+"\t"+o+": " + cs

		printGraded(rating_msg,cur_cs_grade)

	return(cs_cap)

