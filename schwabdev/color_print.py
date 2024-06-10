"""
This file is used to print colored text
Github: https://github.com/tylerebowers/Schwab-API-Python
"""
import sys
OutFile = sys.stderr
Colors = True
if Colors :


	def info(string, end="\n"):
		print(f"\033[92m{'[INFO]: '}\033[00m{string}", end=end, file=OutFile)
		OutFile.flush()


	def warning(string, end="\n"):
		print(f"\033[93m{'[WARN]: '}\033[00m{string}", end=end, file=OutFile)
		OutFile.flush()


	def error(string, end="\n"):
		print(f"\033[91m{'[ERROR]: '}\033[00m{string}", end=end, file=OutFile)
		OutFile.flush()


	def user(string, end="\n"):
		print(f"\033[94m{'[USER]: '}\033[00m{string}", end=end, file=OutFile)
		OutFile.flush()


	def user_input(string, end=""):
		print(f"\033[94m{'[INPUT]: '}\033[00m{string}", end=end, file=OutFile)
		OutFile.flush()
		return input()


else:


	def info(string, end="\n"):
		print(f"[INFO]: {string}", end=end, file=OutFile)
		OutFile.flush()

	def warning(string, end="\n"):
		print(f"[WARN]: {string}", end=end, file=OutFile)
		OutFile.flush()

	def error(string, end="\n"):
		print(f"[ERROR]: {string}", end=end, file=OutFile)
		OutFile.flush()

	def user(string, end="\n"):
		print(f"[USER]: {string}", end=end, file=OutFile)
		OutFile.flush()

	def user_input(string, end=""):
		print(f"[INPUT]: {string}", end=end, file=OutFile)
		OutFile.flush()
		return input()
