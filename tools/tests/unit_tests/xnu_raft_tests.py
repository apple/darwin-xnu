#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Python Imports
import os
import sys
import re

"""
xnu_raft_tests
Automate testing of unit tests for xnu.

2012/02/23
"""

# this needs to be first thing for raft to load its environment correctly
if __name__ == '__main__':
	# The following code allows this test to be invoked outside the harness and should be left unchanged
	args = [os.path.realpath(os.path.expanduser("/usr/local/bin/raft")), "-f"] + sys.argv
	os.execv(args[0], args)


# Library Imports
from raftlibs.coreos import crashReporterStop, crashReporterStart, doPrivileged, runFunctionWithTestReRun
from raftlibs.coreos import runUniversalLogProcess, spotlightStopSubtest, spotlightStartSubtest, svnCheckoutTestTool, svnCheckoutToPath, runSimpleProcess

from raft.core.logging import log_note

# Raft Imports
from __test__ import __path__

# This is a Raft test. For more information see http://raft.apple.com
testDescription  = "Runs all tests defined as targets in Makefile"                 # Add a brief description of test functionality
testVersion      = "0.1"              # Used to differentiate between results for different versions of the test
testState        = DevelopmentState   # Possible values: DevelopmentState, ProductionState


# class definitions
class xnuTest:
	""" A container to hold test and its result """
	def __init__(self,testName):
		self.name = str(testName)
		self.buildStatus = False
		self.executeStatus = False
		self.exitValue = None
		self.comments = ''

	def getName(self):
		return self.name
		
	@staticmethod
	def getSummaryHeader():
		return "| {0: ^40s} |{1: >6s} |{2: >5s} |{3: >10s} |{4}".format("Test Name", "Build", "Run", "ExitVal", "Comments")

	def getSummary(self):
		formatString ="| {0: <40s} |{1: >6s} |{2: >5s} |{3: >10s} |{4}"
		nameVal = str(self.name)
		buildVal = str(self.buildStatus)
		execVal = str(self.executeStatus)
		exitVal = str(self.exitValue)
		commentsVal = str(self.comments)
		return formatString.format(nameVal, buildVal, execVal, exitVal, commentsVal)

# global functions
def getTestsFromMakeFile(makeFilePath):
	makeTargets=[]
	targetRegex = re.compile("^\s*([a-zA-Z0-9_.]+)\s*:\s*([a-zA-Z0-9_.]*).*",re.IGNORECASE|re.DOTALL)
	fh = open(makeFilePath,"r");
	for line in fh:
		tmp_res = targetRegex.findall(line)
		if len(tmp_res) == 1:
			makeTargets.append(xnuTest(tmp_res[0][0]))
	fh.close()
	return makeTargets
	

def buildTest(test, path):
	os.chdir(path)
	result = doCommand("/usr/bin/make",test)
	if result['status'] != 0:
		print "Failed to Build %s" % test
		print "**STDOUT**\n%s" % result['stdout']
		print "**STDERR**\n%s" % result['stderr']
		raise StandardError
	log_note("Built %s successfully" % test)

def executeTest(testObject,path):
	os.chdir(path)
	test = testObject.getName()
	executable_path = os.path.join(path, test)
	print "[TEST] %s" % test
	print "[BEGIN] %s" % test
	try:
		result = runSimpleProcess(executable_path,testName()+"_"+test, wait_time=120)
		testObject.exitValue = result['status']
		if result['status'] == 0:
			print "[PASS] %s returned %d" % (test,result['status'])
	except:
		print "[FAIL] %s returned %d" % (test, result['status'])
		testObject.comments = "Failed due to timeout or file not found error"
	log_note("Completed running test %s" % test)

def removeTestExecutable(test,path):
	os.chdir(path)
	doCommand("/bin/rm",test)
	
def runTest(params):
	# Change to /tmp, because make doesn't support directory paths with spaces
	os.chdir("/private/tmp")	
	output= {'status': 1 }
	try:
		output = svnCheckoutTestTool("unit_tests")
	except:
		pass
	if output['status'] != 0 :
		# since we are not fully published yet. lets get data from a branch
		print "Fetching unit_test roots from Branch instead of trunk"
		baseURL = "http://src.apple.com/svn/xnu/branches/PR-10938974/tools/tests/unit_tests/"
		output = svnCheckoutToPath(baseURL)
		if output['status'] != 0 : 
			logFail("[FAIL] error in checkout from branch")
			sys.exit(1)
		
	local_path = os.path.join(os.getcwd(), "unit_tests")
	makefile_path = os.path.join(local_path, "Makefile")
	build_path = os.path.join(local_path, "BUILD")
	
	
	tests_to_run = getTestsFromMakeFile(makefile_path)
	log_note("Starting raft tests for XNU")
	stats = {"total":len(tests_to_run) , "pass":0, "fail":0}
	for testObject in tests_to_run:
		test = testObject.getName()
		if test == "clean":
			stats["pass"]+=1
			testObject.buildStatus = True
			testObject.executeStatus = True
			testObject.exitValue = 0
			continue

		log_note("Running test :%s" % test)
		try:
			buildTest(test,local_path)
			testObject.buildStatus = True
			res = executeTest(testObject,build_path)
			testObject.executeStatus = True
			if testObject.exitValue == 0 :
				stats["pass"]+=1
			else:
				stats["fail"]+=1
			removeTestExecutable(test,build_path)
			logPass(test)
		except: 
			logFail("[FAIL] %s failed." % test)
	print "Finished running tests. Cleaning up"
	doCommand("/usr/bin/make","clean")
	#Now to print the Summary and statistics
	print "\n\n Test Summary \n"
	print xnuTest.getSummaryHeader()
	for testObject in tests_to_run:
		print testObject.getSummary()
	print "\n===============================\n"
	print "[SUMMARY]"
	print "Total tests: %d" % stats["total"]
	print "Passed     : %d" % stats["pass"]
	print "Failed     : %d" % stats["fail"]
	print "================================\n\n"

	logPass() # This line is implicit and can be removed
