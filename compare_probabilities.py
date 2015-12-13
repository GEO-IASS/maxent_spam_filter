#!/usr/bin/env python
'''
Created on Nov. 23, 2012

@author: alberto

This script compares two classification probabilties and returns the result
'''

# Imports
import sys

# Make sure we have the right command line arguments
if len(sys.argv) == 3:
	prob_ham = float(sys.argv[1])
	prob_spam = float(sys.argv[2])

	if prob_ham >= prob_spam:
		print("ham")
	else:
		print("spam")
else:
    print("Usage: " + sys.argv[0] + "prob_ham prob_spam")
    quit(1);

