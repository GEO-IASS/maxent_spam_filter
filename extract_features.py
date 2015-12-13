#!/usr/bin/env python
'''
Created on Nov. 25, 2012

@author: alberto

This script will read the full path and filename of email messages from stdin
and append the features to the given filename. The first argument is the type
of messages these are.
'''

# Imports
import sys
import os
import email
from feature_extractor import EmailFeatureExtractor

# Define the vectors file
vector_file = "/var/lib/spam_filter/vectors.new"

# Make sure we have the right command line arguments
corpus = ""
filename = ""
if len(sys.argv) == 3:
    # Verify the corpus (category)
    if sys.argv[1] == "ham":
        corpus = "1"
    elif sys.argv[1] == "spam":
        corpus = "2"
    else:
        print("Usage: " + sys.argv[0] + " {spam|ham} output_filename")
        quit(1)

    output_filename = sys.argv[2]
else:
    print("Usage: " + sys.argv[0] + " {spam|ham} output_filename")
    quit(1);


# Initialize the feature extractor
extractor = EmailFeatureExtractor(vector_file)

# Iterate through each line in stdin
for line in sys.stdin:
    message_filename = line.strip()

    # See if the file exists
    if not os.path.exists(message_filename):
        print("Error: \"" + message_filename + "\" does not exist")
        continue

    # Open the file
    fp = open(message_filename, "rb")

    # Parse the file as an email message
    try:
        message = email.message_from_binary_file(fp)

    except:
        fp.close()
        print("Could not parse file: " + filename)
        continue

    # Extract the features
    features = extractor.extract(message)

    # Close the file
    fp.close()

    # Write the features to the output file
    fp = open(output_filename, "a")
    fp.write(corpus)
    for feature_number in sorted(features.keys()):
        fp.write(" " + str(feature_number) + ":" +
                 str(features[feature_number]))
    fp.write("\n")
    fp.close()

extractor.exportVectors()
