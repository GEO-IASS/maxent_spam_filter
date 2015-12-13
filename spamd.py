#!/usr/bin/env python

'''
Provides a SpamAssassin spamd interface for receiving emails and providing
filtering results.
'''

import socketserver
import threading
import tempfile
import subprocess
import pwd
import os
import email
from feature_extractor import EmailFeatureExtractor

class TcpHandler(socketserver.StreamRequestHandler):
	'''
	Define paths and locations
	'''
	mallet = '/opt/spam_filter/mallet/bin/mallet'
	tmp_dir = '/var/spool/spam_filter'
	vectors = '/var/lib/spam_filter/vectors'
	filter_model = '/var/lib/spam_filter/maxent.model'
	rejected_folder = '/srv/mail/spam'

	'''
	Define thresholds and other values
	'''
	reject_threshold = 99.85

	'''
	Handles communications with the server
	'''
	def handle(self):
		# Get the request line (first command)
		request_line = str(self.rfile.readline().strip(), 'iso-8859-1')

		# Separate the words
		words = request_line.split()
		self.command = words[0]
		protocol = words[1]

		# Make sure the command is valid
		if  self.command != "CHECK" and \
			self.command != "SYMBOLS" and \
			self.command != "REPORT" and \
			self.command != "REPORT_IFSPAM" and \
			self.command != "SKIP" and \
			self.command != "PING" and \
			self.command != "PROCESS" and \
			self.command != "TELL":
			# Send a bad response
			self.sendResponse("USAGE", True, 100, "")
			return

		# See if we are dealing with a PING or a SKIP
		if self.command == "PING" or self.command == "SKIP":
			# Send a short OK response
			self.wfile.write(b'SPAMD/1.1 0 EX_OK\r\n\r\n')
			return

		# Get the headers; (we only care about Content-length)
		self.length = 0
		while True:
			raw_header = str(self.rfile.readline().strip(), 'iso-8859-1')
			header = raw_header.split(':', 2)
			if header[0].strip().lower() == 'content-length':
				self.length = int(header[1].strip())
			if not raw_header:
				break

		# Read the specified number of bytes into a temporary file
		temp_file = tempfile.NamedTemporaryFile(dir=self.tmp_dir)

		while self.length > 0:
			# See how many bytes we are going to read
			block_size = 4096
			if self.length > block_size:
				bytes_to_read = block_size
			else:
				bytes_to_read = self.length

			# Read the block and write it to the temp file
			temp_file.write(self.rfile.read(bytes_to_read))

			self.length -= block_size

		# Flush the file to disk
		temp_file.flush()

		# Extract the features from the email message
		fp = open(temp_file.name, "rb")

		# Parse the email message
		try:
			message = email.message_from_binary_file(fp)
		except:
			fp.close()
			self.sendResponse("OK", True, 100,
				"Message could not be parsed as a valid email")
			return

		# Extract information from the message for logging purposes
		recepient = message["X-Envelope-To"]
		subject = message["Subject"]

		# Extract the features
		extractor = EmailFeatureExtractor(self.vectors)
		vector_count = extractor.vectorCount()
		#vector_count = 236655
		features = extractor.extract(message)

		# Close the file, both the binary version and temp file version
		fp.close()
		temp_file.close()

		# Write out the features to another temporary file
		features_file = \
			tempfile.NamedTemporaryFile(dir=self.tmp_dir)
		features_file.write(b'1') # Corpus identifier (ham for now)
		for feature_number in sorted(features.keys()):
			if feature_number <= vector_count:
				features_file.write(bytearray(" " + str(feature_number) + ":" +
					str(features[feature_number]), 'iso-8859-1'))
		features_file.write(b'\n')
		features_file.flush()

		# Call the classifier on the features
		try:
			command = [self.mallet, 'classify-svmlight', '--input',
				features_file.name, '--classifier', self.filter_model,
				'--output', '-']
			output = subprocess.check_output(command, stderr=subprocess.STDOUT)
		except:
			self.sendResponse("TEMPFAIL", False, 0, "")
			features_file.close()
			return

		# Close the features temporary file; this will delete the file
		features_file.close()

		# Interpret the probabilities
		output_words = output.strip().split()
		ham_probability = float(output_words[2]) * 100
		spam_probability = float(output_words[4]) * 100

		# Determine if the message is spam
		if ham_probability >= spam_probability:
			is_spam = False
			message = "The content filter has determined your email is not spam"
		else:
			is_spam = True
			message = "The content filter has determined your email is spam"

		# Send the results
		self.sendResponse("OK", is_spam, spam_probability, message)

		#print(recepient, "|", subject, "|", ham_probability, "|", spam_probability)

		# Log the entry
		with open("/var/log/spam_filter/filter.log", "a") as log_file:
			log_file.write(str(ham_probability) + "|" + str(spam_probability) + "|" + str(recepient) + "|" + (subject) + "\n")


	def sendResponse(self, status, is_spam, probability, message):
		# Exim seems to interpret the value of of spam more than the result;
		# So if the message is not spam, we'll send a score of 2/5; if the
		# message is spam, we'll send 8/5; if the message is over the threshold
		# we'll send 12 / 5 and tell Exim to reject the  message if the score
		# is over 10

		probability = 0;

		# See which status we have
		if status == "OK":
			self.wfile.write(b'SPAMD/1.1 0 EX_OK\r\n')

			# See if we are sending content
			if self.command == "CHECK" or self.command == "SYMBOLS":
				if is_spam:
					if probability >= self.reject_threshold:
						self.wfile.write(bytearray('Spam: True ; 12 / 5\r\n', \
						'iso-8859-1'))
					else:
						self.wfile.write(bytearray('Spam: True ; 8 / 5\r\n', \
						'iso-8859-1'))
				else:
					self.wfile.write(bytearray('Spam: False ; 2 / 5\r\n', \
						'iso-8859-1'))
			elif self.command == "REPORT" or self.command == "PROCESS":
				#self.wfile.write(bytearray('Content-length: %d\r\n' \
				#	% len(eessage), 'iso-8859-1'))
				if is_spam:
					if probability >= self.reject_threshold:
						self.wfile.write(bytearray('Spam: True ; 12 / 5\r\n', \
							"iso-8859-1"))
					else:
						self.wfile.write(bytearray('Spam: True ; 8 / 5\r\n', \
							"iso-8859-1"))
				else:
					self.wfile.write(bytearray('Spam: False ; 2 / 5\r\n', \
						"iso-8859-1"))
				if len(message):
					self.wfile.write(b'\r\n')
					self.wfile.write(bytearray(message, "iso-8859-1") + b'\r\n')
			elif self.command == "REPORT_IFSPAM":
				if is_spam:
					self.wfile.write(bytearray('Content-length: %d\r\n' \
						% len(message), 'iso-8859-1'))
					if probability >= self.reject_threshold:
						self.wfile.write(bytearray('Spam: True ; 12 / 5\r\n', \
							"iso-8859-1"))
					else:
						self.wfile.write(bytearray('Spam: True ; 8 / 5\r\n', \
							"iso-8859-1"))
				else:
					self.wfile.write(bytearray('Spam: False ; 2 / 5\r\n', \
						"iso-8859-1"))
				if len(message) and is_spam:
					self.wfile.write(b'\r\n')
					self.wfile.write(bytearray(message, "iso-8859-1") + b'\r\n')

		elif status == "USAGE":
			self.wfile.write(b'SPAMD/1.1 64 EX_USAGE\r\n')
		elif status == "DATAERR":
			self.wfile.write(b'SPAMD/1.1 65 EX_DATAERR\r\n')
		elif status == "NOUSER":
			self.wfile.write(b'SPAMD/1.1 67 EX_NOUSER\r\n')
		else:
			self.wfile.write(b'SPAMD/1.1 75 EX_TEMPFAIL\r\n')

		# Send the final empty line
		self.wfile.write(b'\r\n')


if __name__ == "__main__":
	HOST, PORT = "localhost", 783

	# Create the socket binding
	server = socketserver.TCPServer((HOST, PORT), TcpHandler)

	# Shed privileges
	mail_user = pwd.getpwnam('vmail')[2]
	os.setuid(mail_user)

	# Listen for incoming connections and move to the background
	server_thread = threading.Thread(target=server.serve_forever())
	server_thread.setDaemon(True)
	server_thread.start()

