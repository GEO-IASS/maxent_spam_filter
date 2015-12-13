#!/usr/bin/env python
'''
Created on Jul 5, 2011
Last modified on Nov. 18, 2012

@author: alberto
'''

import os
import pickle
import re

class EmailFeatureExtractor:
    # Class properties
    __vectors = {}
    __features = {}
    __charset = ""
    
    __vector_file = ""

    bodyNgramSizes = [1, 2, 3]
    bodyTrimSize = 1024
    
    headerNgramSizes = [1, 2, 3]
    headers = ["Subject", "Return-Path", "From", "To", "Reply-To",
               "Mailing-List", "List-Id"]

    
    # Constructor
    def __init__(self, vector_file = "spam_filter.vectors", truncate = False):
        # See if the feature file exists
        if os.path.exists(vector_file):
            # Try to load the file
            try:
                fp = open(vector_file, "rb")
                self.__vectors = pickle.load(fp)
                fp.close()
                
                if len(self.__vectors) < 1:
                    truncate = True
            except:
                truncate = True
        else:
            truncate = True
        
        # Define the Message Parse Error feature
        if truncate:
            self.__vectors = {}
            self.__vectors["MESSAGE_PARSE_ERROR"] = 1
        
        # Save the vector filename
        self.__vector_file = vector_file
        
        
    def vectorCount(self):
        return len(self.__vectors)


    def exportVectors(self):
        try:
            # Open the file
            fp = open(self.__vector_file, "wb")
            pickle.dump(self.__vectors, fp)
            fp.close()
        except:
            print("Could not export vectors!\n")


    def extract(self, message):
        # See what character set we have; if not, set a default
        if message.get_charset() != None:
            self.__charset = message.get_charset()
        else:
            self.__charset = "iso-8859-1"
        
        # Initialize the feature list for this message
        self.__features = {}
        
        # Go through the defined headers
        for header in self.headers:
            # See if the header exists
            if header in message:
                # Go through the n-gram sizes for headers
                for size in self.headerNgramSizes:
                    # Extract the features from the header
                    self.__extractNgrams(size, header, message[header])
        
        # Extract features from the body
        for part in message.walk():
            # See if we have a multipart message
            if part.get_content_maintype() == "multipart":
                continue
            
            # See if we have a non-text attachment
            if part.get_content_maintype() != "text":
                # Count the number of attachments
                self.__increase_feature_count("ATTACHMENT_COUNT")
                
                # Extract ngrams from the attachment name
                self.__increase_feature_count("MULTIPART")
                text = part.get_filename()
                if text:
                    for size in self.headerNgramSizes:
                        self.__extractNgrams(size, "ATTACHMENT", text)
                continue

            if part.get_content_subtype() == "plain":
                self.__increase_feature_count("HAS_PLAIN_TEXT_PART")
                content_type = "PLAIN_TEXT"
            elif part.get_content_subtype() == "html":
                self.__increase_feature_count("HAS_HTML_PART")
                content_type = "HTML"
            else:
                # Consider this an attachment
                self.__increase_feature_count("ATTACHMENT_COUNT")
                
                # Extract n-grams from the attachment name
                self.__increase_feature_count("MULTIPART")
                text = part.get_filename()
                if text:
                    for size in self.headerNgramSizes:
                        self.__extractNgrams(size, "ATTACHMENT", text)
                continue
        
            # Get the text and decode it
            text = part.get_payload()
            if part.get_content_charset() != None:
                self.__charset = part.get_content_charset()
            if isinstance(text, bytes):
                try:
                    text = text.decode(self.__charset)
                except:
                    self._increase_feature_count("BYTE_DECODE_ERROR")
                    text = text.decode(self.__charset, "ignore")
                
            # See if the text part is empty
            if len(text.strip()) == 0:
                self.__increase_feature_count("EMPTY_" + content_type + "_PART")
                continue
            
            # See if the message is longer than twice our trim size
            if len(text) >= self.bodyTrimSize * 2:
                for size in self.bodyNgramSizes:
                    self.__extractNgrams(size,
                                         "BODY_START_" + content_type,
                                         text[:self.bodyTrimSize])
                    self.__extractNgrams(size,
                                         "BODY_END_" + content_type,
                                         text[-self.bodyTrimSize:])
            else:
                # Extract features from the whole text
                for size in self.bodyNgramSizes:
                    self.__extractNgrams(size, "BODY_" + content_type, text)
        
            # See if we need to do stripped HTML
            if content_type == "HTML":
                p = re.compile(r'<.*?>')
                s_text = p.sub('', text)
                
                # See if the message is longer than twice the trim size
                if len(s_text) >= self.bodyTrimSize * 2:
                    self.__extractNgrams(size, "S_BODY_START_HTML",
                                         s_text[:self.bodyTrimSize])
                    self.__extractNgrams(size, "S_BODY_END_HTML",
                                         s_text[-self.bodyTrimSize:])
                else:
                    self.__extractNgrams(size, "S_BODY_HTML", s_text)
                    
        return self.__features
            
    
    def __extractNgrams(self, size, vector_prefix, text):
        # Make sure we have either text or bytes for the text
        if not isinstance(text, str) and not isinstance(text, bytes):
            return
        
        # See if we need to decode bytes
        if isinstance(text, bytes):
            try:
                text = text.decode(self.__charset)
            except:
                self.__increase_feature_count("BYTE_DECODE_ERROR")
                text = text.decode(self.__charset, "ignore")
            
        # Make sure we have a size greater than 0
        if (size <= 0):
            return
        
        # Make sure the length of the text is greater than our ngram size
        if len(text) < size:
            # TODO: allow it to work with small amounts of text
            return
        
        # If size is greater than 1, begin extraction with start symbols
        for i in range(1, size):
            # Initialize the vector name
            vector = vector_prefix + "_" + str(size) + "_"
            
            # Add the start symbols
            for j in range(0, size - i):
                vector += "[start]"
            
            # Add the start of the text
            vector += text[0:i]
            
            # Add the feature
            self.__increase_feature_count(vector)
            
        for i in range(0, len(text) - size + 1):
            # Create the vector
            vector = vector_prefix + "_" + str(size) + "_" + text[i:i+size]
            
            # Add this feature
            self.__increase_feature_count(vector)
        
        # Add the stop symbol
        if size > 1:
            vector = vector_prefix + text[1 - size:] + "[stop]"
        
            # Add the feature
            self.__increase_feature_count(vector)

                
    def __get_vector_number(self, vector):
        if vector not in self.__vectors:
            self.__vectors[vector] = len(self.__vectors) + 1
        return self.__vectors[vector]


    def __increase_feature_count(self, vector, count = 1):
        vector_number = self.__get_vector_number(vector)
        
        if vector_number in self.__features:
            self.__features[vector_number] += count
        else:
            self.__features[vector_number] = count
