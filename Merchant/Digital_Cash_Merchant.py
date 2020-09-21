##-----------------------------------------------------------##
# Module: Customer for digital Cash                           #
# Author: Pragati Sharma                                      #
# Funcionality: This module implements the Bank behavior      #
#         described in Protocol 4 of Digital Cash.            #
# Compatibility: Python 3.8.0                                 # 
##-----------------------------------------------------------##

#####################################
## Begin Imports
# To convert strings/integers to Binary Bit stream. Module imported from Pypl (Python Package Library)
import BitVector
from BitVector import *

# To generate random numbers:
import random

# For RSA implementation importing Crypto Module from Python Package Library. 
import Crypto

# For Encryption Decryption functionality of RSA algorithm importing PKCS1_OAEP from Pypl. It includes SHA1 hash algorithm.
from Crypto.Cipher import PKCS1_OAEP

# This module provides facilities for generating fresh, new RSA keys, constructing them from known components, exporting them, and importing them.
from Crypto.PublicKey import RSA 

# For network connectivity
import socket

# for your code to perform introspection about the system in which its running
import sys  

# To enable encode/decode in base64
import base64

# import only system from os 
import os
from os import system, name 
  
# import sleep to show output for some time period 
from time import sleep 

# Importing Warning to supress DeprecationWarning from getting displayed
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Importing time to add wait delay
import time

## End Imports
#####################################
IP = '127.0.0.1'
bank_addr = (IP, 5005)
merch_addr = (IP, 5006)
BUFFER_SIZE = 1024*64
S = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
S.bind (merch_addr)

#load RSA private key
pvt_key = RSA.importKey(open('bank_pvt_key.pem').read())

# define our clear function
def clear(): 
    # for windows 
    if name == 'nt': 
        _ = system('cls') 
    # for mac and linux(here, os.name is 'posix') 
    else: 
        _ = system('clear') 

# Selects random pairs and sends to the customer
def Select_Secret_Pair ():
    r1  = random.getrandbits(3) #returns an random int with I_n bits
    R = BitVector(intVal = r1, size = 3)
    SP_str = str (R)

    return SP_str

# This module verifies the bank signature 
def Verify_Bank_Signature (data):
    ciphertext = base64.decodebytes(data)
    cipher     = PKCS1_OAEP.new(pvt_key)
    message    = cipher.decrypt(ciphertext)
    msg        = str(message,'utf-8') 
    num_str    = msg[0]
    num_int    = int(num_str)
    
    if (num_int < 5):
        return True
    else: 
        return False


while 1:

    print ("******************************")
    print ("Waiting for Money Order from Customer")
    data, addr = S.recvfrom (BUFFER_SIZE)
    cust_addr = addr
    result = Verify_Bank_Signature(data)
    if (result):
        print ("Verified Signed Money Order")
        msg = Select_Secret_Pair()
    else:
        msg = "ERROR"
    print ("Sending partial pairs to Customer")
    S.sendto (msg.encode(), addr) #send the partial pairs or Error message to customer
    data_to_bank, addr = S.recvfrom (BUFFER_SIZE)
    print ("Depositing Money Order to Bank")
    msg_to_bank = "MO_desposit"
    S.sendto (msg_to_bank.encode(), bank_addr)
    # Sending unique ID and partial identity to bank
    S.sendto (data_to_bank, bank_addr)
    data, addr = S.recvfrom (BUFFER_SIZE)
    Message = data.decode()
    print (Message)
    if (Message[0] == '5'):
        msg = "Payment Received"
    else:
        msg = "Payment Rejected by Bank"
    S.sendto(msg.encode(),cust_addr)
    time.sleep(10)
