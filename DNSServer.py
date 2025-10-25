# DNSServer.py
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Lookup details on fernet in the cryptography.io documentation
def encrypt_with_aes(input_string, password, salt):
    # Generate key from password & salt
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # returns bytes
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    # encrypted_data may be bytes or a utf-8 string; ensure bytes
    if isinstance(encrypted_data, str):
        encrypted_bytes = encrypted_data.encode('utf-8')
    else:
        encrypted_bytes = encrypted_data
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_bytes)
    return decrypted_data.decode('utf-8')

# --- Encryption parameters (change PASSWORD to your NYU Gradescope email) ---
salt = b'Tandon'  # must be a byte-object
password = 'mg8210@nyu.edu'  # <-- REPLACE this with your NYU email registered in Gradescope
input_string = "AlwaysWatching"

# produce encrypted_value and decrypted_value (decrypted_value only for local test)
encrypted_value = encrypt_with_aes(input_string, password, salt)  # bytes
# For storing in a DNS TXT record we cast to string (utf-8). Keep the encrypted package itself unchanged.
encrypted_value_str = encrypted_value.decode('utf-8')
# decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # can be used for testing locally

# For future use
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,  # refresh
            1800,  # retry
            604800,  # expire
            86400,  # minimum
        ),
    },
    # The required records from the assignment (FQDNs must end with a dot)
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value_str,),  # store encrypted package as a TXT string
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and port 53 (standard DNS port)
    # NOTE: binding to port 53 usually requires elevated privileges (sudo) on many systems.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_ip = '127.0.0.1'  # local testing IP (loopback)
    bind_port = 5353  # standard DNS port; use a higher port if you don't run as root
    try:
        server_socket.bind((bind_ip, bind_port))
    except PermissionError:
        print(f"PermissionError: Cannot bind to port {bind_port}. Try running with elevated privileges or change bind_port to >1024 for testing.")
        sys.exit(1)
    except Exception as e:
        print("Failed to bind socket:", e)
        sys.exit(1)

    print(f"DNS server listening on {bind_ip}:{bind_port} (UDP)")

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(4096)
            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)
            # Create a response message using the `dns.message.make_response` method
            response = dns.message.make_response(request)

            # Get the first question from the request
            if len(request.question) == 0:
                # no question - ignore
                continue
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Debug print
            print("Received query from", addr, "for", qname, "type", qtype)

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                # Retrieve the data for the record and create an appropriate `rdata` object for it
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    # answer_data is a list of (pref, server)
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    # expected tuple: (mname, rname, serial, refresh, retry, expire, minimum)
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)
                else:
                    # If answer_data is a single string (like an A record), or an iterable of strings (like TXT)
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        # assume iterable of items (TXT usually a tuple of strings)
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                # Append RRsets and rdata to response
                for rdata in rdata_list:
                    rr = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rr.add(rdata)
                    response.answer.append(rr)

            # Set the AA (Authoritative Answer) flag manually using bitwise ops
            response.flags |= 1 << 10

            # Send response back
            server_socket.sendto(response.to_wire(), addr)
            print("Responded to", addr, "for", qname)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            print("Error handling request:", e)
            # continue serving

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
    # For debug / local test:
    # print("Encrypted Value (stored in nyu.edu TXT):", encrypted_value_str)
    # print("Decrypted Value (check):", decrypt_with_aes(encrypted_value, password, salt))
