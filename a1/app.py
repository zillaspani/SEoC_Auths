import os
import socket
import logging
import json

hostname=""
ip_address=os.environ.get('IP')


def load_confing():
    global hostname, ip_address
    hostname=socket.gethostname()
    logging.basicConfig(
        level=logging.INFO,
        filename=f"data/log/${hostname}_log.log",
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S'
    )

def connect_to_auth(message):
    logging.info("CONNECT_TO_AUTH FROM "+message['THING_ID'])


def session_key_request(message):
     logging.info("SESSION_KEY_REQUEST FROM "+message['THING_ID'])   

def messageCollector(message):
        if message['MESSAGE_TYPE'] == 0:
             connect_to_auth(message)
        elif message['MESSAGE_TYPE'] == 1:
             session_key_request(message)

if __name__=='__main__':
    load_confing()
    UDP_IP = ip_address
    UDP_PORT = 5005

    sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
    sock.bind((UDP_IP, UDP_PORT))
    logging.info("Waiting for request")
    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        logging.info("received message: %s" % data)
        json=json.loads(data)
        messageCollector(json) 