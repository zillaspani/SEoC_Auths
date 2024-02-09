import os
import socket
import logging
import json

hostname=""
ip_address=os.environ.get('IP')
udp_port=os.environ.get('UDP_PORT')

def load_confing():
    global hostname, ip_address
    hostname=socket.gethostname()
    logging.basicConfig(
        level=logging.INFO,
        filename=f"data/log/${hostname}_log.log",
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S'
    )

def register_to_auth(addr,message):
    logging.info("REGISTER_TO_AUTH FROM "+addr+" WITH MESSAGE"+message)


def session_key_request(message):
     logging.info("SESSION_KEY_REQUEST FROM "+message['THING_ID'])   

def messageCollector(addr,message):
        if message['MESSAGE_TYPE'] == 0:
             register_to_auth(addr,message)
        elif message['MESSAGE_TYPE'] == 1:
             session_key_request(message)

if __name__=='__main__':
    
    load_confing()
    UDP_IP = ip_address
    UDP_PORT = udp_port
    sock = socket.socket(socket.AF_INET,
                     socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    logging.info("Waiting for request")
    sock.s
    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        #logging.info("received message: %s" % data)
        json=json.loads(data)
        messageCollector(sock,addr,json)