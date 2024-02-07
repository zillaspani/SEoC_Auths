from flask import Flask
import os
import socket
import logging
import socket

hostname=""
ip_address=os.environ.get('IP')

app = Flask(__name__)

def load_confing():
    global hostname, ip_address
    hostname=socket.gethostname()
    logging.basicConfig(
        level=logging.INFO,
        filename=f"data/log/${hostname}_log.log",
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S'
    )


def send():
    UDP_IP = ip_address
    UDP_PORT = 5006
    MESSAGE = b"Hello, World! From Auth"

    #print("UDP target IP: %s" % UDP_IP)
    #print("UDP target port: %s" % UDP_PORT)
    #print("message: %s" % MESSAGE)

    sock = socket.socket(socket.AF_INET, # Internet
                        socket.SOCK_DGRAM) # UDP
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))


@app.route('/hello')
def hello_word():
    logging.info("pino/hello")
    return 'Hi! I\'m '+hostname+"\nThis is my ip address: "+ip_address+"\n"


if __name__=='__main__':
    load_confing()
    print("Ciao")
    #app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT'))
    send()

    UDP_IP = ip_address
    UDP_PORT = 5005

    sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print("received message: %s" % data)