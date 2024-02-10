import json
import logging
import os
import socket
import threading
import time

class Auth:

    my_things={}

    def __init__(self, ip, port):
        logging.basicConfig(
        level=logging.DEBUG,
        filename=f"data/log/{socket.gethostname()}_log.log",
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S')
        self.ip = ip
        self.port = int(port)
        self.security_level=int(os.environ.get('SEC_LEV'))
        self.resource=int(os.environ.get('RESOURCE'))
        self.avaliable_resorce=int(self.resource)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        self.hostname=socket.gethostname()

    def auth_status(self):
        return f"Available resources: {self.avaliable_resorce}/{self.resource}"

    def encode_message(self,data):
        '''
        Input: Any messages
        Output: stream of bytes
        '''
        message_byte=json.dumps(data).encode("UTF-8")
        return message_byte

    def decode_message(self,data,address):
        '''
        Give message and andress, it will decode the encrypt message in a plaintext message in json format.
        For now, it only trasform the stream in json.
        '''
        plain=json.loads(data)
        return plain

    def check_resource_requirements(self,message,address):
        try:
            resource_needed=int(message['SEC_REQ']) #To define better
            if self.avaliable_resorce-int(message['SEC_REQ'])<0:
                logging.info(f"Auth cannot register {address} cause there aren't enougth resouces avaliable:\nAvailable:{self.avaliable_resorce}\nRequired:{resource_needed}")
                return False
            else:
                self.avaliable_resorce=self.avaliable_resorce-resource_needed
                return True
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during security_requiremts handling, with {address}")

    def check_security_level(self,message,address):
        try:
            security_level_needed=int(message['SEC_REQ'])
            if security_level_needed>self.security_level:
                logging.info(f"Auth cannot register {address} cause it cannot grant the requested security level:\nOffered:{self.security_level}\nRequired:{security_level_needed}")
                return False
            else:
                return True
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during check_security_requiremts handling, with {address}")

    def register_response(self,message,address,accepted):
        try:
            response={
                "MESSAGE_TYPE": 1,
                "AUTH_ID": self.hostname,
                "A_NONCE": os.urandom(10),
                "ACCEPTED": accepted,
            }
            if accepted == 0: #Register request was declined
                pass
            else:
                session_key=self.add_thing(message,address)
                logging.info("Nuova thing aggiunta")
                response['SESSION_KEY']=session_key
                json_response=json.dumps(response)
            
            self.send(address[0],6666,json_response)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_response handling, with {address}")  
                



    def gen_key(self,par1,par2):
        return f"S_K_{par1}_{par2}"
    
    def add_thing(self,message,address):
        try:
            session_key=self.gen_key(self.hostname,message['THING_ID'])
            new_thing={
                "ADDRESS": address[0],
                "PORT": address[1],
                "SEC_REQ": 3,
                "SESSION_KEY": session_key
            }
            self.my_things[message['THING_ID']]=new_thing
            logging.info(f"Thing aggiunta:\n{new_thing}")
            return session_key
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during add_thing handling, with {address}")
        

    def register_to_auth(self,message, address):
        try:
            if not self.check_think_signature(message,address):
                self.register_response(message,address,0)
            if not self.check_security_level(message,address):
                self.register_response(message,address,0)
            if not self.check_resource_requirements(message,address):
                self.register_response(message,address,0)

            logging.info(self.auth_status())
            self.register_response(message,address,1)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_to_auth handling, with {address}")

    def check_think_signature(self,data,address):
        '''
        To be implemented 
        '''
        return True

    def template(self,message,address):
        try:
            pass
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during template handling, with {address}")

    def handle_client(self, data, address):
        logging.info(f"Message:\n'{data.decode()}'\n From: {address}")
        plain_message = self.decode_message(data, address)
        if plain_message['MESSAGE_TYPE'] == 0:
            self.register_to_auth(plain_message, address)
        elif plain_message['MESSAGE_TYPE'] == 1:
            pass
        else:
            logging.error("Message type was not recognized")


    def send(self,receiver_ip,receiver_port,message):
        try:
            logging.info(f"Try to send:\n{message}\n to {receiver_ip}:{receiver_port}")
            UDP_IP = receiver_ip
            UDP_PORT = receiver_port
            MESSAGE = message
            MESSAGE_BYTE=json.dumps(MESSAGE).encode("UTF-8")
            sock = socket.socket(socket.AF_INET, 
                                socket.SOCK_DGRAM) 
            sock.sendto(MESSAGE_BYTE, (UDP_IP, UDP_PORT))
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during send, with {receiver_ip}:{receiver_port}")


    def listenT(self):
        while True:
            data, address = self.socket.recvfrom(1024)
            self.handle_client(data,address)
            

    def start_listening(self):
        logging.info(f"{self.hostname} Start Listening on {self.ip}:{self.port}")
        listening_thread = threading.Thread(target=self.listenT, daemon= True)
        listening_thread.start()
            

if __name__ == "__main__":

    auth_ip = os.environ.get('IP')
    auth_port = os.environ.get('UDP_PORT')
    auth = Auth(auth_ip, auth_port)
    auth.start_listening()    

    while True:
        time.sleep(5)
        logging.info("Working")
