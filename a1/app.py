import json
import logging
import os
import socket
import threading
import time

class Auth:

    registered_entity_table={}
    trusted_auth_table={}

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
        self.load_init_config()

    def load_init_config(self):
        try:
            with open('data/config/config.json', 'r') as json_file:
                data = json.load(json_file)
            logging.info(f"Config file:\n{data}")
            self.registered_entity_table=data['registered_entity_table']
            self.avaliable_resource_align()
            self.trusted_auth_table=data['trusted_auth_table']
            #logging.info(self.registered_entity_table)
        except FileNotFoundError:
            logging.error("Config file not found.")
        except json.JSONDecodeError:
            logging.error("Error decoding JSON data. Check if the JSON config file is valid.")
        except Exception as e:
            logging.error("An unexpected error occurred:", e)

    def avaliable_resource_align(self):
        '''
        Align resources offered by the Auth with preloaded things' resource requirements.
        '''
        try:
            for thing in self.registered_entity_table.values():
                #logging.info(thing)
                self.avaliable_resorce=self.avaliable_resorce-int(thing['SEC_REQ'])

            if self.avaliable_resorce<0: raise Exception("Resource already allocated, please check config file")
            logging.info(self.auth_status())
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during resources alignment.")

    def auth_status(self):
        return f"Available resources: {self.avaliable_resorce}/{self.resource}\nregistered_entity_table:\n{self.registered_entity_table} "

    def encode_message(self,data):
        '''
        Input: Any messages
        Output: stream of bytes
        '''
        try:
            message_byte=json.dumps(data).encode("UTF-8")
            return message_byte
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during encode_message handling")  

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
                "A_NONCE": str(os.urandom(10)),
                "ACCEPTED": accepted,
            }

            if accepted == 0: #Register request was declined
                response['SUGGESTED_AUTH']=self.trusted_auth_table
            else:
                session_key=self.add_thing(message,address)
                logging.info("Nuova thing aggiunta")
                response['SESSION_KEY']=session_key

                
            self.send(address[0],6666,response)
            #self.send(address[0],address[1],response)
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
            self.registered_entity_table[message['THING_ID']]=new_thing
            logging.info(f"Thing aggiunta:\n{new_thing}")
            return session_key
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during add_thing handling, with {address}")

    def check_if_registered(self,message,address):
        '''
        To do:
        True if the things is already registered
        '''
        return False


    def register_to_auth(self,message, address):
        try:
            if self.check_if_registered(message,address):
                pass
            elif not self.check_think_signature(message,address):
                self.register_response(message,address,0)
            elif not self.check_security_level(message,address):
                self.register_response(message,address,0)
            elif not self.check_resource_requirements(message,address):
                self.register_response(message,address,0)
            else:
                self.register_response(message,address,1)
            logging.info(self.auth_status())
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_to_auth handling, with {address}")

    def check_think_signature(self,data,address):
        '''
        To be implemented 
        '''
        return True

    def auth_hello(self,message,address):
        '''
        Make the response at CONNECT_TO_AUTH from Things,
        PS: A_NONCE shuold be stored to verify it in the next massege exchange.
        '''
        try:
            if message['THING_ID'] in self.registered_entity_table:
                response={
                "MESSAGE_TYPE": 3,
                "AUTH_ID": self.hostname,
                "A_NONCE": str(os.urandom(10))
            }
                self.send(address[0],6666,response)
                #self.send(address[0],address[1],response)
            else:
                logging.info("Thing doesn't recognised, ignoring message")
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_hello handling, with {address}")

    def check_nonce(self,message,address):
        '''
        Nonce checking, A_NONCE in this message should be the same of nonce sendend in AUTH_HELLO 
        '''
        return True

    def evaluate_auth_trustness(self,thing):
        return True

    def get_session_key(self,message,address):
        try:
            SESSION_KEYS={}
            for thing in message['WHO']:
                if self.evaluate_auth_trustness(thing):
                    SESSION_KEYS[thing]=self.gen_key(message['THING_ID'],thing)
            
            return SESSION_KEYS
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during template handling, with {address}")

    def session_key_request(self,message,address):
        try:
            if not self.check_nonce(message,address):
                pass
            response={
                "MESSAGE_TYPE": 5,
                "AUTH_ID": self.hostname,
                "A_NONCE": str(os.urandom(10))
            }
            response['SESSION_KEY']=self.get_session_key(message,address)
            logging.debug("PINO")

            self.send(address[0],6666,response)
            #self.send(address[0],address[1],response)


        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during session_key_request handling, with {address}")

    def handle_client(self, data, address):
        logging.info(f"Message:\n'{data.decode()}'\n From: {address}")
        plain_message = self.decode_message(data, address)
        if plain_message['MESSAGE_TYPE'] == 0:
            self.register_to_auth(plain_message, address)
        elif plain_message['MESSAGE_TYPE'] == 2:
            self.auth_hello(plain_message,address)
        elif plain_message['MESSAGE_TYPE'] == 4:
            self.session_key_request(plain_message,address)
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
            logging.info(f"Sent:\n{message}\n to {receiver_ip}:{receiver_port}")
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
            
    def template(self,message,address):
        try:
            pass
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during template handling, with {address}")

if __name__ == "__main__":

    auth_ip = os.environ.get('IP')
    auth_port = os.environ.get('UDP_PORT')
    auth = Auth(auth_ip, auth_port)
    auth.start_listening()    

    while True:
        time.sleep(5)
        logging.info("Working")




