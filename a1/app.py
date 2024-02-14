import json
import logging
import os
import socket
import threading
import time

class Auth:

    registered_entity_table={}
    trusted_auth_table={}
    trusted_auth_things={}

    def __init__(self):
        logging.basicConfig(
        level=logging.DEBUG,
        filename=f"data/log/{socket.gethostname()}_log.log",
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M')
        self.load_init_config()
        self.avaliable_resource_align()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        self.hostname=socket.gethostname()

    def load_init_config(self):
        try:
            with open('data/config/config.json', 'r') as json_file:
                data = json.load(json_file)
            #logging.info(f"Config file:\n{data}")
            self.registered_entity_table=data['registered_entity_table']
            self.ip=data["IP"]
            self.port=data["UDP_PORT"]
            self.security_level=data['SEC_LEV']
            self.resource=data['RESOURCE']
            self.avaliable_resorce=self.resource
            self.trusted_auth_table=data['trusted_auth_table']
            self.trusted_auth_things=data['trusted_auth_things']
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
        '''Return information about the auth, for istances its avaliable resources and its registered entity'''
        return f"Available resources: {self.avaliable_resorce}/{self.resource}\nregistered_entity_table:\n{self.registered_entity_table}\ntrusted_auth_table:\n{self.trusted_auth_table}\ntrusted_auth_things:\n{self.trusted_auth_things}"

        #return f"Available resources: {self.avaliable_resorce}/{self.resource}\nregistered_entity_table:\n{self.registered_entity_table}\ntrusted_auth_table:\{self.trusted_auth_table}\ntrusted_auth_things:\n{self.trusted_auth_things}"

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
        '''
        Check if the Auth can accept a new things due to its resources
        '''
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
        '''
        Check if the Auth can accept a new thing due to its offered security level. The security level offered by an Auth should be greater or equal of the thing's security requirement (SEQ_REQ) 
        '''
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
        '''
        After receiving a REGISTER_TO_AUTH from a Things, the Auth should respond with REGISTER_RESPONSE.
        '''
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
                session_key=self.add_thing(message)
                logging.info("Nuova thing aggiunta")
                response['SESSION_KEY']=session_key

            address=self.get_thing_address(message['THING_ID'])
            self.send(address['ADDRESS'],address['PORT'],response)
            if accepted == 1:
                self.auth_update()
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_response handling, with {address}")  
    
    def auth_update(self):
        """
        After that a Thing become registerd to an Auth, the latter have to notice this to its trusted Auths.
        """
        try:
            thing_list=[]
            for t in self.registered_entity_table.keys():
                thing_list.append(t)
                    
            for auth in self.trusted_auth_table.values():
                message={
                "MESSAGE_TYPE": 8,
                "AUTH_ID": self.hostname,
                "A_NONCE": str(os.urandom(10)),
                "UPDATE": thing_list
                }
                self.send(auth['ADDRESS'],int(auth['PORT']),message)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_update handling")
        

    def gen_key(self,par1,par2):
        '''
        Given two parametes, it will return a key
        '''
        return f"S_K_{par1}_{par2}"
    
    def add_thing(self,message):
        try:
            session_key=self.gen_key(self.hostname,message['THING_ID'])
            new_thing={
                "ADDRESS": message['ADDRESS'],
                "PORT": message['PORT'],
                "SEC_REQ": 3,
                "SESSION_KEY": session_key
            }
            self.registered_entity_table[message['THING_ID']]=new_thing
            logging.info(f"Thing aggiunta:\n{new_thing}")
            return session_key
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during add_thing handling, with {message['ADDRESS']}:{message['PORT']}")

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

    def get_auth_address(self,auth):
        try:
            return self.trusted_auth_table[auth]
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_auth_address for {auth}")

    def get_auth(self,thing):
        for auth in self.trusted_auth_things:
            if thing in self.trusted_auth_things[auth]:
                return auth

    def make_dict_auth_things(self,session_keys):
        '''
        Given a dict of pair <thing,session_key> it will produce a dict group by auth with the rispective set of records
        Example:
        Input: session_keys={'t6': 'S_K_t1_t6', 't8': 'S_K_t1_t8', 't9': 'S_K_t1_t9'}
        Output: d_auth={'a2': {'t6': 'S_K_t6', 't9': 'S_K_t9'}, 'a3': {'t8': 'S_K_t8'}}
        '''
        d_auth={}
        for s in session_keys.keys():
            auth=self.get_auth(s)
            thing=s
            s_key=session_keys[s]
            record={thing:s_key}
            if auth in d_auth:
                d_auth[auth].update(record)
            else:
                d_auth[auth]=record
        return d_auth

    def send_auth_session_key(self,session_keys,sender_thing):
        try:
            d_auth=self.make_dict_auth_things(session_keys)
            for auth in d_auth.keys():
                auth_address=self.get_auth_address(auth)
                message={
                    "MESSAGE_TYPE": 6,
                    "AUTH_ID": self.hostname,
                    "A_NONCE": str(os.urandom(10)),
                    "FROM": sender_thing
                }
                message['SESSION_KEYS']=d_auth[auth]
                self.send(auth_address['ADDRESS'],int(auth_address['PORT']),message)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during send_auth_session_key handling requested by {sender_thing}")
        
    def session_key_request(self,message,address):
        try:
            if not self.check_nonce(message,address):
                pass
            session_key_response={
                "MESSAGE_TYPE": 5,
                "AUTH_ID": self.hostname,
                "A_NONCE": str(os.urandom(10))
            }

            session_keys=self.get_session_key(message,address)
            
            session_key_response['SESSION_KEY']=session_keys

            self.send_auth_session_key(session_keys,message['THING_ID'])

            self.send(address[0],6666,session_key_response)
            #self.send(address[0],address[1],response)


        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during session_key_request handling, with {address}")

    def auth_session_keys(self,message,address):
        try:
            session_keys=message['SESSION_KEYS']
            for t in dict(session_keys).keys():
                thing_address=self.get_thing_address(t)
                logging.info(thing_address)
                response={
                    "MESSAGE_TYPE": 7,
                    "AUTH_ID": self.hostname,
                    "A_NONCE": str(os.urandom(10))
                    }
                response['SESSION_KEY']={message['FROM']:session_keys[t]}
                self.send(thing_address['ADDRESS'],thing_address['PORT'],response)


        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_session_keys handling, with {address}")

    def get_thing_address(self,thing):
        try:
            return self.registered_entity_table[thing]
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_auth_address for {thing}")

    def auth_update(self,message,address):
        try:
            logging.info(self.trusted_auth_things)
            auth=message['AUTH_ID']
            things=message['UPDATE']
            self.trusted_auth_things[auth]=things
            logging.info(self.trusted_auth_things)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_update handling, with {address}")

    def handle_client(self, data, address):
        logging.info(f"Message:\n'{data.decode()}'\n From: {address}")
        plain_message = self.decode_message(data, address)
        if plain_message['MESSAGE_TYPE'] == 0:
            self.register_to_auth(plain_message, address)
        elif plain_message['MESSAGE_TYPE'] == 2:
            self.auth_hello(plain_message,address)
        elif plain_message['MESSAGE_TYPE'] == 4:
            self.session_key_request(plain_message,address)
        elif plain_message['MESSAGE_TYPE'] == 6:
            self.auth_session_keys(plain_message,address)
        elif plain_message['MESSAGE_TYPE']==8:
            self.auth_update(plain_message,address)
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

    #auth_ip = os.environ.get('IP')
    #auth_port = os.environ.get('UDP_PORT')
    #auth = Auth(auth_ip, auth_port)
    auth = Auth()
    auth.start_listening()    

    while True:
        time.sleep(30)
        logging.info("Working")

