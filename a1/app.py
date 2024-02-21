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
    pending_keys={}
    lock = threading.Lock()

    def __init__(self):
        logging.basicConfig(
        level=logging.DEBUG,
        filename=f"data/log/{socket.gethostname()}_log.log",
        format='%(asctime)s,%(msecs)d %(levelname)s %(message)s',
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
            #logging.debug(f"Config file:\n{data}")
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

    def get_message_type(self, type):
        if type == 0:
            return "REGISTER_TO_AUTH"
        elif type == 1:
            return "REGISTER_RESPONSE"
        elif type == 2:
            return "CONNECT_TO_AUTH"
        elif type == 3:
            return "AUTH_HELLO"
        elif type == 4:
            return "SESSION_KEY_REQUEST"
        elif type == 5:
            return "SESSION_KEY_RESPONSE"
        elif type == 6:
            return "AUTH_SESSION_KEYS"
        elif type == 7:
            return "TRIGGER_THING"
        elif type == 8:
            return "AUTH_UPDATE"
        elif type == 9:
            return "UPDATE_REQUEST"
        elif type == 10:
            return "UPDATE_KEYS"
        elif type == 11:
            return "START"
        elif type == 15:
            return "TRUST_RECOMENDATION_REQUEST"
        elif type == 16:
            return "TRUST_RECOMENDATION_RESPONSE"
        else:
            return "Unknown message type"

    def avaliable_resource_align(self):
        '''
        Align resources offered by the Auth with preloaded things' resource requirements.
        '''
        try:
            for thing in self.registered_entity_table.values():
                self.avaliable_resorce=self.avaliable_resorce-int(thing['SEC_REQ'])

            if self.avaliable_resorce<0: raise Exception("Resource already allocated, please check config file")
            logging.debug(self.auth_status())
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during resources alignment.")

    def auth_status(self):
        '''Return information about the auth, for istances its avaliable resources and its registered entity'''
        return f"Available resources: {self.avaliable_resorce}/{self.resource}\nregistered_entity_table:\n{self.registered_entity_table}\ntrusted_auth_table:\n{self.trusted_auth_table}\ntrusted_auth_things:\n{self.trusted_auth_things}"

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
        try:
            plain=json.loads(data)
            return plain
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during decode_message handling, with {address}")

    def check_resource_requirements(self,message,address):
        '''
        Check if the Auth can accept a new things due to its resources
        '''
        try:
            resource_needed=int(message['SEC_REQ']) #To define better
            if self.avaliable_resorce-int(message['SEC_REQ'])<0:
                logging.debug(f"Auth cannot register {address} cause there aren't enougth resouces avaliable:\nAvailable:{self.avaliable_resorce}\nRequired:{resource_needed}")
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
                logging.debug(f"Auth cannot register {address} cause it cannot grant the requested security level:\nOffered:{self.security_level}\nRequired:{security_level_needed}")
                return False
            else:
                return True
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during check_security_requiremts handling, with {address}")

    def evaluate_auth_to_suggest(self,auth):
        '''
        To do
        '''
        try:
            return auth
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during evaluate_auth_to_suggest handling")

    def send_register_response(self,message,address,accepted):
        '''
        After receiving a REGISTER_TO_AUTH from a Things, the Auth should respond with REGISTER_RESPONSE.
        '''
        try:
            response={
                "MESSAGE_TYPE": 1,
                "AUTH_ID": self.hostname,
                "ADDRESS": self.ip,
                "PORT": self.port,
                "A_NONCE": str(os.urandom(2)),
                "ACCEPTED": accepted,
            }
            response['SUGGESTED_AUTH']=self.evaluate_auth_to_suggest(self.trusted_auth_table)
            if accepted == 1:
                session_key=self.add_thing(message)
                logging.info("Nuova thing aggiunta")
                response['SESSION_KEY']=session_key

            self.send(message['ADDRESS'],message['PORT'],response)
            if accepted == 1:
                self.send_auth_update()
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_response handling, with {address}")  
    
    def send_auth_update(self):
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
                "ADDRESS": self.ip,
                "PORT": self.port,
                "AUTH_ID": self.hostname,
                "A_NONCE": str(os.urandom(2)),
                "UPDATE": thing_list
                }
                self.send(auth['ADDRESS'],auth['PORT'],message)
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
                "SESSION_KEY": session_key,
                "LAST": time.time()
            }
            self.lock.acquire()
            self.registered_entity_table[message['THING_ID']]=new_thing
            self.lock.release()
            logging.debug(f"Thing aggiunta:\n{new_thing}")
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
                self.send_register_response(message,address,0)
            elif not self.check_security_level(message,address):
                self.send_register_response(message,address,0)
            elif not self.check_resource_requirements(message,address):
                self.send_register_response(message,address,0)
            else:
                self.send_register_response(message,address,1)
            logging.debug(self.auth_status())
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_to_auth handling, with {address}")

    def check_think_signature(self,data,address):
        '''
        To be implemented 
        '''
        return True

    def connect_to_auth(self,message,address):
        '''
        Make the response at CONNECT_TO_AUTH from Things,
        PS: A_NONCE shuold be stored to verify it in the next massege exchange.
        '''
        try:
            timestamp = time.time()
            if message['THING_ID'] in self.registered_entity_table:
                self.lock.acquire()
                self.registered_entity_table[message['THING_ID']]['LAST'] = timestamp
                self.lock.release()
                response={
                "MESSAGE_TYPE": 3,
                "AUTH_ID": self.hostname,
                "ADDRESS": self.ip,
                "PORT": self.port,
                "A_NONCE": str(os.urandom(2))
            }
                address=self.get_thing_address(message['THING_ID'])
                self.send(address['ADDRESS'],address['PORT'],response)
            else:
                logging.debug("Thing doesn't recognised, ignoring message")
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
                    "ADDRESS": self.ip,
                    "PORT": self.port,
                    "A_NONCE": str(os.urandom(2)),
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
            timestamp = time.time()
            self.lock.acquire()
            self.registered_entity_table[message['THING_ID']]['LAST'] = timestamp
            self.lock.release()
            session_key_response={
                "MESSAGE_TYPE": 5,
                "AUTH_ID": self.hostname,
                "ADDRESS": self.ip,
                "PORT": self.port,
                "A_NONCE": str(os.urandom(2))
            }

            session_keys=self.get_session_key(message,address)
            
            session_key_response['SESSION_KEY']=session_keys

            self.send_auth_session_key(session_keys,message['THING_ID'])

            address=self.get_thing_address(message['THING_ID'])
            self.send(address['ADDRESS'],address['PORT'],session_key_response)



        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during session_key_request handling, with {address}")

    def auth_session_keys(self,message,address):
        try:
            session_keys=message['SESSION_KEYS']
            self.lock.acquire()
            for thing in session_keys:
                record={message['FROM']:session_keys[thing]}
                if thing in self.pending_keys:
                    self.pending_keys[thing].update(record)
                else:
                    self.pending_keys[thing]=record                      
            self.lock.release()

            logging.info(self.pending_keys)

            
                

        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_session_keys handling, with {address}")

    def get_thing_address(self,thing):
        try:
            return self.registered_entity_table[thing]
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_thing_address for {thing}")

    def auth_update(self,message,address):
        '''
        Handling of AUTH_UPDATE message from other Auth
        '''
        try:
            logging.debug(self.trusted_auth_things)
            auth=message['AUTH_ID']
            things=message['UPDATE']
            self.trusted_auth_things[auth]=things
            logging.debug(self.trusted_auth_things)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_update handling, with {address}")

    def get_pending_keys(self,thing):
        try:
            if thing in self.pending_keys:
                self.lock.acquire()
                ret=self.pending_keys.pop(thing)
                self.lock.release()
                return ret
            else:
                return {}

        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_pending_keys handling")

    def update_request(self,message):
        try:
            timestamp = time.time()
            self.lock.acquire()
            self.registered_entity_table[message['THING_ID']]['LAST'] = timestamp
            self.lock.release()
            response={
            "MESSAGE_TYPE": 10,
            "AUTH_ID": self.hostname,
            "ADDRESS": self.ip,
            "PORT": self.port,
            "A_NONCE": str(os.urandom(2)),
            "SESSION_KEYS":self.get_pending_keys(message['THING_ID'])
            }
            self.send(message['ADDRESS'],message['PORT'],response)


        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during update_request handling")

    def trust_recomendation_request(self, message):
        try:
            response={
                "MESSAGE_TYPE": 16,
                "AUTH_ID": self.hostname,
                "ADDRESS": self.ip,
                "PORT": self.port,
                "A_NONCE": str(os.urandom(2))
            }
            for t_auth in self.trusted_auth_things:
                if message['RECEIVER'] in self.trusted_auth_things[t_auth]:
                    response['RECOMENDATION']=self.trusted_auth_table[t_auth]['TRUST']
                    self.send(message['ADDRESS'],message['PORT'],response)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during trust_recomendation_request handling")

    def trust_recomendation_response(self, message):
        try:
            logging.info(message)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during trust_recomendation_response handling")

    def send(self,receiver_ip,receiver_port,message):
        try:
            logging.debug(f"Try to send message to {receiver_ip}:{receiver_port}")
            UDP_IP = receiver_ip
            UDP_PORT = receiver_port
            MESSAGE = message
            MESSAGE_BYTE=json.dumps(MESSAGE).encode("UTF-8")
            sock = socket.socket(socket.AF_INET, 
                                socket.SOCK_DGRAM) 
            sock.sendto(MESSAGE_BYTE, (UDP_IP, UDP_PORT))
            logging.info(f"Sent {self.get_message_type(message['MESSAGE_TYPE'])}:\n{message}\nto {receiver_ip}:{receiver_port}")
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during send, with {receiver_ip}:{receiver_port}")

    def handle_client(self, data, address):
        plain_message = self.decode_message(data, address)
        logging.info(f"Received {self.get_message_type(plain_message['MESSAGE_TYPE'])}\nmessage: {plain_message} from {plain_message['ADDRESS']}:{plain_message['PORT']}")
        if plain_message['MESSAGE_TYPE'] == 0:
            self.register_to_auth(plain_message, address)
        elif plain_message['MESSAGE_TYPE'] == 2:
            self.connect_to_auth(plain_message,address)
        elif plain_message['MESSAGE_TYPE'] == 4:
            self.session_key_request(plain_message,address)
        elif plain_message['MESSAGE_TYPE'] == 6:
            self.auth_session_keys(plain_message,address)
        elif plain_message['MESSAGE_TYPE']==8:
            self.auth_update(plain_message,address)
        elif plain_message['MESSAGE_TYPE']==9:
            self.update_request(plain_message)
        elif plain_message['MESSAGE_TYPE']==15:
            self.trust_recomendation_request(plain_message)
        elif plain_message['MESSAGE_TYPE']==16:
            self.trust_recomendation_response(plain_message)
        else:
            logging.error("Message type was not recognized")

    def listenT(self):
        while True:
            data, address = self.socket.recvfrom(1024)
            self.handle_client(data,address)

    def resourceT(self):
        for thing in self.registered_entity_table:
            self.registered_entity_table[thing]['LAST']=time.time()
        while True:
            time.sleep(30)
            now=time.time()
            to_delete=[]
            for thing in self.registered_entity_table:
                delta=now-self.registered_entity_table[thing]['LAST']
                logging.debug(f"Delfa of {thing} is {delta}")
                if delta > 30:
                    to_delete.append(thing)

            for thing in to_delete:
                self.lock.acquire()
                deleted=self.registered_entity_table.pop(thing)
                logging.info(f"Deleted Thing {deleted}")
                logging.info(self.registered_entity_table)
                self.avaliable_resorce+=deleted['SEC_REQ']
                self.lock.release()        
            logging.info(self.auth_status())
            self.send_auth_update()

    def start_listening(self):
        logging.debug(f"{self.hostname} Start Listening on {self.ip}:{self.port}")
        listening_thread = threading.Thread(target=self.listenT, daemon= True)
        listening_thread.start()
        #resource_thread = threading.Thread(target=self.resourceT, daemon= True)
        #resource_thread.start()
            
    def template(self,message):
        try:
            pass
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during template handling")

if __name__ == "__main__":
    auth = Auth()
    auth.start_listening()    

    while True:
        time.sleep(30)
        logging.debug("Working")

