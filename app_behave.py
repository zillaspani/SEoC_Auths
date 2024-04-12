import json
import logging
import math
import os
import socket
import random as rnd
import threading
import time
class Auth:
    registered_entity_table={}
    trusted_auth_table={}
    trusted_auth_things={}
    pending_keys={}
    lock = threading.Lock()
    session_keys_stat=[0,0] # 0 total
    register_stat=[0,0]     # 1 accepted
    migration_plan={}
    MIGRATION=False
    TRUST=False
    def __init__(self):
        logging.basicConfig(
        level=logging.INFO,
        filename=f"data/log/{socket.gethostname()}_log.log",
        format='%(asctime)s,%(msecs)d %(levelname)s %(message)s',
        datefmt='%H:%M')
        self.load_init_config()
        self.avaliable_resource_align()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        self.hostname=socket.gethostname()
        logging.info(self.auth_status())

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
            self.request_accepted=data['REQUEST_ACCEPTED']
            self.total_request = data['TOTAL_REQUEST']
            self.avaliable_resorce=self.resource
            self.trusted_auth_table=data['trusted_auth_table']
            self.trusted_auth_things=data['trusted_auth_things']
            with open('data/config/plan.json', 'r') as json_file:
                data = json.load(json_file)
            self.migration_plan=self.ingest_plan(data['autoClientList'])
            logging.info(self.migration_plan)
        except FileNotFoundError:
            logging.error("Config file not found.")
        except json.JSONDecodeError:
            logging.error("Error decoding JSON data. Check if the JSON config file is valid.")
        except Exception as e:
            logging.error("An unexpected error occurred:", e)

    def ingest_plan(self, plan):
        digested_plan={}
        with open('data/config/address.json', 'r') as json_file:
            data = json.load(json_file)
        for p in plan:
            thing=p['name']
            backupTo=p['backupTo']
            l={}
            for a in backupTo:
                auth=f"a{a}"
                if auth in self.trusted_auth_table and self.TRUST:
                    accepted=self.trusted_auth_table[auth]['A_REQUEST']
                    total=self.trusted_auth_table[auth]['T_REQUEST']
                    accepted_index=len(accepted)-1
                    total_index=len(total)-1
                    p=(accepted[accepted_index]+1)/(total[total_index]+2) # (15)
                    if self.entropy(p)>=0: 
                        l[auth]=data[auth]
                elif not self.TRUST:
                    l[auth]=data[auth]
            digested_plan[thing]=l


        return digested_plan

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
        elif type == 12:
            return "FORWARD_AUTH_SESSION_KEYS"
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

    def evaluate_auth_to_suggest(self,accepted,thing):
        '''
        To do
        '''
        try:
            if accepted ==1:
                pass
            else:
                pass


            suggested_auth={}
            if not self.MIGRATION:
                for auth in self.trusted_auth_table:
                    suggested_auth[auth]={'ADDRESS':self.trusted_auth_table[auth]['ADDRESS'],'PORT':self.trusted_auth_table[auth]['PORT']}
                    break #just one
            else:
                suggested_auth=self.migration_plan[thing]
            
            return suggested_auth
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
            response['SUGGESTED_AUTH']=self.evaluate_auth_to_suggest(accepted,message['THING_ID'])
            if accepted == 1:
                self.request_accepted+=1
                self.register_stat[1]+=1
                session_key=self.add_thing(message)
                logging.info("Nuova thing aggiunta")
                response['SESSION_KEY']=session_key

            self.total_request+=1
            self.register_stat[0]+=1
            self.send(message['ADDRESS'],message['PORT'],response)
            if accepted == 1:
                self.send_auth_update()

        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_response handling, with {address}")  

    def get_recomendation(self,auth):
        '''
        For now, it return only the last value of the list
        '''
        try:

            len_=len(self.trusted_auth_table[auth]['TRUST'])
            
            return self.trusted_auth_table[auth]['TRUST'][len_-1]
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_recomendation for {auth} handling")

    def get_neighbors(self,ex_auth):
        try:
            neighbors={}
            for auth in self.trusted_auth_table:
                if auth != ex_auth:
                    neighbors[auth] = {}
                    neighbors[auth]['ADDRESS']=self.trusted_auth_table[auth]['ADDRESS']
                    neighbors[auth]['PORT']=self.trusted_auth_table[auth]['PORT']
                    neighbors[auth]['TRUST']=self.get_recomendation(auth)
                    neighbors[auth]['THINGS']=self.trusted_auth_things[auth]
                
            return neighbors


        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_neighbors handling")

    def eval_trust(self,auth):
        try:
            accepted=self.trusted_auth_table[auth]['A_REQUEST']
            total=self.trusted_auth_table[auth]['T_REQUEST']
            accepted_index=len(accepted)-1
            total_index=len(total)-1
            p=(accepted[accepted_index]+1)/(total[total_index]+2) # (15)
            self.trusted_auth_table[auth]['TRUST'].append(self.entropy(p))
            
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during eval_trust handling")

    def h(self,p):
        #As was defined in the paper
        return (-1*p)*math.log2(p)-(1-p)*math.log2(1-p)  

    def entropy(self,p):
        try:
            #(1)
            if p==1: return 1
            if p==0: return -1
            if p==0.5: return 0

            if p > 0.5 and p <1:
                return 1 - self.h(p)
            elif p > 0 and p < 0.5:
                return self.h(p)-1
            else:
                raise ValueError
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during entropy handling")

    def auth_update(self,message,address):
        '''
        Handling of AUTH_UPDATE message from other Auth
        '''
        try:
            auth=message['AUTH_ID']
            self.trusted_auth_things[auth]=message['THINGS']
            self.trusted_auth_table[auth]['A_REQUEST'].append(message['A_REQUEST'])
            self.trusted_auth_table[auth]['T_REQUEST'].append(message['T_REQUEST'])
            self.eval_trust(auth)
            self.trusted_auth_table[auth]['RESOURCE'].append(message['RESOURCE'])
            self.trusted_auth_table[auth]['SEC_LEV'].append(message['SEC_LEV'])
            self.trusted_auth_table[auth]['NEIGHBORS']=message['NEIGHBORS']
            logging.debug(self.trusted_auth_things)
            logging.debug(self.trusted_auth_table)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_update handling, with {address}")

    def send_auth_update(self):
        """
        After that a Thing become registerd to an Auth, the latter have to notice this to its trusted Auths.
        """
        try:
            thing_list=[]
            for t in self.registered_entity_table.keys():
                thing_list.append(t)
                    
            for auth in self.trusted_auth_table:
                message={
                "MESSAGE_TYPE": 8,
                "ADDRESS": self.ip,
                "PORT": self.port,
                "AUTH_ID": self.hostname,
                "A_NONCE": str(os.urandom(2)),
                "RESOURCE": self.avaliable_resorce,
                "SEC_LEV": self.security_level,
                "A_REQUEST": self.request_accepted,
                "T_REQUEST": self.total_request, 
                "THINGS": thing_list,
                "NEIGHBORS": self.get_neighbors(auth)
                }
                self.send(self.trusted_auth_table[auth]['ADDRESS'],self.trusted_auth_table[auth]['PORT'],message)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_update handling")
        
    def gen_key(self,par1,par2):
        '''
        Given two parametes, it will return a key
        '''
        return f"S_K_by_{self.hostname}_{par1}_{par2}"
    
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
            p_trust=self.request_accepted/self.total_request
            rand=rnd.random()
            if self.check_if_registered(message,address):
                pass
            elif not self.check_think_signature(message,address) or rand<=(1-p_trust):
                self.send_register_response(message,address,0)
            elif not self.check_security_level(message,address)or rand<=(1-p_trust):
                self.send_register_response(message,address,0)
            elif not self.check_resource_requirements(message,address)or rand<=(1-p_trust):
                self.send_register_response(message,address,0)
            else:
                self.send_register_response(message,address,1)
                to_delete_from_auth=self.get_auth(message['THING_ID'])
                if to_delete_from_auth is not None:
                    self.trusted_auth_things[to_delete_from_auth].remove(message['THING_ID']) #Elimino dalla lista dei vicini  

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

    def get_auth_neighbors(self, thing):
        for auth in self.trusted_auth_table:
            for n_auth in self.trusted_auth_table[auth]['NEIGHBORS']:
                if thing in self.trusted_auth_table[auth]['NEIGHBORS'][n_auth]['THINGS']:
                    return auth,n_auth
        return None,None

    def make_trust(self,t_auth,n_auth):
        '''
        A ----- B ----- C
        A want avaluate the trust of C using the informations ghatered from B that is trusted
        '''
        t_a_b=self.trusted_auth_table[t_auth]['TRUST']
        t_b_c=self.trusted_auth_table[t_auth]['NEIGHBORS'][n_auth]['TRUST']
        trust=t_a_b[len(t_a_b)-1]*t_b_c
        if trust > 0.0:
            return True
        else:
            return False

    def evaluate_auth_trustness(self,thing):
        '''
        Given a thing hostname it will check if the auth can generate the session key accorting to the grade of trusting.
        Input: Thing hostname
        Output: {True/False},{1/0}
        Meaning of {1,0}
        - 0 if the thing belong to a trusted auth
        - 1 if the thing belong to a trusted auth's neighbor 
        '''
        try:
            if thing in self.registered_entity_table:
                return True,2

            auth=self.get_auth(thing)
            if auth is not None:
                return True,0
            else:
                t_auth,n_auth=self.get_auth_neighbors(thing)
                logging.debug(f"t_auth {t_auth}, n_auth {n_auth}")
                if t_auth is not None and self.make_trust(t_auth,n_auth):
                    return True,1

            return False,-1     
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during evaluate_auth_trustness handling")

    def get_session_key(self,message,address):
        try:
            SESSION_KEYS={}
            FORWARD_SESSION_KEYS={}
            TO_STORE={}
            p_trust=self.request_accepted/self.total_request
            rand=rnd.random()
            for thing in message['WHO']:
                if not rand <= (1-p_trust):
                    result,forward=self.evaluate_auth_trustness(thing)
                    if result:
                        if forward==0:
                            SESSION_KEYS[thing]=self.gen_key(message['THING_ID'],thing)
                        if forward==2:
                            TO_STORE[thing]=self.gen_key(message['THING_ID'],thing)
                        if forward==1:
                            FORWARD_SESSION_KEYS[thing]=self.gen_key(message['THING_ID'],thing)
                        
            
            self.total_request+=len(message['WHO'])
            self.request_accepted+=len(SESSION_KEYS)+len(FORWARD_SESSION_KEYS)+len(TO_STORE)
            self.session_keys_stat[0]+=len(message['WHO'])
            self.session_keys_stat[1]+=len(SESSION_KEYS)+len(FORWARD_SESSION_KEYS)+len(TO_STORE)
            return SESSION_KEYS,FORWARD_SESSION_KEYS,TO_STORE
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_session_key handling, with {address}")

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
        return None

    def get_auth_neighbors_address(self,auth):
        try:
            for t_auth in self.trusted_auth_table:
                for n_auth in self.trusted_auth_table[t_auth]['NEIGHBORS']:
                    if n_auth == auth:
                        return self.trusted_auth_table[t_auth]['NEIGHBORS'][n_auth] 
            return None
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_auth_neighbors_address for {auth}")

    def forward_auth_session_key(self,session_keys,sender_thing):
        try:
            d_auth=self.make_dict_auth_things_for_neighbors(session_keys)
            logging.debug(f"d_auth {d_auth}")
            for auth in d_auth.keys():
                auth_address=self.get_auth_neighbors_address(auth)
                message={
                    "MESSAGE_TYPE": 12,
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
            logging.error(f"Error during forward_auth_session_key handling requested by {sender_thing}")

    def make_dict_auth_things_for_neighbors(self,session_keys):
        '''
        Given a dict of pair <thing,session_key> it will produce a dict group by auth with the rispective set of records
        Example:
        Input: session_keys={'t6': 'S_K_t1_t6', 't8': 'S_K_t1_t8', 't9': 'S_K_t1_t9'}
        Output: d_auth={'a2': {'t6': 'S_K_t6', 't9': 'S_K_t9'}, 'a3': {'t8': 'S_K_t8'}}
        '''
        d_auth={}
        for s in session_keys.keys():
            auth=self.get_auth_neighbors(s)[1]
            thing=s
            s_key=session_keys[s]
            record={thing:s_key}
            if auth in d_auth:
                d_auth[auth].update(record)
            else:
                d_auth[auth]=record
        return d_auth

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

            session_keys,forward_session_key,to_store=self.get_session_key(message,address) 
            logging.info(f"Session key={session_keys} forw_session key={forward_session_key} to_store={to_store}")
            merged_keys=session_keys.copy()
            merged_keys.update(forward_session_key)
            merged_keys.update(to_store)
            logging.info(f"merged_session key={merged_keys}")
            session_key_response['SESSION_KEY']=merged_keys #da inviare dalla thing che ha richiesto
            if to_store!={}:
                self.add_pending_key(message['THING_ID'],to_store) #La comunicazione avviene tra things afferenti alla stessa auth
            if session_keys != {}:
                self.send_auth_session_key(session_keys,message['THING_ID']) #Inoltro la chiavi all'auth trusted 
            if forward_session_key != {}:
                self.forward_auth_session_key(forward_session_key,message['THING_ID']) #Inoltro l'eventuale chiave alla trusted auth derivata 
            address=self.get_thing_address(message['THING_ID'])
            self.send(address['ADDRESS'],address['PORT'],session_key_response) #Invio la lista merged alla thinhs





        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during session_key_request handling, with {address}")

    def add_pending_key(self,thing_to,session_keys):
        try:
            self.lock.acquire()
            for thing in session_keys:
                    record={thing_to:session_keys[thing]}
                    if thing in self.pending_keys:
                        self.pending_keys[thing].update(record)
                    else:
                        self.pending_keys[thing]=record
            logging.info(f"PENDING KEYS 2:\n{self.pending_keys}")                                 
            self.lock.release()
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during add_pendig_key handling")
    
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

            logging.info(f"PENDING KEYS:\n{self.pending_keys}")

            
                

        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during auth_session_keys handling, with {address}")

    def get_thing_address(self,thing):
        try:
            return self.registered_entity_table[thing]
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_thing_address for {thing}")

    def get_pending_keys(self,thing):
        try:
            if thing in self.pending_keys:
                self.lock.acquire()
                ret=self.pending_keys.get(thing)
                #ret=self.pending_keys.pop(thing)
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
        elif plain_message['MESSAGE_TYPE']==12:
            self.auth_session_keys(plain_message,address)
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
                if thing in self.pending_keys:
                    self.pending_keys.pop(thing)
                self.avaliable_resorce+=deleted['SEC_REQ']
                self.lock.release()        
            logging.info(self.auth_status())
            self.send_auth_update()
            self.send_logger()

    def send_logger(self):
        try:
            record=f"DATA {self.hostname} ---> {self.register_stat}-{self.session_keys_stat}\n"
            MESSAGE_BYTE=json.dumps(record).encode("UTF-8")
            sock = socket.socket(socket.AF_INET, 
                                socket.SOCK_DGRAM) 
            sock.sendto(MESSAGE_BYTE, (self.ip, 2203))
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during send_logger handling")

    def start_listening(self):
        logging.debug(f"{self.hostname} Start Listening on {self.ip}:{self.port}")
        listening_thread = threading.Thread(target=self.listenT, daemon= True)
        listening_thread.start()
        resource_thread = threading.Thread(target=self.resourceT, daemon= True)
        resource_thread.start()
            
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

