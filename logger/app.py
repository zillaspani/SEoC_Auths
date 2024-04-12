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
        level=logging.INFO,
        filename=f"data/log/logger_log.log",
        format='%(asctime)s.%(msecs)03d %(message)s',
        datefmt='%H:%M:%S')
        self.load_init_config()
        self.socket_con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_con.bind((self.ip, self.port_connect))
        self.socket_talk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_talk.bind((self.ip, self.port_talk))
        self.socket_reg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_reg.bind((self.ip, self.port_register))
        self.socket_data = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_data.bind((self.ip, self.port_data))

    def load_init_config(self):
        try:
            with open('data/config/config.json', 'r') as json_file:
                data = json.load(json_file)
            #logging.debug(f"Config file:\n{data}")
            self.ip=data["IP"]
            self.port_connect=data["UDP_PORT_CONNECT"]
            self.port_talk=data["UDP_PORT_TALK"]
            self.port_register=data["UDP_PORT_REGISTER"]
            self.port_data=data["UDP_PORT_DATA"]
        except FileNotFoundError:
            logging.error("Config file not found.")
        except json.JSONDecodeError:
            logging.error("Error decoding JSON data. Check if the JSON config file is valid.")
        except Exception as e:
            logging.error("An unexpected error occurred:", e)

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





    def handle_client(self, data, address):
        self.lock.acquire()
        plain_message = self.decode_message(data, address)
        logging.info(f"{plain_message}")
        self.lock.release()

    def listenC(self):
        while True:
            data, address = self.socket_con.recvfrom(1024)
            self.handle_client(data,address)

    def listenT(self):
        while True:
            data, address = self.socket_talk.recvfrom(1024)
            self.handle_client(data,address)
    
    def listenR(self):
        while True:
            data, address = self.socket_reg.recvfrom(1024)
            self.handle_client(data,address)

    def listenD(self):
        while True:
            data, address = self.socket_data.recvfrom(1024)
            self.handle_client(data,address)

    def start_listening(self):
        #logging.debug(f"Start Listening on {self.ip}:{self.port}")
        listeningC_thread = threading.Thread(target=self.listenC, daemon= True)
        listeningT_thread = threading.Thread(target=self.listenT, daemon= True)
        listeningR_thread = threading.Thread(target=self.listenR, daemon= True)
        listeningD_thread = threading.Thread(target=self.listenD, daemon= True)
        listeningC_thread.start()
        listeningR_thread.start()
        listeningT_thread.start()
        listeningD_thread.start()
            
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
        #logging.debug("Working")

