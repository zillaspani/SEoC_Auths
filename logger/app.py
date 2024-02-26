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
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))

    def load_init_config(self):
        try:
            with open('data/config/config.json', 'r') as json_file:
                data = json.load(json_file)
            #logging.debug(f"Config file:\n{data}")
            self.ip=data["IP"]
            self.port=data["UDP_PORT"]
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
        plain_message = self.decode_message(data, address)
        logging.info(f"{plain_message}")

    def listenT(self):
        while True:
            data, address = self.socket.recvfrom(1024)
            self.handle_client(data,address)


    def start_listening(self):
        #logging.debug(f"Start Listening on {self.ip}:{self.port}")
        listening_thread = threading.Thread(target=self.listenT, daemon= True)
        listening_thread.start()
            
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

