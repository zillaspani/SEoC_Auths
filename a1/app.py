import logging
import os
import socket
import threading
import time

class Auth:
    def __init__(self, ip, port):
        logging.basicConfig(
        level=logging.DEBUG,
        filename=f"data/log/${socket.gethostname()}_log.log",
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S')
        self.ip = ip
        self.port = int(port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        self.hostname=socket.gethostname()

    def handle_client(self, data, address):
        logging.info(f"Ricevuto il messaggio '{data.decode()}' da {address}")
        # To do: Implementare gestione messaggi

    def listenT(self):
        while True:
            logging.info("Waiting")
            data, address = self.socket.recvfrom(1024)
            self.handle_client(data,address)
            logging.info("Waiting2")
            

    def start_listening(self):
        logging.info("Start Listening")
        listening_thread = threading.Thread(target=self.listenT, daemon= True)
        listening_thread.start()
            

if __name__ == "__main__":

    auth_ip = os.environ.get('IP')
    auth_port = os.environ.get('UDP_PORT')

    # Crea un'istanza del server UDP
    auth = Auth(auth_ip, auth_port)

    # Avvia il server per ascoltare le richieste dei client
    auth.start_listening()
    

    while True:
        time.sleep(5)
        logging.info("Working")
