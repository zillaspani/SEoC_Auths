import re
import json
import pandas as pd

from datetime import datetime
data=[]

def row_tokinizer(riga):
    pattern = r'(\d{2}:\d{2},\d{3}) (CONNECT|TALK) (\w+) ---> (\w+)'
    match = re.match(pattern, riga)
    if match:
        tempo = match.group(1)
        azione = match.group(2)
        origine = match.group(3)
        destinazione = match.group(4)
        return tempo, azione, origine, destinazione
    else:
        return None

def analysis():
    t_start= datetime.strptime(data[0][0], "%H:%M:%S,%f")
    t_end= datetime.strptime(data[len(data)-1][0], "%H:%M:%S,%f")
    n=30
    time=datetime.timedelta(t_end,t_start)
    interval=time/n
    
    print(f"t_start {t_start}")
    print(f"t_end {t_end}")
    print(f"time {time}")
    print(f"interval {interval}")
    #for row in data:




def read_file_log(nome_file):
    with open(nome_file, 'r') as file:
        rows = file.readlines()
        for row in rows:
            row = row.strip()  # Rimuove eventuali spazi bianchi all'inizio o alla fine
            tokens = row_tokinizer(row)
            if tokens:
                time, action, source, dest = tokens
                print("Tempo:", time)
                print("Azione:", action)
                print("Origine:", source)
                print("Destinazione:", dest)
                print()  # Stampa una riga vuota tra le righe del log
                data.append([time,action,source,dest])
            

# Esempio di utilizzo
nome_file = "./data/log/logger_log.log"  # Sostituire con il percorso del proprio file di log
read_file_log(nome_file)
analysis()