import pandas as pd
import matplotlib.pyplot as plt

# Leggi i dati dal file di log e convertili in una struttura dati appropriata
def leggi_log(file_path):
    log_data = []
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(' ')
            if len(parts)!=1:
                timestamp = parts[0]
                action = parts[1]
                source = parts[2]
                dest = parts[4]
                log_data.append((timestamp, action,source,dest))
    return log_data

# Elabora i dati e conta il numero di connessioni per ogni secondo
def elabora_dati(log_data):
    df = pd.DataFrame(log_data, columns=['timestamp', 'action','source', 'dest'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%H:%M:%S.%f')
    df = df[~df['action'].str.contains('TALK')]
    df = df.drop_duplicates()
    connessioni_per_secondo = df.resample('s', on='timestamp').size()
    return connessioni_per_secondo

# Crea il grafico
def crea_grafico(connessioni_per_secondo):
    connessioni_per_secondo.plot(kind='line', figsize=(10, 6))
    plt.title('Numero di connessioni per secondo')
    plt.xlabel('Tempo')
    plt.ylabel('Numero di connessioni')
    plt.grid(True)
    plt.show()

# Esecuzione del processo
log_data = leggi_log('./data/log/logger_log.log')
connessioni_per_secondo = elabora_dati(log_data)
crea_grafico(connessioni_per_secondo)
