import pandas as pd
import matplotlib.pyplot as plt

# Leggi i dati dal file di log e convertili in una struttura dati appropriata
def leggi_log(file_path):
    log_data = []
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(' ')
            if len(parts) > 1:
                timestamp = parts[0]
                action = parts[1]
                source = parts[2]
                dest = parts[4]
                log_data.append((timestamp, action, source, dest))
    return log_data

# Elabora i dati e conta il numero di connessioni e "talk" per ogni intervallo di tempo
def elabora_dati(log_data, intervallo):
    df = pd.DataFrame(log_data, columns=['timestamp', 'action', 'source', 'dest'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%H:%M:%S.%f')
    df = df[~df['action'].str.contains('TALK')]
    df = df.drop_duplicates()
    connessioni_per_secondo = df.resample(intervallo, on='timestamp').size()
    return connessioni_per_secondo

# Crea il grafico
def crea_grafico(connessioni_per_secondo_conn, connessioni_per_secondo_talk):
    plt.figure(figsize=(10, 6))
    connessioni_per_secondo_conn.plot(label='Connessioni', color='blue')
    connessioni_per_secondo_talk.plot(label='Talk', color='red')
    plt.title('Numero di connessioni e "talk" per ogni intervallo di tempo')
    plt.xlabel('Tempo')
    plt.ylabel('Numero')
    plt.legend()
    plt.grid(True)
    plt.show()

# Esecuzione del processo
log_data = leggi_log('./data/log/logger_log.log')
connessioni_per_secondo_conn = elabora_dati(log_data, '500L')
connessioni_per_secondo_talk = elabora_dati(log_data, '500L')
crea_grafico(connessioni_per_secondo_conn, connessioni_per_secondo_talk)
