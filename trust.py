import math


def main():
    #print(f"Trust({1})={trust_value(1)}")
    print(f"Trust({0.9})={trust_value(0.5)}")
    #print(f"Trust({0})={trust_value(0)}")

def trust_value(p):
    if p >= 0.5 and p <= 1:
        return 1-h(p)
    elif p > 0.0 and p < 0.5:
        return h(p)-1
    else: return -2

def h(p):
    x = -p * math.log2(p) - (1 - p) * math.log2(1 - p)
    print(x)
    return x
    #return ((-1*p)*math.log2(p))-((1-p)*math.log2(1-p))


def send_trust_raccomandation_request():
    #Thing Ta want to establish a connection with Tb using it auth Aa to obtain the session key to allow the to communicate securely
    #Thing Ta from auth Aa to auth Ab cause it want migrate from Aa to Ab  
    #   1:
    #   Seleziona le Auth trusted che hanno un valore di trusted > una soglia 
    #   Selezione i Auth non trusted (Nel mio caso non devo farlo)
    #   Tale insieme di Auth viene chiamato Z
    #   2:
    #   Invia un TRR alle Auth selezionate allo step 1, l'insieme Z
    #      
    #   TRR:
    #   {requestID, sender, receiver, azione, Z, max_trasmit, TLL, trasmission_path (no nel mio caso)}
    #   
    #   requestID: Identificativo univoco della richiesta, serve per controllare se ho gia rivuto un TTR
    #   sender: Auth che invia il TTR
    #   receiver: Thing Tb in case of session_key_request or auth Ab in case of migration request
    #   azione: session_key [0] or migration [1]
    #   max_trasmit: ad ogni hop max_trasmit--, se max_trasmit==0 return 0 se l'auth non è in Z, altrimenti un valore
    #   Time To Live
    #
    #   3:
    #   Aspetta finche non ricevi le risposte alle raccomandation request (ovviamente con timeout)
    pass

def process_trust_raccomandation_request():
    #Processing process when an auth receive a TRR 
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    pass






if __name__ == "__main__":
    main()