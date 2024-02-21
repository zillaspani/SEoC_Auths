import os
import json
import time

class trr:

    TTL=5

    def __init__(self, sender, receiver, action, z_list):
        try:
            self.requestID = os.urandom(5).hex()
            self.sender = sender
            self.receiver = receiver
            if action == 0 or action == 1:
                self.action = action
            else:
                raise ValueError("Action must be 0 or 1")
            self.z_list = z_list
            self.max_transit = 2
            self.timestamp = time.time()
        except ValueError as ve:
            print(ve)
        except Exception as ex:
            print(ex)

    def toJSON(self):
        return json.dumps(self.__dict__)

    @staticmethod
    def fromJSON(json_str):
        try:
            data = json.loads(json_str)
            return trr(data['sender'], data['receiver'], data['action'], data['z_list'])
        except KeyError as ke:
            print(f"Missing key in JSON: {ke}")
        except json.JSONDecodeError as je:
            print(f"Error decoding JSON: {je}")
        except Exception as ex:
            print(f"An error occurred: {ex}")
    
    def isValid(self):
        try:
            #Check time to live
            now=time.time()
            delta=now-self.timestamp
            if delta > self.TTL:
                return False
            else:
                return True
        except Exception as ex:
            pass 

def main():
    pino = trr("t1", "a2", 0, ["a3", "a4"])
    json_str = pino.toJSON()
    print(json_str)
    pino2 = trr.fromJSON(json_str)
    print(pino2.toJSON())

if __name__ == "__main__":
    main()
