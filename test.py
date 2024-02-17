import json
import datetime
import time
def main():
  with open('a1/data/config/config.json', 'r') as json_file:
      data = json.load(json_file)
  hostname=data['HOSTNAME']
  ip=data["IP"]
  port=data["UDP_PORT"]
  registered_entity_table=load_things(data['registered_entity_table'])
  check(registered_entity_table)
    




def load_things(things):
    for thing in things:
      timestamp = time.time()
      things[thing]['LAST'] = timestamp
      time.sleep(6)
    return things

def check(things):
    now = time.time()
    for thing in things:
        diff = (now - things[thing]['LAST'])
        print(diff)
        if diff > 5 * 1000:
            print(thing)




  


if __name__ == "__main__":
    main()
