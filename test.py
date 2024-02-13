session_keys={'t6': 'S_K_t6', 't8': 'S_K_t8', 't9': 'S_K_t9'}

trusted_auth_things={
      "a2": [
        "t6",
        "t9",
        "t10",
        "t11"
      ],
      "a3":[
        "t8",
        "t10",
        "t29"
      ]
    }

registered_entity_table={
      "t1":{
        "ADDRESS": "192.168.1.100",
        "PORT": 6666,
        "SEC_REQ": 3,
        "SESSION_KEY":"S_K_a1_t1"
      },
      "t2":{
        "ADDRESS": "192.168.1.100",
        "PORT": 6667,
        "SEC_REQ": 3,
        "SESSION_KEY":"S_K_a1_t2"
      },
      "t3":{
        "ADDRESS": "192.168.1.100",
        "PORT": 6668,
        "SEC_REQ": 3,
        "SESSION_KEY":"S_K_a1_t2"
      },
        "t4":{
        "ADDRESS": "192.168.1.100",
        "PORT": 6668,
        "SEC_REQ": 3,
        "SESSION_KEY":"S_K_a1_t2"
      }
    }

trusted_auth_table={
      "a2":{
        "ADDRESS":"192.168.1.100",
        "PORT":"6667"
      },
      "a3":{
        "ADDRESS":"192.168.1.100",
        "PORT":"6668"
      }
    }

def get_auth(thing):
    for auth in trusted_auth_things:
        if thing in trusted_auth_things[auth]:
            return auth


def main():
    for auth in trusted_auth_table.values():
        print(f"{auth['ADDRESS']}+{auth['PORT']}")
  


if __name__ == "__main__":
    main()
