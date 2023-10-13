import hashlib


def saslprep(string):
    #TODO
    return string

def ha1(username, realm, password):
    print(username, realm, password)
    return hashlib.md5(':'.join((username, realm, saslprep(password))).encode()).digest()
