from jostedal.utils import saslprep, ha1
from jostedal.stun import attributes
import os
import logging


logger = logging.getLogger(__name__)


class CredentialMechanism(object):
    def update(self, message):
        pass


class ShortTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.1
    """
    def __init__(self, username, password):
        self.username = username
        self.hmac_key = saslprep(password).encode()

    def update(self, msg):
        msg.add_attr(attributes.Username, self.username)
        msg.add_attr(attributes.MessageIntegrity, self.hmac_key)


class LongTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.2
    """
    def __init__(self, realm, users={}):
        self.nonce = self.generate_nonce()
        self.realm = realm
        self.hmac_keys = {}
        for username, credentials in users.items():
            key = credentials.get('key')
            if not key:
                password = credentials.get('password')
                if not password:
                    logger.warning("Invalid credentials for %s", username)
                    continue
            self.hmac_keys[username] = ha1(username, self.realm, password)

    def add_user(self, username, password):
        self.hmac_keys[username] = ha1(username, self.realm, password)

    def generate_nonce(self, length=16):
        return os.urandom(length//2).hex()

    def update(self, msg):
        msg.add_attr(attributes.Nonce, self.nonce.encode())
        msg.add_attr(attributes.Realm, self.realm.encode())
        msg.add_attr(attributes.MessageIntegrity, self.hmac_keys[msg.get_attr(attributes.Username)])

    def __str__(self):
        return "realm={}".format(self.realm)

    def __repr__(self, *args, **kwargs):
        return "LongTermCredentialMechanism({})".format(self)
