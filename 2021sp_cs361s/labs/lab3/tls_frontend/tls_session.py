import asyncio, time, struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac # avoid name collision
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from scapy.all import *
from scapy.layers.tls.keyexchange import _TLSSignature
from scapy.layers.tls.handshake import _TLSCKExchKeysField
from datetime import datetime, timedelta

from .debug import Debug
from .utils import DHParamsSerialization

randstring = Debug.replayable(Debug.random)
timestamp  = Debug.replayable(time.time)
ServerDHParams = Debug.replayable(ServerDHParams, DHParamsSerialization)

class TLSSession:
    def __init__(self):
        # manually set value
        self.tls_version = 0x303
        self.read_seq_num = 0
        self.write_seq_num = 0
        self.PRF = PRF()

        self.client_time = None
        self.client_random_bytes = None
        
        self.server_time = None
        self.server_random_bytes = None

        self.server_rsa_privkey = None
        self.client_dh_params = None

        self.mac_key_size = 20
        self.enc_key_size = 16
        #self.iv_size = 16

        self.handshake = True

        # automatically calculated
        self.client_random = None
        self.server_random = None
        self.server_dh_params = ServerDHParams()
        #self.server_dh_params.fill_missing()
        self.server_dh_privkey = self.server_dh_params.tls_session.server_kx_privkey
        self.client_dh_pubkey = None
        self.pre_master_secret = None
        self.master_secret = None
        self.read_mac = None
        self.write_mac = None
        self.read_enc = None
        self.write_enc = None
        self.read_iv = None
        self.write_iv = None
        self.key_block_len = (2*self.mac_key_size)+(2*self.enc_key_size)#+(2*self.iv_size)

        self.handshake_messages = b""

    def set_client_random(self, time_part, random_part):
        # STUDENT TODO
        """
        1. set client_time, client_bytes
        2. calculate client_random. There is a method for this
        """

        self.client_time = time_part
        self.client_random_bytes = random_part
        self.client_random = self.time_and_random(self.client_time, self.client_random_bytes)

    def set_server_random(self):
        # STUDENT TODO
        """
        1. set server_time, server_bytes
        2. calculate server_random. There is a method for this
        """


        self.server_time = int(timestamp())
        self.server_random_bytes = randstring(28)
        self.server_random = self.time_and_random(self.server_time, self.server_random_bytes)
        print(len(self.server_random), self.server_random)

    def set_server_rsa_privkey(self, rsa_privkey):
        self.server_rsa_privkey = rsa_privkey

    def set_client_dh_params(self, client_params):
        self.client_dh_params = client_params  
        p = pkcs_os2ip(self.server_dh_params.dh_p)
        g = pkcs_os2ip(self.server_dh_params.dh_g)
        pn = dh.DHParameterNumbers(p,g)
        y = pkcs_os2ip(self.client_dh_params.dh_Yc)
        public_key_numbers = dh.DHPublicNumbers(y, pn)
        self.client_dh_pubkey = public_key_numbers.public_key(default_backend())
        self._derive_keys()

    def _derive_keys(self):
        # STUDENT TODO
        """
        1. calculate pre_master_secret
        2. calculate master_secret
        3. calculate a key block
        4. split the key block into read and write keys for enc and mac
        """

        self.pre_master_secret = self.server_dh_privkey.exchange(self.client_dh_pubkey)
        print("==============", self.pre_master_secret)
        self.master_secret = self.PRF.compute_master_secret(self.pre_master_secret, self.client_random, self.server_random)
        key_block = self.PRF.derive_key_block(self.master_secret, self.server_random, self.client_random,self.key_block_len)

        print("==============", key_block)

        self.read_mac, key_block = (key_block[: self.mac_key_size], key_block[self.mac_key_size :])
        self.write_mac, key_block = (key_block[: self.mac_key_size], key_block[self.mac_key_size :])

        self.read_enc, key_block = (key_block[: self.enc_key_size], key_block[self.enc_key_size :])
        self.write_enc, key_block = (key_block[: self.enc_key_size], key_block[self.enc_key_size :])

        print("==============", key_block)
        

    def tls_sign(self, bytes):
        """
        1. Create a TLSSignature object. set sig_alg to 0x0401
        2. use this object to sign the bytes
        """
        sig = None # this should be the signature object
        return sig


    def decrypt_tls_pkt(self, tls_pkt, **kargs):
        # scapy screws up and changes the first byte if it can't decrypt it
        # from 22 to 23 (handshake to application). Check if this happens and fix
        packet_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)
        tls_pkt_bytes = struct.pack("!B",packet_type)+tls_pkt_bytes[1:]
        
        # STUDENT TODO
        """
        1. The beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS decryption process on tls_pkt_bytes
        3. Technically, you don't have to do the hmac. wget will do it right
        4. But if you check the hmac, you'll know your implementation is correct!
        5. return ONLY the decrypted plaintext data
        6. NOTE: When you do the HMAC, don't forget to re-create the header with the plaintext len!
        """
        plaintext = b''
        header = tls_pkt_bytes[:5]
        data = tls_pkt_bytes[5:]
        iv = data[:16]
        data = data[16:]
        assert len(data) < 2 ** 16

        cipher = Cipher(algorithms.AES(self.read_enc), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        plaintext_data = decryptor.update(data) + decryptor.finalize()
        pad_len = int(plaintext_data[-1]) + 1
        print(plaintext_data)
        print(pad_len)
        plaintext_no_pad = plaintext_data[:-pad_len]
        mac = plaintext_no_pad[-20:]

        plaintext_no_mac = plaintext_no_pad[:-20]
        mac_hdr = header[:3] + struct.pack("!H", len(plaintext_no_mac))
        cmac = self.compute_mac(mac_hdr, plaintext_no_mac, False)

        print(len(plaintext_no_mac), plaintext_no_mac)
        print(len(mac), len(cmac))
        print(mac, cmac)

        assert mac == cmac

        return plaintext_no_mac

    def encrypt_tls_pkt(self, tls_pkt, test_iv=None):
        pkt_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)

        # scapy can make some mistakes changing the first bytes on handshakes
        if tls_pkt_bytes[0] != pkt_type:
            Debug.print(tls_pkt_bytes[0], pkt_type)
            tls_pkt_bytes = struct.pack("!B",pkt_type)+tls_pkt_bytes[1:]
        
        # no matter what, should only have one msg
        plaintext_msg = tls_pkt.msg[0]
        plaintext_bytes = raw(plaintext_msg)
        
        # STUDENT TODO
        """
        1. the beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS encryption process on the plaintext_bytes
        3. You have to do hmac. This is the write mac key
        4. You have to compute a pad
        5. You can use os.urandom(16) to create an explicit IV
        6. return the iv + encrypted data
        """
        
        ciphertext = b""
        
        mac = self.compute_mac(tls_pkt_bytes[:5], plaintext_bytes)
        temp2 = (len(plaintext_bytes) + len(mac)) % 16
        pad_len = 16 - temp2

        pad = struct.pack("!B", pad_len - 1) * pad_len
        full_pt = plaintext_bytes + mac + pad
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.write_enc), modes.CBC(iv), default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(full_pt) + encryptor.finalize()
        ciphertext = iv + ciphertext

        print(len(ciphertext), ciphertext)

        header = tls_pkt_bytes[:3] + struct.pack("!H", len(ciphertext))
        ciphertext = header + ciphertext

        print(len(ciphertext), ciphertext)

        return ciphertext

    def record_handshake_message(self, m):
        self.handshake_messages += m

    def compute_handshake_verify(self, mode):
        # STUDENT TODO
        """
        1. use PRF.compute_verify_data to compute the handshake verify data
            arg_1: the string "server"
            arg_2: mode
            arg_3: all the handshake messages so far
            arg_4: the master secret
        """
        verify_data = b""
        verify_data = self.PRF.compute_verify_data("server", mode, self.handshake_messages, self.master_secret)
        return verify_data

    def time_and_random(self, time_part, random_part=None):
        if random_part is None:
            random_part = randstring(28)
        return struct.pack("!I",time_part) + random_part

        
        
