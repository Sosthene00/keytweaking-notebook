from ecc.util import *
from tx.script import *

from io import BytesIO
import requests

class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
                self.id(),
                self.version,
                tx_ins,
                tx_outs,
                self.locktime,
            )

    def id(self):
        return self.hash().hex()

    def hash(self):
        return hash256(self.serialize())[::-1]

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        total_in = 0
        for tx_in in self.tx_ins:
            total_in += tx_in.value(testnet=self.testnet)
        total_out = 0
        for tx_out in self.tx_outs:
            total_out += tx_out.amount
        return (total_in - total_out)

    def sig_hash(self, input_index, prev_scriptpubkey):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                result += TxIn(
                        prev_tx=tx_in.prev_tx,
                        prev_index=tx_in.prev_index,
                        # script_sig=tx_in.script_pubkey(self.testnet),
                        script_sig=prev_scriptpubkey,
                        sequence=tx_in.sequence,
                    ).serialize()
            else:
                result += TxIn(
                        prev_tx=tx_in.prev_tx,
                        prev_index=tx_in.prev_index,
                        sequence=tx_in.sequence,
                    ).serialize() 
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        result += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(result)
        return h256

    def sign_input(self, input_index, key, prev_scriptpubkey):
        z = self.sig_hash(input_index, prev_scriptpubkey)
        der = key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = key.point.sec()
        script_sig = Script([sig, sec])
        self.tx_ins[input_index].script_sig = script_sig
        return self.verify_input(input_index, prev_scriptpubkey)

    def verify_input(self, input_index, prev_scriptpubkey):
        tx_in = self.tx_ins[input_index]
        script_pubkey = prev_scriptpubkey
        z = self.sig_hash(input_index, script_pubkey)
        combined = tx_in.script_sig + script_pubkey
        return combined.evaluate(z)

    def verify(self):
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def is_coinbase(self):
        return (len(self.tx_ins) == 1) and (self.tx_ins[0].prev_tx == bytes(32)) \
                and (self.tx_ins[0].prev_index == '0xffffffff')

    def coinbase_height(self):
        if self.is_coinbase() == False:
            return False
        return little_endian_to_int(self.tx_ins[0].script_sig.cmds[0])


    @classmethod
    def parse(cls, stream, testnet=False):
        serialized_version = stream.read(4)
        version = little_endian_to_int(serialized_version)
        tx_ins_nb = read_varint(stream)
        tx_ins = []
        for _ in range(tx_ins_nb):
            tx_ins.append(TxIn.parse(stream))
        tx_outs_nb = read_varint(stream)
        tx_outs = []
        for _ in range(tx_outs_nb):
            tx_outs.append(TxOut.parse(stream))
        locktime = little_endian_to_int(stream.read(4))
        return cls(version, tx_ins, tx_outs, locktime, testnet=testnet)

class TxIn:

    def __init__(self, prev_tx: bytes, prev_index: int, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx[::-1].hex(),
            self.prev_index,
        )

    def serialize(self):
        result = self.prev_tx
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey

    @classmethod
    def parse(cls, stream):
        prev_tx = stream.read(32)
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_tx[::-1], prev_index, script_sig, sequence)

class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    def serialize(self):
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

    @classmethod
    def parse(cls, stream):
        amount = little_endian_to_int(stream.read(8))
        length = read_varint(stream)
        script_pubkey = Script(stream.read(length))
        return cls(amount, script_pubkey)

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://blockstream.info/testnet/api'
        else:
            return 'https://blockstream.info/api'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}/hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError('not the same id: {} vs {}'.format(tx.id(),
                    tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

