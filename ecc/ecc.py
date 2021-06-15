# Elliptic Curves library for cryptography
import hmac, hashlib

from ecc.util import *
from io import BytesIO

P = pow(2, 256) - pow(2, 32) - 977
A = 0
B = 7
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class FieldElement:

    def __init__(self, num, prime):
        if num == None or prime == None:
            error = 'None value not allowed'
            raise ValueError(error)
        if  num >= prime or num < 0: 
            error = f'{num} not in field range 0 to {prime - 1}'
            raise ValueError(error)
        self.num = num 
        self.prime = prime

    def __repr__(self):
        # this overwrite the standard `print()` function
        return f'FieldElement {self.prime}({self.num})'

    def __eq__(self, other):
        # this overwrite the standard `==` operator
        if other is None:
            return False # return an error instead of simply False?
        # you need two things to compare, if not it should fail
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        # this overwrite the standard `!=` operator
        return not self == other
    
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime) # return self.__class__ means retur a new object of the same class

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot substract two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)  

    def __mul__(self, other):
        if isinstance(other, S256Point):
            return int(self.num) * other
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)  

    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        num = self.num * pow(other.num, (self.prime-2), self.prime) % self.prime
        return self.__class__(num, self.prime)

    def __rmul__(self, coefficient):
        coef = self.__class__(coefficient, self.prime)
        return self * coef

class Point:

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + self.a * self.x + self.b:
            raise ValueError(f'({self.x}, {self.y}) is not on the curve')

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
                and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return f'Point({self.x}, {self.y})_{self.a}_{self.b}'

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'Points {self}, {other} are not on the same curve')

        if self.x is None:
            return other
        if other.x is None:
            return self

        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        if self.x != other.x:
            m = (other.y - self.y) / (other.x - self.x)
            x = pow(m, 2) - self.x - other.x
            y = m * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other:
            m = (3 * pow(self.x, 2) + self.a) / (2 * self.y)
            x = pow(m, 2) - 2 * self.x
            y = m * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result

    

class S256Field(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)
    
    def to_int(self):
        return self.num

    def sqrt(self):
        return self**((P + 1) // 4)
    
    def to_bytes(self, length, order):
        return self.num.to_bytes(32, 'big')

class S256Point(Point):

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return self.sec().hex()

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z, sig):
        z = int.from_bytes(z, 'big')
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r

    def verify_schnorr(self, m, sig):
        e = ecc.util.generate_secret(ecc.util.to_string(self, sig.r, m))
        return sig.s * G == sig.r + e * self

    def sec(self, compressed=True):
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') \
                    + self.y.num.to_bytes(32, 'big')

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=True):
        h160 = self.hash160()
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)

    @classmethod
    def parse(self, sec_bin):
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x, y=y)
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        alpha = x**3 + S256Field(B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)


    def create_commitment(self, domain, protocol, msg):
        # implementation of LNPBP 1
        # hash domain and protocol
        domain_digest = hashlib.sha256(domain.encode('utf-8')).digest()
        protocol_digest = hashlib.sha256(protocol.encode('utf-8')).digest()
        # hash both tags' hashes with the msg
        lnpbp1_msg = domain_digest + protocol_digest + msg.encode('utf-8')
        # HMAC s and P to get the tweaking factor f
        HMAC = hmac.new(self.sec(), None, hashlib.sha256)
        HMAC.update(lnpbp1_msg)
        f = int.from_bytes(HMAC.digest(), 'big')
        # assert f < p
        try:
            f < P
        except:
            print("ERROR: tweak overflow secp256k1 order")
        # Compute a new PrivateKey with f as secret
        return PrivateKey(f)

    def tweak_pubkey(self, tweak):
        # add F to P
        return self + tweak

    def verify_commitment(self, domain, protocol, msg, commitment):
        return self + self.create_commitment(domain, protocol, msg).point == commitment

G = S256Point(Gx, Gy)

class PrivateKey:

    def __init__(self, secret, compressed=True, testnet=True):
        if type(secret) is not int:
            self.secret = S256Field(generate_secret(secret))
        else:
            self.secret = S256Field(secret)
        self.point = self.secret * G
        self.compressed = compressed
        self.testnet = testnet

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z: bytes):
        # redefine z as an int
        z = int.from_bytes(z, 'big')
        
        # compute the nonce k deterministically
        k = self.deterministic_k(z)
        
        # compute r, wich is basically the x coordinate of the point that correspond to k
        r = (k * G).x.num
        
        # compute the inverse k
        k_inv = pow(k, N - 2, N)
        
        # we can now compute the signature proper
        s = (z + r * self.secret.to_int()) * k_inv % N
        
        # This is an optimisation to keep the signature slightly smaller
        if s > N / 2:
            s = N - s
            
        # the signature is composed of r and s. Both elements are necessary.
        return Signature(r, s)

    def sign_schnorr(self, z):
        # redefine z as an int
        z = int.from_bytes(z, 'big')
        
        k = self.deterministic_k(z)
        R = k * G
        e = ecc.util.generate_secret(ecc.util.to_string(self.point, R, m))
        s = k + e * self.secret % N
        return Signature(R, s)

    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest() 
        v = hmac.new(k, v, s256).digest() 
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest() 
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate  # <2>
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()

    def wif(self):
        secret_bytes = self.secret.num.to_bytes(32, 'big')
        if self.testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        if self.compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        return encode_base58_checksum(prefix + secret_bytes + suffix)

# TODO: straighten up this method
    @classmethod
    def from_wif(cls, wif): 
        compressed = False
        testnet = True
        combined = decode_base58(wif, 38)
        if combined[0] == 128:
            testnet = False
        elif combined[0] != 239:
            raise ValueError(f"Not a valid wif format: wrong network byte {combined[0]}")
        if combined[-1] == 1:
            compressed = True
            combined = combined[:-1]
        secret = int.from_bytes(combined[1:], 'big')
        return cls(secret, compressed, testnet)


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        res = self.der()
        return res.hex()

    def der(self):
            rbin = self.r.to_bytes(32, byteorder='big')
            # remove all null bytes at the beginning
            rbin = rbin.lstrip(b'\x00')
            # if rbin has a high bit, add a \x00
            if rbin[0] & 0x80:
                rbin = b'\x00' + rbin
            result = bytes([2, len(rbin)]) + rbin  # <1>
            sbin = self.s.to_bytes(32, byteorder='big')
            # remove all null bytes at the beginning
            sbin = sbin.lstrip(b'\x00')
            # if sbin has a high bit, add a \x00
            if sbin[0] & 0x80:
                sbin = b'\x00' + sbin
            result += bytes([2, len(sbin)]) + sbin
            return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)
