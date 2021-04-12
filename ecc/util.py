import hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
SIGHASH_ALL = 1
PERIOD = 60*60*24*14

def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def string_to_byte(s):
    return s.encode()

def generate_secret(s):
    raw_secret = string_to_byte(str(s))
    return int.from_bytes(hash256(raw_secret), 'big')

def to_string(*args):
    a = [args]
    b = ""
    for thing in args[:]:
        b += str(thing)
    return b

def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder='big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address {} {}'.format(checksum,
            hash256(combined[:-4])[:4]))
    return combined[1:-4]

def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()

def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])

def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

def int_to_little_endian(a, length):
    return a.to_bytes(length, 'little')

def read_varint(s):
    i = s.read(1)[0]
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    else:
        return i

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))

def find_duplicate(key, filename):
    with open(filename, "r") as file:
        for line in file:
            if line.rstrip('\n') == str(key):
                return True
        return False

def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256**(exponent - 3)
    
def target_to_bits(target):
    raw_bytes = target.to_bytes(32, 'big')
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] > 0x7f:
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits

def bit_field_to_bytes(bit_field):
    if len(bit_field) % 8 != 0:
        raise RuntimeError('bit_field does not have a length that is divisible by 8')
    result = bytearray(len(bit_field) // 8)
    for i, bit in enumerate(bit_field):
        byte_index, bit_index = divmod(i, 8)
        if bit:
            result[byte_index] |= 1 << bit_index
    return bytes(result)


def bytes_to_bit_field(some_bytes):
    flag_bits = []
    # iterate over each byte of flags
    for byte in some_bytes:
        # iterate over each bit, right-to-left
        for _ in range(8):
            # add the current bit (byte & 1)
            flag_bits.append(byte & 1)
            # rightshift the byte 1
            byte >>= 1
    return flag_bits

def merkle_parent(hash1, hash2):
    return hash256(hash1 + hash2)

def merkle_parent_level(hashes):
    if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    parent_level = []
    for i in range(0, len(hashes), 2):
        parent = merkle_parent(hashes[i], hashes[i + 1])
        parent_level.append(parent)
    return parent_level

def merkle_root(hashes):
    current_level = hashes
    while len(current_level) > 1:
        print(*hashes)
        current_level = merkle_parent_level(current_level)
        print(*current_level)
    return current_level[0]
