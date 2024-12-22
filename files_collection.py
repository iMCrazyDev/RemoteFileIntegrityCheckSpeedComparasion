import hashlib
import reedsolo
from array import array
import random
import numpy as np

from commpy.channelcoding.convcode import Trellis, conv_encode, viterbi_decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Cryptodome.Util.Padding import unpad


class ReedSolomon:
    def __init__(self, primitive_poly):
        self.prim = primitive_poly
        self.rs = reedsolo.RSCodec(c_exp=16, prim=self.prim, fcr=1)  # Поле GF(2^16)

    def encode(self, data_array):
        return self.rs.encode(data_array)

    def decode(self, encoded_data):
        decoded_data, _, _ = self.rs.decode(encoded_data)
        return array('i', decoded_data)

class ConvolutionCodes:
    def __init__(self):
        pass

    def decode(self, data_bytes):
        data_bits = np.unpackbits(np.frombuffer(data_bytes, dtype=np.uint8)).astype(int)
        g_matrix = np.array([[0o7, 0o5]])
        M = np.array([2])
        trellis = Trellis(M, g_matrix)

        decoded_bits = viterbi_decode(
            data_bits.astype(float),
            trellis,
            tb_depth=5,
            decoding_type='hard'
        )
        return decoded_bits

class FilesCollection:
    def __init__(self, number_of_files, generate_merkle_root=True, generate_solomones=True, generate_aes=False, generate_conv=False):
        self.file_hashes = [self.generate_random_sha256() for _ in range(number_of_files)]
        self.solomones = []
        self.merkle_root = None

        if generate_conv:
            self.conv = ConvolutionCodes()
            self.convolution_codes = [self.conv.decode(bytes.fromhex(hash_bytes)) for hash_bytes in self.file_hashes]

        if generate_aes:
            self.aes = [self.encrypt_aes(hash_bytes.encode('utf-8')) for hash_bytes in self.file_hashes]

        if generate_solomones:
            self.rs = ReedSolomon(self.generate_valid_primitive_poly())
            self.solomones = [self.rs.encode(self.bytes_to_array_i(bytes.fromhex(hash_bytes))) for hash_bytes in self.file_hashes]

        if generate_merkle_root:
            self.merkle_root = self.build_merkle_tree(self.file_hashes)

    def get_all_aes(self):
        return list(self.aes)

    def get_all_hashes(self):
        return list(self.file_hashes)

    def get_all_solomones(self):
        return list(self.solomones)

    def get_merkle_root(self):
        return self.merkle_root

    def get_verification_path(self, file_index):
        path = []
        current_level = self.file_hashes[:]
        index = file_index

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]

                if index == i or index == i + 1:
                    if index == i:
                        path.append((right, False))
                    else:
                        path.append((left, True))

                next_level.append(self.hash_two_values(left, right))

            index //= 2
            current_level = next_level

        return path

    def build_merkle_tree(self, hashes):
        if not hashes:
            raise ValueError("Hash list cannot be empty.")

        current_level = hashes[:]

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                next_level.append(self.hash_two_values(left, right))

            current_level = next_level

        return current_level[0]

    @staticmethod
    def verify_merkle_path(leaf_hash, path, merkle_root):
        computed_hash = leaf_hash

        for hash_value, is_left in path:
            if is_left:
                computed_hash = FilesCollection.hash_two_values(hash_value, computed_hash)
            else:
                computed_hash = FilesCollection.hash_two_values(computed_hash, hash_value)

        return computed_hash == merkle_root

    @staticmethod
    def hash_two_values(hash1, hash2):
        combined = (hash1 + hash2).encode('utf-8')
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def generate_random_sha256():
        random_bytes = random.randbytes(32)
        return hashlib.sha256(random_bytes).hexdigest()

    @staticmethod
    def generate_valid_primitive_poly():
        return 0x1100B
    @staticmethod
    def encrypt_aes(data):
        key = b'1234567890abcdef'  # 16-byte key
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return encrypted_data

    @staticmethod
    def decrypt_aes(data):
        key = b'1234567890abcdef'  # 16-byte key
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted_data

    @staticmethod
    def bytes_to_array_i(data_bytes):
        data_array = array('i')
        for i in range(0, len(data_bytes), 2):
            if i + 1 < len(data_bytes):
                value = (data_bytes[i] << 8) | data_bytes[i + 1]
            else:
                value = (data_bytes[i] << 8)
            data_array.append(value)
        return data_array

