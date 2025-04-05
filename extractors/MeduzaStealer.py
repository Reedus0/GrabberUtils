import re
import struct
import base64
import json

from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex
from Grabber.config.sample import Sample


def MeduzaStealer():

    def generate_key(long_key: bytes, short_key: bytes, round: int) -> bytes:
        result = bytearray(64)
        result[:16] = b"expand 32-byte k"

        def pack_values(index, key):
            return key[index] | ((key[index + 1] | (int.from_bytes(key[index + 2:index + 4], 'little') << 8)) << 8)

        struct.pack_into("<I", result, 16, pack_values(0, long_key))
        struct.pack_into("<I", result, 20, pack_values(4, long_key))
        struct.pack_into("<I", result, 24, pack_values(8, long_key))
        struct.pack_into("<I", result, 28, pack_values(12, long_key))
        struct.pack_into("<I", result, 32, pack_values(16, long_key))
        struct.pack_into("<I", result, 36, pack_values(20, long_key))
        struct.pack_into("<I", result, 40, pack_values(24, long_key))
        struct.pack_into("<I", result, 44, pack_values(28, long_key))

        struct.pack_into("<Q", result, 48, round)

        struct.pack_into("<I", result, 56, pack_values(0, short_key))
        struct.pack_into("<I", result, 60, pack_values(4, short_key))

        return bytes(result)

    def rotate_left(value, shift):
        return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

    def quarter_round(a, b, c, d):
        a = (a + b) & 0xFFFFFFFF
        d ^= a
        d = rotate_left(d, 16)

        c = (c + d) & 0xFFFFFFFF
        b ^= c
        b = rotate_left(b, 12)

        a = (a + b) & 0xFFFFFFFF
        d ^= a
        d = rotate_left(d, 8)

        c = (c + d) & 0xFFFFFFFF
        b ^= c
        b = rotate_left(b, 7)

        return a, b, c, d

    def chacha20_block(state):
        working_state = state.copy()
        for _ in range(10):
            working_state[0], working_state[4], working_state[8], working_state[12] = \
                quarter_round(working_state[0], working_state[4],
                              working_state[8], working_state[12])
            working_state[1], working_state[5], working_state[9], working_state[13] = \
                quarter_round(working_state[1], working_state[5],
                              working_state[9], working_state[13])
            working_state[2], working_state[6], working_state[10], working_state[14] = \
                quarter_round(working_state[2], working_state[6],
                              working_state[10], working_state[14])
            working_state[3], working_state[7], working_state[11], working_state[15] = \
                quarter_round(working_state[3], working_state[7],
                              working_state[11], working_state[15])

            working_state[0], working_state[5], working_state[10], working_state[15] = \
                quarter_round(working_state[0], working_state[5],
                              working_state[10], working_state[15])
            working_state[1], working_state[6], working_state[11], working_state[12] = \
                quarter_round(working_state[1], working_state[6],
                              working_state[11], working_state[12])
            working_state[2], working_state[7], working_state[8], working_state[13] = \
                quarter_round(working_state[2], working_state[7],
                              working_state[8], working_state[13])
            working_state[3], working_state[4], working_state[9], working_state[14] = \
                quarter_round(working_state[3], working_state[4],
                              working_state[9], working_state[14])

        for i in range(16):
            working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

        return working_state

    def decrypt_chacha20(input_bytes):
        assert len(input_bytes) == 64
        state = list(struct.unpack('<16I', input_bytes))
        output = chacha20_block(state)
        return struct.pack('<16I', *output)

    def decrypt_config(config, key):
        result = []

        subkey = key
        for i in range(len(config)):
            if (i % 64 == 0):
                key = list(key)
                key[48] = i // 64
                key = bytes(key)
                subkey = decrypt_chacha20(key)

            result.append(chr(config[i] ^ subkey[i % len(subkey)]))

        return "".join(result)

    def get_c2(sample: Sample, regex_result: re.Match):
        extract_result = regex_result[1]

        virtual_offset = sample.getVirtualAddress(
            regex_result.start()) + int.from_bytes(extract_result, "little")
        physical_offset = sample.getPhysicalAddress(virtual_offset + 13)


        if (extract_result):
            long_key = base64.b64decode(sample.readASCIIString(physical_offset - 0x40))
            short_key = base64.b64decode(sample.readASCIIString(physical_offset - 0x10))
            config = base64.b64decode(sample.readASCIIString(physical_offset))

            generated_key = generate_key(bytes(long_key), bytes(short_key), 0)
            decrypted_config = decrypt_config(bytes(config), generated_key)

            json_config = json.loads(decrypted_config)
            return json_config["ip"]

    c2 = Regex(
        "c2",
        "custom",
        (
            b"\\x41\\xB8.{4}"
            b"\\x48\\x8D\\x15(.{4})"
            b"\\x48\\x8D\\x4C\\x24\\x70"
            b"\\xE8.{4}"
            b"\\x90"
            b"\\x4C\\x8D.{3}"
        ),
        get_c2)

    return Extractor("MeduzaStealer", [c2])
