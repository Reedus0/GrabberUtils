import re
import ctypes

from Grabber.config.sample import Sample
from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex
from Grabber.config.processor import Processor

from Cryptodome.Cipher import ARC4


def SmokeLoaderId():
    def get_botnet_id(sample: Sample, regex_result: re.Match):
        original_data = sample.getData()

        sample_length = len(original_data) - 1
        start_non_zero_data = 0
        for i in range(sample_length):
            current_byte = original_data[sample_length-i]
            if current_byte != 0:
                start_non_zero_data = sample_length-i
                break
        try:
            botnet_id = original_data[start_non_zero_data -
                                      3:start_non_zero_data+1].decode("utf-8")
        except UnicodeDecodeError:
            botnet_id = None

        return botnet_id

    botnet_id = Regex(
        "botnet_id",
        "custom",
        (
            b"(.)"
        ),
        get_botnet_id)

    return Extractor("SmokeLoaderId", [botnet_id])


def ExtractSmokeLoader(lib_path: str):

    def decompress_final_stage(buffer):
        allowed_bytes = [0xE8, 0xEE, 0x31, 0x1F]

        if (buffer[-1] not in allowed_bytes):
            return []
        buffer[-1] = 0xE8

        lzsa = ctypes.CDLL(lib_path + "/" + "lzsa.so")

        lzsa.lzsa2_decompress.argtypes = [ctypes.POINTER(
            ctypes.c_char), ctypes.POINTER(ctypes.c_char)]

        pointer_buffer = (ctypes.c_char * len(buffer))(*buffer)
        pointer_out = (ctypes.c_char * 0x40000)()

        lzsa.lzsa2_decompress(
            ctypes.cast(pointer_out, ctypes.POINTER(ctypes.c_char)),
            ctypes.cast(pointer_buffer, ctypes.POINTER(ctypes.c_char))
        )

        return pointer_out[:]

    def get_xor_key(sample: Sample):
        original_data = sample.getData()

        xor_key = 0

        for i in range(255):
            sample.setData(bytearray([x ^ i for x in original_data]))
            xor_key_extractor.extract(sample)
            xor_key = xor_key_extractor.getResult()["xor_key"]
            if (xor_key):
                break
        else:
            sample.setData(original_data)
            return

        sample.setData(original_data)
        return xor_key

    xor_key = Regex(
        "xor_key",
        "int32",
        (
            b"\\xBA(.{4})"
            b"\\x8B\\x4D\\x0C"
        ))

    xor_key_extractor = Extractor("xor_key", [xor_key])

    def get_final_stage(sample: Sample, regex_result: re.Match):
        if (regex_result):
            offset = int.from_bytes(regex_result.group(1), "little")
            size = int.from_bytes(regex_result.group(2), "little")
            return [offset, size]
        return None

    final_stage = Regex(
        "final_stage",
        "custom",
        (
            b"\\xEB."
            b"\\x8D\\x83(.{4})"
            b"\\xB9(.{4})"
        ),
        get_final_stage)

    final_stage_extractor = Extractor("final_stage", [final_stage])

    def decrypt_final_stage(sample: Sample):
        original_data = sample.getData()

        final_stage = []

        for i in range(255):
            sample.setData(bytearray([x ^ i for x in original_data]))
            final_stage_extractor.extract(sample)
            final_stage = final_stage_extractor.getResult()["final_stage"]
            if (final_stage):
                break
        else:
            sample.setData(original_data)
            return

        sample.setData(original_data)

        return final_stage

    def extract_final_stage(sample: Sample, xor_key: int, offset: int, size: int):
        original_data = sample.getData()

        final_stage = []

        bytes_key = xor_key.to_bytes(4, byteorder="little")
        physical_offset = sample.getPhysicalAddress(0x400000 + offset)

        for i in range(size):
            final_stage.append(
                original_data[physical_offset + i] ^ bytes_key[i % len(bytes_key)])

        return final_stage

    def decrypt(sample: Sample):
        final_stage = decrypt_final_stage(sample)

        if (not final_stage):
            return

        offset, size = final_stage[0], final_stage[1]

        xor_key = get_xor_key(sample)

        if (not xor_key):
            return

        extracted_stage = extract_final_stage(
            sample, xor_key, offset, size)
        decompressed_data = decompress_final_stage(extracted_stage[4:])

        decompressed_sample = Sample()
        decompressed_sample.setData(bytearray(decompressed_data))

        return decompressed_sample

    return Processor("SmokeLoader", decrypt)


def SmokeLoader():

    decrypt_key = Regex(
        "rc4_decrypt_key",
        "int32",
        (
            b"\\xC7\\x45\\x8F(.{4})"
            b"\\xE8.{4}"
        ))

    encrypt_key = Regex(
        "rc4_encrypt_key",
        "int32",
        (
            b"\\xC7\\x44\\x24\\x40(.{4})"
            b"\\xE8.{4}"
        ))

    def get_c2_url(sample: Sample, regex_result: re.Match):
        original_data = sample.getData()

        result = []

        negative_offset = int.from_bytes(regex_result[1], "little")
        offset = regex_result.start() - (0xFFFFFFFF - negative_offset) + 6

        for i in range(original_data[offset]):
            result.append(original_data[offset + i + 5])

        cipher = ARC4.new(bytearray(original_data[offset + 1:offset + 5]))
        msg = cipher.decrypt(bytearray(result))
        return msg.decode()

    c2 = Regex(
        "c2",
        "custom",
        (
            b"\\x48\\x8D\\x15(.{4})"
            b"\\x48\\x8B\\xCF"
        ),
        get_c2_url)

    return Extractor("SmokeLoader", [c2, encrypt_key, decrypt_key])
