import re
import ctypes

from Grabber.config.sample import Sample
from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex

from Cryptodome.Cipher import ARC4


def SmokeLoader(lib_path: str):

    def decompress_final_stage(buffer):
        if (buffer[-1] != 0xE8 and buffer[-1] != 0xEE):
            return []
        if (buffer[-1] == 0xEE):
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

    c2_url = Regex(
        "c2_url",
        "custom",
        (
            b"\\x48\\x8D\\x15(.{4})"
            b"\\x48\\x8B\\xCF"
        ),
        get_c2_url)

    c2_url_extractor = Extractor("c2_url", [c2_url])

    def decrypt(sample: Sample, regex_result: re.Match):
        final_stage = decrypt_final_stage(sample)

        if (not final_stage):
            return

        offset, size = final_stage[0], final_stage[1]

        xor_key = get_xor_key(sample)

        if (not xor_key):
            return

        extracted_stage = extract_final_stage(sample, xor_key, offset, size)
        decompressed_data = decompress_final_stage(extracted_stage[4:])

        decompressed_sample = Sample()
        decompressed_sample.setData(bytearray(decompressed_data))

        c2_url_extractor.extract(decompressed_sample)
        c2_url = c2_url_extractor.getResult()["c2_url"]

        return c2_url

    c2 = Regex(
        "c2",
        "custom",
        (
            b"(.)"
        ),
        decrypt)

    return Extractor("SmokeLoader", [c2])

# https://dns.google/resolve?name=microsoft.com
# Software\Microsoft\Internet Explorer
# advapi32.dll
# Location:
# plugin_size
# user32
# advapi32
# urlmon
# ole32
# winhttp
# ws2_32
# dnsapi
# shell32
# shlwapi
# svcVersion
# Version
# .bit
# %sFF
# %02x
# %s%08X%08X
# %s\%hs
# %s%s
# regsvr32 /s %s
# %APPDATA%
# %TEMP%
# .exe
# .dll
# .bat
# :Zone.Identifier
# POST
# Content-Type: application/x-www-form-urlencoded
# open
# Host: %s
# PT10M
# 1999-11-30T00:00:00
# Firefox Default Browser Agent %hs
# Accept: */*
# Referer: http://%S%s/
# Accept: */*
# Referer: https://%S%s/
# .com
# .org
# .net
# explorer.exe
