import random
import string
from time import sleep

from Grabber.mimic.mimic import Mimic

from Cryptodome.Cipher import ARC4
import requests


class SmokeLoaderMimic(Mimic):

    __bot_id: str = ""
    _required_parmas: list[str] = [
        "c2", "botnet_id", "rc4_encrypt_key", "rc4_decrypt_key"]

    def formPacket(self, command: int, command_option: int | None = None) -> bytes:
        packet = b""

        packet += b"\xE6\x07"  # version, 2 bytes

        if (not self.__bot_id):
            self.__bot_id = "".join(random.choice(
                string.ascii_uppercase + string.digits) for _ in range(40))
            self.__bot_id += "\x00"

        packet += self.__bot_id.encode()  # bot id, 41 bytes

        packet += b"DESKTOP-DLKA3HD\x00"  # computer name, 16 bytes

        packet += self._config["botnet_id"].encode()  # botnet_id, 6 bytes
        packet += b"\x00" * (6 - len(self._config["botnet_id"]))

        packet += b"\xA1"  # win ver, 1 byte
        packet += b"\x01"  # win bit, 1 byte
        packet += b"\x00"  # bot priv, 1 byte

        packet += command.to_bytes(2, "little")  # command id, 2 bytes

        if (command_option):
            packet += command_option.to_bytes(4, "little")
        else:
            packet += b"\x00" * 4

        packet += b"\x01\x00\x00\x00"  # command packet, 4 bytes

        fill_length = random.randint(50, 200)
        fill = "".join(random.choice(string.printable)
                       for _ in range(fill_length))

        packet += fill.encode()  # fill to 128 bytes
        packet += b"\x00"  # last null byte

        cipher = ARC4.new(
            self._config["rc4_encrypt_key"].to_bytes(4, "little"))
        encrypted_packet = cipher.decrypt(packet)

        return encrypted_packet

    def formHeaders(self) -> dict:
        domains = [".net", ".com", ".org"]

        referer_length = random.randint(10, 20)
        referer = "http://" + "".join(random.choice(string.ascii_lowercase)
                                      for _ in range(referer_length))

        referer += random.choice(domains)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "Keep-Alive",
            "Accept": "*/*",
            "Referer": referer
        }

        return headers

    def decryptResponse(self, response: bytes) -> bytes:
        cipher = ARC4.new(
            self._config["rc4_decrypt_key"].to_bytes(4, "little"))
        msg = cipher.decrypt(response)

        return msg

    def run(self) -> None:
        while (1):
            packet = self.formPacket(10001)
            headers = self.formHeaders()

            r = requests.post(
                self._config["c2"], data=packet, headers=headers)
            encrypted_response = r.content
            print(encrypted_response)

            sleep(600)
