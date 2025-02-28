import hashlib
import base64

from Grabber.mimic.mimic import Mimic

from Cryptodome.Cipher import DES3
import requests


class DotnetLoaderMimic(Mimic):

    _required_parmas: list[str] = ["url", "key", "iv"]

    def decrypt(self, data: bytes) -> bytes:
        key = base64.b64decode(self._config["key"])
        iv = base64.b64decode(self._config["iv"])

        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        result = cipher.decrypt(data)
        return result

    def run(self) -> None:
        r = requests.get(self._config["url"])
        encrypted_payload = r.content
        payload = self.decrypt(encrypted_payload)

        self.saveSample(hashlib.sha256(payload).hexdigest(), payload)
