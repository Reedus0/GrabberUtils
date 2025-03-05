import hashlib
import base64

from Grabber.mimic.mimic import Mimic

from Cryptodome.Cipher import DES3, ARC2
import requests


class PureCrypterLoaderMimic(Mimic):

    _required_parmas: list[str] = ["url", "key", "iv", "algorithm"]

    def decrypt(self, data: bytes) -> bytes:
        match (self._config["algorithm"]):
            case "DES3":
                key = base64.b64decode(self._config["key"])
                iv = base64.b64decode(self._config["iv"])

                cipher = DES3.new(key, DES3.MODE_CBC, iv)
                result = cipher.decrypt(data)
                return result
            case "RC2":
                key = base64.b64decode(self._config["key"])
                iv = base64.b64decode(self._config["iv"])

                cipher = ARC2.new(key, ARC2.MODE_CBC, iv, effective_keylen=128)
                result = cipher.decrypt(data)
                return result

        return bytearray()

    def run(self) -> None:
        r = requests.get(self._config["url"])
        encrypted_payload = r.content
        payload = self.decrypt(encrypted_payload)

        self.saveSample(hashlib.sha256(payload).hexdigest(), payload)
