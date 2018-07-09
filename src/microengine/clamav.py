import clamd
import os

from io import BytesIO
from microengine import Microengine

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0

class ClamavMicroengine(Microengine):
    """Clamav microengine scans samples through clamd"""
    def __init__(self, polyswarmd_addr, keyfile, password):
        super().__init__(polyswarmd_addr, keyfile, password)
        self.clamd = clamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)

    async def scan(self, guid, content):
        result = self.clamd.instream(BytesIO(content)).get('stream')
        if len(result) >= 2 and result[0] == 'FOUND':
            return True, True, result[1]

        return True, False, ''
