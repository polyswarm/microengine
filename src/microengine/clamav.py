import clamd
import os

from io import BytesIO
from polyswarmclient.microengine import Microengine

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0

class ClamavMicroengine(Microengine):
    """Microengine which scans samples through clamd"""

    def __init__(self, polyswarmd_addr, keyfile, password, api_key=None, testing=False):
        """Initialize a ClamAV microengine

        Args:
            polyswarmd_addr (str): Address of polyswarmd
            keyfile (str): Path to private key file to use to sign transactions
            password (str): Password to decrypt the encrypted private key
            api_key (str): API key to use with polyswarmd
        """
        super().__init__(polyswarmd_addr, keyfile, password, api_key, testing)
        self.clamd = clamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)

    async def scan(self, guid, content):
        """Scan an artifact with ClamAV

        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            content (bytes): Content of the artifact to be scan
        Returns:
            (bool, bool, str): Tuple of bit, verdict, metadata

            bit (bool): Whether to include this artifact in the assertion or not
            verdict (bool): Whether this artifact is malicious or not
            metadata (str): Optional metadata about this artifact
        """
        result = self.clamd.instream(BytesIO(content)).get('stream')
        if len(result) >= 2 and result[0] == 'FOUND':
            return True, True, result[1]

        return True, False, ''
