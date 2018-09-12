import yara
import tempfile
import os
import clamd

from io import BytesIO
from polyswarmclient.microengine import Microengine

# ClamAV config
CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0

# Yara rules import
RULES_DIR = 'data/yara-rules/'


class MultiMicroengine(Microengine):
    """Microengine which matches yara rules and scans samples through clamd"""

    def __init__(self, polyswarmd_addr, keyfile, password, api_key=None, testing=False, insecure_transport=False):
        """Initialize a ClamAV/Yara microengine

        Args:
            polyswarmd_addr (str): Address of polyswarmd
            keyfile (str): Path to private key file to use to sign transactions
            password (str): Password to decrypt the encrypted private key
            api_key (str): API key to use with polyswarmd
        """
        super().__init__(polyswarmd_addr, keyfile, password, api_key, testing, insecure_transport=False)
        self.clamd = clamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT,
                                              CLAMD_TIMEOUT)
        self.rules = yara.compile(RULES_DIR + "malware/MALW_Eicar")

    async def scan(self, guid, content, chain):
        """Scan an artifact with ClamAV + YARA

        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            content (bytes): Content of the artifact to be scan
        Returns:
            (bool, bool, str): Tuple of bit, verdict, metadata

            bit (bool): Whether to include this artifact in the assertion or not
            verdict (bool): Whether this artifact is malicious or not
            metadata (str): Optional metadata about this artifact
        """

        yara_res = False
        clam_res = False
        yara_metadata = ''
        clam_metadata = ''

        # Yara rule matching
        matches = self.rules.match(data=content)
        if matches:
            yara_res = True

        # ClamAV scan
        result = self.clamd.instream(BytesIO(content)).get('stream')
        if len(result) >= 2 and result[0] == 'FOUND':
            clam_res = True
            clam_metadata = result[1]

        # We assert on all artifacts
        bit = True

        # If either finds a match, trust it and send it along
        # If not, assert it is benign
        verdict = yara_res or clam_res
        metadata = ' '.join([yara_metadata, clam_metadata]).strip()

        return bit, verdict, metadata
