import yara
import tempfile
import os

from polyswarmclient.microengine import Microengine

RULES_DIR = 'data/yara-rules/'


class YaraMicroengine(Microengine):
    """Microengine which matches samples against yara rules"""

    def __init__(self, polyswarmd_addr, keyfile, password, api_key=None, testing=False, insecure_transport=False):
        """Initialize a Yara microengine

        Args:
            polyswarmd_addr (str): Address of polyswarmd
            keyfile (str): Path to private key file to use to sign transactions
            password (str): Password to decrypt the encrypted private key
            api_key (str): API key to use with polyswarmd
        """
        super().__init__(polyswarmd_addr, keyfile, password, api_key, testing, insecure_transport)
        self.rules = yara.compile(RULES_DIR + "malware/MALW_Eicar")

    async def scan(self, guid, content):
        """Scan an artifact with YARA

        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            content (bytes): Content of the artifact to be scan
        Returns:
            (bool, bool, str): Tuple of bit, verdict, metadata

            bit (bool): Whether to include this artifact in the assertion or not
            verdict (bool): Whether this artifact is malicious or not
            metadata (str): Optional metadata about this artifact
        """
        matches = self.rules.match(data=content)
        if matches:
            return True, True, ''

        return True, False, ''
