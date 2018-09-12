import base64

from polyswarmclient.microengine import Microengine

EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')

class EicarMicroengine(Microengine):
    """Microengine which tests for the EICAR test file"""

    async def scan(self, guid, content):
        """Scan an artifact searching for the EICAR string

        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            content (bytes): Content of the artifact to be scan
        Returns:
            (bool, bool, str): Tuple of bit, verdict, metadata

            bit (bool): Whether to include this artifact in the assertion or not
            verdict (bool): Whether this artifact is malicious or not
            metadata (str): Optional metadata about this artifact
        """
        if content == EICAR:
            return True, True, ''

        return False, False, ''
