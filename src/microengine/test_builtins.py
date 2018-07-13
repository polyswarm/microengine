from microengine.testbase import CommonMicroEngineTests
from microengine.clamav import ClamavMicroengine
import unittest


class TestClamAV(unittest.TestCase, CommonMicroEngineTests):
    micro_engine_cls = ClamavMicroengine

    # todo anymore tests that clamscan should be put through?