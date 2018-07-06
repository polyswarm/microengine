import os

from microengine import Microengine

POLYSWARMD_ADDR = os.environ.get('POLYSWARMD_ADDR', 'localhost:31337')
KEYFILE = 'keyfile'
PASSWORD = 'password'

class ScratchMicroengine(Microengine):
    pass

if __name__ == '__main__':
    ScratchMicroengine(POLYSWARMD_ADDR, KEYFILE, PASSWORD).run()
