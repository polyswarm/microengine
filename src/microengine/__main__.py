import click

from microengine.scratch import ScratchMicroengine
from microengine.eicar import EicarMicroengine
from microengine.clamav import ClamavMicroengine

@click.command()
@click.option('--polyswarmd-addr', envvar='POLYSWARMD_ADDR', default='localhost:31337',
        help='Address of polyswarmd instance')
@click.option('--keyfile', envvar='MICROENGINE_KEYFILE', type=click.Path(exists=True), default='keyfile',
        help='Keystore file containing the private key to use with this microengine')
@click.option('--password', envvar='MICROENGINE_PASSWORD', prompt=True, hide_input=True,
        help='Password to decrypt the keyfile with')
@click.option('--backend', envvar='MICROENGINE_BACKEND', type=click.Choice(['scratch', 'eicar', 'clamav']), default='scratch',
        help='Backend to use')
def main(polyswarmd_addr, keyfile, password, backend):
    if backend == 'scratch':
        ScratchMicroengine(polyswarmd_addr, keyfile, password).run()
    elif backend == 'eicar':
        EicarMicroengine(polyswarmd_addr, keyfile, password).run()
    elif backend == 'clamav':
        ClamavMicroengine(polyswarmd_addr, keyfile, password).run()


if __name__ == '__main__':
    main()
