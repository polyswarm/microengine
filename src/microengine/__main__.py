import click
import importlib
import logging
import sys

from microengine.clamav import ClamavMicroengine
from microengine.eicar import EicarMicroengine
from microengine.multi import MultiMicroengine
from microengine.scratch import ScratchMicroengine
from microengine.yara import YaraMicroengine


def choose_backend(backend):
    """Resolves microengine name string to implementation

    Args:
        backend (str): Name of the backend to load, either one of the predefined
            implementations or the name of a module to load
            (module:ClassName syntax or default of module:Microengine)
    Returns:
        (Class): Microengine class of the selected implementation
    Raises:
        (Exception): If backend is not found
    """
    micro_engine_class = None
    if backend == 'scratch':
        micro_engine_class = ScratchMicroengine
    elif backend == 'eicar':
        micro_engine_class = EicarMicroengine
    elif backend == 'clamav':
        micro_engine_class = ClamavMicroengine
    elif backend == 'yara':
        micro_engine_class = YaraMicroengine
    elif backend == 'multi':
        micro_engine_class = MultiMicroengine
    else:
        import_l = backend.split(":")
        micro_engine_module_s = import_l[0]

        micro_engine_module = importlib.import_module(micro_engine_module_s)
        micro_engine_class = micro_engine_module.Microengine if ":" not in backend else getattr(micro_engine_module, import_l[1])

    if micro_engine_class is None:
        raise Exception("No microengine backend found {0}".format(backend))

    return micro_engine_class


@click.command()
@click.option('--log', default='INFO',
        help='Logging level')
@click.option('--polyswarmd-addr', envvar='POLYSWARMD_ADDR', default='localhost:31337',
        help='Address (host:port) of polyswarmd instance')
@click.option('--keyfile', envvar='KEYFILE', type=click.Path(exists=True), default='keyfile',
        help='Keystore file containing the private key to use with this microengine')
@click.option('--password', envvar='PASSWORD', prompt=True, hide_input=True,
        help='Password to decrypt the keyfile with')
@click.option('--api-key', envvar='API_KEY', default='',
        help='API key to use with polyswarmd')
@click.option('--backend', envvar='BACKEND', default='scratch',
        help='Backend to use')
@click.option('--testing', default=-1,
        help='Activate testing mode for integration testing, respond to N bounties and N offers then exit')
@click.option('--insecure-transport', is_flag=True,
        help='Connect to polyswarmd via http:// and ws://, mutially exclusive with --api-key')
def main(log, polyswarmd_addr, keyfile, password, api_key, backend, testing, insecure_transport):
    """Entrypoint for the microengine driver

    Args:
        polyswarmd_addr(str): Address of polyswarmd
        keyfile (str): Path to private key file to use to sign transactions
        password (str): Password to decrypt the encrypted private key
        backend (str): Backend implementation to use
        api_key(str): API key to use with polyswarmd
        testing (int): Mode to process N bounties then exit (optional)
        insecure_transport (bool): Connect to polyswarmd without TLS
    """
    loglevel = getattr(logging, log.upper(), None)
    if not isinstance(loglevel, int):
        logging.error('invalid log level')
        sys.exit(-1)
    logging.basicConfig(level=loglevel, format='%(levelname)s:%(name)s:%(asctime)s %(message)s')

    micro_engine_class = choose_backend(backend)
    micro_engine_class(polyswarmd_addr, keyfile, password, api_key, testing, insecure_transport).run()


if __name__ == '__main__':
    main()
