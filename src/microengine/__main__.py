import click
from src.microengine.backend import choose_backend


@click.command()
@click.option('--polyswarmd-addr', envvar='POLYSWARMD_ADDR', default='localhost:31337',
        help='Address of polyswarmd instance')
@click.option('--keyfile', envvar='MICROENGINE_KEYFILE', type=click.Path(exists=True), default='keyfile',
        help='Keystore file containing the private key to use with this microengine')
@click.option('--password', envvar='MICROENGINE_PASSWORD', prompt=True, hide_input=True,
        help='Password to decrypt the keyfile with')
@click.option('--backend', envvar='MICROENGINE_BACKEND', default='scratch',
        help='Backend to use')
@click.option('--testing', default=-1,
        help='Activate testing mode for integration testing, respond to N bounties then exit')
def main(polyswarmd_addr, keyfile, password, backend, testing):
    micro_engine_class = choose_backend(backend)

    micro_engine_class(polyswarmd_addr, keyfile, password).run(testing)

if __name__ == '__main__':
    main()
