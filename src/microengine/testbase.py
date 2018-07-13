import unittest
import uuid

import click

from microengine.util import get_test_key_and_pw
import asyncio
from malware_repo_client.client import PolySwarmMalwareRepoClient, DummyMalwareRepoClient
from microengine.backend import choose_backend


class CommonMicroEngineTests:

    malware_repo_client_cls = DummyMalwareRepoClient
    test_polyswarm_d_port = "localhost:31337"

    def test_scan_random_mal_not(self):
        key_path, pw = get_test_key_and_pw()

        for t in [True, False]:

            mal_md, mal_content = self.malware_repo_client_cls().get_random_file(malicious_filter=t)

            event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(event_loop)

            async def run_t():

                me = self.micro_engine_cls(self.test_polyswarm_d_port, key_path, pw)
                guid = str(uuid.uuid4())
                cor = me.scan(guid, mal_content)

                bit, infected, infected_str = await cor
                self.assertEqual(infected, t)

            coro = asyncio.coroutine(run_t)
            event_loop.run_until_complete(coro())
            event_loop.close()

@click.command()
@click.option('--malware_repo', envvar='POLYSWARM_MALWARE_REPO_URL', default='dummy',
        help='Backend to use')
@click.option('--backend', envvar='MICROENGINE_BACKEND', default='scratch',
        help='Backend to use')
def main(malware_repo, backend):
    micro_engine_class = choose_backend(backend)

    if malware_repo != 'dummy':
        # todo less than optimal, but if this is set then we

        CommonMicroEngineTests.malware_repo_client_cls = PolySwarmMalwareRepoClient

    class RunnableTest(unittest.TestCase, CommonMicroEngineTests):
        micro_engine_cls = micro_engine_class
        # this is set at runtime

    suite = unittest.TestLoader().loadTestsFromTestCase(RunnableTest)

    runner = unittest.TextTestRunner()
    runner.run(suite)


if __name__ == "__main__":
    main()