import aiohttp
import asyncio
import base58
import functools
import json
import logging
import sys
import websockets

from queue import PriorityQueue
from web3.auto import w3 as web3

# These values come from the BountyRegistry contract
MINIMUM_BID = 62500000000000000
ARBITER_VOTE_WINDOW = 25
ASSERTION_REVEAL_WINDOW = 100


class Microengine(object):
    """Base class for microengines, override scan() and/or bid() to customize
    behavior"""

    def __init__(self, polyswarmd_addr, keyfile, password, api_key=None):
        """Initialize a microengine

        Args:
            polyswarmd_addr (str): Address of polyswarmd
            keyfile (str): Path to private key file to use to sign transactions
            password (str): Password to decrypt the encrypted private key
        """
        self.polyswarmd_addr = polyswarmd_addr
        self.api_key = api_key
        self.testing = -1

        with open(keyfile, 'r') as f:
            self.priv_key = web3.eth.account.decrypt(f.read(), password)

        self.address = web3.eth.account.privateKeyToAccount(
            self.priv_key).address
        logging.info('Using account: %s', self.address)
        self.schedule = PriorityQueue()

    async def scan(self, guid, content):
        """Override this to implement custom scanning logic

        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            content (bytes): Content of the artifact to be scan
        Returns:
            (bool, bool, str): Tuple of bit, verdict, metadata

            bit (bool): Whether to include this artifact in the assertion or not
            verdict (bool): Whether this artifact is malicious or not
            metadata (str): Optional metadata about this artifact
        """
        return True, True, ''

    def bid(self, guid):
        """Override this to implement custom bid calculation logic

        Args:
            guid (str): GUID of the bounty under analysis, use to correlate with artifacts in the same bounty
        Returns:
            (int): Amount of NCT to bid in base NCT units (10 ^ -18)
        """
        return MINIMUM_BID

    def schedule_empty(self):
        """Is our schedule of future events empty?

        Returns:
            (bool): True if schedule is empty, else False
        """
        return self.schedule.empty()

    def schedule_peek(self):
        """Check the next event without dequeing it

        Returns:
            Next event object
        """
        if self.schedule.queue:
            return self.schedule.queue[0]
        return None

    def schedule_get(self):
        """Dequeue and return the next event

        Returns:
            Next event object
        """
        return self.schedule.get()

    def schedule_put(self, block_number, obj):
        """Add an event to the schedule

        Args:
            block_number (int): Block number on which to process the queued event
            obj: Event object to queue
        """
        self.schedule.put((block_number, obj))


    async def run_sockets(self, testing, offers, loop):
        """Run this microengine

        Args:
            testing (int): Mode to process N bounties then exit (optional)
        """
        self.testing = testing
<<<<<<< HEAD
        asyncio.get_event_loop().run_until_complete(listen_for_events(self))
=======
        self.offers = offers

        tasks = [asyncio.ensure_future(listen_for_events(self, loop))]


        if offers:
            tasks.append(asyncio.ensure_future(listen_for_offers(self, loop)))

        await asyncio.gather(*tasks)

    def run(self, testing=-1, offers=False):
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.run_sockets(testing, offers, loop))
        finally:
            loop.close()
>>>>>>> create multiwebsocket setup


@functools.total_ordering
class SecretAssertion(object):
    """An assertion which has yet to be publically revealed"""

    def __init__(self, guid, index, nonce, verdicts, metadata):
        """Initialize a secret assertion

        Args:
            guid (str): GUID of the bounty being asserted on
            index (int): Index of the assertion to reveal
            nonce (str): Secret nonce used to reveal assertion
            verdicts (List[bool]): List of verdicts for each artifact in the bounty
            metadata (str): Optional metadata
        """
        self.guid = guid
        self.index = index
        self.nonce = nonce
        self.verdicts = verdicts
        self.metadata = metadata

    def __eq__(self, other):
        return self.guid == other.guid

    def __lt__(self, other):
        return self.guid < other.guid


@functools.total_ordering
class UnsettledBounty(object):
    """A bounty which has yet to be settled"""

    def __init__(self, guid):
        """Initialize an unsettled bounty

        Args:
            guid (str): GUID of the bounty being asserted on
        """
        self.guid = guid

    def __eq__(self, other):
        return self.guid == other.guid

    def __lt__(self, other):
        return self.guid < other.guid


def check_response(response):
    """Check the status of responses from polyswarmd

    Args:
        response: Response dict parsed from JSON from polyswarmd
    Returns:
        (bool): True if successful else False
    """
    return response['status'] == 'OK'


def is_valid_ipfs_hash(ipfs_hash):
    # TODO: Further multihash validation
    try:
        return len(ipfs_hash) < 100 and base58.b58decode(ipfs_hash)
    except:
        pass

    return False


async def get_artifact(microengine, session, ipfs_hash, index):
    """Retrieve an artifact from IPFS via polyswarmd

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        ipfs_hash (str): IPFS hash of the artifact to retrieve
        index (int): Index of the sub artifact to retrieve
    Returns:
        (bytes): Content of the artifact
    """
    if not is_valid_ipfs_hash(ipfs_hash):
        return None

    uri = 'http://{0}/artifacts/{1}/{2}'.format(microengine.polyswarmd_addr,
                                                ipfs_hash, index)
    async with session.get(uri) as response:
        if response.status == 200:
            return await response.read()

        return None


async def post_transactions(microengine, session, transactions):
    """Post a set of (signed) transactions to Ethereum via polyswarmd, parsing the emitted events

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        transactions (List[Transaction]): The transactions to sign and post
    Returns:
        Response JSON parsed from polyswarmd containing emitted events
    """
    signed = []
    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, microengine.priv_key)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    uri = 'http://{0}/transactions'.format(microengine.polyswarmd_addr)
    async with session.post(uri, json={'transactions': signed}) as response:
        j = await response.json()
        if microengine.testing >= 0 and 'errors' in j.get('result', {}):
            logging.error('Received transaction error in testing mode: %s', j)
            sys.exit(1)

        return j


async def post_assertion(microengine, session, guid, bid, mask, verdicts):
    """Post an assertion to polyswarmd

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        guid (str): The bounty to assert on
        bid (int): The amount to bid
        mask (List[bool]): Which artifacts in the bounty to assert on
        verdicts (List[bool]): Verdict (malicious/benign) for each of the artifacts in the bounty
    Returns:
        Response JSON parsed from polyswarmd containing emitted events
    """
    uri = 'http://{0}/bounties/{1}/assertions'.format(
        microengine.polyswarmd_addr, guid)
    assertion = {
        'bid': str(bid),
        'mask': mask,
        'verdicts': verdicts,
    }

    async with session.post(uri, json=assertion) as response:
        response = await response.json()

    if not check_response(response):
        return None, []

    nonce = response['result']['nonce']
    response = await post_transactions(microengine, session,
                                       response['result']['transactions'])

    if not check_response(response):
        return None, []

    try:
        return nonce, response['result']['assertions']
    except:
        logging.warning('expected assertion, got: %s', response)
        return None, []


async def post_reveal(microengine, session, guid, index, nonce, verdicts,
                      metadata):
    """Post an assertion reveal to polyswarmd

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        guid (str): The bounty which we have asserted on
        index (int): The index of the assertion to reveal
        nonce (str): Secret nonce used to reveal assertion
        verdicts (List[bool]): Verdict (malicious/benign) for each of the artifacts in the bounty
        metadata (str): Optional metadata
    Returns:
        Response JSON parsed from polyswarmd containing emitted events
    """
    uri = 'http://{0}/bounties/{1}/assertions/{2}/reveal'.format(
        microengine.polyswarmd_addr, guid, index)
    reveal = {
        'nonce': nonce,
        'verdicts': verdicts,
        'metadata': metadata,
    }

    async with session.post(uri, json=reveal) as response:
        response = await response.json()

    if not check_response(response):
        return None

    response = await post_transactions(microengine, session,
                                       response['result']['transactions'])

    if not check_response(response):
        return None

    try:
        return response['result']['reveals']
    except:
        logging.warning('expected reveal, got: %s', response)
        return None


async def settle_bounty(microengine, session, guid):
    """Settle a bounty via polyswarmd

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        guid (str): The bounty which we are settling
    Returns:
        Response JSON parsed from polyswarmd containing emitted events
    """
    uri = 'http://{0}/bounties/{1}/settle'.format(microengine.polyswarmd_addr,
                                                  guid)
    async with session.post(uri) as response:
        response = await response.json()

    if not check_response(response):
        return Nonce

    response = await post_transactions(microengine, session,
                                       response['result']['transactions'])

    if not check_response(response):
        return None

    try:
        return response['result']['transfers']
    except:
        logging.warning('expected transfer, got: %s', response)
        return None


async def handle_new_block(microengine, session, number):
    """Perform scheduled events when a new block is reported

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        number (int): The current block number reported from polyswarmd
    Returns:
        Response JSON parsed from polyswarmd containing emitted events
    """
    ret = []
    while microengine.schedule_peek(
    ) and microengine.schedule_peek()[0] < number:
        exp, task = microengine.schedule_get()
        if isinstance(task, SecretAssertion):
            ret.append(await
                       post_reveal(microengine, session, task.guid, task.index,
                                   task.nonce, task.verdicts, task.metadata))
        elif isinstance(task, UnsettledBounty):
            ret.append(await settle_bounty(microengine, session, task.guid))

    return ret


async def handle_new_bounty(microengine, session, guid, author, uri, amount,
                            expiration):
    """Scan and assert on a posted bounty

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        guid (str): The bounty to assert on
        author (str): The bounty author
        uri (str): IPFS hash of the root artifact
        amount (str): Amount of the bounty in base NCT units (10 ^ -18)
        expiration (int): Block number of the bounty's expiration
    Returns:
        Response JSON parsed from polyswarmd containing placed assertions
    """
    mask = []
    verdicts = []
    metadatas = []
    for i in range(256):
        content = await get_artifact(microengine, session, uri, i)
        if not content:
            logging.debug('no more artifacts')
            break

        logging.info('scanning artifact: %s', i)
        bit, verdict, metadata = await microengine.scan(guid, content)
        mask.append(bit)
        verdicts.append(verdict)
        metadatas.append(metadata)

    nonce, assertions = await post_assertion(microengine, session, guid,
                                             microengine.bid(guid), mask,
                                             verdicts)
    for a in assertions:
        sa = SecretAssertion(guid, a['index'], nonce, verdicts,
                             ';'.join(metadatas))
        microengine.schedule_put(int(expiration), sa)

        ub = UnsettledBounty(guid)
        microengine.schedule_put(
            int(expiration) + ASSERTION_REVEAL_WINDOW + ARBITER_VOTE_WINDOW,
            ub)

    return assertions


async def listen_for_events(microengine, loop):
    """Listen for events via websocket connection to polyswarmd

    Args:
        microengine (Microengine): The microengine instance
    """
    print('colin seale****************************************************************************************************************************************************')
    uri = 'ws://{0}/events'.format(microengine.polyswarmd_addr)
    async with aiohttp.ClientSession() as session:
        async with websockets.connect(uri) as ws:
            while microengine.testing != 0 or not microengine.schedule_empty():
                event = json.loads(await ws.recv())
                logging.debug('Event from events function %s', event)

    #             if event['event'] == 'block':
    #                 number = event['data']['number']
    #                 if number % 100 == 0:
    #                     logging.debug('Block %s', number)

    #                 block_results = await handle_new_block(
    #                     microengine, session, number)
    #                 if block_results:
    #                     logging.info('Block results: %s', block_results)
    #             elif event['event'] == 'bounty':
    #                 if microengine.testing == 0:
    #                     logging.info(
    #                         'bounty received but 0 bounties remaining in test mode, ignoring'
    #                     )
    #                     continue
    #                 elif microengine.testing > 0:
    #                     microengine.testing = microengine.testing - 1
    #                     logging.info('%s bounties remaining in test mode', microengine.testing)

    #                 bounty = event['data']
    #                 logging.info('received bounty: %s', bounty)

    #                 assertions = await handle_new_bounty(
    #                     microengine, session, **bounty)
    #                 logging.info('created assertions: %s', assertions)

    #         if microengine.testing == 0:
    #             logging.info('exiting test mode')
    #             # This is delayed by a few seconds, presumably for event loop cleanup
    #             sys.exit(0)


async def listen_for_messages(microengine, loop):
    print('RUNNING listen_for_messages here !!!!!!!')
    uri = 'ws://{0}/{1}/messages'.format(microengine.polyswarmd_addr, event['data']['guid'])
    async with aiohttp.ClientSession() as session:
        async with websockets.connect(uri) as message_ws:
            while True:
                init_event = json.loads(await message_ws.recv())
                print(init_event)
        

async def listen_for_offers(microengine, loop):
    """Listen for events via websocket connection to polyswarmd

    Args:
        microengine (Microengine): The microengine instance
    """
    uri = 'ws://{0}/events'.format(microengine.polyswarmd_addr)
    headers = {'Authorization': microengine.api_key} if microengine.api_key else {}
    async with aiohttp.ClientSession(headers=headers) as session:
        async with websockets.connect(uri, extra_headers=headers) as ws:
            while microengine.testing != 0 or not microengine.schedule_empty():
                event = json.loads(await ws.recv())
<<<<<<< HEAD
                if event['event'] == 'block':
                    number = event['data']['number']
                    if number % 100 == 0:
                        logging.debug('Block %s', number)

                    block_results = await handle_new_block(
                        microengine, session, number)
                    if block_results:
                        logging.info('Block results: %s', block_results)
                elif event['event'] == 'bounty':
                    if microengine.testing == 0:
                        logging.info(
                            'bounty received but 0 bounties remaining in test mode, ignoring'
                        )
                        continue
                    elif microengine.testing > 0:
                        microengine.testing = microengine.testing - 1
                        logging.info('%s bounties remaining in test mode',
                                     microengine.testing)

                    bounty = event['data']
                    logging.info('received bounty: %s', bounty)

                    assertions = await handle_new_bounty(
                        microengine, session, **bounty)
                    logging.info('created assertions: %s', assertions)

            if microengine.testing == 0:
                logging.info('exiting test mode')
                # This is delayed by a few seconds, presumably for event loop cleanup
                sys.exit(0)
=======
                logging.debug('Event from offers function %s', event)
                # if event['event'] == 'initialized_channel':
                #     asyncio.ensure_future(listen_for_messages(), loop=loop)
                # if event['event'] == 'block':
                #     number = event['data']['number']
                #     if number % 100 == 0:
                #         logging.debug('Block %s', number)

                #     block_results = await handle_new_block(
                #         microengine, session, number)
                #     if block_results:
                #         logging.info('Block results: %s', block_results)
                # elif event['event'] == 'bounty':
                #     if microengine.testing == 0:
                #         logging.info(
                #             'bounty received but 0 bounties remaining in test mode, ignoring'
                #         )
                #         continue
                #     elif microengine.testing > 0:
                #         microengine.testing = microengine.testing - 1
                #         logging.info('%s bounties remaining in test mode', microengine.testing)

                #     bounty = event['data']
                #     logging.info('received bounty: %s', bounty)

                #     assertions = await handle_new_bounty(
                #         microengine, session, **bounty)
                #     logging.info('created assertions: %s', assertions)

            # if microengine.testing == 0:
            #     logging.info('exiting test mode')
            #     # This is delayed by a few seconds, presumably for event loop cleanup
            #     sys.exit(0)
>>>>>>> create multiwebsocket setup
