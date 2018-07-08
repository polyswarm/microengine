import aiohttp
import asyncio
import json
import websockets

from queue import PriorityQueue
from web3.auto import w3 as web3

# These values come from the BountyRegistry contract
MINIMUM_BID = '62500000000000000'
ARBITER_VOTE_WINDOW = 25
ASSERTION_REVEAL_WINDOW = 25


class Microengine(object):
    """Base class for microengines, override scan() and/or bid() to customize behavior"""

    def __init__(self, polyswarmd_addr, keyfile, password):
        """Initialize a microengine"""
        self.polyswarmd_addr = polyswarmd_addr

        with open(keyfile, 'r') as f:
            self.priv_key = web3.eth.account.decrypt(f.read(), password)

        self.address = web3.eth.account.privateKeyToAccount(
            self.priv_key).address
        self.schedule = PriorityQueue() 

    async def scan(self, guid, content):
        """Override this to implement custom scanning logic"""
        return True, True, ''

    def bid(self, guid):
        """Override this to implement custom bid calculation logic"""
        return MINIMUM_BID

    def schedule_peek(self):
        """Check the next event without dequeing it"""
        if self.schedule.queue:
            return self.schedule.queue[0]
        return None

    def schedule_get(self):
        """Dequeue and return the next event"""
        return self.schedule.get()

    def schedule_put(self, block_number, obj):
        """Add an event to the schedule"""
        self.schedule.put((block_number, obj))

    def run(self):
        """Run this microengine"""
        asyncio.get_event_loop().run_until_complete(listen_for_events(self))


class SecretAssertion(object):
    """An assertion which has yet to be publically revealed"""

    def __init__(self, guid, index, nonce, verdicts, metadata):
        """Initialize a secret assertion"""
        self.guid = guid
        self.index = index
        self.nonce = nonce
        self.verdicts = verdicts
        self.metadata = metadata


class UnsettledBounty(object):
    """A bounty which has yet to be settled"""

    def __init__(self, guid):
        """Initialize an unsettled bounty"""
        self.guid = guid


def check_response(response):
    """Check the status of responses from polyswarmd"""
    return response['status'] == 'OK'


async def get_artifact(microengine, session, ipfs_hash, index):
    """Retrieve an artifact from IPFS via polyswarmd"""
    uri = 'http://{0}/artifacts/{1}/{2}'.format(microengine.polyswarmd_addr,
                                                ipfs_hash, index)
    async with session.get(uri) as response:
        if response.status == 200:
            return await response.read()

        return None


async def post_transactions(microengine, session, transactions):
    """Post a set of (signed) transactions to Ethereum via polyswarmd, parsing the emitted events"""
    signed = []
    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, microengine.priv_key)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    uri = 'http://{0}/transactions'.format(microengine.polyswarmd_addr)

    async with session.post(uri, json={'transactions': signed}) as response:
        return await response.json()


async def post_assertion(microengine, session, guid, bid, mask, verdicts):
    """Post an assertion to polyswarmd"""
    uri = 'http://{0}/bounties/{1}/assertions?account={2}'.format(
        microengine.polyswarmd_addr, guid, microengine.address)
    assertion = {
        'bid': bid,
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
        print('expected assertion, got:', response)
        return None, []


async def post_reveal(microengine, session, guid, index, nonce, verdicts,
                      metadata):
    """Post an assertion reveal to polyswarmd"""
    uri = 'http://{0}/bounties/{1}/assertions/{2}/reveal?account={3}'.format(
        microengine.polyswarmd_addr, guid, index, microengine.address)
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
        print('expected reveal, got:', response)
        return None


async def settle_bounty(microengine, session, guid):
    """Settle a bounty via polyswarmd"""
    uri = 'http://{0}/bounties/{1}/settle?account={2}'.format(
        microengine.polyswarmd_addr, guid, microengine.address)

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
        print('expected transfer, got:', response)
        return None


async def handle_new_block(microengine, session, number):
    """Perform scheduled events when a new block is reported"""
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
    """Scan and assert on a posted bounty"""
    mask = []
    verdicts = []
    metadatas = []
    for i in range(256):
        content = await get_artifact(microengine, session, uri, i)
        if not content:
            print('no more artifacts')
            break

        print('scanning artifact:', i)
        bit, verdict, metadata = await microengine.scan(guid, content)
        mask.append(bit)
        verdicts.append(verdict)
        metadatas.append(metadata)

    nonce, assertions = await post_assertion(microengine, session, guid,
                                             microengine.bid(guid), mask, verdicts)
    for a in assertions:
        sa = SecretAssertion(guid, a['index'], nonce, verdicts, ';'.join(metadatas))
        microengine.schedule_put(int(expiration) + ARBITER_VOTE_WINDOW, sa)

        ub = UnsettledBounty(guid)
        microengine.schedule_put(
            int(expiration) + ARBITER_VOTE_WINDOW + ASSERTION_REVEAL_WINDOW,
            ub)

    return assertions


async def listen_for_events(microengine):
    """Listen for events via websocket connection to polyswarmd"""
    uri = 'ws://{0}/events'.format(microengine.polyswarmd_addr)
    async with aiohttp.ClientSession() as session:
        async with websockets.connect(uri) as ws:
            while True:
                event = json.loads(await ws.recv())
                if event['event'] == 'block':
                    number = event['data']['number']
                    if number % 100 == 0:
                        print('Block', number)

                    block_results = await handle_new_block(microengine, session, number)
                    if block_results:
                        print(block_results)
                elif event['event'] == 'bounty':
                    bounty = event['data']
                    print('received bounty:', bounty)

                    assertions = await handle_new_bounty(
                        microengine, session, **bounty)
                    print('created assertions:', assertions)
