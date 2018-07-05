import aiohttp
import asyncio
import json
import os
import sys
import websockets

from queue import PriorityQueue
from web3.auto import w3 as web3


# USER CODE: Replace this functionality with your scanning logic
async def scan(content):
    """Scan a stream representing a bounty artifact"""
    return True, True


def unlock_key(keyfile, password):
    """Open an encrypted keystore file and decrypt it"""
    with open(keyfile, 'r') as f:
        priv_key = web3.eth.account.decrypt(f.read(), password)

    address = web3.eth.account.privateKeyToAccount(priv_key).address
    return (address, priv_key)


KEYFILE = 'keyfile'
PASSWORD = 'password'
ADDRESS, PRIV_KEY = unlock_key(KEYFILE, PASSWORD)
POLYSWARMD_ADDR = os.environ.get('POLYSWARMD_ADDR', 'localhost:31337')

# These values come from the BountyRegistry contract
BID = '62500000000000000'
ARBITER_VOTE_WINDOW = 25
ASSERTION_REVEAL_WINDOW = 25

schedule = PriorityQueue()


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
    print(response)
    return response['status'] == 'OK'


async def get_artifact(session, ipfs_hash, index):
    """Retrieve an artifact from IPFS via polyswarmd"""
    uri = 'http://{0}/artifacts/{1}/{2}'.format(POLYSWARMD_ADDR, ipfs_hash,
                                                index)
    async with session.get(uri) as response:
        if response.status == 200:
            return response.content

        return None


async def post_transactions(session, transactions):
    """Post a set of (signed) transactions to Ethereum via polyswarmd, parsing the emitted events"""
    signed = []
    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, PRIV_KEY)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    uri = 'http://{0}/transactions'.format(POLYSWARMD_ADDR)

    async with session.post(uri, json={'transactions': signed}) as response:
        return await response.json()


async def post_assertion(session, guid, bid, mask, verdicts):
    """Post an assertion to polyswarmd"""
    uri = 'http://{0}/bounties/{1}/assertions?account={2}'.format(
        POLYSWARMD_ADDR, guid, ADDRESS)
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
    response = await post_transactions(session,
                                       response['result']['transactions'])

    if not check_response(response):
        return None, []

    try:
        return nonce, response['result']['assertions']
    except:
        print('expected assertion, got:', response)
        return None, []


async def post_reveal(session, guid, index, nonce, verdicts, metadata):
    """Post an assertion reveal to polyswarmd"""
    uri = 'http://{0}/bounties/{1}/assertions/{2}/reveal?account={3}'.format(
        POLYSWARMD_ADDR, guid, index, ADDRESS)
    reveal = {
        'nonce': nonce,
        'verdicts': verdicts,
        'metadata': metadata,
    }

    async with session.post(uri, json=reveal) as response:
        response = await response.json()

    if not check_response(response):
        return None

    response = await post_transactions(session,
                                       response['result']['transactions'])

    if not check_response(response):
        return None

    try:
        return response['result']['reveals']
    except:
        print('expected reveal, got:', response)
        return None


async def settle_bounty(session, guid):
    """Settle a bounty via polyswarmd"""
    uri = 'http://{0}/bounties/{1}/settle?account={2}'.format(
        POLYSWARMD_ADDR, guid, ADDRESS)

    async with session.post(uri) as response:
        response = await response.json()

    if not check_response(response):
        return Nonce

    response = await post_transactions(session,
                                       response['result']['transactions'])

    if not check_response(response):
        return None

    try:
        return response['result']['transfers']
    except:
        print('expected transfer, got:', response)
        return None


async def handle_new_block(session, number):
    """Perform scheduled events when a new block is reported"""
    ret = []
    while schedule.queue and schedule.queue[0][0] < number:
        exp, task = schedule.get()
        if isinstance(task, SecretAssertion):
            ret.append(await
                       post_reveal(session, task.guid, task.index, task.nonce,
                                   task.verdicts, task.metadata))
        elif isinstance(task, UnsettledBounty):
            ret.append(await settle_bounty(session, task.guid))

    return ret


async def handle_new_bounty(session, guid, author, uri, amount, expiration):
    """Scan and assert on a posted bounty"""
    mask = []
    verdicts = []
    for i in range(256):
        content = await get_artifact(session, uri, i)
        if not content:
            print('no more artifacts')
            break

        print('scanning artifact:', i)
        bit, verdict = await scan(content)
        mask.append(bit)
        verdicts.append(verdict)

    nonce, assertions = await post_assertion(session, guid, BID, mask,
                                             verdicts)
    for a in assertions:
        sa = SecretAssertion(guid, a['index'], nonce, verdicts, '')
        schedule.put((int(expiration) + ARBITER_VOTE_WINDOW, sa))

        ub = UnsettledBounty(guid)
        schedule.put(
            (int(expiration) + ARBITER_VOTE_WINDOW + ASSERTION_REVEAL_WINDOW,
             ub))

    return assertions


async def listen_for_events():
    """Listen for events via websocket connection to polyswarmd"""
    uri = 'ws://{0}/events'.format(POLYSWARMD_ADDR)
    async with aiohttp.ClientSession() as session:
        async with websockets.connect(uri) as ws:
            while True:
                event = json.loads(await ws.recv())
                if event['event'] == 'block':
                    print(await handle_new_block(session,
                                                 event['data']['number']))
                elif event['event'] == 'bounty':
                    print(await handle_new_bounty(session, **event['data']))


def main(argv):
    asyncio.get_event_loop().run_until_complete(listen_for_events())


if __name__ == '__main__':
    main(sys.argv)
