import aiohttp
import asyncio
import base58
import functools
import json
import logging
import sys
import websockets
from eth_account.messages import defunct_hash_message
from queue import PriorityQueue
from web3.auto import w3 as web3
from pprint import pprint, pformat

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
        self.base_nonce = 0
        self.base_nonce_lock = asyncio.Lock()

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


    async def run_sockets(self, testing, loop):
        """Run this microengine

        Args:
            testing (int): Mode to process N bounties and offers then exit (optional)
        """
        self.testing = { 'bounties': testing, 'offers': testing }

        tasks = [asyncio.ensure_future(listen_for_events(self, loop))]

        await asyncio.gather(*tasks)

    def run(self, testing=-1):
        loop = asyncio.get_event_loop()
        try:
            loop.create_task(self.run_sockets(testing, loop))
            loop.run_forever()
        finally:
            loop.close()

class OfferChannel(object):
    def __init__(self, guid, offer_amount=0, ambassador_balance=0, expert_balance=0):

        self.guid = guid
        self.offer_amount = offer_amount
        self.ambassador_balance = ambassador_balance
        self.expert_balance = expert_balance
        self.nonce = 0
        self.last_message = None
        self.event_socket = None
        self.msg_socket = None

    def set_state(self, state):
        # TODO: change to be a persistant database so all the assertions can be saved
        # cureent saving just the last state/signiture for disputes

        self.offer_amount = state['state']['offer_amount']
        self.ambassador_balance = state['state']['ambassador_balance']
        self.expert_balance = state['state']['expert_balance']
        self.last_message = state

    async def close_sockets(self):
        if self.event_socket:
            await self.event_socket.close()

        if self.msg_socket:
            await self.msg_socket.close()

    def __eq__(self, other):
        return self.guid == other.guid

    def __lt__(self, other):
        return self.guid < other.guid


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
    status = response.get('status')
    return status and status == 'OK'


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
    params = {'account': microengine.address}
    if not is_valid_ipfs_hash(ipfs_hash):
        return None

    uri = '{0}/artifacts/{1}/{2}'.format(microengine.polyswarmd_addr,
                                                ipfs_hash, index)
    async with session.get(uri, params=params) as response:
        if response.status == 200:
            return await response.read()

        return None


async def get_base_nonce(microengine, session):
    """Get account's initial base nonce from polyswarmd

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
    Returns:
        Response JSON parsed from polyswarmd containing nonce
    """
    params = {'account': microengine.address}
    uri = '{0}/nonce'.format(microengine.polyswarmd_addr)

    async with microengine.base_nonce_lock:
        async with session.get(uri, params=params) as response:
            response = await response.json()

            if not check_response(response):
                logging.error('Invalid nonce response, got %s', response)
                return False

            microengine.base_nonce = response['result']
            logging.info('Got base nonce of: %s', microengine.base_nonce)
            return True



async def post_transactions(microengine, session, transactions):
    """Post a set of (signed) transactions to Ethereum via polyswarmd, parsing the emitted events

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        transactions (List[Transaction]): The transactions to sign and post
    Returns:
        Response JSON parsed from polyswarmd containing emitted events
    """
    params = {'account': microengine.address}

    signed = []
    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, microengine.priv_key)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    uri = '{0}/transactions'.format(microengine.polyswarmd_addr)
    async with session.post(uri, json={'transactions': signed}, params=params) as response:
        response = await response.json()
        if (microengine.testing['bounties'] >= 0 or microengine.testing['offers'] >= 0) and 'errors' in response.get('result', {}):
            logging.error('Received transaction error in testing mode: %s', response)
            sys.exit(1)

        return response


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
    uri = '{0}/bounties/{1}/assertions'.format(
        microengine.polyswarmd_addr, guid)
    assertion = {
        'bid': str(bid),
        'mask': mask,
        'verdicts': verdicts,
    }

    async with microengine.base_nonce_lock:
        params = {'account': microengine.address, 'base_nonce': microengine.base_nonce}
        async with session.post(uri, json=assertion, params=params) as response:
            response = await response.json()

        if not check_response(response):
            return None, []

        nonce = response['result']['nonce']
        transactions = response['result']['transactions']
        microengine.base_nonce += len(transactions)

    response = await post_transactions(microengine, session, transactions)

    if not check_response(response):
        return None, []

    try:
        return nonce, response['result']['assertions']
    except:
        logging.error('expected assertion, got: %s', response)
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
    uri = '{0}/bounties/{1}/assertions/{2}/reveal'.format(
        microengine.polyswarmd_addr, guid, index)
    reveal = {
        'nonce': nonce,
        'verdicts': verdicts,
        'metadata': metadata,
    }

    async with microengine.base_nonce_lock:
        params = {'account': microengine.address, 'base_nonce': microengine.base_nonce}
        async with session.post(uri, json=reveal, params=params) as response:
            response = await response.json()

        if not check_response(response):
            return None

        transactions = response['result']['transactions']
        microengine.base_nonce += len(transactions)

    response = await post_transactions(microengine, session, transactions)

    if not check_response(response):
        return None

    try:
        return response['result']['reveals']
    except:
        logging.error('expected reveal, got: %s', response)
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
    uri = '{0}/bounties/{1}/settle'.format(microengine.polyswarmd_addr,
                                                  guid)
    async with microengine.base_nonce_lock:
        params = {'account': microengine.address, 'base_nonce': microengine.base_nonce}
        async with session.post(uri, params=params) as response:
            response = await response.json()

        if not check_response(response):
            return None

        transactions = response['result']['transactions']
        microengine.base_nonce += len(transactions)

    response = await post_transactions(microengine, session, transactions)

    if not check_response(response):
        return None

    try:
        return response['result']['transfers']
    except:
        logging.error('expected transfer, got: %s', response)
        return None


async def handle_new_block(microengine, session, number):
    """Perform scheduled events when a new block is reported

    Args:
        microengine (Microengine): The microengine instance
        session (aiohttp.ClientSession): Client sesssion
        number (int): The current block number reported from polyswarmd
    """
    while microengine.schedule_peek(
    ) and microengine.schedule_peek()[0] < number:
        exp, task = microengine.schedule_get()
        if isinstance(task, SecretAssertion):
            logging.info('Got reveals: %s', await
                       post_reveal(microengine, session, task.guid, task.index,
                                   task.nonce, task.verdicts, task.metadata))
        elif isinstance(task, UnsettledBounty):
            logging.info('Got settles: %s', await settle_bounty(microengine, session, task.guid))
        elif isinstance(task, OfferChannel):
            await close_disputed_channel(microengine, task, session, task.guid)


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
    logging.info('Got nonce: %s, assertions: %s', nonce, assertions)
    for a in assertions:
        sa = SecretAssertion(guid, a['index'], nonce, verdicts,
                             ';'.join(metadatas))
        microengine.schedule_put(int(expiration), sa)

        ub = UnsettledBounty(guid)
        microengine.schedule_put(
            int(expiration) + ASSERTION_REVEAL_WINDOW + ARBITER_VOTE_WINDOW,
            ub)

    return assertions

async def generate_state(session, microengine, **kwargs):
    params = {'account': microengine.address}

    async with session.post(microengine.polyswarmd_addr + '/offers/state', json=kwargs, params=params) as response:
        return (await response.json())['result']['state']

def sign_state(state, private_key):
    def to_32byte_hex(val):
       return web3.toHex(web3.toBytes(val).rjust(32, b'\0'))

    state_hash = to_32byte_hex(web3.sha3(hexstr=state))
    state_hash = defunct_hash_message(hexstr=state_hash)
    sig = web3.eth.account.signHash((state_hash), private_key=private_key)

    return {'r':web3.toHex(sig.r), 'v':sig.v, 's':web3.toHex(sig.s), 'state': state}


async def join_offer(microengine, session, guid, sig):
    uri = '{0}/offers/{1}/join'.format(microengine.polyswarmd_addr, guid)

    async with microengine.base_nonce_lock:
        params = {'account': microengine.address, 'base_nonce': microengine.base_nonce}
        async with session.post(uri, json=sig, params=params) as response:
            response = await response.json()

        if not check_response(response):
            return {}

        transactions = response['result']['transactions']
        microengine.base_nonce += len(transactions)

    return await post_transactions(microengine, session, transactions)


async def challenge_settle(microengine, offer_channel, session, guid):
    uri = '{0}/offers/{1}/challenge'.format(microengine.polyswarmd_addr, str(guid))

    prev_state = offer_channel.last_message
    sig = sign_state(prev_state['raw_state'], microengine.priv_key)
    challenge = create_signiture_dict(sig, prev_state, prev_state['raw_state'])

    async with microengine.base_nonce_lock:
        params = {'account': microengine.address, 'base_nonce': microengine.base_nonce}
        async with session.post(uri, json=challenge, params=params) as response:
            response = await response.json()

        if not check_response(response):
            return {}

        transactions = response['result']['transactions']
        microengine.base_nonce += len(transactions)

    return await post_transactions(microengine, session, transactions)


async def check_payout(offer_message, msg):
    has_correct_ambassador_balance = offer_message.last_message['state']['ambassador_balance'] - offer_message.last_message['state']['offer_amount'] == msg['state']['ambassador_balance']
    has_correct_expert_balance = offer_message.last_message['state']['expert_balance'] + offer_message.last_message['state']['offer_amount'] == msg['state']['expert_balance']
    has_correct_nonce = offer_message.last_message['state']['nonce'] + 1 == msg['state']['nonce']
    # TODO: needs to check that the correct ambassador address signed here

    return has_correct_ambassador_balance and has_correct_expert_balance and has_correct_nonce

async def check_offer(offer_message, msg):
    offer_message.last_message['state']['offer_amount'] == msg['state']['offer_amount']
    # TODO: needs to check that the correct ambassador address signed here

    return offer_message.last_message['state']['offer_amount'] == msg['state']['offer_amount']

async def accept_offer(microengine, session, ws, offer_message, guid):
    current_state = offer_message['state']
    uri = offer_message['artifact']
    mask = []
    verdicts = []

    for i in range(256):
        content = await get_artifact(microengine, session, uri, i)
        if not content:
            logging.debug('no more artifacts')
            break

        logging.info('scanning artifact: %s', i)

        bit, verdict, metadata = await microengine.scan(guid, content)

        verdicts.append(verdict)

        mask.append(bit)
    
    raw_state = await generate_state(session, microengine, close_flag=0,
        nonce=current_state['nonce'] + 1,
        ambassador=current_state['ambassador'],
        expert=microengine.address,
        msig_address= current_state['msig_address'],
        ambassador_balance= current_state['ambassador_balance'] - current_state['offer_amount'],
        expert_balance= current_state['expert_balance'] + current_state['offer_amount'],
        artifact_hash=uri, guid=str(current_state['guid']),
        offer_amount=current_state['offer_amount'],
        mask=mask,
        verdicts=verdicts)

    sig = sign_state(raw_state, microengine.priv_key)
    sig['type'] = 'accept'
    sig['artifact'] = offer_message['artifact']

    await ws.send(json.dumps(sig))

async def dispute_channel(microengine, offer_channel, session, guid):
    uri = '{0}/offers/{1}/settle'.format(microengine.polyswarmd_addr, str(guid))

    prev_state = offer_channel.last_message
    sig = sign_state(prev_state['raw_state'], microengine.priv_key)

    async with microengine.base_nonce_lock:
        params = {'account': microengine.address, 'base_nonce': microengine.base_nonce}
        async with session.post(uri, json=create_signiture_dict(offer_channel.last_message, sig, offer_channel.last_message['raw_state']), params=params) as response:
            response = await response.json()

        if not check_response(response):
            return None

        transactions = response['result']['transactions']
        microengine.base_nonce += len(transactions)

    res = await post_transactions(microengine, session, transactions)

    logging.info('Sent Channel Dispute \n%s', pformat(offer_channel.last_message['state']))



def create_signiture_dict(ambassador_sig, expert_sig, state):
    ret = { 'v': [], 'r': [], 's': [], 'state':state }

    ret['v'].append(int(ambassador_sig['v']))
    ret['r'].append(ambassador_sig['r'])
    ret['s'].append(ambassador_sig['s'])

    ret['v'].append(int(expert_sig['v']))
    ret['r'].append(expert_sig['r'])
    ret['s'].append(expert_sig['s'])

    return ret

async def close_disputed_channel(microengine, offer_channel, session, guid):
    sig = sign_state(offer_channel.last_message['raw_state'], microengine.priv_key)
    params = {'account': microengine.address, 'base_nonce': microengine.base_nonce}
    async with session.post(microengine.polyswarmd_addr + '/offers/' + str(offer_channel.guid) + '/closeChallenged', params=params, json=create_signiture_dict(offer_channel.last_message, sig, offer_channel.last_message['raw_state'])) as response:
        response = await response.json()

    transactions = response['result']['transactions']
    microengine.base_nonce += len(transactions)

    ret = await post_transactions(microengine, session, transactions)

    return ret

async def listen_for_events(microengine, loop):
    """Listen for events via websocket connection to polyswarmd

    Args:
        microengine (Microengine): The microengine instance
    """
    # http:// -> ws://, https:// -> wss://
    uri = '{0}/events'.format(microengine.polyswarmd_addr).replace('http', 'ws', 1)

    # if no protocol is specified, assume ws://
    if not uri.startswith('ws'):
        uri = 'ws://' + uri

    headers = {'Authorization': microengine.api_key} if microengine.api_key else {}
    params = {'account': microengine.address} if microengine.address else {}

    async with aiohttp.ClientSession(headers=headers) as session:
        if not await get_base_nonce(microengine, session):
            logging.error('error retrieving nonce')
            sys.exit(1)

        async with websockets.connect(uri, extra_headers=headers) as ws:
            while (microengine.testing['bounties'] != 0 and microengine.testing['offers'] != 0) or not microengine.schedule_empty():
                event = json.loads(await ws.recv())
                if event['event'] == 'initialized_channel' and event['data']['expert'] == microengine.address:
                    guid = event['data']['guid']
                    offer_channel = OfferChannel(guid)
                    logging.info('Offer Channel Initialized \n%s', pformat(event['data']))
                    loop.create_task(listen_for_offer_messages(microengine, offer_channel, loop, guid))
                    loop.create_task(listen_for_offer_events(microengine, offer_channel, loop, guid))

                if event['event'] == 'block':
                    number = event['data']['number']
                    if number % 100 == 0:
                        logging.info('Block %s', number)

                    loop.create_task(handle_new_block(microengine, session, number))
                elif event['event'] == 'bounty':
                    if microengine.testing['bounties'] == 0:
                        logging.info(
                            'bounty received but 0 bounties remaining in test mode, ignoring'
                        )
                        continue
                    elif microengine.testing['bounties'] > 0:
                        microengine.testing['bounties'] = microengine.testing['bounties'] - 1
                        logging.info('%s bounties remaining in test mode', microengine.testing)

                    bounty = event['data']
                    logging.info('received bounty: %s', bounty)

                    loop.create_task(handle_new_bounty(microengine, session, **bounty))

            if microengine.testing['bounties'] == 0 and microengine.testing['offers'] == 0:
                logging.info('exiting test mode')
                loop.stop()


async def listen_for_offer_events(microengine, offer_channel, loop, guid):
    # http:// -> ws://, https:// -> wss://
    uri = '{0}/events/{1}'.format(microengine.polyswarmd_addr.replace('http', 'ws', 1), guid)

    # if no protocol is specified, assume ws://
    if not uri.startswith('ws'):
        uri = 'ws://' + uri

    headers = {'Authorization': microengine.api_key} if microengine.api_key else {}

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with websockets.connect(uri, extra_headers=headers) as ws:
                offer_channel.event_socket = ws;
                while not ws.closed:
                    event = json.loads(await ws.recv())
                    if event['event'] == 'closed_agreement':
                        await offer_channel.close_sockets()
                    elif event['event'] == 'settle_started':
                        nonce = int(event['data']['nonce'])
                        settle_period_end = int(event['data']['settle_period_end'])

                        if nonce < offer_channel.nonce:
                            await challenge_settle(microengine, offer_channel, session, guid)
                        else:
                            logging.info('Settling Offer Channel Started \n%s', pformat(event['event']))
                            microengine.schedule_put(settle_period_end, offer_channel)

                    elif event['event'] == 'settle_challenged':
                        if nonce < offer_channel.nonce:
                            await challenge_settle(microengine, offer_channel, session, guid)
                        else:
                            microengine.schedule_put(settle_period_end, offer_channel)

                    if microengine.testing['bounties'] == 0 and microengine.testing['offers'] == 0:
                        offer_channel.close_sockets()
                        logging.info('exiting test mode')
                        loop.stop()
    except Exception as e:
        logging.error('ERROR IN OFFER EVENT SOCKET!')
        logging.error(str(e))
        raise e
    else:
        pass


async def listen_for_offer_messages(microengine, offer_channel, loop, guid):
    uri = '{0}/messages/{1}'.format(microengine.polyswarmd_addr.replace('http', 'ws', 1), guid)
    # if no protocol is specified, assume ws://
    if not uri.startswith('ws'):
        uri = 'ws://' + uri

    headers = {'Authorization': microengine.api_key} if microengine.api_key else {}

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with websockets.connect(uri, extra_headers=headers) as ws:
                offer_channel.msg_socket = ws;
                while not offer_channel.msg_socket.closed:
                    msg = json.loads(await offer_channel.msg_socket.recv())
                    if 'type' in msg and msg['type'] == 'open':
                        sig = sign_state(msg['raw_state'], microengine.priv_key)
                        await join_offer(microengine, session, guid, sig)
                        logging.info('Sending Offer Channel Join Message \n%s', pformat(msg['state']))
                        sig['type'] = 'join'
                        offer_channel.set_state(msg)
                        await offer_channel.msg_socket.send(json.dumps(sig))
                    elif msg['type'] == 'offer':
                        offer_okay = await check_offer(offer_channel, msg)
                        
                        if offer_okay:
                            if microengine.testing['offers'] > 0:
                                microengine.testing['offers'] = microengine.testing['offers'] - 1
                                logging.info('Offers left: %s', microengine.testing['offers'])
                            logging.info('Received Good Offer:\n%s', pformat(msg['state']))
                            offer_channel.set_state(msg)
                            await accept_offer(microengine, session, offer_channel.msg_socket, msg, guid)
                        else:
                            logging.info('Received Bad Offer - Will Dispute:\n%s', pformat(msg['state']))
                            
                            await dispute_channel(microengine, offer_channel, session, guid)

                    elif msg['type'] == 'payout':
                        pay_okay = await check_payout(offer_channel, msg)

                        if pay_okay:
                            logging.info('Received Good Pay:\n%s', pformat(msg['state']))
                            offer_channel.set_state(msg)
                        else:
                            logging.info('Received Bad Pay - Will Dispute:\n%s', pformat(msg['state']))
                            await dispute_channel(microengine, offer_channel, session, guid)

                    elif msg['type'] == 'close':
                        sig = sign_state(msg['raw_state'], microengine.priv_key)
                        sig['type'] = 'close'
                        await ws.send(json.dumps(sig))
                        await offer_channel.close_sockets()

                    if microengine.testing['bounties'] == 0 and microengine.testing['offers'] == 0:
                        offer_channel.close_sockets()
                        logging.info('exiting test mode')
                        loop.stop()

    except Exception as e:
        logging.error('ERROR IN MESSAGE SOCKET!')
        logging.error(str(e))
        raise e
    else:
        pass
