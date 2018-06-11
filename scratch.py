import subprocess
import sys
import requests
import asyncio
import websockets
import tempfile
import os
#INPUT NEEDED:PATH TO BACKEND BINARY/SCRIPT
PATH = 'WHEREVER YOUR BACKEND BINARY/SCRIPT/WHATEVER YOU USED IS LOCATED'
#HOST = os.environ['POLYSWARMD_HOST']
HOST = 'localhost:31337'
MICROENGINE_HOST = ''



# Description: Helper function to create object of given object 
# Params: str to be decoded
# return: decoded json object
# TODO: 
def jsonify(encoded):
	decoded = '';

	try:
		decoded = encoded.json()
	except ValueError:
		sys.exit("Error in jsonify: ", sys.exc_info()[0])

	return decoded


# Description: Helper function to get guid and uri
# Params: str response
# return: tuple (guid, uri)
# TODO: 
def parseEventData(str):
	#split on ""
	splitArr = str.split('"')[1::2]

	#return element after 'guid' and after 'uri'
	index = splitArr.index('guid')
	index2 = splitArr.index('uri')
	return (splitArr[index+1], splitArr[index2+1])


# Description: Helper function that creates a tempfile to hold artifact contents
# Params: Hash of artifact already in artifacts dir
# return: tuple (guid, uri)
# TODO: 
def createTempFile(uri):
	(tmp, tmpPath) = tempfile.mkstemp()

	write(tmp, getArtifact(uri).encode())
	close(tmp)

	return tmpPath


def setAccount():
	response = ''

	try:
		response = requests.get('http://'+HOST+'/accounts')
	except:
		print("Error in unlockAccount: ", sys.exc_info()[0])
		sys.exit()

	accountList = jsonify(response)


	if accountList['status'] != "OK":
		sys.exit("invalid accounts")

	global MICROENGINE_HOST
	MICROENGINE_HOST = accountList['result'][0]


# Description: Unlock test account for use
# Params: N/A
# return: True for success, False for fail
# TODO: Create new account, take account as argument (?). check if acc NEEDS to be unlocked
def unlockAccount():

	#retrieve account to unlock
	setAccount()

	#unlock account
	headers = {'Content-Type': 'application/json'}
	dataUnlock = '{"password": "password"}'
	try:
		response = requests.post('http://'+HOST+'/accounts/'+MICROENGINE_HOST+'/unlock', headers=headers, data=dataUnlock)
	
	except:
		print("Error in unlockAccount: ", sys.exc_info()[0])

	unlockJSON = jsonify(response)
	statusUnlock = unlockJSON['status']

	#check that acocunt was unlocked
	if statusUnlock !='OK':
		#print(unlockJSON)		
		return False

	print("Unlock: "+ statusUnlock)

	return True


# Description: Call GET on polyswarmd for specific hash
# Params: Hash of artifact already in artifacts dir
# return: artifact file contents
# TODO: 256 artifacts per... like the Go scratch.
def getArtifact(uri):

	response = ''
	try:
		response = requests.get('http://'+HOST+'/artifacts/'+uri+'/0')
	except error as e:
		sys.exit(e.message)

	return response.text


# Description: Scan file using BitDefender. Parse result to get infection or not
# Params: File to be scanned
# return: True for infected file and False for non-infected

def scan(item):
	result = ''

	#scan file given
	try:
		result = subprocess.check_output([PATH, item]).decode("utf-8").split('\n')
	except subprocess.CalledProcessError as e:
		result = e.output.decode("utf-8").split('\n')

	#print(result)

	#check for infected line
	for line in result:
		if(line.find('infected: ') is not -1):
			print("Infected")
			return True	

	#if pass all lines AND dont see infected in output, then not infected as detected by former anal backend
	print("Not Infected")
	return False


# Description: Relay verdict to swarm
# Params: Verdict - true or false, guid - the bounty that was scanned
# return: status of post
# TODO: Parse response
def sendVerdict(verdict, guid):
	if verdict is True:
		verdict = 'true'
	else:
		verdict = 'false'

	headers = {'Content-Type': 'application/json'}
	data = '{"bid": "62500000000000000", "mask": [true], "verdicts": ['+verdict+'], "metadata": "foo"}'

	try:
		response = requests.post('http://'+HOST+'/bounties/'+guid+'/assertions', headers=headers, data=data)
	except:
		print("Error in sendVerdict: ", sys.exc_info()[0])

	#parse for success/status
	json = jsonify(response)

	print("sendVerdict:")
	print(json)


# Description: 	Listen for events on daemon. When bounty is posted, scan item and 
#				send verdict
# Params: N/A
# return: N/A
# TODO: 
async def waitForEvent():
	async with websockets.connect('ws://'+HOST+'/events') as websocket:
		while True:
			event = await websocket.recv()
			if 'bounty' in event:
				print("Bounty created")
				(guid, uri) = parseEventData(event)
				tmp = createTempFile(uri)
				verdict = scan(tmp)
				if verdict is True or verdict is False:
					sendVerdict(verdict, guid)
				else:
					print("Verdict not useable. Not sending verdict")


# Description: Start infinite loop to listen
# Params: N/A
# return: N/A
# TODO: Relatively useless right now...
if __name__ == "__main__":
	unlockAccount();
	asyncio.get_event_loop().run_until_complete(waitForEvent())
