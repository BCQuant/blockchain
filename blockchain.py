import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import os

import requests
#from flask import Flask, jsonify, request

import asyncio
import aiohttp
from aiohttp import web

node = 'http://localhost'

qnt_hashes = {}
nodes = {}

def prepare_node(address):
    if not address:
        return address
    parsed_url = urlparse(address)
    
    if parsed_url.netloc:
        return parsed_url.netloc
    elif parsed_url.path:
        # Accepts an URL without scheme like '192.168.0.5:5000'.
        return parsed_url.path
    else:
        raise ValueError('Invalid URL')

def add_key(key, node=None):
    hash = hashlib.sha256(key).hexdigest()
    qnt_hashes[hash] = key
    
    if node is not None:
        node = prepare_node(node)
        nodes[node] = hash

def get_hash(obj, key_hash=None,node=None):
    if node is not None:
        node = prepare_node(node)
        key_hash = nodes[node]
    block_string = json.dumps(obj, sort_keys=True).encode()
    
    key = qnt_hashes.get(key_hash) if qnt_hashes.get(key_hash) else ''
    hash = hashlib.sha256(block_string + key).hexdigest()
    return hash


def check_hash(obj, key_hash=None, result='', node=None):
    if node is not None:
        node = prepare_node(node)
        key_hash = nodes[node]
    return get_hash(obj, key_hash) == result

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def remove_nodes(self):
        self.nodes = set()

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block['previous_hash']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for cur_node in neighbours:
            response = requests.get(f'http://{cur_node}/chain?node={node}')
            if response.status_code == 200:
                data = response.json()
                length = data['length']
                chain = data['chain']
                
                # Check if the length is longer and the chain is valid
                if length > max_length and check_hash(chain, result=data['hash'], node=cur_node) and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        #return guess_hash[:4] == "0000"
        return True

# Instantiate the Node
#app = Flask(__name__)
app = web.Application()
# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

#@app.route('/mine', methods=['GET'])
def mine(request):
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return web.json_response(response)


# @app.route('/transactions/new', methods=['POST'])
async def new_transaction(request):
    values = await request.json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    
    
    if not all(k in values for k in required):
        return web.json_response({'error':'Missing values'}, status=400)
        
    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return web.json_response(response, status=201)


#@app.route('/chain', methods=['GET'])
def full_chain(request):
    cur_node = None
    if 'node' in request.rel_url.query:
        cur_node = request.rel_url.query.get('node')
        print(cur_node)
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'node': node,
    }
    if cur_node is not None:
        response['hash'] = get_hash(blockchain.chain, node=cur_node)
    
    return web.json_response(response)


#@app.route('/nodes', methods=['GET'])
def get_nodes(request):
    response = {
        'message': 'Nodes',
        'total_nodes': list(blockchain.nodes),
    }
    return web.json_response(response)

#@app.route('/nodes/remove', methods=['GET'])
def remove_nodes(request):
    blockchain.remove_nodes()
    response = {
        'message': 'Nodes removed',
        'total_nodes': list(blockchain.nodes),
    }
    return web.json_response(response, status=201)

    
#@app.route('/nodes/register', methods=['POST'])
async def register_nodes(request):
    values = await request.json()

    nodes = values.get('nodes')
    if nodes is None:
        return web.json_response({"error":"Error: Please supply a valid list of nodes"}, status=400)
    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return web.json_response(response, status=201)


#@app.route('/nodes/resolve', methods=['GET'])
def consensus(request):
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return web.json_response(response)

waiting_for_addition = False
current_key = None
async def key_insert(request):
    print('inserting')
    data = await request.json()
    global waiting_for_addition
    
    if waiting_for_addition:
        return web.json_response({}, status=400)
        
    if 'node' not in data:
        return web.json_response({}, status=400)
    
    waiting_for_addition = True
    global current_key
    current_key = asyncio.Future()
    if 'recipient' not in data:
        session = aiohttp.ClientSession()
        asyncio.ensure_future(session.post('http://' + prepare_node(data['node']) + '/key/insert', json={'node':node, 'recipient':True}))
        #aiohttp.post(, data=json.dumps())
        #await asyncio.sleep(0.2)
        #os.system("KeyByCURL.out " + data['node'] + '/key/update' + ' ' + node + '/key/update')
    key = await current_key
    waiting_for_addition = False
    add_key(key, node=data['node'])
    
    return web.json_response({'success':True}, status=201)

async def key_update(request):
    global current_key
    global waiting_for_addition
    if not waiting_for_addition:
        return web.json_response({'success':False}, status=400)
    
    key = await request.content.read()
    print('Got key =', key)
    
    key = key.strip()
    current_key.set_result(key)
    
    return web.json_response({'success':True}, status=201)
    
async def get_debug_info(request):
    qnt_hashes

    return web.json_response({'qnt_hashes':{ k:qnt_hashes[k].decode('ascii') for k in qnt_hashes.keys()}, 'nodes':nodes})
    

app.router.add_get ('/mine', mine)
app.router.add_post('/transactions/new', new_transaction)
app.router.add_get ('/chain', full_chain)
app.router.add_get ('/nodes', get_nodes)

app.router.add_post('/nodes/register', register_nodes)
app.router.add_get ('/nodes/remove', remove_nodes)
app.router.add_get ('/nodes/resolve', consensus)

app.router.add_post('/key/insert', key_insert)
app.router.add_post('/key/update', key_update)

app.router.add_get('/debug', get_debug_info)

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('--host', default='localhost', type=str, help='server host')
    args = parser.parse_args()
    port = args.port
    host = args.host
    node = 'http://' + host + ':' + str(port)
    
    #app.run(host='0.0.0.0', port=port)
    web.run_app(app, port=port, host=host)
