import asyncio
import json
import logging
from contextlib import asynccontextmanager
import socket
import json
import sys
import itertools
import selectors
import hashlib
import bitcoin
from bitcoinlib.keys import Address
from typing import Union, List, Any, Dict, Optional
from Bitcoin import bech32m_bip350


methods = ["blockchain.block.header",
           "blockchain.block.headers",
           "blockchain.estimatefee",
           "blockchain.headers.subscribe",
           "blockchain.scripthash.get_balance",
           "blockchain.scripthash.get_history",
           "blockchain.scripthash.get_mempool",
           "blockchain.scripthash.listunspent",
           "blockchain.transaction.broadcast", 
           "blockchain.transaction.get",
           "blockchain.transaction.get_merkle",
           "blockchain.transaction.get_tsc_merkle",
           "blockchain.transaction.id_from_pos",
           "mempool.get_fee_histogram",
           "server.banner",
           "server.donation_address",
           "server.features",
           "server.peers.subscribe",
           "server.ping",
           "server.version"]

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def _next_request_id_factory():
    return itertools.count(1)

class RPCError(Exception):
    def __init__(self, id: int, error: dict) -> None:
        super().__init__(error.get("message"))
        self.id = id
        self.error = error

class MobickRPCsocket:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.counter = _next_request_id_factory()
        self.selector = selectors.DefaultSelector()
        self.reader, self.writer = None, None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def disconnect(self) -> None:
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()

    @asynccontextmanager
    async def manage_connection(self):
        try:
            await self.connect()
            yield
        finally:
            await self.disconnect()

    async def send_request(self, method: str, params: dict = None) -> dict:
        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params else [],
            "id": next(self.counter)
        }
        request_str = json.dumps(request_data) + '\n'
        self.writer.write(request_str.encode())
        await self.writer.drain()
        return await self.read_response(request_data["id"])

    async def read_response(self, request_id: int) -> dict:
        response_bytes = b''
        while True:
            chunk = await self.reader.read(2048)
            response_bytes += chunk
            if b'\n' in chunk:
                break

        try:
            response_data = json.loads(response_bytes.decode())
        except json.JSONDecodeError as e:
            raise RPCError(request_id, {"message": f"Failed to parse JSON response: {e}"})

        if "error" in response_data:
            raise RPCError(response_data.get("id"), response_data.get("error"))

        return response_data["result"]
    
    def address_to_electrum_scripthash(self, address):

            address1 = Address.parse(address)

            if address1.witness_type == 'segwit':
                decode = bech32m_bip350.decode(addr=address, hrp='bc')
                scriptPubKey= "00" + hex(len(decode[1]))[2:] + bytes(decode[1]).hex()
                scripthash = hashlib.sha256(bytes.fromhex(scriptPubKey)).digest()[::-1].hex()
                
            elif address1.witness_type == 'taproot':
                decode = bech32m_bip350.decode(addr=address, hrp='bc')
                scriptPubKey= "5120" + bytes(decode[1]).hex()
                scripthash = hashlib.sha256(bytes.fromhex(scriptPubKey)).digest()[::-1].hex()

            else:
                scriptPubKey = bitcoin.address_to_script(address)
                scripthash = hashlib.sha256(bytes.fromhex(scriptPubKey)).digest()[::-1].hex()
            
            return scripthash
    
    async def block_header(self, height: int, cp_height: int = 0) -> str:

        return await self.send_request(method=methods[0], params=[height, cp_height])
    
    async def block_headers(self, start_height: int, count: int, cp_height: int = 0) -> Dict:
 
        return await self.send_request(method=methods[1], params=[start_height, count, cp_height] )
    
    async def estimate_fee(self, number: int) -> float:
        # The number of blocks to target for confirmation
        return await self.send_request(method=methods[2], params=[number])
    
    async def headers_subscribe(self) -> Dict: 
        #  "Subscribe to receive block headers when a new block is found."
        return await self.send_request(method=methods[3], params=[])
    
    async def get_balance(self, address: str) -> Dict:

        scripthash = self.address_to_electrum_scripthash(address)
        return await self.send_request(method=methods[4], params=[scripthash])
    
    async def get_history(self, address: str) -> List[Dict]:
        # "Return the confirmed and unconfirmed history of a script hash."
        scripthash = self.address_to_electrum_scripthash(address)
        return await self.send_request(method=methods[5], params=[scripthash])
    
    async def get_mempool(self, address: str) -> List:
        # "Return the unconfirmed transactions of a script hash."
        scripthash = self.address_to_electrum_scripthash(address)
        return await self.send_request(method=methods[6], params=[scripthash])

    async def list_unspent(self, address: str) -> List[Dict]:

        scripthash = self.address_to_electrum_scripthash(address)
        return await self.send_request(method=methods[7], params=[scripthash])
    
    async def broadcast_transaction(self, tx_hexstring: str):
        
        return await self.send_request(method=methods[8], params=[tx_hexstring])

    async def get_transaction(self, txid: str, verbose: bool=True) -> Dict:

        return await self.send_request(method=methods[9], params=[txid, verbose])
    
    async def get_merkel(self, txid: str, height: int) -> Dict:

        return await self.send_request(method=methods[10], params=[txid, height])

    @DeprecationWarning
    async def get_tsc_merkle(self, txid: str, height: int, txid_or_tx: str="txid", target_type: str="block_hash"):
        # "not supported in ElectrumX version 1.16.0"
        if txid_or_tx not in ["txid", "tx"]:
            raise ValueError("Invalid parameter")
        if target_type not in ["block_hash", "block_header", "merkle_root"]:
            raise ValueError("Invalid parameter")
        
        return await self.send_request(method=methods[11], params=[txid, height, txid_or_tx, target_type])
    
    async def id_from_pos(self, height: int, tx_pos: str, merkle: bool=True) -> Dict:
        # "Return a transaction hash and optionally a merkle proof, given a block height and a position in the block."
        return await self.send_request(method=methods[12], params=[height, tx_pos, merkle])
    
    async def get_fee_histogram(self) -> List:
        
        return await self.send_request(method=methods[13], params=[])
    
    async def server_banner(self) -> str:

        return await self.send_request(method=methods[14], params=[])
    
    async def server_donation(self) -> str:

        return await self.send_request(method=methods[15], params=[])
    
    async def server_features(self) -> Dict:

        return await self.send_request(method=methods[16], params=[])
    
    async def server_peers_subscribe(self) -> List:

        return await self.send_request(method=methods[17], params=[])
    
    async def server_ping(self) -> None:

        return await self.send_request(method=methods[18], params=[])

    async def server_version(self, client_name: str="", protocol_version: Union[str, List[str]]="1.4") -> List:
        # client_name => A string identifying the connecting client software.
        # protocol_version => An array [protocol_min, protocol_max], each of which is a string. 
        #                     If protocol_min and protocol_max are the same, they can be passed as a single string 
        #                     rather than as an array of two strings, as for the default value.

        return await self.send_request(method=methods[19], params=[client_name, protocol_version])


def deserialize_header(header: Union[str, bytes]) -> List[Dict]:
    try:
        header = bytes.fromhex(header)
    except:
        pass
    assert len(header) % 80 == 0
    
    num_parts = len(header) // 80
    parts = [header[i * 80 : (i + 1) * 80] for i in range(num_parts)]
    result = []
    for part in parts:
        result.append(
            {"version": part[:4][::-1].hex(),
            "prevhash": part[4:36][::-1].hex(),
            "merkle_root": part[36:68][::-1].hex(),
            "timestamp": part[68:72][::-1].hex(),
            "bits": part[72:76][::-1].hex(),
            "nonce": part[76:80][::-1].hex()})
    return result


# Example usage of RPC client
async def main():

    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
    async with rpc.manage_connection():
        try:
            print(await rpc.block_header(height=1000, cp_height=0))
            print(await rpc.block_headers(start_height=1000, count=10, cp_height=0))
            print(await rpc.estimate_fee(number=6))
            print(await rpc.headers_subscribe())
            print(await rpc.get_balance('bc1qdapypxj43wm3c9z0ke8jewe8ygv9yueef0rk3lhwggw89pdznyyq745sl5'))
            print(await rpc.get_history('bc1qdapypxj43wm3c9z0ke8jewe8ygv9yueef0rk3lhwggw89pdznyyq745sl5'))
            print(await rpc.get_mempool('1377msqsMLd4WToHgbFCJHJh51woBG5TvF'))
            print(await rpc.list_unspent('bc1pzhupp97yxu5pdj23evwg2f7vhfwqfr8k3t0ujr4majpy9uxqdk3spqq4zt'))
            print(json.dumps(await rpc.get_transaction(txid='315a109d4a0e801ee831d360e6445db4f1ab87b4c355713fc39ddf107309b029', verbose=True),indent=4))
            print(await rpc.get_merkel(txid='e67a0550848b7932d7796aeea16ab0e48a5cfe81c4e8cca2c5b03e0416850114', height=111194))
            # print(await rpc.get_tsc_merkle(txid='6a9611ab2996acc61f9b0491ea1f57834ec244c3c5f7595728c06048aa937554',
            #                    height=758152, txid_or_tx="txid", target_type="block_hash"))
            print(await rpc.id_from_pos(height=758152, tx_pos=2, merkle=True))
            print(await rpc.get_fee_histogram())
            print(await rpc.server_banner())
            print(await rpc.server_donation())
            print(await rpc.server_features())
            print(await rpc.server_peers_subscribe())
            print(await rpc.server_ping())
            print(await rpc.server_version(client_name="ElectrumX", protocol_version=["1.2", "1.8"]))

        except RPCError as e:
            logging.error(f"RPC Error: {e}")


if __name__ == "__main__":
    asyncio.run(main=main())
    

