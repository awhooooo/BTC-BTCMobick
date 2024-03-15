import socket
import json
import sys
import itertools
import hashlib
import asyncio
import bitcoin
import selectors
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


def _next_request_id_factory():
    return itertools.count(1)


class RPCError(Exception):
    """
    Enrich the `Error` - https://www.jsonrpc.org/specification#error_object
    with the `id` of the request that caused the error.
    """
    def __init__(self, id: int, error: dict) -> None:
        super().__init__(error.get("message"))
        self.id = id
        self.error = error


class MobickRPCsocket:

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.counter = _next_request_id_factory()
        self.selector = selectors.DefaultSelector()
        
    def connect(self) -> None:
        self.socket.connect((self.host, self.port))
        self.socket.setblocking(False)  # Set to non-blocking mode
        self.selector.register(self.socket, selectors.EVENT_READ)

    def disconnect(self) -> None:
        self.selector.unregister(self.socket)
        self.socket.close()
               

    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:

        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params is not None else [],
            "id": next(self.counter)
        }

        request_str = json.dumps(request_data) + '\n'

        try:
            self.socket.sendall(request_str.encode())
        except OSError as e:
            raise RPCError(id=request_data["id"], error={"message": f"Failed to send request: {e}"})

        response_bytes = b''
        while not b'\n' in response_bytes:
            try:
                events = self.selector.select(timeout=1)  # Wait for data availability
                if not events:
                    break  # Break if no events (timeout)
                for key, mask in events:
                    if mask & selectors.EVENT_READ:
                        chunk = key.fileobj.recv(2048)
                        response_bytes += chunk
                        if b'\n' in chunk:
                            break  # Break out of the inner loop
            except asyncio.TimeoutError:
                raise RPCError(id=request_data["id"], error={"message": "Timed out waiting for response"})

        if not response_bytes:
            raise RPCError(id=request_data["id"], error={"message": "No response received"})

        try:
            response_data = json.loads(response_bytes.decode())
        except json.JSONDecodeError as e:
            raise RPCError(id=request_data["id"], error={"message": f"Failed to parse JSON response: {e}"})

        if response_data.get("error") is not None:
                raise RPCError(id=response_data.get("id"), error=response_data.get("error"))
        else:
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


async def query_balances(addresses: List[str], rpc: MobickRPCsocket) -> Dict[str, Dict]:
    balances = {}
    for address in addresses:
        try:
            balance = await rpc.get_balance(address)
            balances[address] = balance["confirmed"] / (10 ** 8)
        except RPCError as e:
            print(f"Error querying balance for address {address}: {e}")
            balances[address] = None
    return balances


async def main():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    rpc.connect()
    print("connected")
    print(await rpc.block_header(height=1000, cp_height=0))
    print(await rpc.block_headers(start_height=1000, count=10, cp_height=0))
    print(await rpc.estimate_fee(number=6))
    print(await rpc.headers_subscribe())
    print(await rpc.get_balance('bc1q07alqsvf47x4jwmc7xd5me2rjqgc4jtsjlrpvc'))
    print(await rpc.get_history('bc1qy9de0qt94562vutkfvvqsvupqljufd4h3u3zl9ljxlrn7y2damzqx792cw'))
    print(await rpc.get_mempool('1377msqsMLd4WToHgbFCJHJh51woBG5TvF'))
    print(await rpc.list_unspent('1377msqsMLd4WToHgbFCJHJh51woBG5TvF'))
    print(await rpc.get_transaction(txid='e67a0550848b7932d7796aeea16ab0e48a5cfe81c4e8cca2c5b03e0416850114', verbose=True))
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
    rpc.disconnect()
    print("disconnected")


if __name__ == "__main__":

    asyncio.run(main=main())
    

