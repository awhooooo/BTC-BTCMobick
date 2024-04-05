import requests
import json
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor


# http://blockchain2.mobick.info/api/docs
api_calls = {"utxo-set": "/api/blockchain/utxo-set",
             "address": "/api/address/%s/?limit=%s&offset=%s&sort=%s",
             "mining": "/api/mining/next-block",
             "unconfirmed_txs": "/api/mining/next-block/txids",
             "transaction": "/api/tx/%s",
             "block": "/api/block/%s",
             "height": "/api/blocks/tip"}


class BTCMobickExplorer:

    def __init__(self, base_url):
        self.base_url = base_url    # "https://blockchain2.mobick.info"


    def request_and_jsonize(self, url: str):
        response = requests.get(url=url)
        json_data = json.loads(response.text)
        return json_data


    def get_block(self, block):
        url = self.base_url + api_calls["block"] % (str(block))
        result = self.request_and_jsonize(url)
        return result


    def history(self, address: str, limit=10000, offset=0, sort="desc"):

        url = self.base_url + api_calls["address"] % (address, str(limit), str(offset), sort)
        result = self.request_and_jsonize(url)
        return result.get('txHistory', {}).get('blockHeightsByTxid', 0)


    def get_tx(self, txhash: str):

        url = self.base_url + api_calls["transaction"] % (txhash)
        result = self.request_and_jsonize(url)
        return result


    def get_balance(self, address: str, limit=10, offset=0, sort="desc"):

        url = self.base_url + api_calls["address"] % (address, str(limit), str(offset), sort)
        result = self.request_and_jsonize(url)
        balance = result.get('txHistory', {}).get('balanceSat', 0) + result.get('txHistory', {}).get('unconfirmedBalanceSat', 0)
        return balance / (10 ** 8)
    

    async def _get_balance_async(self, session, address):
        url = self.base_url + api_calls["address"] % (address, "10", "0", "desc")
        async with session.get(url) as response:
            result = await response.json()
            balance = result.get('txHistory', {}).get('balanceSat', 0) / 10 ** 8
            return {"address": address, "balance": balance}


    async def get_balances_async(self, addresses):
        async with aiohttp.ClientSession() as session:
            tasks = [self._get_balance_async(session, addr) for addr in addresses]
            return await asyncio.gather(*tasks)
        

    def current_block_height(self):
        
        url = self.base_url + api_calls["height"]
        result = self.request_and_jsonize(url)
        return result.get("height", 0)


    def unconfirmed_transactions(self):
        
        url = self.base_url + api_calls["unconfirmed_txs"]
        result = self.request_and_jsonize(url)
        return result
    

def main():
    
    start = time.time()
    explorer = BTCMobickExplorer("http://blockchain2.mobick.info")
    print('\n')
    print("block #1000 => ", explorer.get_block(1000))
    print('\n')
    print("block #0 => ", explorer.get_block("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"))
    print('\n')
    print("tx history 1DvZpgNxn7vYVw9YUGcmReX44DJFrMmrRN => ", explorer.history("1DvZpgNxn7vYVw9YUGcmReX44DJFrMmrRN"))
    print('\n')
    print("tx 68b5e0b6c8f7e0d064b2b695bedd3beabc09a36fad000b9e9b455fb414bfd0ca => ", explorer.get_tx("68b5e0b6c8f7e0d064b2b695bedd3beabc09a36fad000b9e9b455fb414bfd0ca"))
    print('\n')
    print("balance 1DvZpgNxn7vYVw9YUGcmReX44DJFrMmrRN => ", explorer.get_balance("1DvZpgNxn7vYVw9YUGcmReX44DJFrMmrRN"))
    print('\n')
    print("current block height => ", explorer.current_block_height())
    print('\n')
    print("unconfirmed transaction => ", explorer.unconfirmed_transactions())

    Jeju_tx1 = explorer.get_tx("dbaca864c2494e969af60a75d872da9aaf9022c9941c6a34eae168c7329431d5")
    Jeju_tx2 = explorer.get_tx("66632e2e6edbb61e6ac9ad16d33b11821a5d5b2148cbb1155e4ebf5df7180828")
    Jeju_tx3 = explorer.get_tx("5ffdbc9418946a02895a835be11b448818def8e18bc2fd0540847cb90fed2128")
    Sydney_tx = explorer.get_tx("06b76a12d735f9010137382ecb5c07cf87a166c722a6a5d7d50280462c3f44e9")
    Montville_tx = explorer.get_tx("4cc002a09c7900d346c6586821eb38f921a259f582d87003b86ad11311e260fd")
    
    Jeju = []
    Sydney = []
    Montville = []
    unspent_Jeju = []
    spent_Jeju = []
    unspent_Sydney = []
    spent_Sydney = []
    unspent_Montville = []
    spent_Montville = []

    for i in range(1001):
        Jeju.append(Jeju_tx1['vout'][i]['scriptPubKey']['addresses'][0])
    for i in range(800):
        Jeju.append(Jeju_tx2['vout'][i]['scriptPubKey']['addresses'][0])
    for i in range(2000):
        Jeju.append(Jeju_tx3['vout'][i]['scriptPubKey']['addresses'][0])
    for i in range(300):
        Sydney.append(Sydney_tx['vout'][i]['scriptPubKey']['addresses'][0])
    for i in range(501):
        Montville.append(Montville_tx['vout'][i]['scriptPubKey']['addresses'][0])

    # Using asyncio
    loop = asyncio.get_event_loop()
    balances_async = loop.run_until_complete(explorer.get_balances_async(Jeju + Sydney + Montville))
    for data in balances_async:
        print(data["address"], "==>", data["balance"])
    print("file running time => ", time.time() - start, " seconds")


if __name__ == "__main__":
    main()
    
