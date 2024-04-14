from Mobick.Mobick_RPC import *


async def main1():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    rpc.connect()
    tx1 = await rpc.get_transaction(txid="f55137f99a3b753a4ca892f9567ad1b3f6e6a89391bb8003ed7ce6d354bf0af9")
    script_bytes = bytes.fromhex(tx1['vin'][0]['txinwitness'][1])
    # print(int.from_bytes(script_bytes[54:56], byteorder='little'))

    data = b''
    i = 53
    while i + script_bytes[i] <= len(script_bytes):
        if script_bytes[i] >= 1 and script_bytes[i] <=75:
            next_byte_length = script_bytes[i]
            data += script_bytes[i+1:i+1+next_byte_length]
            i += 1 + next_byte_length
        elif script_bytes[i] == 76:
            next_byte_length = int.from_bytes(script_bytes[i+1], byteorder='little')
            data += script_bytes[i+2:i+2+next_byte_length]
            i += 2 + next_byte_length
        elif script_bytes[i] == 77:
            next_byte_length = int.from_bytes(script_bytes[i+1:i+3], byteorder='little')
            data += script_bytes[i+3:i+3+next_byte_length]
            i += 3 + next_byte_length
        else:
            print("Wrong Transaction")
            break
    
    # print(len(data))
    with open('/Users/ME/Downloads/Homer_Simpson.png', 'wb') as file:
        file.write(data)
        file.close()

    rpc.disconnect()


async def main2():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    rpc.connect()

    tx2 = await rpc.get_transaction(txid="98103fcecad6738036ceff8fc7a6b9801f020639f4b961babb71ce2b2048a3b6")
    script_bytes = bytes.fromhex(tx2['vin'][0]['txinwitness'][1])

    data = b''
    i = 59
    while i + script_bytes[i] <= len(script_bytes):
        if script_bytes[i] >= 1 and script_bytes[i] <=75:
            next_byte_length = script_bytes[i]
            data += script_bytes[i+1:i+1+next_byte_length]
            i += 1 + next_byte_length
        elif script_bytes[i] == 76:
            next_byte_length = int.from_bytes(script_bytes[i+1], byteorder='little')
            data += script_bytes[i+2:i+2+next_byte_length]
            i += 2 + next_byte_length
        elif script_bytes[i] == 77:
            next_byte_length = int.from_bytes(script_bytes[i+1:i+3], byteorder='little')
            data += script_bytes[i+3:i+3+next_byte_length]
            i += 3 + next_byte_length
        else:
            print("Wrong Transaction")
            break
    
    # print(len(data))
    with open('/Users/ME/Downloads/BTCMobick_Whitepaper.pdf', 'wb') as file:
        file.write(data)
        file.close()

    rpc.disconnect()

if __name__ == "__main__":
    asyncio.run(main=main1())
    asyncio.run(main=main2())


