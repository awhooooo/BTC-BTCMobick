from Mobick.Mobick_RPC import *


async def main():

    rpc = MobickRPCsocket(host="3.39.215.205", port=40008)
    rpc.connect()
    tx1 = await rpc.get_transaction(txid="1e70a584606fa9c6f4c4e8a497bda757819d89dc201fa2da0b89b05e54bc8658")
    script_bytes = bytes.fromhex(tx1['vin'][0]['txinwitness'][1])
    # print(int.from_bytes(script_bytes[54:56], byteorder='little'))

    data = b''
    i = 53
    while i + script_bytes[i] <= len(script_bytes):
        if script_bytes[i] == 76:
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
    with open('/Users/ME/Downloads/extraction.png', 'wb') as file:
        file.write(data)
        file.close()

    rpc.disconnect()


if __name__ == "__main__":
    asyncio.run(main=main())



