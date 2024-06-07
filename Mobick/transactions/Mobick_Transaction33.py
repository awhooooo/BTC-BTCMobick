import sys
sys.path.append("/Users/ieunmi/PycharmProjects/pythonProject")
from bitcoinutils.setup import setup
from bitcoinutils.utils import *
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import *
from Mobick.Mobick_RPC2 import *
from Mobick.MRC_20 import *


setup("mainnet")

priv1 = PrivateKey(wif="secret for obvious reason 1")
priv2 = PrivateKey(wif="secret for obvious reason 2")
priv3 = PrivateKey(wif="secret for obvious reason 3")
priv4 = PrivateKey(wif="secret for obvious reason 4")
priv5 = PrivateKey(wif="secret for obvious reason 5")

pub1 = priv1.get_public_key()
pub2 = priv2.get_public_key()
pub3 = priv3.get_public_key()
pub4 = priv4.get_public_key()
pub5 = priv5.get_public_key()


async def main1():

    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
    async with rpc.manage_connection():
        try:
            address1 = pub1.get_taproot_address()
            print(address1.to_string())

            utxos = await rpc.list_unspent(address1.to_string())
            print(utxos)

            with open('/Users/legacy/사진자료/homer.png', 'rb') as img_file:
                image_bytes = img_file.read()

            segments = []
            # Loop through the image bytes and divide it into segments with 520 bytes
            for i in range(0, len(image_bytes), 520):
                segment = image_bytes[i:i + 520]
                segments.append(segment.hex())

            inscription_script1 = Script([pub1.to_x_only_hex(), "OP_CHECKSIG", "OP_FALSE", "OP_IF", "ord".encode('utf-8').hex(),
                                        "01", "image/png".encode('utf-8').hex(), "OP_FALSE"] + segments + ["OP_ENDIF"])
            address2 = pub2.get_taproot_address([inscription_script1])

            ins1_1 = TxInput(txid=utxos[0]['tx_hash'], txout_index=utxos[0]['tx_pos'])
            outs1_1 = TxOutput(amount=200000, script_pubkey=address2.to_script_pub_key())
            outs1_2 = TxOutput(amount=utxos[0]['value']-210000, script_pubkey=address1.to_script_pub_key())
            tx1 = Transaction(inputs=[ins1_1], outputs=[outs1_1, outs1_2], has_segwit=True)
            
            sig1_1 = priv1.sign_taproot_input(tx=tx1, txin_index=0, utxo_scripts=[address1.to_script_pub_key()], amounts=[utxos[0]['value']])
            tx1.witnesses.append(TxWitnessInput([sig1_1]))
            
            print("\nRaw signed transaction:\n" + tx1.serialize())
            print(await rpc.broadcast_transaction(tx_hexstring=tx1.serialize()))

        except RPCError as e:
            logging.error(f"RPC Error: {e}")


async def main2():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    async with rpc.manage_connection():
        try:
            with open('/Users/legacy/사진자료/homer.png', 'rb') as img_file:
                image_bytes = img_file.read()

            segments = []
            # Loop through the image bytes and divide it into segments with 520 bytes
            for i in range(0, len(image_bytes), 520):
                segment = image_bytes[i:i + 520]
                segments.append(segment.hex())

            inscription_script1 = Script([pub1.to_x_only_hex(), "OP_CHECKSIG", "OP_FALSE", "OP_IF", "ord".encode('utf-8').hex(),
                                        "01", "image/png".encode('utf-8').hex(), "OP_FALSE"] + segments + ["OP_ENDIF"])
            address1 = pub1.get_taproot_address()
            address2 = pub2.get_taproot_address([inscription_script1])

            utxos = await rpc.list_unspent(address2.to_string())
            print(utxos)
            
            # address2 = P2trAddress(address="bc1pz4qtl0ykzngtdsq28pnlk4r4etrweru59cn5g9043wx4e0aarfhqa6rlme")

            ins2_1 = TxInput(txid=utxos[0]['tx_hash'], txout_index=utxos[0]['tx_pos'])
            outs2_1 = TxOutput(amount=190000, script_pubkey=address1.to_script_pub_key())
            tx2 = Transaction(inputs=[ins2_1], outputs=[outs2_1], has_segwit=True)

            sig2_1 = priv1.sign_taproot_input(tx=tx2, txin_index=0, utxo_scripts=[address2.to_script_pub_key()], 
                                            amounts=[utxos[0]['value']], script_path=True, tapleaf_script=inscription_script1, tweak=False)
            
            control_block2 = ControlBlock(pubkey=pub2, script_to_spend=inscription_script1, is_odd=address2.is_odd())
            tx2.witnesses.append(TxWitnessInput([sig2_1, inscription_script1.to_hex(), control_block2.to_hex()]))

            # print("\nRaw signed transaction:\n" + tx2.serialize())
            await rpc.broadcast_transaction(tx_hexstring=tx2.serialize())
            
        except RPCError as e:
            logging.error(f"RPC Error: {e}")



async def main3():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    async with rpc.manage_connection():
        try:
            tx3 = await rpc.get_transaction(txid="f55137f99a3b753a4ca892f9567ad1b3f6e6a89391bb8003ed7ce6d354bf0af9")

        except RPCError as e:
            logging.error(f"RPC Error: {e}")

    script_bytes = bytes.fromhex(tx3['vin'][0]['txinwitness'][1])
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
    with open('/Users/ieunmi/Downloads/homerland.png', 'wb') as file:
        file.write(data)
        file.close()

    rpc.disconnect()


async def main4():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    async with rpc.manage_connection():
        try:

            address1 = pub1.get_taproot_address()
            print(address1.to_string())
            utxos = await rpc.list_unspent(address1.to_string())
            print(utxos)
            
            with open('/Users/legacy/Documents/BTCMobick Whitepaper.pdf', 'rb') as pdf_file:
                pdf_bytes = pdf_file.read()

            segments = []
            # Loop through the image bytes and divide it into segments with 520 bytes
            for i in range(0, len(pdf_bytes), 520):
                segment = pdf_bytes[i:i + 520]
                segments.append(segment.hex())

            inscription_script2 = Script([pub1.to_x_only_hex(), "OP_CHECKSIG", "OP_FALSE", "OP_IF", "ord".encode('utf-8').hex(),
                                        "01", "application/pdf".encode('utf-8').hex(), "OP_FALSE"] + segments + ["OP_ENDIF"])
            address3 = pub2.get_taproot_address([inscription_script2])

            ins4_1 = TxInput(txid=utxos[0]['tx_hash'], txout_index=utxos[0]['tx_pos'])
            outs4_1 = TxOutput(amount=200000, script_pubkey=address3.to_script_pub_key())
            outs4_2 = TxOutput(amount=utxos[0]['value']-210000, script_pubkey=address1.to_script_pub_key())
            tx4 = Transaction(inputs=[ins4_1], outputs=[outs4_1, outs4_2], has_segwit=True)

            sig4_1 = priv1.sign_taproot_input(tx=tx4, txin_index=0, utxo_scripts=[address1.to_script_pub_key()], amounts=[utxos[0]['value']])
            tx4.witnesses.append(TxWitnessInput([sig4_1]))
            
            print("\nRaw signed transaction:\n" + tx4.serialize())
            print(await rpc.broadcast_transaction(tx_hexstring=tx4.serialize()))

        except RPCError as e:
                logging.error(f"RPC Error: {e}")


async def main5():

    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
    async with rpc.manage_connection():
        try:
    
            with open('/Users/legacy/Documents//BTCMobick Whitepaper.pdf', 'rb') as pdf_file:
                pdf_bytes = pdf_file.read()

            segments = []
            # Loop through the image bytes and divide it into segments with 520 bytes
            for i in range(0, len(pdf_bytes), 520):
                segment = pdf_bytes[i:i + 520]
                segments.append(segment.hex())

            inscription_script2 = Script([pub1.to_x_only_hex(), "OP_CHECKSIG", "OP_FALSE", "OP_IF", "ord".encode('utf-8').hex(),
                                        "01", "application/pdf".encode('utf-8').hex(), "OP_FALSE"] + segments + ["OP_ENDIF"])
            
            address1 = pub1.get_taproot_address()
            address3 = pub2.get_taproot_address([inscription_script2])

            print(address1.to_string())
            utxos = await rpc.list_unspent(address3.to_string())
            print(utxos)

            ins5_1 = TxInput(txid=utxos[0]['tx_hash'], txout_index=utxos[0]['tx_pos'])
            outs5_1 = TxOutput(amount=utxos[0]['value']-46000, script_pubkey=address1.to_script_pub_key())
            tx5 = Transaction(inputs=[ins5_1], outputs=[outs5_1], has_segwit=True)

            sig5_1 = priv1.sign_taproot_input(tx=tx5, txin_index=0, utxo_scripts=[address3.to_script_pub_key()], amounts=[utxos[0]['value']],
                                            script_path=True, tapleaf_script=inscription_script2, tweak=False)
            control_block5 = ControlBlock(pubkey=pub2, script_to_spend=inscription_script2, is_odd=address3.is_odd())
            tx5.witnesses.append(TxWitnessInput([sig5_1, inscription_script2.to_hex(), control_block5.to_hex()]))
            
            print("\nRaw signed transaction:\n" + tx5.serialize())
            print(await rpc.broadcast_transaction(tx_hexstring=tx5.serialize()))

        except RPCError as e:
                logging.error(f"RPC Error: {e}")


async def main6():

    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
    async with rpc.manage_connection():
        try:
            tx6 = await rpc.get_transaction(txid="98103fcecad6738036ceff8fc7a6b9801f020639f4b961babb71ce2b2048a3b6")
        except RPCError as e:
            logging.error(f"RPC Error: {e}")

    script_bytes = bytes.fromhex(tx6['vin'][0]['txinwitness'][1])

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
    with open('/Users/legacy/Downloads/extraction.pdf', 'wb') as file:
        file.write(data)
        file.close()

async def main7():

    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
    async with rpc.manage_connection():
        try:
            tr_script_p2pk1 = Script([pub1.to_x_only_hex(), "OP_CHECKSIG"])
            tr_script_p2pk2 = Script([pub2.to_x_only_hex(), "OP_CHECKSIG"])
            tr_script_p2pk3 = Script([pub3.to_x_only_hex(), "OP_CHECKSIG"])
            tr_script_p2pk4 = Script([pub4.to_x_only_hex(), "OP_CHECKSIG"])
            tr_script_p2pk5 = Script([pub5.to_x_only_hex(), "OP_CHECKSIG"])
            all_leafs = [[tr_script_p2pk1, tr_script_p2pk2], [tr_script_p2pk3, [tr_script_p2pk4, tr_script_p2pk5]]]

            address4 = pub1.get_taproot_address(all_leafs)
            address5 = P2pkhAddress("16vnUfDxdMWYKYpw4gCqkwCHRy7jtzgJgn")
            print(address4.to_string())

            utxos = await rpc.list_unspent("bc1psly7fjsww8mtmgwwr2rllujscwlfrzznqp4239cxvl5t22fjndrq5pwe93")
            ins7 = TxInput(txid=utxos[0]['tx_hash'], txout_index=utxos[0]['tx_pos'])
            outs7 = TxOutput(amount=utxos[0]['value']-1000, script_pubkey=address5.to_script_pub_key())
            tx7 = Transaction(inputs=[ins7], outputs=[outs7], has_segwit=True)

            sig7_1 = priv4.sign_taproot_input(tx=tx7, txin_index=0, utxo_scripts=[address4.to_script_pub_key()],
                                              amounts=[utxos[0]['value']], script_path=True, 
                                              tapleaf_script=tr_script_p2pk4, tweak=False)
            
            # If using get_tag_hashed_merkle_root
            merkleroot1 = get_tag_hashed_merkle_root(scripts=all_leafs)
            
            # If manually constructing the tree
            leaf1 = tapleaf_tagged_hash(tr_script_p2pk1)
            leaf2 = tapleaf_tagged_hash(tr_script_p2pk2)
            leaf3 = tapleaf_tagged_hash(tr_script_p2pk3)
            leaf4 = tapleaf_tagged_hash(tr_script_p2pk4)
            leaf5 = tapleaf_tagged_hash(tr_script_p2pk5)

            branch_ab = tapbranch_tagged_hash(leaf1, leaf2)
            branch_de = tapbranch_tagged_hash(leaf4, leaf5)
            branch_cde = tapbranch_tagged_hash(leaf3, branch_de)
            merkleroot2 = tapbranch_tagged_hash(branch_ab, branch_cde)
            assert(merkleroot1 == merkleroot2)

            # tapleaves and tapbranches in order

            #                      TB_ABCDE
            #                     /       \
            #                    /         \
            #                   /          TL_CDE
            #                  /           /  \
            #                 /           /    \
            #              TB_AB         /    TL_DE
            #               / \         /      / \
            #              /   \       /      /   \
            #            TL_A TL_B   TL_C   TL_D TL_E

            control_block7_1 = ControlBlock(pubkey=pub1, script_to_spend=tr_script_p2pk4, scripts=leaf5 + leaf3 + branch_ab, is_odd=address4.is_odd())
            tx7.witnesses.append(TxWitnessInput([sig7_1, tr_script_p2pk4.to_hex(), control_block7_1.to_hex()]))
            print("\nRaw signed transaction:\n" + tx7.serialize())
            print(await rpc.broadcast_transaction(tx_hexstring=tx7.serialize()))

        except RPCError as e:
            logging.error(f"RPC Error: {e}")


if __name__ == "__main__":

    # asyncio.run(main=main1())
    # asyncio.run(main=main2())
    # asyncio.run(main=main3())
    # asyncio.run(main=main4())
    # asyncio.run(main=main5())
    # asyncio.run(main=main6())
    asyncio.run(main=main7())
