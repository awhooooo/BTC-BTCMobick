import sys
import bitcoin
import asyncio
import json
import struct
sys.path.append("/Users/ieunmi/PycharmProjects/pythonProject")
from bitcoinlib.keys import Address
from bitcoinlib.transactions import *
from Mobick.rawECDSA import *
from Mobick.Mobick_RPC import *


priv_key_hex1 = "secret for obvious reason 1"
priv_key_hex2 = "secret for obvious reason 2"
address1 = Address.parse("1377msqsMLd4WToHgbFCJHJh51woBG5TvF")
address2 = Address.parse("16vnUfDxdMWYKYpw4gCqkwCHRy7jtzgJgn")

async def main1():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    rpc.connect()
    utxos = await rpc.list_unspent(address=address1.address)
    
    ins1 = Input(prev_txid=utxos[0]['tx_hash'], output_n=utxos[0]['tx_pos'],
                 keys=[priv_key_hex1],
                 script=bitcoin.address_to_script(address1.address),
                 address=address1.address, sequence=0xffffffff,
                 compressed=True, sigs_required=1, index_n=0, value=utxos[0]['value'],
                 double_spend=False, locktime_cltv=None, locktime_csv=None, key_path='',
                 witness_type='legacy', witnesses=None, encoding='base58', strict=True)

    outs1 = Output(value=utxos[0]['value'] - 20000, 
                   address=address2.address, public_hash=None, lock_script=None, 
                   spent=False, output_n=0, script_type=None, encoding=None, strict=True)
    
    tx1 = Transaction(inputs=[ins1], outputs=[outs1], locktime=0, version=2,
                      fee=ins1.value - outs1.value,
                      input_total=ins1.value, output_total=outs1.value,
                      status='new', coinbase=False,
                      verified=False, witness_type='legacy', flag=None)
    
    ins2 = Input(prev_txid=utxos[1]['tx_hash'], output_n=utxos[1]['tx_pos'],
                 keys=[priv_key_hex1],
                 script=bitcoin.address_to_script(address1.address),
                 address=address1.address, sequence=0xffffffff,
                 compressed=True, sigs_required=1, index_n=0, value=utxos[1]['value'],
                 double_spend=False, locktime_cltv=None, locktime_csv=None, key_path='',
                 witness_type='legacy', witnesses=None, encoding='base58', strict=True)
    
    ins3 = Input(prev_txid=utxos[2]['tx_hash'], output_n=utxos[2]['tx_pos'],
                 keys=[priv_key_hex1],
                 script=bitcoin.address_to_script(address1.address),
                 address=address1.address, sequence=0xffffffff,
                 compressed=True, sigs_required=1, index_n=0, value=utxos[2]['value'],
                 double_spend=False, locktime_cltv=None, locktime_csv=None, key_path='',
                 witness_type='legacy', witnesses=None, encoding='base58', strict=True)
    
    outs2 = Output(value=utxos[1]['value'] + utxos[2]['value'] - 30000, 
                   address=address2.address, public_hash=None, lock_script=None, 
                   spent=False, output_n=0, script_type=None, encoding=None, strict=True)
    
    tx2 = Transaction(inputs=[ins2, ins3], outputs=[outs2], locktime=0, version=2,
                      fee=ins2.value + ins3.value - outs2.value,
                      input_total=ins2.value + ins3.value, output_total=outs2.value,
                      status='new', coinbase=False,
                      verified=False, witness_type='legacy', flag=None)
    
    tx1.sign(keys=ins1.keys)
    tx2.sign(keys=ins2.keys)
    tx2.sign(keys=ins3.keys)

    print(json.dumps(tx1.as_dict(), indent=4))
    print('\n')
    print(json.dumps(tx2.as_dict(), indent=4))

    rpc.disconnect()


async def main2():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    rpc.connect()
    utxos = await rpc.list_unspent(address=address1.address)

    version = struct.pack("<L", 2).hex()
    marker = "00"
    flag = "01"
    sequence = "ffffffff"

    input_count = struct.pack('<B', 1).hex()
    prev_txid1 = bytes.fromhex(utxos[0]['tx_hash'])[::-1].hex()
    input_index1 = struct.pack("<L", utxos[0]['tx_pos']).hex()

    input_script = bitcoin.address_to_script(address1.address)
    input_script_length = hex(len(bytes.fromhex(input_script)))[2:]

    output_count = struct.pack('<B', 1).hex()
    value1 = struct.pack("<Q", utxos[0]['value'] - 20000).hex()
    output_script1 = bitcoin.address_to_script(address2.address)
    output_script_length1 = hex(len(bytes.fromhex(output_script1)))[2:]

    locktime = struct.pack("<L", 0).hex()
    sighash_code = struct.pack("<L", 1).hex()

    hash_preimage1 = version + input_count + prev_txid1 + input_index1 + input_script_length + input_script + sequence + \
                     output_count + value1 + output_script_length1 + output_script1 + locktime + sighash_code
    
    (r1, s1) = sign_message(private_key=int(priv_key_hex1, base=16), message=hash_preimage1)
    signature1 = der(r1, s1)
    signature_length1 = format(len(signature1) + 1, 'x')

    compressed_pub_key1 = bitcoin.encode_pubkey(
        bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(priv_key_hex1, 'hex')), 'hex_compressed')
    scriptSig1 = signature_length1 + signature1.hex() + "01" + hex(len(bytes.fromhex(compressed_pub_key1)))[2:] + compressed_pub_key1
    scriptSig1_length = hex(len(bytes.fromhex(scriptSig1)))[2:]
    
    payload1 = version + input_count + prev_txid1 + input_index1 + scriptSig1_length + scriptSig1 + sequence + \
           output_count + value1 + output_script_length1 + output_script1 + locktime
    
    print(await rpc.broadcast_transaction(tx_hexstring=payload1))
    rpc.disconnect()


async def main3():

    rpc = MobickRPCsocket(host="13.55.48.220", port=40008)
    rpc.connect()
    tx1 = await rpc.get_transaction(txid="61f8042dcdad992fa977c005405b6296983926e31e0057b0a948131f8ab94c8e")
    tx2 = await rpc.get_transaction(txid="2d3f439ac955918541fb3846c053be78123832f86a726f6ccd3550f5f1704e70")
    der_sig1 = tx1['vin'][0]['scriptSig']['asm'].split('[ALL] ')[0]
    der_sig2 = tx2['vin'][0]['scriptSig']['asm'].split('[ALL] ')[0]

    """
    1 => First off, note that r1 = r2 (because r = x * mod(n) and P = kG is the same for both signatures).
    2 => Consider that (s1 - s2)mod(n) = k^(-1)(z1 - z2)mod(n) (this result comes directly from the equation for s).
    3 => Now multiply each side of the equation by k
    4 => Divide by (s1 - s2) to get k = (z1 - z2)(s1 - s2)^(-1)mod(n)
    5 => s1 = k^(-1)(z1 + r1 * pk) mod(n)  s2 = k^(-1)(z2 + r2 * pk) mod(n)
    6 => pk = r1^(-1) * (s1 * k - z1) mod(n) = r2^(-1) * (s2 * k - z2) mod(n)
    in this case, we know that the k value was identical in both transactions (which was 11111222223333334444444)
    """

    # reconstructing the hash preimage of both transactions
    sighash_code = struct.pack("<L", 1).hex()
    input_script = bitcoin.address_to_script(address1.address)
    input_script_length = hex(len(bytes.fromhex(input_script)))[2:]
    hash_preimage1 = "0200000001501e2a111d3e0c59b0aa61127d4bd2b820a0ef75f66c137e1c77289739330fc601000000" + input_script_length + input_script + \
                     "ffffffff01a8d07813000000001976a9144104a317c03e67143814d1b88f17e77d0b17904c88ac00000000" + sighash_code
    hash_preimage2 = "0200000001c276c6a290421a5dab5914bc170f6512290de53153897599fc3dc7e62242786d00000000" + input_script_length + input_script + \
                     "ffffffff0180710e00000000001976a9144104a317c03e67143814d1b88f17e77d0b17904c88ac00000000" + sighash_code
    

    z1 = hash_message(message=hash_preimage1, truncate=True)
    z2 = hash_message(message=hash_preimage2, truncate=True)
    r1, s1 = der_to_rs(bytes.fromhex(der_sig1))
    r2, s2 = der_to_rs(bytes.fromhex(der_sig2))
    # s1 = curve.n - s1
    s2 = curve.n - s2
    
    assert(r1 == r2)
    k = ((z1 - z2) * inverse_mod((s1 - s2), curve.n)) % curve.n
    assert((s1 - s2) % curve.n == (inverse_mod(k, curve.n) * (z1 - z2)) % curve.n)
    print(k)
    pk1 = (inverse_mod(r1, curve.n) * (s1 * k - z1)) % curve.n
    pk2 = (inverse_mod(r2, curve.n) * (s2 * k - z2)) % curve.n
    assert(pk1 == pk2)
    print(hex(pk1))
    print(bitcoin.encode_privkey(hex(pk1)[2:], 'wif_compressed'))
    assert(address1.address == bitcoin.privkey_to_address(bitcoin.encode_privkey(pk1, 'wif_compressed')))
    
    rpc.disconnect()



if __name__ ==  "__main__":
    # asyncio.run(main=main1())
    # asyncio.run(main=main2())
    asyncio.run(main=main3())

