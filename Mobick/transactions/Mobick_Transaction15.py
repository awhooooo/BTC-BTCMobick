import hashlib
import socket
import time
import struct
import base58
import bech32
import json
import bitcoin
import bitcoinlib
import ecdsa
from Mobick.Mobick_RPC import *

def Native_P2WPKH(private_key):

    pubkey = bitcoin.encode_pubkey(bitcoin.fast_multiply(
        bitcoin.G, bitcoin.decode_privkey(private_key, 'hex')), 'hex_compressed')
    pubkeyHash = hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pubkey)).digest()).digest()
    witness_program = bech32.convertbits(pubkeyHash, 8 ,5)
    address = bech32.bech32_encode(hrp='bc', data=[0] + witness_program)

    return address

def Native_P2WSH(private_key):

    pubkey = bitcoin.encode_pubkey(bitcoin.fast_multiply(
        bitcoin.G, bitcoin.decode_privkey(private_key, 'hex')), 'hex_compressed')
    witnessScript = "21" + pubkey + "ac"  # PUSHDATA 33 bytes <pubkey> OP_CHECKSIG
    scripthash = hashlib.sha256(bytes.fromhex(witnessScript)).digest()
    witness_program = bech32.convertbits(scripthash, 8, 5)
    address = bech32.bech32_encode(hrp='bc', data=[0] + witness_program)

    return address

pk1 = '0a24f7d94c224924c6b9569d01132468d1b83ad92010b3d77b2f48c816f67e91'
wif1 = 'secret for obvious reason1'
p2wpkh1 = 'bc1q07alqsvf47x4jwmc7xd5me2rjqgc4jtsjlrpvc'
p2wsh1 = 'bc1qy9de0qt94562vutkfvvqsvupqljufd4h3u3zl9ljxlrn7y2damzqx792cw'

pk2= 'b02b4c44859b0f3f1667eafb91d391d0281eed89c184ee9096d53a0437e0c5e1'
wif2 = 'secret for obvious reason2'
p2wpkh2 = 'bc1q602nz7gdfpn2gelpm5sa43rr9e4qqmhm6ja6mp'
p2wsh2 = 'bc1q0up7cy0pqnne875nur9dn2rvps88rhkaj2uj3c6wejyhlexrvresh53v5u'

pk3 = 'd3cc30aeffd0c3d7588944581495966b085c86719c028ffad2a29246636694e1'
wif3 = 'secret for obvious reason3'
p2wpkh3 = 'bc1q62qmcqa5jqw7r34ms3rgfad7068funr55wpx94'
p2wsh3 = 'bc1qcfzh4cy3s0slst8zjey4qc8nhy6d7hj8t28kdvg4834yl72rs9rq48h75r'

utxo = [{'txid': '462fa06d3a61b928ed4c59195a70f86ff721ff69829cbe0154eb85e5d62b9229', 'vout': 0},
        {'txid': '286e6fa6b9d3d10f00b9a432d026dae62bacd9970d5f1426cb46cfdfe5cade36', 'vout': 0},
        {'txid': '678623b096710abc5e4f8280638cb6f90fa4b37cb3cfbeea5ee574d80541c6bd', 'vout': 0}]

version = struct.pack("<L", 2).hex()
marker = "00"
flag = "01"
sequence = struct.pack("<L", 0xffffffff).hex()

input_count = struct.pack('<B', 3).hex()
prev_txid1 = bytes.fromhex(utxo[0]['txid'])[::-1].hex()
input_index1 = struct.pack("<L", utxo[0]['vout']).hex()
balance1 = struct.pack("<Q", 1000000).hex()
compressed_pub_key1 = bitcoin.encode_pubkey(
    bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(pk1, 'hex')), 'hex_compressed')
scriptCode1 = "21" + compressed_pub_key1 + "ac"
scriptCode1_length = hex(len(bytes.fromhex(scriptCode1)))[2:]

prev_txid2 = bytes.fromhex(utxo[1]['txid'])[::-1].hex()
input_index2 = struct.pack("<L", utxo[1]['vout']).hex()
balance2 = struct.pack("<Q", 500000).hex()
compressed_pub_key2 = bitcoin.encode_pubkey(
    bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(pk2, 'hex')), 'hex_compressed')
scriptCode2 = "21" + compressed_pub_key2 + "ac"
scriptCode2_length = hex(len(bytes.fromhex(scriptCode2)))[2:]

prev_txid3 = bytes.fromhex(utxo[2]['txid'])[::-1].hex()
input_index3 = struct.pack("<L", utxo[2]['vout']).hex()
balance3 = struct.pack("<Q", 7000000).hex()
compressed_pub_key3 = bitcoin.encode_pubkey(
    bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(pk3, 'hex')), 'hex_compressed')
scriptCode3 = "21" + compressed_pub_key3 + "ac"
scriptCode3_length = hex(len(bytes.fromhex(scriptCode3)))[2:]

output_count = struct.pack('<B', 2).hex()
value1 = struct.pack("<Q", 0).hex()
output_script1 = '6a' + '2d' + "This transaction is for testing purpose only.".encode('utf-8').hex()
output_script_length1 = hex(len(bytes.fromhex(output_script1)))[2:]

value2 = struct.pack("<Q", 8460000).hex()
output_script2 = bitcoin.address_to_script('1377msqsMLd4WToHgbFCJHJh51woBG5TvF')
output_script_length2 = hex(len(bytes.fromhex(output_script2)))[2:]

locktime = struct.pack("<L", 0).hex()
sighash_code = struct.pack("<L", 1).hex()

hashSequence = hashlib.sha256(hashlib.sha256(bytes.fromhex(sequence * 3)).digest()).hexdigest()
hashPrevOuts = hashlib.sha256(hashlib.sha256(bytes.fromhex(prev_txid1 + input_index1 +
    prev_txid2 + input_index2 + prev_txid3 + input_index3)).digest()).hexdigest()
hashOutputs = hashlib.sha256(hashlib.sha256(bytes.fromhex(
    value1 + output_script_length1 + output_script1 +
    value2 + output_script_length2 + output_script2)).digest()).hexdigest()

hash_preimage1 = version + hashPrevOuts + hashSequence + prev_txid1 + input_index1 + \
                 scriptCode1_length + scriptCode1 + balance1 + sequence + hashOutputs + locktime + sighash_code

hash_preimage2 = version + hashPrevOuts + hashSequence + prev_txid2 + input_index2 + \
                 scriptCode2_length + scriptCode2 + balance2 + sequence + hashOutputs + locktime + sighash_code

hash_preimage3 = version + hashPrevOuts + hashSequence + prev_txid3 + input_index3 + \
                 scriptCode3_length + scriptCode3 + balance3 + sequence + hashOutputs + locktime + sighash_code

signing_key1 = ecdsa.SigningKey.from_string(bytes.fromhex(pk1), curve=ecdsa.SECP256k1)
sighash1 = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_preimage1)).digest()).digest()
signature1 = signing_key1.sign_digest(sighash1, sigencode=ecdsa.util.sigencode_der_canonize)
signature1_length = hex(len(signature1 + bytes([1])))[2:]

signing_key2 = ecdsa.SigningKey.from_string(bytes.fromhex(pk2), curve=ecdsa.SECP256k1)
sighash2 = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_preimage2)).digest()).digest()
signature2 = signing_key2.sign_digest(sighash2, sigencode=ecdsa.util.sigencode_der_canonize)
signature2_length = hex(len(signature2 + bytes([1])))[2:]

signing_key3 = ecdsa.SigningKey.from_string(bytes.fromhex(pk3), curve=ecdsa.SECP256k1)
sighash3 = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_preimage3)).digest()).digest()
signature3 = signing_key3.sign_digest(sighash3, sigencode=ecdsa.util.sigencode_der_canonize)
signature3_length = hex(len(signature3 + bytes([1])))[2:]

witness1 = "02" + signature1_length + signature1.hex() + "01" + scriptCode1_length + scriptCode1
witness2 = "02" + signature2_length + signature2.hex() + "01" + scriptCode2_length + scriptCode2
witness3 = "02" + signature3_length + signature3.hex() + "01" + scriptCode3_length + scriptCode3

payload = version + marker + flag + input_count + \
    prev_txid1 + input_index1 + "00" + sequence + \
    prev_txid2 + input_index2 + "00" + sequence + \
    prev_txid3 + input_index3 + "00" + sequence + \
    output_count + value1 + output_script_length1 + output_script1 + \
    value2 + output_script_length2 + output_script2 + \
    witness1 + witness2 + witness3 + locktime

async def main():
    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
        async with rpc.manage_connection():
            try:
               print(await rpc.broadcast_transaction(tx_hexstring=payload))
            except RPCError as e:
            logging.error(f"RPC Error: {e}")


if __name__ == "__main__":
    asyncio.run(main=main())
