import hashlib
import struct
import ecdsa
import json, bitcoin, bitcoinlib
from bitcoinlib.config.opcodes import *
from bitcoinlib.keys import *
from bitcoinlib.transactions import *
from bitcoinutils.setup import setup
from bitcoinutils.script import Script
from bitcoinutils.keys import *
from bitcoinutils.constants import *
from Mobick.Mobick_RPC import *


# p2sh cltv redeem script
# <expiry time> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
# <expiry time> b17576a914 <pubKeyHash> 88ac
# expiry_time = struct.pack("<L", int(time.time() + 3600)).hex()
# op_checklocktimeverify_script1 = "04{}b17576a914{}88ac".format(expiry_time, output_hash160_1)


setup(network="mainnet")
priv1 = PrivateKey(wif='L2rBJ7KNsGtSfgyEGE3xoXQa4KNUoBB3FLRN4WbLawpRgqAHuVDA')
pub1 = priv1.get_public_key()
pubkeyHash = hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pub1.to_hex())).digest()).hexdigest()

expiry_time = struct.pack("<L", 1713352486)
# redeem_script = Script([expiry_time, "OP_CHEKCLOCKTIMEVERIFY", "OP_DROP", "OP_DUP", "OP_HASH160", pubkeyHash, "OP_EQUALVERIFY", "OP_CHECKSIG"])
redeem_script = "04{}b17576a914{}88ac".format(expiry_time.hex(), pubkeyHash)
scripthash = hashlib.sha256(bytes.fromhex(redeem_script)).digest()
witness_program = bech32.convertbits(scripthash, 8, 5)
address1 = bech32.bech32_encode(hrp='bc', data=[0] + witness_program)

address1_1 = bitcoinlib.keys.Address(data=redeem_script, encoding='bech32', script_type='p2wsh')
utxo = [{'txid': 'd184c821ac5eebd134390f1af02b42f5e677be0858205100e589380f8d87c505', 'vout': 0}]
assert (address1 == address1_1.address)

# ins1 = bitcoinlib.transactions.Input(prev_txid=utxo[0]['txid'], output_n=utxo[0]['vout'],
#                                      keys=[bitcoin.decode_privkey(priv1.to_wif(), 'wif_compressed')], address=address1, sequence=0xffffffff,
#                                      script=bitcoinlib.scripts.Script(commands=[expiry_time, op.op_checklocktimeverify, op.op_drop, op.op_dup, op.op_hash160, pubkeyHash, op.op_equalverify, op.op_checksig], script_types=['p2wsh']),
#                                      compressed=True, sigs_required=1, index_n=0, value=1000000,
#                                      double_spend=False, locktime_cltv=None, locktime_csv=None, key_path='',
#                                      witness_type='segwit', witnesses=None, encoding='bech32', strict=True)

# outs1 = bitcoinlib.transactions.Output(value=980000,
#                                        address='1EKzgpZGX2zBxeWw5Dw5zMGYHVUiV21MZP',
#                                        public_hash=None, lock_script=None,
#                                        spent=False, output_n=0, script_type='p2pkh',
#                                        encoding='base58', strict=True)

# tx = bitcoinlib.transactions.Transaction(inputs=[ins1], outputs=[outs1],
#                                          locktime=int(time.time()) - 50000, version=2,
#                                          fee=ins1.value - outs1.value,
#                                          input_total=ins1.value, output_total=outs1.value,
#                                          status='new', coinbase=False,
#                                          verified=False, witness_type='segwit', flag=None)

# tx.sign(keys=ins1.keys, index_n=0)
# print(json.dumps(tx.as_dict(), indent=4))


version = struct.pack("<L", 2).hex()
marker = "00"
flag = "01"
sequence = struct.pack("<L", 0xffffffff-1).hex()

input_count = struct.pack('<B', 1).hex()
prev_txid1 = bytes.fromhex(utxo[0]['txid'])[::-1].hex()
input_index1 = struct.pack("<L", utxo[0]['vout']).hex()
balance1 = struct.pack("<Q", 1000000).hex()
compressed_pub_key1 = bitcoin.encode_pubkey(
    bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(priv1.to_wif(), 'wif_compressed')), 'hex_compressed')
scriptCode1 = redeem_script
scriptCode1_length = hex(len(bytes.fromhex(scriptCode1)))[2:]

output_count = struct.pack('<B', 1).hex()
value1 = struct.pack("<Q", 980000).hex()
output_script1 = bitcoin.address_to_script('1EKzgpZGX2zBxeWw5Dw5zMGYHVUiV21MZP')
output_script_length1 = hex(len(bytes.fromhex(output_script1)))[2:]

locktime = struct.pack("<L", 1713353200).hex()
sighash_code = struct.pack("<L", 1).hex()

hashSequence = hashlib.sha256(hashlib.sha256(bytes.fromhex(sequence)).digest()).hexdigest()
hashPrevOuts = hashlib.sha256(hashlib.sha256(bytes.fromhex(prev_txid1 + input_index1)).digest()).hexdigest()
hashOutputs = hashlib.sha256(hashlib.sha256(bytes.fromhex(value1 + output_script_length1 + output_script1)).digest()).hexdigest()

hash_preimage1 = version + hashPrevOuts + hashSequence + prev_txid1 + input_index1 + \
                 scriptCode1_length + scriptCode1 + balance1 + sequence + hashOutputs + locktime + sighash_code

signing_key1 = ecdsa.SigningKey.from_string(bytes.fromhex("a7f27c87de203bf5749bfa58304f75f1cfc9d24963cc29d7d59d348097fee9b8"), curve=ecdsa.SECP256k1)
sighash1 = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_preimage1)).digest()).digest()
signature1 = signing_key1.sign_digest(sighash1, sigencode=ecdsa.util.sigencode_der_canonize)
signature1_length = hex(len(signature1 + bytes([1])))[2:]

witness1 = "03" + signature1_length + signature1.hex() + "01" + "21" + compressed_pub_key1 + scriptCode1_length + scriptCode1
payload = version + marker + flag + input_count + prev_txid1 + input_index1 + "00" + sequence + \
    output_count + value1 + output_script_length1 + output_script1 + witness1 + locktime

# print(payload)
async def main():
    
    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
    rpc.connect(True)
    await rpc.broadcast_transaction(tx_hexstring=payload)
    rpc.disconnect()


if __name__ == "__main__":
    asyncio.run(main=main())
    
    
    
