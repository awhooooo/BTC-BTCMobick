import hashlib
import bitcoin
import ecdsa 
import base58
import bech32
import struct
from Mobick.Mobick_RPC import *

def redeem_script(private_key):

    pub_key_compressed = bitcoin.encode_pubkey(
        bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(private_key, 'hex')), 'hex_compressed')
    keyhash = hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pub_key_compressed)).digest()).hexdigest()

    return "0014{}".format(keyhash)

def scriptPubKey(private_key):

    hash1 = hashlib.sha256(bytes.fromhex(redeem_script(private_key))).digest()
    hash2 = hashlib.new("ripemd160", hash1).digest()

    return "a914{}87".format(hash2.hex())

def p2sh_address(private_key):

    address = base58.b58encode_check(b'\x05' + bytes.fromhex(scriptPubKey(private_key)[4:44])).decode('utf-8')

    return address


priv_key_hex = ["75300daccdb575cfa15193158d4144d659f9e8c4edde23dd703b503545d4934e",  # p2sh
                "2f8d3f95874dc0185b9542577f548f94e975a94807ef0dbe9c308134ddaba00e",  # legacy
                "75cf5693abfa0da407da1645e4dcd324dbbb8bdee3ff93555531744dbca91b16",  # p2wpkh
                "86cc2bdc5018fed5b1539f32b790a052d27332a8fa4be2c59b6efee651a0970b",  # p2sh
                "a516570121aa5e378f4c0f0c7d20a22e1e27bfc612833ecbccf4b99431b5bb46",  # legacy
                "04c63cf2f4e60c019e10dd06dae4ada66f916485d5807681ae6f47ef5074091c"]  # p2wpkh

wif = ["L19WSkwL76ydSuRcgD7zQwx8utbL7HtAvVdkYAeMovLVqByRDE4j",
       "Kxp9Nx2pmtnQkuV4iDLUKqEhWcghxDcBzWU4EA5Ux2UX6r2fPmaS",
       "L1AibUT575vQhPhQnfoWmHFhRtYYh7rKaP7Jty9xo1EupMx28wsm",
       "L1jjraazDgqei79xjbiwep5e2TNUxR6Q4VodiGsaoFUU1z9ewPYz",
       "L2kcrQc6ztWiKGkmAWzjiNm7HTFhUkZ5UvedDo23BoSGSSowcirq",
       "KwNzU69MSUKgYTxoHdLpNxcPNSjWbMsxKCbLEodYgJcYiNLmZ9Le"]

input_addresses = ["3Jq3bNQPvbiH7Gmfp9EXsuNFRu6Xu7uexB",
                   "14fmG9vuM28hgy3D7BR5VkHtH57jLtmvLf",
                   "bc1qq337wjdc2qz6sen0d6ar5jqm3tyfygyy0yttwc"]

output_addresses = ["31j2Mn4qSKp5sczTbCyZSznNCTN58rGhBh",
                    "1377msqsMLd4WToHgbFCJHJh51woBG5TvF",
                    "bc1qmasraztqy3ze0smd00pr0wxsgupuawdsrk4cdt"]

prev_txid = [{'txid': "f523e7d84396f932b7c257002d439adf79da64a38ea6dc3431089388a93b706c", 'vout': 0},
             {'txid': "1b294f33fb2ac1fefba348337370bfefe8c84614f3dbf9bcddd6ba6ccc04c42d", 'vout': 0},
             {'txid': "0ae1297f90301df352a32073acb10ce132921e6b3d91f96b58e84207af345b0f", 'vout': 0}]

version = struct.pack("<L", 2).hex()
marker = "00"
flag = "01"
sequence = "ffffffff"

input_count = struct.pack('<B', 3).hex()
prev_txid1 = bytes.fromhex(prev_txid[0]['txid'])[::-1].hex()
input_index1 = struct.pack("<L", prev_txid[0]['vout']).hex()
balance1 = struct.pack("<Q", int(0.0434715 * (10**8))).hex()
scriptcode1 = bitcoin.address_to_script(bitcoin.privkey_to_address(
    bitcoin.encode_privkey(bitcoin.decode_privkey(priv_key_hex[0], 'hex_compressed'), 'wif_compressed')))

prev_txid2 = bytes.fromhex(prev_txid[1]['txid'])[::-1].hex()
input_index2 = struct.pack("<L", prev_txid[1]['vout']).hex()
balance2 = struct.pack("<Q", int(0.0048515 * (10**8))).hex()
scriptcode2 = bitcoin.address_to_script(bitcoin.privkey_to_address(
    bitcoin.encode_privkey(bitcoin.decode_privkey(priv_key_hex[1], 'hex_compressed'), 'wif_compressed')))

prev_txid3 = bytes.fromhex(prev_txid[2]['txid'])[::-1].hex()
input_index3 = struct.pack("<L", prev_txid[2]['vout']).hex()
balance3 = struct.pack("<Q", int(0.01 * (10**8))).hex()
scriptcode3 = bitcoin.address_to_script(bitcoin.privkey_to_address(
    bitcoin.encode_privkey(bitcoin.decode_privkey(priv_key_hex[2], 'hex_compressed'), 'wif_compressed')))

hashSequence = hashlib.sha256(hashlib.sha256(bytes.fromhex(sequence * 3)).digest()).hexdigest()
hashPrevOuts = hashlib.sha256(hashlib.sha256(bytes.fromhex(prev_txid1 + input_index1 +
    prev_txid2 + input_index2 + prev_txid3 + input_index3)).digest()).hexdigest()

output_count = struct.pack('<B', 3).hex()
value1 = struct.pack('<Q', int(0.005 * (10**8))).hex()
output_script1 = bitcoin.address_to_script(output_addresses[0])
output_script_length1 = hex(len(bytes.fromhex(output_script1)))[2:]

value2 = struct.pack('<Q', int(0.05 * (10**8))).hex()
output_script2 = bitcoin.address_to_script(output_addresses[1])
output_script_length2 = hex(len(bytes.fromhex(output_script2)))[2:]

value3 = struct.pack('<Q', int(0.0025 * (10**8))).hex()
decode = bech32.decode(hrp='bc', addr=output_addresses[2])
output_witness_program3 = bytes(decode[1]).hex()

hashOutputs = hashlib.sha256(hashlib.sha256(bytes.fromhex(value1 + output_script_length1 + output_script1 + value2 +
    output_script_length2 + output_script2 + value3 + "160014" + output_witness_program3)).digest()).hexdigest()

locktime = struct.pack("<L", 0).hex()
sighash_code = struct.pack("<L", 1).hex()

hash_preimage1 = version + hashPrevOuts + hashSequence + prev_txid1 + input_index1 + "19" + scriptcode1 + \
    balance1 + sequence + hashOutputs + locktime + sighash_code    # Segwit

hash_preimage2 = version + input_count + \
    prev_txid1 + input_index1 + "00" + sequence + \
    prev_txid2 + input_index2 + "19" + scriptcode2 + sequence + \
    prev_txid3 + input_index3 + "00" + sequence + \
    output_count + value1 + output_script_length1 + output_script1 + \
    value2 + output_script_length2 + output_script2 + \
    value3 + "160014" + output_witness_program3 + \
    locktime + sighash_code    # Legacy

hash_preimage3 = version + hashPrevOuts + hashSequence + prev_txid3 + input_index3 + "19" + scriptcode3 + \
    balance3 + sequence + hashOutputs + locktime + sighash_code    # Native Segwit

signing_key1 = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key_hex[0]), curve=ecdsa.SECP256k1)
sighash1 = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_preimage1)).digest()).digest()
signature1 = signing_key1.sign_digest(sighash1, sigencode=ecdsa.util.sigencode_der_canonize)
signature_length1 = hex(len(bytes.fromhex(signature1.hex() + "01")))[2:]
compressed_pub_key1 = bitcoin.encode_pubkey(
    bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(priv_key_hex[0], 'hex')), 'hex_compressed')

signing_key2 = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key_hex[1]), curve=ecdsa.SECP256k1)
sighash2 = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_preimage2)).digest()).digest()
signature2 = signing_key2.sign_digest(sighash2, sigencode=ecdsa.util.sigencode_der_canonize)
signature_length2 = hex(len(bytes.fromhex(signature2.hex() + "01")))[2:]
compressed_pub_key2 = bitcoin.encode_pubkey(
    bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(priv_key_hex[1], 'hex')), 'hex_compressed')

signing_key3 = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key_hex[2]), curve=ecdsa.SECP256k1)
sighash3 = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_preimage3)).digest()).digest()
signature3 = signing_key3.sign_digest(sighash3, sigencode=ecdsa.util.sigencode_der_canonize)
signature_length3 = hex(len(bytes.fromhex(signature3.hex() + "01")))[2:]
compressed_pub_key3 = bitcoin.encode_pubkey(
    bitcoin.fast_multiply(bitcoin.G, bitcoin.decode_privkey(priv_key_hex[2], 'hex')), 'hex_compressed')

scriptSig2 = signature_length2 + signature2.hex() + "01" + hex(len(bytes.fromhex(compressed_pub_key2)))[2:] + compressed_pub_key2
scriptSig2_length = hex(len(bytes.fromhex(scriptSig2)))[2:]
witness1 = "02" + hex(len(signature1 + bytes([1])))[2:] + signature1.hex() + "01" + \
    hex(len(bytes.fromhex(compressed_pub_key1)))[2:] + compressed_pub_key1
witness2 = "00"
witness3 = "02" + hex(len(signature3 + bytes([1])))[2:] + signature3.hex() + "01" + \
    hex(len(bytes.fromhex(compressed_pub_key3)))[2:] + compressed_pub_key3

payload = version + marker + flag + input_count + \
    prev_txid1 + input_index1 + "1716" + redeem_script(priv_key_hex[0]) + sequence + \
    prev_txid2 + input_index2 + scriptSig2_length + scriptSig2 + sequence + \
    prev_txid3 + input_index3 + "00" + sequence + \
    output_count + value1 + output_script_length1 + output_script1 + \
    value2 + output_script_length2 + output_script2 + \
    value3 + "160014" + output_witness_program3 + \
    witness1 + witness2 + witness3 + locktime

print(payload)

async def main():
    rpc = MobickRPCsocket(host="220.85.71.15", port=40008)
        async with rpc.manage_connection():
            try:
               print(await rpc.broadcast_transaction(tx_hexstring=payload))
            except RPCError as e:
            logging.error(f"RPC Error: {e}")


if __name__ == "__main__":
    asyncio.run(main=main())
