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
