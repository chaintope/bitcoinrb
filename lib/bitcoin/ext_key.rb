module Bitcoin

  def self.hmac_sha512(key, data)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA512'), key, data)
  end

  # Integers modulo the order of the curve(secp256k1)
  CURVE_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337

  # BIP32 Extended private key
  class ExtKey

    attr_accessor :depth
    attr_accessor :number
    attr_accessor :chain_code
    attr_accessor :key
    attr_accessor :parent_fingerprint

    # generate master key from seed.
    # @params [String] seed a seed data with hex format.
    def self.generate_master(seed)
      ext_key = ExtKey.new
      ext_key.depth = ext_key.number = 0
      ext_key.parent_fingerprint = '00000000'
      l = Bitcoin.hmac_sha512('Bitcoin seed', seed.htb)
      left = l[0..31].bth.to_i(16)
      raise 'invalid key' if left >= CURVE_ORDER || left == 0
      ext_key.key = Bitcoin::Key.new(priv_key: l[0..31].bth)
      ext_key.chain_code = l[32..-1]
      ext_key
    end

    # get ExtPubkey from priv_key
    def ext_pubkey
      k = ExtPubkey.new
      k.depth = depth
      k.number = number
      k.parent_fingerprint = parent_fingerprint
      k.chain_code = chain_code
      k.pubkey = key.pubkey
      k
    end

    # serialize extended private key
    def to_payload
      Bitcoin.chain_params.extended_privkey_version.htb << [depth].pack('C') <<
          parent_fingerprint.htb << [number].pack('N') << chain_code << [0x00].pack('C') << key.priv_key.htb
    end

    # Base58 encoded extended private key
    def to_base58
      h = to_payload.bth
      hex = h + Bitcoin.calc_checksum(h)
      Base58.encode(hex)
    end

    # get private key(hex)
    def priv
      key.priv_key
    end

    # get public key(hex)
    def pub
      key.pubkey
    end

    # get address
    def addr
      key.to_p2pkh
    end

    # get segwit p2wpkh address
    def segwit_addr
      ext_pubkey.segwit_addr
    end

    # get key identifier
    def identifier
      Bitcoin.hash160(key.pubkey)
    end

    # get fingerprint
    def fingerprint
      identifier.slice(0..7)
    end

    # derive new key
    def derive(number)
      new_key = ExtKey.new
      new_key.depth = depth + 1
      new_key.number = number
      new_key.parent_fingerprint = fingerprint
      if number > (2**31 -1)
        data = [0x00].pack('C') << key.priv_key.htb << [number].pack('N')
      else
        data = key.pubkey.htb << [number].pack('N')
      end
      l = Bitcoin.hmac_sha512(chain_code, data)
      left = l[0..31].bth.to_i(16)
      raise 'invalid key' if left >= CURVE_ORDER
      child_priv = (left + key.priv_key.to_i(16)) % CURVE_ORDER
      raise 'invalid key ' if child_priv >= CURVE_ORDER
      new_key.key = Bitcoin::Key.new(priv_key: child_priv.to_s(16).rjust(64, '0'))
      new_key.chain_code = l[32..-1]
      new_key
    end

    # import private key from Base58 private key address
    def self.from_base58(address)
      data = StringIO.new(Base58.decode(address).htb)
      ext_key = ExtKey.new
      data.read(4).bth # version
      ext_key.depth = data.read(1).unpack('C').first
      ext_key.parent_fingerprint = data.read(4).bth
      ext_key.number = data.read(4).unpack('N').first
      ext_key.chain_code = data.read(32)
      data.read(1) # 0x00
      ext_key.key = Bitcoin::Key.new(priv_key: data.read(32).bth)
      ext_key
    end

  end

  # BIP-32 Extended public key
  class ExtPubkey
    attr_accessor :depth
    attr_accessor :number
    attr_accessor :chain_code
    attr_accessor :pubkey # hex format
    attr_accessor :parent_fingerprint

    # serialize extended pubkey
    def to_payload
      Bitcoin.chain_params.extended_pubkey_version.htb << [depth].pack('C') <<
          parent_fingerprint.htb << [number].pack('N') << chain_code << pub.htb
    end

    def pub
      pubkey
    end

    # get address
    def addr
      Bitcoin::Key.new(pubkey: pubkey).to_p2pkh
    end

    # get segwit p2wpkh address
    def segwit_addr
      hash160 = Bitcoin.hash160(pub)
      p2wpkh = [ ["00", "14", hash160].join ].pack("H*").bth
      segwit_addr = Bech32::SegwitAddr.new
      segwit_addr.hrp = Bitcoin.chain_params.address_version == '00' ? 'bc' : 'tb'
      segwit_addr.script_pubkey = p2wpkh
      segwit_addr.addr
    end

    # get key identifier
    def identifier
      Bitcoin.hash160(pub)
    end

    # get fingerprint
    def fingerprint
      identifier.slice(0..7)
    end

    # Base58 encoded extended pubkey
    def to_base58
      h = to_payload.bth
      hex = h + Bitcoin.calc_checksum(h)
      Base58.encode(hex)
    end

    # derive child key
    def derive(number)
      new_key = ExtPubkey.new
      new_key.depth = depth + 1
      new_key.number = number
      new_key.parent_fingerprint = fingerprint
      raise 'hardened key is not support' if number > (2**31 -1)
      data = pub.htb << [number].pack('N')
      l = Bitcoin.hmac_sha512(chain_code, data)
      left = l[0..31].bth.to_i(16)
      raise 'invalid key' if left >= CURVE_ORDER
      p1 = Bitcoin::Secp256k1::GROUP.generator.multiply_by_scalar(left)
      p2 = Bitcoin::Key.new(pubkey: pubkey).to_point
      new_key.pubkey = ECDSA::Format::PointOctetString.encode(p1 + p2, compression: true).bth
      new_key.chain_code = l[32..-1]
      new_key
    end

    # import pub key from Base58 private key address
    def self.from_base58(address)
      data = StringIO.new(Base58.decode(address).htb)
      ext_pubkey = ExtPubkey.new
      data.read(4).bth # version
      ext_pubkey.depth = data.read(1).unpack('C').first
      ext_pubkey.parent_fingerprint = data.read(4).bth
      ext_pubkey.number = data.read(4).unpack('N').first
      ext_pubkey.chain_code = data.read(32)
      ext_pubkey.pubkey = data.read(33).bth
      ext_pubkey
    end
  end

end
