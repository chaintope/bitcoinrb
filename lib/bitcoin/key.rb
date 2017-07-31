module Bitcoin

  # bitcoin key class
  class Key

    attr_accessor :priv_key
    attr_accessor :pub_key
    attr_accessor :compressed

    def initialize(priv_key: nil, pubkey: nil, compressed: true)
      extend Bitcoin.secp_impl
      @priv_key = priv_key
      if pubkey
        @pub_key = pubkey
      else
        @pub_key = generate_pubkey(priv_key, compressed: compressed) if priv_key
      end
      @compressed = compressed
    end

    # import private key from wif format
    # https://en.bitcoin.it/wiki/Wallet_import_format
    def self.from_wif(wif)
      compressed = wif.size == 52
      hex = Base58.decode(wif)
      version, key, flag, checksum = hex.unpack("a2a64a#{compressed ? 2 : 0}a8")
      raise ArgumentError, 'invalid version' unless version == Bitcoin.chain_params.privkey_version
      raise ArgumentError, 'invalid checksum' unless Bitcoin.calc_checksum(version + key + flag) == checksum
      new(priv_key: key, compressed: compressed)
    end

    # export private key with wif format
    def to_wif
      version = Bitcoin.chain_params.privkey_version
      hex = version + priv_key
      hex += '01' if compressed?
      hex += Bitcoin.calc_checksum(hex)
      Base58.encode(hex)
    end

    # sign +data+ with private key
    def sign(data)
      sign_data(data, priv_key)
    end

    # verify signature using public key
    def verify(sig, origin)
      verify_sig(origin, sig, pub_key)
    end

    # get pay to pubkey hash address
    def to_p2pkh
      Bitcoin::Script.to_p2pkh(Bitcoin.hash160(pub_key)).to_addr
    end

    # get pay to witness pubkey hash address
    def to_p2wpkh
      Bitcoin::Script.to_p2wpkh(Bitcoin.hash160(pub_key)).to_addr
    end

    def compressed?
      @compressed
    end

    # check +pubkey+ (hex) is compress or uncompress pubkey.
    def self.compress_or_uncompress_pubkey?(pubkey)
      p = pubkey.htb
      return false if p.bytesize < 33
      case p[0]
        when "\x04"
          return false unless p.bytesize == 65
        when "\x02", "\x03"
          return false unless p.bytesize == 33
        else
          return false
      end
      true
    end

    # check +pubkey+ (hex) is compress pubkey.
    def self.compress_pubkey?(pubkey)
      p = pubkey.htb
      p.bytesize == 33 && ["\x02", "\x03"].include?(p[0])
    end

    # check +sig+ is low.
    def self.low_signature?(sig)
      s = sig.unpack('C*')
      len_r = s[3]
      len_s = s[5 + len_r]
      val_s = s.slice(6 + len_r, len_s)
      max_mod_half_order = [
          0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
          0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,
          0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0]
      compare_big_endian(val_s, [0]) > 0 &&
          compare_big_endian(val_s, max_mod_half_order) <= 0
    end

    private

    def self.compare_big_endian(c1, c2)
      c1, c2 = c1.dup, c2.dup # Clone the arrays

      while c1.size > c2.size
        return 1 if c1.shift > 0
      end

      while c2.size > c1.size
        return -1 if c2.shift > 0
      end

      c1.size.times{|idx| return c1[idx] - c2[idx] if c1[idx] != c2[idx] }
      0
    end

  end

end
