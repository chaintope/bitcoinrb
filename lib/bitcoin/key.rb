module Bitcoin

  # bitcoin key class
  class Key

    attr_accessor :priv_key
    attr_accessor :pub_key
    attr_accessor :compressed

    def initialize(priv_key: nil, pubkey: nil, compressed: true)
      extend Bitcoin.secp_impl
      @priv_key = priv_key
      @pub_key = pubkey ? pubkey : generate_pubkey(priv_key, compressed: compressed)
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

    # get pay to pubkey hash address
    def to_p2pkh
      Bitcoin::Script.to_p2pkh(Bitcoin.hash160(pub_key)).to_addr
    end

    # get pay to witness pubkey hash address
    def to_p2wpkh
      Bitcoin::Script.to_p2wpkh(pub_key).addr
    end

    def compressed?
      @compressed
    end

  end

end
