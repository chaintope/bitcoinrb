module Bitcoin

  # Block Header
  class BlockHeader

    attr_accessor :version
    attr_accessor :prev_hash
    attr_accessor :merkle_root
    attr_accessor :time # unix timestamp
    attr_accessor :bits
    attr_accessor :nonce

    def initialize(version, prev_hash, merkle_root, time, bits, nonce)
      @version = version
      @prev_hash = prev_hash
      @merkle_root = merkle_root
      @time = time
      @bits = bits
      @nonce = nonce
    end

    def self.parse_from_payload(payload)
      version, prev_hash, merkle_root, time, bits, nonce = payload.unpack('Va32a32VVV')
      new(version, prev_hash.reverse.bth, merkle_root.reverse.bth, time, bits, nonce)
    end

    def to_payload
      [version, prev_hash.htb.reverse, merkle_root.htb.reverse, time, bits, nonce].pack('Va32a32VVV')
    end

    # compute difficulty target from bits.
    def difficulty_target
      exponent = ((bits >> 24) & 0xff)
      mantissa = bits & 0x7fffff
      mantissa *= -1 if (bits & 0x800000) > 0
      (mantissa * 2 ** (8 * (exponent - 3)))
    end

    # block hash
    def hash
      calc_hash
    end

    # evaluate block header
    def valid?
      valid_pow? && valid_timestamp?
    end

    # evaluate valid proof of work.
    def valid_pow?
      hash.hex < difficulty_target
    end

    # evaluate valid timestamp.
    # https://en.bitcoin.it/wiki/Block_timestamp
    def valid_timestamp?
      time <= Time.now.to_i + Bitcoin::MAX_FUTURE_BLOCK_TIME
    end

    # compute chain work of this block.
    # @return [Integer] a chain work.
    def work
      target = difficulty_target
      return 0 if target < 1
      (2**256) / (target + 1)
    end

    def ==(other)
      other && other.to_payload == to_payload
    end

    private

    def calc_hash
      Bitcoin.double_sha256(to_payload).reverse.bth
    end

  end

end