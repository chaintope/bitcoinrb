module Bitcoin

  # Block Header
  class BlockHeader

    include Bitcoin::HexConverter

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
      new(version, prev_hash.bth, merkle_root.bth, time, bits, nonce)
    end

    def to_payload
      [version, prev_hash.htb, merkle_root.htb, time, bits, nonce].pack('Va32a32VVV')
    end

    # compute difficulty target from bits.
    def difficulty_target
      exponent = ((bits >> 24) & 0xff)
      mantissa = bits & 0x7fffff
      mantissa *= -1 if (bits & 0x800000) > 0
      (mantissa * 2 ** (8 * (exponent - 3)))
    end

    def hash
      calc_hash.to_i(16)
    end

    def block_hash
      calc_hash
    end

    # block hash(big endian)
    def block_id
      block_hash.rhex
    end

    # evaluate block header
    def valid?
      valid_pow? && valid_timestamp?
    end

    # evaluate valid proof of work.
    def valid_pow?
      block_id.hex < difficulty_target
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
      115792089237316195423570985008687907853269984665640564039457584007913129639936.div(target + 1) # 115792089237316195423570985008687907853269984665640564039457584007913129639936 is 2**256
    end

    def ==(other)
      other && other.to_payload == to_payload
    end

    private

    def calc_hash
      Bitcoin.double_sha256(to_payload).bth
    end

  end

end