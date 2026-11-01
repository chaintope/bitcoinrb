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

    # Parse block header from payload.
    # @param [String|StringIO] payload block header paylaod
    # @return [Bitcoin::BlockHeader]
    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      version, prev_hash, merkle_root, time, bits, nonce = Bitcoin.read_exact(buf, 80).unpack('Va32a32VVV')
      new(version, prev_hash.bth, merkle_root.bth, time, bits, nonce)
    end

    def to_payload
      [version, prev_hash.htb, merkle_root.htb, time, bits, nonce].pack('Va32a32VVV')
    end

    # Decode a compact target the way Bitcoin Core's arith_uint256::SetCompact does.
    # @param [Integer] compact The 32 bit compact encoding, such as the bits of a block header.
    # @return [Integer] The target. It is negative when the sign bit is set, and it may not fit in
    # 256 bits, see .compact_overflow?.
    def self.decode_compact(compact)
      exponent = (compact >> 24) & 0xff
      mantissa = compact & 0x7fffff
      target = exponent <= 3 ? mantissa >> (8 * (3 - exponent)) : mantissa << (8 * (exponent - 3))
      (compact & 0x800000).zero? ? target : -target
    end

    # Whether the target of +compact+ does not fit in 256 bits, as Bitcoin Core's SetCompact reports it.
    # @param [Integer] compact The 32 bit compact encoding.
    # @return [Boolean]
    def self.compact_overflow?(compact)
      exponent = (compact >> 24) & 0xff
      mantissa = compact & 0x7fffff
      mantissa != 0 && (exponent > 34 || (mantissa > 0xff && exponent > 33) || (mantissa > 0xffff && exponent > 32))
    end

    # compute difficulty target from bits.
    # @return [Integer] see .decode_compact.
    def difficulty_target
      BlockHeader.decode_compact(bits)
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

    # evaluate valid proof of work, as Bitcoin Core's CheckProofOfWork does: the target has to be positive,
    # fit in 256 bits and be no easier than the proof of work limit of the current chain, and the block
    # hash has to be no greater than the target.
    def valid_pow?
      target = difficulty_target
      return false if target <= 0 || BlockHeader.compact_overflow?(bits)
      return false if target > BlockHeader.decode_compact(Bitcoin.chain_params.proof_of_work_limit)
      block_id.hex <= target
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
      return 0 if target < 1 || BlockHeader.compact_overflow?(bits)
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