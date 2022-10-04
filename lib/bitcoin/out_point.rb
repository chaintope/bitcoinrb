module Bitcoin

  # outpoint class
  class OutPoint

    include Bitcoin::HexConverter

    COINBASE_HASH = '0000000000000000000000000000000000000000000000000000000000000000'
    COINBASE_INDEX = 4294967295

    attr_reader :tx_hash
    attr_reader :index

    def initialize(tx_hash, index = -1)
      @tx_hash = tx_hash
      @index = index
    end

    def self.from_txid(txid, index)
      self.new(txid.rhex, index)
    end

    # Parse from payload
    # @param [String|StringIO] payload prvout payload with binary format
    # @return [Bitcoin::OutPoint]
    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      hash, index = buf.read(36).unpack('a32V')
      OutPoint.new(hash.bth, index)
    end

    def coinbase?
      tx_hash == COINBASE_HASH && index == COINBASE_INDEX
    end

    def to_payload
      [tx_hash.htb, index].pack('a32V')
    end

    def self.create_coinbase_outpoint
      new(COINBASE_HASH, COINBASE_INDEX)
    end

    def valid?
      index >= 0 && (!coinbase? && tx_hash != COINBASE_HASH)
    end

    # convert hash to txid
    def txid
      tx_hash.rhex
    end

    def to_s
      return "[#{index}]" unless tx_hash
      "#{txid}[#{index}]"
    end

  end

end
