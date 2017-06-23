module Bitcoin

  # outpoint class
  class OutPoint

    COINBASE_HASH = '0000000000000000000000000000000000000000000000000000000000000000'
    COINBASE_INDEX = 4294967295

    attr_reader :hash
    attr_reader :index

    def initialize(hash, index)
      @hash = hash
      @index = index
    end

    def coinbase?
      hash == COINBASE_HASH && index == COINBASE_INDEX
    end

    def to_payload
      [hash.htb.reverse, index].pack('a32V')
    end

  end

end
