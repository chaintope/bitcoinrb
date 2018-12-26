module Bitcoin

  class BitStreamWriter

    MAX_BIT = 2**64

    attr_reader :stream
    attr_accessor :buffer
    attr_accessor :offset

    def initialize
      @stream = ''
      @buffer = 0
      @offset = 0
    end

    def write(data, nbits)
      raise "nbits must be between 0 and 64" if nbits < 0 || nbits > 64
      while nbits > 0
        bits = [8 - offset, nbits].min
        tmp = (data << (64 - nbits)) & 0b1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111
        self.buffer |= (tmp >> (64 - 8 + offset))
        self.offset += bits
        nbits -= bits
        flush if offset == 8
      end
    end

    def flush
      return if offset == 0
      self.stream << [buffer.to_even_length_hex].pack('H*')
      self.offset = 0
      self.buffer = 0
    end

  end


  class BitStreamReader

    attr_reader :buffer
    attr_reader :offset

    def initialize
      @offset = 8
      # @buffer =
    end

    # offset
    def read(bits)

    end

  end

end