module Bitcoin

  class BitStreamWriter

    MAX_BIT = 4611686018427387904 # 2**64

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
      self.stream << buffer.itb
      self.offset = 0
      self.buffer = 0
    end

  end

  class BitStreamReader

    attr_reader :stream
    attr_accessor :buffer
    attr_accessor :offset

    def initialize(payload)
      @offset = 8
      @buffer = 0
      @stream = StringIO.new(payload)
    end

    # offset
    def read(nbits)
      raise 'nbits must be between 0 and 64' if nbits < 0 || nbits > 64
      data = 0
      while nbits > 0
        if offset == 8
          raise IOError, 'stream is empty.' if stream.eof?
          self.buffer = stream.read(1).bth.to_i(16)
          self.offset = 0
        end
        bits = [8 - offset, nbits].min
        data <<= bits
        tmp = (buffer << offset) & 255
        data = data | (tmp >> (8 - bits))
        self.offset += bits
        nbits -= bits
      end
      data
    end

  end

end