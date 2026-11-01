require 'siphash'

module Bitcoin

  # Golomb-coded set filter
  # see https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
  class GCSFilter

    MAX_ELEMENTS_SIZE = 4294967296 # 2**32

    attr_reader :p # Golomb-Rice coding parameter
    attr_reader :m # Inverse false positive rate
    attr_reader :n # Number of elements in the filter
    attr_reader :key # SipHash key
    attr_reader :encoded # encoded filter with hex format.

    # initialize Filter object.
    # @param [String] key the 128-bit key used to randomize the SipHash outputs.
    # @param [Integer] p the bit parameter of the Golomb-Rice coding.
    # @param [Integer] m which determines the false positive rate.
    # @param [Array] elements the filter elements.
    # @param [String] encoded_filter encoded filter with hex format.
    # @return [Bitcoin::GCSFilter]
    # @raise [ArgumentError] If a parameter is out of range, or +encoded_filter+ is not the encoding of
    # exactly N elements, as Bitcoin Core's GCSFilter checks it.
    def initialize(key, p, m, elements: nil, encoded_filter: nil)
      raise ArgumentError, 'specify either elements or encoded_filter.' if elements.nil? && encoded_filter.nil?
      raise ArgumentError, 'key must be 16 bytes.' unless key.is_a?(String) && key.bytesize == 16
      raise ArgumentError, 'p must be between 0 and 32.' unless p.is_a?(Integer) && p.between?(0, 32)
      raise ArgumentError, 'm must be a positive integer.' unless m.is_a?(Integer) && m > 0
      @key = key.b
      @p = p
      @m = m
      if elements
        raise ArgumentError, 'elements size must be < 2**32.' if elements.size >= MAX_ELEMENTS_SIZE
        @n = elements.size
        encoded = Bitcoin.pack_var_int(@n)
        bit_writer = Bitcoin::BitStreamWriter.new
        unless elements.empty?
          last_value = 0
          hashed_set = elements.map{|e| hash_to_range(e) }.sort
          hashed_set.each do |v|
            delta = v - last_value
            golomb_rice_encode(bit_writer, p, delta)
            last_value = v
          end
        end
        bit_writer.flush
        encoded << bit_writer.stream
        @encoded = encoded.bth
      else
        raise ArgumentError, 'encoded_filter must be a hex string.' unless encoded_filter.is_a?(String) && encoded_filter.valid_hex?
        @encoded = encoded_filter
        buf = StringIO.new(encoded_filter.htb)
        @n = Bitcoin.unpack_var_int_from_io(buf)
        raise ArgumentError, 'N must be < 2**32.' if @n >= MAX_ELEMENTS_SIZE
        # The filter has to hold exactly N elements: neither fewer, nor bytes after the last one.
        bit_reader = Bitcoin::BitStreamReader.new(buf.read)
        begin
          @n.times { golomb_rice_decode(bit_reader, p) }
        rescue IOError
          raise ArgumentError, 'encoded_filter is truncated.'
        end
        raise ArgumentError, 'encoded_filter contains excess data.' unless bit_reader.stream.eof?
      end
    end

    # Range of element hashes, F = N * M
    def f
      n * m
    end

    # Hash a data element to an integer in the range [0, F).
    # @param [String] element with binary format.
    # @return [Integer]
    def hash_to_range(element)
      hash = SipHash.digest(key, element.b) # bytes, whatever the encoding of the string says
      map_into_range(hash, f)
    end

    # Checks if the element may be in the set. False positives are possible with probability 1/M.
    # @param [String] element with binary format
    # @return [Boolean] whether element in set.
    def match?(element)
      query = hash_to_range(element)
      match_internal?([query], 1)
    end

    # Checks if any of the given elements may be in the set. False positives are possible with probability 1/M per element checked.
    # This is more efficient that checking Match on multiple elements separately.
    # @param [Array] elements list of elements with binary format.
    # @return [Boolean] whether element in set.
    def match_any?(elements)
      queries = elements.map{|e| hash_to_range(e) }.sort
      match_internal?(queries, queries.size)
    end

    private

    # hash are then mapped uniformly over the desired range by multiplying with F and taking the top 64 bits of the 128-bit result.
    # https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    # https://stackoverflow.com/a/26855440
    def map_into_range(x, y)
      (x * y) >> 64
    end

    # Checks if the elements may be in the set.
    # @param [Array[Integer]] hashes the query hash list.
    # @param [Integer] size query size.
    # @return [Boolean] whether elements in set.
    def match_internal?(hashes, size)
      n, payload = Bitcoin.unpack_var_int(encoded.htb)
      bit_reader = Bitcoin::BitStreamReader.new(payload)
      value = 0
      hashes_index = 0
      n.times do
        delta = golomb_rice_decode(bit_reader, p)
        value += delta
        loop do
          return false if hashes_index == size
          return true if hashes[hashes_index] == value
          break if hashes[hashes_index] > value
          hashes_index += 1
        end
      end
      false
    end

    # encode golomb rice
    def golomb_rice_encode(bit_writer, p, x)
      q = x >> p
      while q > 0
        nbits = q <= 64 ? q : 64
        bit_writer.write(-1, nbits) # 18446744073709551615 is 2**64 - 1 = ~0ULL in cpp.
        q -= nbits
      end
      bit_writer.write(0, 1)
      bit_writer.write(x, p)
    end

    # decode golomb rice
    def golomb_rice_decode(bit_reader, p)
      q = 0
      while bit_reader.read(1) == 1
        q +=1
      end
      r = bit_reader.read(p)
      (q << p) + r
    end

  end
end
