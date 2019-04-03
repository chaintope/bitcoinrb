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
    def initialize(key, p, m, elements: nil, encoded_filter: nil)
      raise 'specify either elements or encoded_filter.' if elements.nil? && encoded_filter.nil?
      raise 'p must be <= 32' if p > 32
      @key = key
      @p = p
      @m = m
      if elements
        raise 'elements size must be < 2**32.' if elements.size >= MAX_ELEMENTS_SIZE
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
        @encoded = encoded_filter
        @n, payload = Bitcoin.unpack_var_int(encoded_filter.htb)
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
      hash = SipHash.digest(key, element)
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
