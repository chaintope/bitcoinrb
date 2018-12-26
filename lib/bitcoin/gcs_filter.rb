require 'siphash'

module Bitcoin

  # Golomb-coded set filter
  # see https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
  class GCSFilter

    attr_reader :elements # elements in the filter
    attr_reader :p # Golomb-Rice coding parameter
    attr_reader :m # Inverse false positive rate
    attr_reader :key # SipHash key
    attr_reader :encoded

    # initialize Filter object.
    # @param [String] key the 128-bit key used to randomize the SipHash outputs.
    # @param [Integer] p the bit parameter of the Golomb-Rice coding.
    # @param [Integer] m which determines the false positive rate.
    # @param [Array] elements the filter elements.
    # @return [Bitcoin::GCSFilter]
    def initialize(key, p, m, elements)
      raise 'elements size must be < 2**32.' if elements.size >= (2**32)
      raise 'p must be <= 32' if p > 32
      @key = key
      @p = p
      @m = m
      @elements = elements
      encoded = Bitcoin.pack_var_int(n)
      bit_writer = Bitcoin::BitStreamWriter.new
      unless elements.empty?
        last_value = 0
        hashed_set = elements.reverse.map{|e| hash_to_range(e) }.sort
        hashed_set.each do |v|
          delta = v - last_value
          golomb_rice_encode(bit_writer, p, delta)
          last_value = v
        end
      end
      bit_writer.flush
      encoded << bit_writer.stream
      @encoded = encoded.bth
    end

    # Number of elements in the filter
    def n
      elements.size
    end

    # Range of element hashes, F = N * M
    def f
      n * m
    end

    # Hash a data element to an integer in the range [0, F).
    # @param [String] element with hex format.
    def hash_to_range(element)
      hash = SipHash.digest(key, element)
      map_into_range(hash, f)
    end

    private

    # hash are then mapped uniformly over the desired range by multiplying with F and taking the top 64 bits of the 128-bit result.
    # https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    # https://stackoverflow.com/a/26855440
    def map_into_range(x, y)
      (x * y) >> 64
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

  end
end
