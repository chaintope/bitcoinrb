require "murmurhash3"
module Bitcoin
  class BloomFilter
    LN2_SQUARED = 0.4804530139182014246671025263266649717305529515945455 # log(2) ** 2
    LN2 = 0.6931471805599453094172321214581765680755001343602552 # log(2)

    MAX_BLOOM_FILTER_SIZE = 36_000 # bytes
    MAX_HASH_FUNCS = 50

    attr_reader :filter, :hash_funcs, :tweak

    def initialize(filter, hash_funcs, tweak)
      @filter = filter
      @hash_funcs = hash_funcs
      @tweak = tweak
    end

    # Create a new bloom filter.
    # @param [Integer] elements_length the number of elements
    # @param [Float] fp_rate the false positive rate chosen by the client
    # @param [Integer] tweak A random value to add to the seed value in the hash function used by the bloom filter
    def self.create_filter(elements_length, fp_rate, tweak = 0)
      # The size S of the filter in bytes is given by (-1 / pow(log(2), 2) * N * log(P)) / 8
      len = [[(-elements_length * Math.log(fp_rate) / (LN2_SQUARED * 8)).to_i, MAX_BLOOM_FILTER_SIZE].min, 1].max
      filter = Array.new(len, 0)
      # The number of hash functions required is given by S * 8 / N * log(2)
      hash_funcs = [[(filter.size * 8 * LN2 / elements_length).to_i, MAX_HASH_FUNCS].min, 1].max
      BloomFilter.new(filter, hash_funcs, tweak)
    end

    # @param [String] data The data element to add to the current filter.
    def add(data)
      return if full?
      hash_funcs.times do |i|
        hash = to_hash(data, i)
        set_bit(hash)
      end
    end

    # Returns true if the given data matches the filter
    # @param [String] data The data to check the current filter
    # @return [Boolean] true if the given data matches the filter
    def contains?(data)
      return true if full?
      hash_funcs.times do |i|
        hash = to_hash(data, i)
        return false unless check_bit(hash)
      end
      true
    end

    def clear
      filter.fill(0)
      @full = false
    end

    def to_a
      filter
    end

    private
    def to_hash(data, i)
      MurmurHash3::V32.str_hash(data, (i * 0xfba4c795 + tweak) & 0xffffffff)  % (filter.length * 8)
    end

    def set_bit(data)
      filter[data >> 3] |= (1 << (7 & data))
    end

    def check_bit(data)
      filter[data >> 3] & (1 << (7 & data)) != 0
    end

    def full?
      @full |= filter.all? {|byte| byte == 0xff}
    end
  end
end
