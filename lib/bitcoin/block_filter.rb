module Bitcoin

  # Compact Block Filter
  # https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
  # This implementation ported the implementation of Bitcoin Core's blockfilter.cpp.
  # https://github.com/bitcoin/bitcoin/blob/master/src/blockfilter.cpp
  class BlockFilter

    TYPE = {basic: 0}

    # basic filter params
    BASIC_FILTER_P = 19
    BASIC_FILTER_M = 784931

    attr_accessor :filter_type
    attr_accessor :filter
    attr_accessor :block_hash

    # Constructor
    # @param [Integer] filter_type
    # @param [Bitcoin::GCSFilter] filter a GCS filter.
    # @param [String] block_hash a block hash with hex format.
    # @return [Bitcoin::BlockFilter]
    def initialize(filter_type, filter, block_hash)
      @filter_type = filter_type
      @filter = filter
      @block_hash = block_hash
    end

    # Build BlockFilter from the block data.
    # @param [Integer] filter_type a filter type(basic or extended).
    # @param [Bitcoin::Block] block target block object.
    # @param [Array[Bitcoin::Script]] prev_out_scripts The previous output script (the script being spent) for each input, except for the coinbase transaction.
    # @return [Bitcoin::BlockFilter] block filter object.
    def self.build_from_block(filter_type, block, prev_out_scripts)
      block_hash = block.block_hash.htb[0...16]
      filter = case filter_type
               when TYPE[:basic]
                 GCSFilter.new(block_hash, BASIC_FILTER_P, BASIC_FILTER_M, elements: build_basic_filter_elements(block, prev_out_scripts))
               else
                 raise "unknown filter type: #{filter_type}."
               end
      BlockFilter.new(filter_type, filter, block.block_hash)
    end

    # Decode Block Filter from encoded filter
    # @param [Integer] filter_type filter type.
    # @param [String] block_hash block hash with hex format. not little endian.
    # @param [String] encoded encoded_filter with hex format.
    # @return [Bitcoin::BlockFilter] block filter object.
    def self.decode(filter_type, block_hash, encoded)
      filter = case filter_type
               when TYPE[:basic]
                GCSFilter.new(block_hash.htb[0...16], BASIC_FILTER_P, BASIC_FILTER_M, encoded_filter: encoded)
              else
                raise "unknown filter type: #{filter_type}."
               end
      BlockFilter.new(filter_type, filter, block_hash)
    end

    # calculate filter hash.
    # @return [String] this filter hash with hex format.
    def filter_hash
      Bitcoin.double_sha256(encoded_filter.htb).bth
    end

    # calculate filter header which calculates from previous filter header and current filter hash.
    # @param [String] prev_header a previous header with hex format.
    # @return [String] header of this filter with hex format.
    def header(prev_header)
      Bitcoin.double_sha256(filter_hash.htb + prev_header.htb).bth
    end

    # get encoded filter.
    def encoded_filter
      filter.encoded
    end

    # build basic filter elements
    # @param [Bitcoin::Block] block current block
    # @param [Array[Bitcoin::Script]] prev_out_scripts The previous output script (the script being spent) for each input, except for the coinbase transaction.
    # @return [Array[String]] basic filter elements
    def self.build_basic_filter_elements(block, prev_out_scripts)
      elements = []
      block.transactions.each do |tx|
        elements += tx.outputs.select{|o|
          !o.script_pubkey.empty? && !o.script_pubkey.op_return?}.map{|o| o.script_pubkey.to_payload}
      end
      elements += prev_out_scripts.select{|s|!s.empty? && !s.op_return?}.map(&:to_payload)
      elements.uniq
    end

    private_class_method :build_basic_filter_elements

  end

end
