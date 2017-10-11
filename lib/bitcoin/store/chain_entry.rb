module Bitcoin
  module Store

    # wrap a block header object with extra data.
    class ChainEntry

      attr_reader :header
      attr_reader :height

      # @param [Bitcoin::BlockHeader] header a block header.
      # @param [Integer] height a block height.
      def initialize(header, height)
        @header = header
        @height = height
      end

      # get database key
      def key
        Bitcoin::Store::KEY_PREFIX[:entry] + header.hash
      end

      # block hash
      def hash
        header.hash
      end

      # previous block hash
      def prev_hash
        header.prev_hash
      end

      # whether genesis block
      def genesis?
        Bitcoin.chain_params.genesis_block.header == header
      end

      # @param [String] payload a payload with binary format.
      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        len = Bitcoin.unpack_var_int_from_io(buf)
        height = buf.read(len).reverse.bth.to_i(16)
        new(Bitcoin::BlockHeader.parse_from_payload(buf.read(80)), height)
      end

      # build next block +StoredBlock+ instance.
      # @param [Bitcoin::BlockHeader] next_block a next block candidate header.
      # @return [Bitcoin::Store::ChainEntry] a next stored block (not saved).
      def build_next_block(next_block)
        ChainEntry.new(next_block, height + 1)
      end

      # generate payload
      def to_payload
        height_value = height.to_s(16)
        height_value = '0' + height_value if height_value.length.odd?
        height_value = height_value.htb.reverse
        Bitcoin.pack_var_int(height_value.bytesize) + height_value + header.to_payload
      end

    end

  end

end
