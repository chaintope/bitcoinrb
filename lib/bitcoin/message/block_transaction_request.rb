module Bitcoin
  module Message

    # BIP-152 Compact Block's data format.
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki#BlockTransactionsRequest
    class BlockTransactionRequest

      attr_accessor :block_hash # When matching with Bitcoin::BlockHeader#hash It is necessary to reverse the byte order.
      attr_accessor :indexes

      def initialize(block_hash, indexes)
        @block_hash = block_hash
        @indexes = indexes
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        block_hash = buf.read(32).bth
        index_len = Bitcoin.unpack_var_int_from_io(buf)
        indexes = index_len.times.map{Bitcoin.unpack_var_int_from_io(buf)}
        # index data differentially encoded
        offset = 0
        index_len.times do |i|
          index = indexes[i]
          index += offset
          indexes[i] = index
          offset = index + 1
        end
        self.new(block_hash, indexes)
      end

      def to_payload
        p = block_hash.htb << Bitcoin.pack_var_int(indexes.size)
        indexes.size.times do |i|
          index = indexes[i]
          index -= indexes[i-1] + 1 if i > 0
          p << Bitcoin.pack_var_int(index)
        end
        p
      end

    end

  end
end
