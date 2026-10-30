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
        block_hash = buf.read(32)
        raise Bitcoin::Message::Error, 'Invalid getblocktxn payload. block hash is missing.' if block_hash.nil? || block_hash.bytesize < 32
        index_len = Bitcoin.unpack_var_int_from_io(buf)
        raise Bitcoin::Message::Error, 'Invalid getblocktxn payload. index count is missing.' if index_len.nil?
        # Each index takes at least one byte, so a count the payload cannot hold is rejected before
        # anything is allocated for it.
        raise Bitcoin::Message::Error, "Invalid getblocktxn payload. index count #{index_len} exceeds the payload." if index_len > (buf.size - buf.pos)
        # index data differentially encoded. Bitcoin Core keeps every decoded index within 16 bits.
        indexes = []
        offset = 0
        index_len.times do
          index = Bitcoin.unpack_var_int_from_io(buf)
          raise Bitcoin::Message::Error, 'Invalid getblocktxn payload. index is missing.' if index.nil?
          index += offset
          raise Bitcoin::Message::Error, 'Invalid getblocktxn payload. index overflowed 16 bits.' if index > 0xffff
          indexes << index
          offset = index + 1
        end
        self.new(block_hash.bth, indexes)
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
