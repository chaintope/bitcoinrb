module Bitcoin
  module Message

    # BIP-152 Compact Block's data format.
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki#BlockTransactions
    class BlockTransactions

      attr_accessor :block_hash
      attr_accessor :transactions

      def initialize(block_hash, transactions)
        @block_hash = block_hash
        @transactions = transactions
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        block_hash = Bitcoin.read_exact(buf, 32).bth
        tx_count = Bitcoin.unpack_var_int_from_io(buf)
        raise Bitcoin::Message::Error, "blocktxn tx count #{tx_count} exceeds #{MAX_COMPACT_BLOCK_TX_COUNT}." if tx_count > MAX_COMPACT_BLOCK_TX_COUNT
        txn = tx_count.times.map{Bitcoin::Tx.parse_from_payload(buf)}
        self.new(block_hash, txn)
      end

      def to_payload
        block_hash.htb << Bitcoin.pack_var_int(transactions.size) << transactions.map(&:to_payload).join
      end

    end

  end
end