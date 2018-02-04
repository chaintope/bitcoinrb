module Bitcoin
  module Message

    # blocktxn message.
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki#blocktxn
    class BlockTxn < Base

      COMMAND = 'blocktxn'

      attr_accessor :block_transactions

      def initialize(block_transactions)
        @block_transactions = block_transactions
      end

      def self.parse_from_payload(payload)
        self.new(BlockTransactions.parse_from_payload(payload))
      end

      def to_payload
        block_transactions.to_payload
      end

    end

  end
end
