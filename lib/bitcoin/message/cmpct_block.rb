module Bitcoin
  module Message

    # cmpctblock message
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
    class CmpctBlock < Base

      COMMAND = 'cmpctblock'

      attr_accessor :header_and_short_ids

      def initialize(header_and_short_ids)
        @header_and_short_ids = header_and_short_ids
      end

      # generate CmpctBlock from Block data.
      # @param [Bitcoin::Block] block the block to generate CmpctBlock.
      # @param [Integer] version Compact Block version specified by sendcmpct message.
      # @param [Integer] nonce
      # @return [Bitcoin::Message::CmpctBlock]
      def self.from_block(block, version, nonce = SecureRandom.hex(8).to_i(16))
        raise 'Unsupported version.' unless [1, 2].include?(version)
        h = HeaderAndShortIDs.new(block.header, nonce)
        block.transactions[1..-1].each do |tx|
          h.short_ids << h.short_id(version == 1 ? tx.txid : tx.wtxid)
        end
        h.prefilled_txn << PrefilledTx.new(0, block.transactions.first)
        self.new(h)
      end

      def self.parse_from_payload(payload)
        self.new(HeaderAndShortIDs.parse_from_payload(payload))
      end

      def to_payload
        header_and_short_ids.to_payload
      end

    end

  end
end
