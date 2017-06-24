module Bitcoin
  module Message

    # tx message
    # https://bitcoin.org/en/developer-reference#tx
    class Tx < Base

      COMMAND = 'tx'

      attr_accessor :tx
      attr_accessor :use_segwit

      def initialize(tx, use_segwit = false)
        @tx = tx
        @use_segwit = use_segwit
      end

      def self.parse_from_payload(payload)
        tx = Bitcoin::Tx.parse_from_payload(payload)
        new(tx, tx.witness?)
      end

      def to_payload
        use_segwit ? tx.to_payload : tx.serialize_old_format
      end

    end

  end
end
