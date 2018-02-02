module Bitcoin
  module Message

    # A PrefilledTransaction structure is used in HeaderAndShortIDs to provide a list of a few transactions explicitly.
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
    class PrefilledTx

      attr_accessor :index
      attr_accessor :tx

      def initialize(index, tx)
        @index = index
        @tx = tx
      end

      def self.parse_from_io(io)
        index = Bitcoin.unpack_var_int_from_io(io)
        tx = Bitcoin::Tx.parse_from_payload(io)
        self.new(index, tx)
      end

      def to_payload
        Bitcoin.pack_var_int(index) << tx.to_payload
      end

    end

  end
end
