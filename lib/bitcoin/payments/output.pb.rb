module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#Output
    class Output < Protobuf::Message

      optional :uint64, :amount, 1, {default: 0}

      required :bytes, :script, 2

      # convert to TxOut object.
      # @return [Bitcoin::TxOut]
      def to_tx_out
        Bitcoin::TxOut.new(value: amount, script_pubkey: Bitcoin::Script.parse_from_payload(script))
      end

    end

  end
end
