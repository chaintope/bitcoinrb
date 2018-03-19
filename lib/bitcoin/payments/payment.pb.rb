module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#Payment
    class Payment < Protobuf::Message

      optional :bytes, :merchant_data, 1

      repeated :bytes, :transactions, 2

      repeated Bitcoin::Payments::Output, :refund_to, 3

      optional :string, :memo, 4

      def self.parse_from_payload(payload)
        decode(payload)
      end

      def transactions
        @values[:transactions].map{|raw_tx|Bitcoin::Tx.parse_from_payload(raw_tx)}
      end

    end

  end
end
