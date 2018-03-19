module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#PaymentACK
    class PaymentACK < Protobuf::Message

      required Bitcoin::Payments::Payment, :payment, 1

      optional :string, :memo, 2

      def self.parse_from_payload(payload)
        decode(payload)
      end
    end

  end
end
