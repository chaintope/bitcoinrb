module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#PaymentDetailsPaymentRequest
    class PaymentDetails < Protobuf::Message

      optional :string, :network, 1, {default: 'main'}

      repeated Bitcoin::Payments::Output, :outputs, 2

      required :uint64, :time, 3

      optional :uint64, :expires, 4

      optional :string, :memo, 5

      optional :string, :payment_url, 6

      optional :bytes, :merchant_data, 7

    end

  end
end
