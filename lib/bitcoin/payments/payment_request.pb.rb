module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#PaymentDetailsPaymentRequest
    class PaymentRequest < Protobuf::Message

      optional :uint32, :payment_details_version, 1, {default: 1}

      optional :string, :pki_type, 2, {default: 'none'}

      optional :bytes, :pki_date, 3

      required :bytes, :serialized_payment_details, 4

      optional :bytes, :signature, 5

      def self.parse_from_payload(payload)
        self.decode(payload)
      end

      # verify +pki_data+.
      # @return [Struct] pki information.
      def verify_pki_data
        d = Struct.new(:display_name, :merchant_sign_key, :root_auth, :root_auth_name)
        d
      end

      # get payment details
      # @return [Bitcoin::Payments:PaymentDetails]
      def details
        PaymentDetails.decode(serialized_payment_details)
      end

    end

  end
end
