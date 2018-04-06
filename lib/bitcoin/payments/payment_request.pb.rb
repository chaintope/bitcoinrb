module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#PaymentDetailsPaymentRequest
    class PaymentRequest < Protobuf::Message

      optional :uint32, :payment_details_version, 1, {default: 1}

      optional :string, :pki_type, 2, {default: 'none'}

      optional :bytes, :pki_data, 3

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

      # get certificates
      # @return [Array[OpenSSL::X509::Certificate]]
      def certs
        return [] unless has_pki?
        X509Certificates.decode(pki_data).certs
      end

      # whether exist +pki_data+.
      def has_pki?
        pki_type != 'none'
      end

      # verify signature.
      def valid_sig?
        return false unless has_pki?
        digest = case pki_type
                   when 'x509+sha256'
                     OpenSSL::Digest::SHA256.new
                   when 'x509+sha1'
                     OpenSSL::Digest::SHA1.new
                   else
                     raise "pki_type: #{pki_type} is invalid type."
                 end
        certs.first.public_key.verify(digest, signature, sig_message)
      end

      # verify expire time for payment request.
      def valid_time?
        expires = details.expires
        return true if expires == 0
        Time.now.to_i <= expires
      end

      private

      # Generate data to be signed
      def sig_message
        PaymentRequest.new(payment_details_version: payment_details_version,
                           pki_type: pki_type, pki_data: pki_data, signature: '',
                           serialized_payment_details: serialized_payment_details).encode
      end

    end

  end
end
