module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#Certificates
    class X509Certificates < Protobuf::Message

      repeated :bytes, :certificate, 1

      # get certificates
      # @return [Array[OpenSSL::X509::Certificate]]
      def certs
        certificate.map{|v|OpenSSL::X509::Certificate.new(v)}
      end

    end

  end
end
