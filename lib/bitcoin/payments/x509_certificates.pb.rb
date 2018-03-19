module Bitcoin
  module Payments

    # https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki#Certificates
    class X509Certificates < Protobuf::Message

      repeated :bytes, :certificate, 1

    end

  end
end
