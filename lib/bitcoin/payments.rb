require 'protobuf'

module Bitcoin
  module Payments

    autoload :Output, 'bitcoin/payments/output.pb'
    autoload :Payment, 'bitcoin/payments/payment.pb'
    autoload :PaymentACK, 'bitcoin/payments/payment_ack.pb'
    autoload :PaymentDetails, 'bitcoin/payments/payment_details.pb'
    autoload :PaymentRequest, 'bitcoin/payments/payment_request.pb'
    autoload :X509Certificates, 'bitcoin/payments/x509_certificates.pb'

  end
end
