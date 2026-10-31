module Bitcoin
  module Message

    # feefilter message
    # https://bitcoin.org/en/developer-reference#feefilter
    class FeeFilter < Base

      COMMAND = 'feefilter'

      # The fee rate (in satoshis per kilobyte)
      attr_accessor :fee_rate

      def initialize(fee_rate)
        @fee_rate = fee_rate
      end

      def self.parse_from_payload(payload)
        raise Bitcoin::Message::Error, 'Payload must be 8 bytes.' unless payload.bytesize == 8
        new(payload.unpack1('Q<'))
      end

      def to_payload
        [fee_rate].pack('Q<')
      end

    end
  end
end