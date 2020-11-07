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
        new(payload.unpack1('Q'))
      end

      def to_payload
        [fee_rate].pack('Q')
      end

    end
  end
end