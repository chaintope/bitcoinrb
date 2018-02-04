module Bitcoin
  module Message

    # getblocktxn message.
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
    class GetBlockTxn < Base

      COMMAND = 'getblocktxn'

      attr_accessor :request

      def initialize(request)
        @request = request
      end

      def self.parse_from_payload(payload)
        self.new(BlockTransactionRequest.parse_from_payload(payload))
      end

      def to_payload
        request.to_payload
      end

    end

  end
end
