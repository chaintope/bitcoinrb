module Bitcoin
  module Message

    # ping message class
    # https://bitcoin.org/en/developer-reference#ping
    class Ping < Base

      COMMAND = 'ping'

      attr_accessor :nonce

      def initialize(nonce = SecureRandom.random_number(0xffffffff))
        @nonce = nonce
      end

      def self.parse_from_payload(payload)
        new(payload.unpack1('Q'))
      end

      def to_payload
        [nonce].pack('Q')
      end

      def to_response
        Pong.new(nonce)
      end

    end
  end
end
