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
        raise Bitcoin::Message::Error, 'Payload must be empty or 8 bytes.' unless payload.empty? || payload.bytesize == 8
        new(payload.unpack1('Q<'))
      end

      def to_payload
        nonce ? [nonce].pack('Q<') : ''
      end

      # Generate pong message as a response. Return nil if the ping has no nonce
      # (sent by a node before BIP-31), since such a ping does not expect a pong.
      def to_response
        Pong.new(nonce) if nonce
      end

    end
  end
end
