module Bitcoin
  module Message

    # pong message
    # https://bitcoin.org/en/developer-reference#pong
    class Pong < Base

      COMMAND = 'pong'

      attr_reader :nonce

      def initialize(nonce)
        @nonce = nonce
      end

      def self.parse_from_payload(payload)
        raise Bitcoin::Message::Error, 'Payload must be 8 bytes.' unless payload.bytesize == 8
        new(payload.unpack1('Q<'))
      end

      def to_payload
        [nonce].pack('Q<')
      end
    end

  end
end
