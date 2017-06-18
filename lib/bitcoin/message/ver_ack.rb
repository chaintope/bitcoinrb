module Bitcoin
  module Message

    # verack message
    # https://bitcoin.org/en/developer-reference#verack
    class VerAck < Base

      def command
        'verack'
      end

      def to_payload
        ''
      end

    end

  end
end