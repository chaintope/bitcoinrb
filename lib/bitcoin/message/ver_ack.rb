module Bitcoin
  module Message

    # verack message
    # https://bitcoin.org/en/developer-reference#verack
    class VerAck < Base

      COMMAND = 'verack'

      def to_payload
        ''
      end

    end

  end
end