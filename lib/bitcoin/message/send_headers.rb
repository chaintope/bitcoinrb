module Bitcoin
  module Message

    # sendheaders message
    # https://bitcoin.org/en/developer-reference#sendheaders
    class SendHeaders < Base

      COMMAND = 'sendheaders'

      def to_payload
        ''
      end
    end

  end
end
