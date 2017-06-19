module Bitcoin
  module Message

    # getaddr message
    # https://bitcoin.org/en/developer-reference#getaddr
    class GetAddr < Base

      def command
        'getaddr'
      end

      def to_payload
        ''
      end

    end

  end
end
