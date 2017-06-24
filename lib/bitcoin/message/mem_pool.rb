module Bitcoin
  module Message

    # mempool message
    # https://bitcoin.org/en/developer-reference#mempool
    class MemPool < Base

      COMMAND = 'mempool'

      def to_payload
        ''
      end

    end

  end
end
