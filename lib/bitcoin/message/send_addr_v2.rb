module Bitcoin
  module Message
    class SendAddrV2 < Base

      COMMAND = 'sendaddrv2'

      def to_payload
        ''
      end

    end
  end
end