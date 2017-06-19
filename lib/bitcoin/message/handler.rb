module Bitcoin
  module Message

    # Default P2P message handler.
    class Handler

      attr_reader :logger
      attr_reader :connection

      def initialize(connection, logger = Bitcoin::Logger.create(:parser))
        @connection = connection
        @logger = logger
      end

      # handle p2p message.
      def handle(message)
        logger.info "handle message #{message.bth}"
        parse_header(message)

      end

      private

      def parse_header(message)
        head_magic = Bitcoin.chain_params.magic_head
        raise Error, "invalid message header. message = #{message}" if message.nil? || message.size < HEADER_SIZE

        magic, command, length, checksum = message.unpack('a4A12Va4')
        unless magic.bth == head_magic
          logger.error("invalid header magic. #{magic.bth}")
          connection.close
        end

        payload = message[HEADER_SIZE...(HEADER_SIZE + length)]
        unless Bitcoin.double_sha256(payload)[0...4] == checksum
          logger.error("invalid header checksum. #{checksum}")
          connection.close
        end

      end

    end
  end
end