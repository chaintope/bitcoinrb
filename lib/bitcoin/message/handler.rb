module Bitcoin
  module Message

    # Default P2P message handler.
    class Handler

      attr_reader :logger

      def initialize(logger = Bitcoin::Logger.create(:parser))
        @logger = logger
      end

      # handle p2p message.
      def handle(message)
        logger.info "handle message #{message.bth}"
        head_magic = Bitcoin.chain_params.magic_head
        raise Error, "invalid message header. message = #{message}" if message.nil? || message.size < Bitcoin::Message::HEADER_SIZE

        # parse header
        magic, command, lenght, checksum = message.unpack("a4A12Va4")
        raise Error, "invalid header magic. #{magic.bth}" unless magic.bth == head_magic
      end

    end
  end
end