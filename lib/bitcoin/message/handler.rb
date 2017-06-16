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
        logger.info "handle message #{message}"
        head_magic = Bitcoin.chain_params.magic_head
        raise Error, "invalid message headeer. message = #{message}" if message.nil? || message.size != Bitcoin::Message::HEADER_SIZE
      end

    end
  end
end