module Bitcoin

  module Network

    # Basic Bitcoin P2P connection class
    class Connection < EM::Connection

      include MessageHandler

      attr_reader :peer, :logger

      # remote peer version.
      attr_accessor :version

      # if true, this peer send new block announcements using a headers message rather than an inv message.
      attr_accessor :sendheaders

      # minimum fee(in satoshis per kilobyte) for relay tx
      attr_accessor :fee_rate

      def initialize(peer)
        @peer = peer
        @logger = Bitcoin::Logger.create(:debug)
        @sendheaders = false
        @attr_accessor = 0
        @message = ''
      end

      def post_init
        logger.info "connected. #{addr}"
        begin_handshake
      end

      # handle receiving data from remote node.
      def receive_data(data)
        handle(data)
      end

      def post_handshake
        peer.post_handshake
      end

      def addr
        peer.addr
      end

      # close network connection.
      def close(msg = '')
        logger.info "close connection with #{addr}. #{msg}"
        close_connection_after_writing
        EM.stop
      end

    end

  end

end
