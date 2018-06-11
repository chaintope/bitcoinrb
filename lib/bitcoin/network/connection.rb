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
        @logger = peer.logger
        @sendheaders = false
        @attr_accessor = 0
        @message = ''
        self.pending_connect_timeout = 5.0
      end

      def post_init
        logger.info "connected. #{addr}"
        peer.conn_time = Time.now.to_i
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
      end

      def handle_error(e)
        peer.handle_error(e)
      end

      def unbind
        logger.info "unbind. #{addr}"
        peer.unbind
      end

      private

      # start handshake
      def begin_handshake
        logger.info "begin handshake with #{addr}"
        send_message(peer.local_version)
      end
    end
  end
end
