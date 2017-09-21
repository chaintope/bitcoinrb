module Bitcoin

  module Network

    # Basic Bitcoin P2P connection class
    class Connection < EM::Connection

      include MessageHandler

      attr_reader :host, :port, :logger
      attr_accessor :connected

      # if true, this peer send new block announcements using a headers message rather than an inv message.
      attr_accessor :sendheaders

      # minimum fee(in satoshis per kilobyte) for relay tx
      attr_accessor :fee_rate

      def initialize(host, port)
        @host = host
        @port = port
        @logger = Bitcoin::Logger.create(:debug)
        @connected = false
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

    end

  end

end
