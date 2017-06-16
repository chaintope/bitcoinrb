module Bitcoin

  # Basic Bitcoin P2P connection class
  class Connection < EM::Connection

    attr_reader :host, :port, :handler, :logger

    def initialize(host, port)
      @host = host
      @port = port
      @logger = Bitcoin::Logger.create(:connection)
      @handler = Message::Handler.new(@logger)
    end

    def post_init
      logger.info "connected. #{remote_node}"
    end

    # handle receiving data from remote node.
    def receive_data(data)
      logger.info "receive data from #{remote_node}, dadta : #{data}"
      handler.handle(data)
    end

    private

    def remote_node
      "#{host}:#{port}"
    end

    # start handshake
    def begin_handshake
      logger.info "begin handshake with #{remote_node}"
    end

  end

end
