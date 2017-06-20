module Bitcoin

  # Basic Bitcoin P2P connection class
  class Connection < EM::Connection

    attr_reader :host, :port, :handler, :logger
    attr_accessor :connected

    # if true, this peer send new block announcements using a headers message rather than an inv message.
    attr_accessor :sendheaders

    # minimum fee(in satoshis per kilobyte) for relay tx
    attr_accessor :fee_rate

    def initialize(host, port)
      @host = host
      @port = port
      @logger = Bitcoin::Logger.create(:connection)
      @handler = Message::Handler.new(self, @logger)
      @connected = false
      @sendheaders = false
      @attr_accessor = 0
    end

    def post_init
      logger.info "connected. #{remote_node}"
      begin_handshake
    end

    # handle receiving data from remote node.
    def receive_data(data)
      logger.info "receive data from #{remote_node}, data : #{data}"
      handler.handle(data)
    end

    # close network connection.
    def close
      logger.info "close connection with #{remote_node}."
      close_connection_after_writing
      EM.stop
    end

    def handshake_done
      logger.info 'handshake finished.'
      @connected = true
    end

    private

    def remote_node
      "#{host}:#{port}"
    end

    # start handshake
    def begin_handshake
      logger.info "begin handshake with #{remote_node}"
      ver = Bitcoin::Message::Version.new(remote_addr: remote_node)
      send_data(ver.to_pkt)
    end

  end

end
