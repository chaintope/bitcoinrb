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
      @logger = Bitcoin::Logger.create(:debug)
      @connected = false
      @sendheaders = false
      @attr_accessor = 0
    end

    def post_init
      logger.info "connected. #{addr}"
      begin_handshake
    end

    # handle receiving data from remote node.
    def receive_data(data)
      handle(data)
    end

    # handle p2p message.
    def handle(message)
      logger.info "handle message #{message.bth}"
      begin
        parse(message)
      rescue Error => e
        logger.error("invalid header magic. #{e.message}")
        conn.close
      end
    end

    def parse(message)
      @message += message
      command, payload, rest = parse_header
      return unless command

      handle_command(command, payload)
      @message = ""
      parse(rest) if rest && rest.bytesize > 0
    end

    def parse_header
      head_magic = Bitcoin.chain_params.magic_head
      return if @message.nil? || @message.size < HEADER_SIZE

      magic, command, length, checksum = @message.unpack('a4A12Va4')
      raise Error, "invalid header magic. #{magic.bth}" unless magic.bth == head_magic

      payload = @message[HEADER_SIZE...(HEADER_SIZE + length)]
      return if payload.size < length
      raise Error, "header checksum mismatch. #{checksum.bth}" unless Bitcoin.double_sha256(payload)[0...4] == checksum

      rest = @message[(HEADER_SIZE + length)..-1]
      [command, payload, rest]
    end

    def handle_command(command, payload)
      logger.info("process command #{command}. payload = #{payload.bth}")
      case command
        when Version::COMMAND
          on_version(Version.parse_from_payload(payload))
        when VerAck::COMMAND
          on_ver_ack
        when GetAddr::COMMAND
          on_get_addr
        when Addr::COMMAND
          on_addr(Addr.parse_from_payload(payload))
        when SendHeaders::COMMAND
          on_send_headers
        when FeeFilter::COMMAND
          on_fee_filter(FeeFilter.parse_from_payload(payload))
        when Ping::COMMAND
          on_ping(Ping.parse_from_payload(payload))
        when Pong::COMMAND
          on_pong(Pong.parse_from_payload(payload))
        when GetHeaders::COMMAND
          on_get_headers(GetHeaders.parse_from_payload(payload))
        when Headers::COMMAND
          on_headers(Headers.parse_from_payload(payload))
        when Block::COMMAND
          on_block(Block.parse_from_payload(payload))
        when Tx::COMMAND
          on_tx(Tx.parse_from_payload(payload))
        when NotFound::COMMAND
          on_not_found(NotFound.parse_from_payload(payload))
        when MemPool::COMMAND
          on_mem_pool
        when Reject::COMMAND
          on_reject(Reject.parse_from_payload(payload))
        when SendCmpct::COMMAND
          on_send_cmpct(SendCmpct.parse_from_payload(payload))
        when Inv::COMMAND
          on_inv(Inv.parse_from_payload(payload))
        else
          logger.warn("unsupported command received. #{command}")
          conn.close("with command #{command}")
      end
    end

    # close network connection.
    def close(msg = '')
      logger.info "close connection with #{addr}. #{msg}"
      close_connection_after_writing
      EM.stop
    end

    def send_message(msg)
      logger.info "send message #{msg.class::COMMAND}"
      send_data(msg.to_pkt)
    end

    # start handshake
    def begin_handshake
      logger.info "begin handshake with #{addr}"
      ver = Bitcoin::Message::Version.new(remote_addr: addr, start_height: 0) # TODO use start_height in wallet
      send_message(ver)
    end

    def handshake_done
      logger.info 'handshake finished.'
      @connected = true
    end

    def addr
      "#{host}:#{port}"
    end
    
  end

end
