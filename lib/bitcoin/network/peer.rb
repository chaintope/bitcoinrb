module Bitcoin
  module Network

    # remote peer class.
    class Peer

      # Interval for pinging peers.
      PING_INTERVAL = 30

      attr_reader :logger
      attr_accessor :id
      attr_accessor :local_version
      attr_accessor :last_send
      attr_accessor :last_recv
      attr_accessor :bytes_sent
      attr_accessor :bytes_recv
      attr_accessor :conn_time
      attr_accessor :last_ping
      attr_accessor :last_ping_nonce
      attr_accessor :last_pong
      attr_accessor :min_ping
      attr_accessor :outbound # TODO need implements to accept inbound connection
      attr_accessor :best_hash
      attr_accessor :best_height
      # remote peer info
      attr_reader :host
      attr_reader :port
      # remote peer connection
      attr_accessor :conn
      attr_accessor :connected
      attr_accessor :primary
      # parent pool
      attr_reader :pool
      attr_reader :chain
      attr_accessor :fee_rate

      def initialize(host, port, pool)
        @host = host
        @port = port
        @pool = pool
        @chain = pool.chain
        @connected = false
        @primary = false
        @logger = Bitcoin::Logger.create(:debug)
        @outbound = true
        @best_hash = -1
        @best_height = -1
        @min_ping = -1
        @bytes_sent = 0
        @bytes_recv = 0
        current_height = @chain.latest_block.height
        @local_version = Bitcoin::Message::Version.new(remote_addr: addr, start_height: current_height)
      end

      def connect
        self.conn ||= EM.connect(host, port, Bitcoin::Network::Connection, self)
      end

      def connected?
        @connected
      end

      def outbound?
        @outbound
      end

      def addr
        "#{host}:#{port}"
      end

      # calculate ping-pong time.
      def ping_time
        last_pong ? (last_pong - last_ping) / 1e6 : -1
      end

      # set last pong
      def last_pong=(time)
        @last_pong = time
        @min_ping = ping_time if min_ping == -1 || ping_time < min_ping
      end

      def post_handshake
        @connected = true
        pool.handle_new_peer(self)
        # require remote peer to use headers message instead fo inv message.
        conn.send_message(Bitcoin::Message::SendHeaders.new)
        EM.add_periodic_timer(PING_INTERVAL) {send_ping}
      end

      # start block header download
      def start_block_header_download
        logger.debug "[#{addr}] start block header download."
        get_headers = Bitcoin::Message::GetHeaders.new(
            Bitcoin.chain_params.protocol_version, [chain.latest_block.hash])
        conn.send_message(get_headers)
      end

      # broadcast tx.
      def broadcast_tx(tx)
        conn.send_message(Bitcoin::Message::Tx.new(tx, support_witness?))
      end

      # check the remote peer support witness.
      def support_witness?
        return false unless remote_version
        remote_version.services & Bitcoin::Message::SERVICE_FLAGS[:witness] > 0
      end

      # check the remote peer supports compact block.
      def support_cmpct?
        return false if remote_version.version < Bitcoin::Message::VERSION[:compact]
        return true unless local_version.services & Bitcoin::Message::SERVICE_FLAGS[:witness] > 0
        return false unless support_witness?
        remote_version.version >= Bitcoin::Message::VERSION[:compact_witness]
      end

      # get peer's block type.
      def block_type
        Bitcoin::Message::Inventory::MSG_FILTERED_BLOCK # TODO need other implementation
      end

      # get remote peer's version message.
      # @return [Bitcoin::Message::Version]
      def remote_version
        conn.version
      end

      # Whether to try and download blocks and transactions from this peer.
      def primary?
        primary
      end

      # handle headers message
      # @params [Bitcoin::Message::Headers]
      def handle_headers(headers)
        headers.headers.each do |header|
          break unless header.valid?
          entry = chain.append_header(header)
          @best_hash = entry.hash
          @best_height = entry.height
        end
        start_block_header_download if headers.headers.size > 0 # next header download
      end

      # handle error
      def handle_error(e)
        pool.handle_error(e)
      end

      # close peer connection.
      def close(msg = '')
        conn.close(msg)
      end

      # generate Bitcoin::Message::NetworkAddr object from this peer info.
      # @return [Bitcoin::Message::NetworkAddr]
      def to_network_addr
        v = remote_version
        addr = Bitcoin::Message::NetworkAddr.new
        addr.time = v.timestamp
        addr.services = v.services
        addr.ip = host
        addr.port = port
        addr
      end

      # send +addr+ message to remote peer
      def send_addrs
        addrs = pool.peers.select{|p|p != self}.map(&:to_network_addr)
        conn.send_message(Bitcoin::Message::Addr.new(addrs))
      end

      # handle block inv message.
      def handle_block_inv(hashes)
        getdata = Bitcoin::Message::GetData.new(
            hashes.map{|h|Bitcoin::Message::Inventory.new(block_type, h)})
        conn.send_message(getdata)
      end

      # send ping message.
      def send_ping
        ping = Bitcoin::Message::Ping.new
        @last_ping = Time.now.to_i
        @last_pong = -1
        @last_ping_nonce = ping.nonce
        conn.send_message(ping)
      end

    end

  end
end
