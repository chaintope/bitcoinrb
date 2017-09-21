module Bitcoin
  module Network

    # remote peer class.
    class Peer

      # remote peer info
      attr_reader :host
      attr_reader :port
      # remote peer connection
      attr_accessor :conn
      attr_accessor :connected
      # parent pool
      attr_reader :pool
      attr_accessor :fee_rate

      def initialize(host, port, pool)
        @host = host
        @port = port
        @pool = pool
        @connected = false
      end

      def connect
        self.conn ||= EM.connect(host, port, Bitcoin::Network::Connection, self)
      end

      def connected?
        @connected
      end

      def addr
        "#{host}:#{port}"
      end

      def post_handshake
        @connected = true
        pool.handle_new_peer(self)
      end

      # broadcast tx.
      def broadcast_tx(tx)
        send_message(Bitcoin::Message::Tx.new(tx, ))
      end

      # check the remote peer support segwit.
      def support_segwit?
        return false unless conn.version
        conn.version.services & Bitcoin::Message::SERVICE_FLAGS[:witness] > 0
      end

    end

  end
end
