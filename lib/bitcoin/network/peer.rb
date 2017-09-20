module Bitcoin
  module Network

    # remote peer class.
    class Peer < Bitcoin::Network::Connection

      attr_reader :pool
      attr_accessor :fee_rate

      def initialize(host, port, pool)
        super(host, port)
        @pool = pool
      end

      def post_handshake
        pool.handle_new_peer(self)
      end
    end

  end
end
