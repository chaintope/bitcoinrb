module Bitcoin

  module Network

    # Time between pings automatically sent out for latency probing and keepalive (in seconds).
    PING_INTERVAL = 2 * 60
    # Time after which to disconnect, after waiting for a ping response (or inactivity).
    TIMEOUT_INTERVAL = 20 * 60
    # Maximum number of automatic outgoing nodes
    MAX_OUTBOUND_CONNECTIONS = 4

    # peer pool class.
    class Pool

      attr_reader :peers # active peers
      attr_reader :pending_peers # currently connecting peer
      attr_reader :chain
      attr_reader :max_outbound
      attr_reader :logger
      attr_reader :peer_discovery
      attr_accessor :started

      def initialize
        @peers = []
        @pending_peers = []
        @max_outbound = MAX_OUTBOUND_CONNECTIONS
        @chain = Bitcoin::Node::SPVBlockChain.new
        @logger = Bitcoin::Logger.create(:debug)
        @peer_discovery = PeerDiscovery.new
        @started = false
      end

      # connecting other peers and begin network activity.
      def start
        raise 'Cannot start a peer pool twice.' if started
        logger.debug 'Start connecting other pears.'
        addr_list = peer_discovery.peers
        port = Bitcoin.chain_params.default_port
        Parallel.map(addr_list, in_processes: Bitcoin::PARALLEL_THREAD) do |ip|
          if peers.size < MAX_OUTBOUND_CONNECTIONS
            EM.run do
              peer = Peer.new(ip, port, self)
              pending_peers << peer
              peer.connect
            end
          end
        end
        @started = true
      end

      # detect new peer connection.
      def handle_new_peer(peer)
        logger.debug "connected new peer #{peer.addr}."
        unless peers.find(&:primary?)
          peer.primary = true
          peer.start_block_header_download
        end
        peers << peer
        pending_peers.delete(peer)
      end

      # terminate peers.
      def terminate
        peers.each {|peer| peer.close('terminate')}
        @peers = []
        @started = false
      end

      # broadcast tx to connecting peer.
      def broadcast(tx)
        peers.each {|peer| peer.broadcast(tx) }
      end

      private

      # get primary peer
      def primary_peer
        peers.find(&:primary?)
      end

    end

  end
end