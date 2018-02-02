module Bitcoin
  module Node

    # SPV class
    class SPV

      attr_reader :chain
      attr_reader :pool
      attr_reader :logger
      attr_accessor :running
      attr_reader :configuration
      attr_accessor :server

      def initialize(configuration)
        @chain = Bitcoin::Store::SPVChain.new
        @configuration = configuration
        @pool = Bitcoin::Network::Pool.new(@chain, @configuration)
        @logger = Bitcoin::Logger.create(:debug)
        @running = false

        # TODO : optimize bloom filter parameters
        # TODO : load public keys in wallet.
        @bloom = Bitcoin::BloomFilter.new(512, 0.01)
      end

      # open the node.
      def run
        # TODO need process running check.
        return if running
        logger.debug 'SPV node start running.'
        EM.run do
          # EM.start_server('0.0.0.0', Bitcoin.chain_params.default_port, Bitcoin::Network::InboundConnector, self)
          pool.start
          @server = Bitcoin::RPC::HttpServer.run(self, configuration.port)
        end
      end

      # close the node.
      def shutdown
        pool.terminate
        logger.debug 'SPV node shutdown.'
      end

      # broadcast a transaction
      def broadcast(tx)
        pool.broadcast(tx)
        logger.debug "broadcast tx: #{tx.to_payload.bth}"
      end

      # new bloom filter.
      def filter_load
        pool.filter_load(@bloom)
      end

      # add filter element to bloom filter.
      # [String] element. the hex string of txid, public key, public key hash or outpoint.
      def filter_add(element)
        @bloom.add(element)
        pool.filter_add(element)
      end

      # clear bloom filter.
      def filter_clear
        pool.filter_clear
      end
    end
  end
end
