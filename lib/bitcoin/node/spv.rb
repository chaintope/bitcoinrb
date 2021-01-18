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
      attr_accessor :wallet
      attr_accessor :bloom

      # Initialize spv settings
      # @param [Bitcoin::Node::Configuration] configuration configuration for spv.
      #
      # ```ruby
      # config = Bitcoin::Node::Configuration.new(network: :mainnet)
      # spv = Bitcoin::Node::SPV.new(config)
      # spv.run
      # ````
      def initialize(configuration)
        @chain = Bitcoin::Store::SPVChain.new
        @configuration = configuration
        @pool = Bitcoin::Network::Pool.new(self, @chain, @configuration)
        @logger = Bitcoin::Logger.create(:debug)
        @running = false
        @wallet = Bitcoin::Wallet::Base.current_wallet
        # TODO : optimize bloom filter parameters
        setup_filter
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
        logger.debug "broadcast tx: #{tx.to_hex}"
      end

      # add filter element to bloom filter.
      # [String] element. the hex string of txid, public key, public key hash or outpoint.
      def filter_add(element)
        bloom.add(element)
        pool.filter_add(element)
      end

      # clear bloom filter.
      def filter_clear
        pool.filter_clear
      end

      def add_observer(observer)
        pool.add_observer(observer)
      end

      def delete_observer(observer)
        pool.delete_observer(observer)
      end

      private

      def setup_filter
        @bloom = Bitcoin::BloomFilter.create_filter(512, 0.01)
        wallet.watch_targets.each{|t|bloom.add(t.htb)} if wallet
      end
    end
  end
end
