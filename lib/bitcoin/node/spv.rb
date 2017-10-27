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
      end

      # open the node.
      def run
        # TODO need process running check.
        return if running
        logger.debug 'SPV node start running.'
        EM.run do
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

    end

  end
end
