module Bitcoin
  module Node

    # SPV class
    class SPV

      attr_reader :pool
      attr_reader :logger
      attr_accessor :running

      def initialize
        @pool = Bitcoin::Network::Pool.new(Bitcoin::Store::SPVChain.new)
        @logger = Bitcoin::Logger.create(:debug)
        @running = false
      end

      # open the node.
      def run
        return if running
        logger.debug 'SPV node start running.'
        pool.start
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
