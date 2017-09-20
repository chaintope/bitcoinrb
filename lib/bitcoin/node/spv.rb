module Bitcoin
  module Node

    # SPV class
    class SPV

      attr_reader :pool
      attr_reader :logger
      attr_accessor :running

      def initialize
        @pool = Bitcoin::Network::Pool.new
        @logger = Bitcoin::Logger.create(:debug)
        @running = false
      end

      # open the node.
      def run
        return if running
        pool.start
        logger.debug 'SPV node run.'
      end

      # close the node.
      def close
        pool.close
        logger.debug 'SPV node close.'
      end

      # broadcast a transaction
      def broadcast(tx)
        pool.broadcast(tx)
        logger.debug "broadcast tx: #{tx.to_payload.bth}"
      end

    end

  end
end
