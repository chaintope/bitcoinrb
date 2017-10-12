module Bitcoin
  module Node

    class SPVBlockChain

      attr_reader :block_store
      attr_reader :logger

      def initialize(block_store = Bitcoin::Store::SPVChain.new)
        @logger = Bitcoin::Logger.create(:debug)
        @block_store = block_store
      end

      # get tha latest block header stored by the block store.
      # @return [Bitcoin::BlockHeader]
      def latest_block_header
        # TODO
        Bitcoin.chain_params.genesis_block.header
      end

      # add block header to block store.
      def add_block_header(header)
        logger.debug "add block header to block store. hash = #{header.hash}"
      end

    end

  end
end