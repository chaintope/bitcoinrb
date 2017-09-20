module Bitcoin
  module Node

    class SPVBlockChain

      attr_reader :block_store

      def initialize(block_store = Bitcoin::Store::SPVBlockStore.new)
        @block_store = block_store
      end

    end

  end
end