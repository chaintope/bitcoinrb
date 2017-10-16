module Bitcoin
  module RPC

    # RPC server's request handler.
    module RequestHandler

      # Returns an object containing various state info regarding blockchain processing.
      def getblockchaininfo
        h = {}
        h[:chain] = Bitcoin.chain_params.network
        best_block = node.chain.latest_block
        h[:headers] = best_block.height
        h[:bestblockhash] = best_block.hash
        h[:chainwork] = best_block.header.work
        h[:mediantime] = node.chain.mtp(best_block.hash)
        h
      end

      # shutdown node
      def stop
        node.shutdown
      end

    end

  end
end
