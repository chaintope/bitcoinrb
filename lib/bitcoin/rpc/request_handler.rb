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

      # get block header information.
      def getblockheader(hash, verbose)
        entry = node.chain.find_entry_by_hash(hash)
        if verbose
          {
              hash: hash,
              height: entry.height,
              version: entry.header.version,
              versionHex: entry.header.version.to_s(16),
              merkleroot: entry.header.merkle_root,
              time: entry.header.time,
              mediantime: node.chain.mtp(hash),
              nonce: entry.header.nonce,
              bits: entry.header.bits.to_s(16),
              previousblockhash: entry.prev_hash,
              nextblockhash: node.chain.next_hash(hash)
          }
        else
          entry.header.to_payload.bth
        end
      end

    end

  end
end
