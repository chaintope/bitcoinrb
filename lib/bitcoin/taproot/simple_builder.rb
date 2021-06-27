module Bitcoin
  module Taproot

    # Utility class to construct Taproot outputs from internal key and script tree.
    # SimpleBuilder builds a script tree that places all lock scripts, in the order they are added, as leaf nodes.
    # It is not possible to specify the depth of the locking script or to insert any intermediate nodes.
    class SimpleBuilder
      include Bitcoin::Opcodes

      attr_reader :internal_key, :leaves

      # Initialize builder.
      # @param [String] internal_key Internal public key with hex format.
      # @param [Array[Bitcoin::Script]] scripts Scripts for each lock condition.
      # @param [Integer] leaf_ver The leaf version of tapscript.
      # @raise [Bitcoin::Taproot::Builder] +internal_pubkey+ dose not xonly public key or script in +scripts+ does not instance of Bitcoin::Script.
      # @return [Bitcoin::Taproot::SimpleBuilder]
      def initialize(internal_key, *scripts, leaf_ver: Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        raise Error, 'Internal public key must be 32 bytes' unless internal_key.htb.bytesize == 32
        @leaves = scripts.map { |script| LeafNode.new(script, leaf_ver) }
        @internal_key = internal_key
      end

      # Add lock script to leaf node.
      # @param [Bitcoin::Script] script lock script.
      # @param [Integer] leaf_ver The leaf version of tapscript.
      # @raise [Bitcoin::Taproot::Builder] If +script+ does not instance of Bitcoin::Script.
      # @return [Bitcoin::Taproot::SimpleBuilder] self
      def <<(script, leaf_ver: Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        leaves << LeafNode.new(script, leaf_ver)
        self
      end

      # Build P2TR script.
      # @return [Bitcoin::Script] P2TR script.
      def build
        parents = leaves
        loop do
          parents = parents.each_slice(2).map { |pair| combine_hash(pair) }
          break if parents.size == 1
        end
        p = Bitcoin::Key.new(pubkey: "02#{internal_key}", key_type: Key::TYPES[:compressed])
        t = Bitcoin.tagged_hash('TapTweak', internal_key.htb + parents.first)
        key = Bitcoin::Key.new(priv_key: t.bth, key_type: Key::TYPES[:compressed])
        q = key.to_point + p.to_point
        Bitcoin::Script.new << OP_1 << ECDSA::Format::FieldElementOctetString.encode(q.x, q.group.field)
      end

      private

      def combine_hash(pair)
        if pair.size == 1
          pair[0].is_a?(LeafNode) ? pair[0].leaf_hash : pair[0]
        else
          hash1 = pair[0].is_a?(LeafNode) ? pair[0].leaf_hash : pair[0]
          hash2 = pair[1].is_a?(LeafNode) ? pair[1].leaf_hash : pair[1]

          # Lexicographically sort a and b's hash, and compute parent hash.
          payload = hash1.bth < hash2.bth ? hash1 + hash2 : hash2 + hash1
          Bitcoin.tagged_hash('TapBranch', payload)
        end
      end

    end
  end

end
