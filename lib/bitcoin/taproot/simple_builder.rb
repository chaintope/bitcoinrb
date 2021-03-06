module Bitcoin
  module Taproot

    # Utility class to construct Taproot outputs from internal key and script tree.
    # SimpleBuilder builds a script tree that places all lock scripts, in the order they are added, as leaf nodes.
    # It is not possible to specify the depth of the locking script or to insert any intermediate nodes.
    class SimpleBuilder
      include Bitcoin::Opcodes

      attr_reader :internal_key # String with hex format
      attr_reader :leaves # Array[LeafNode]

      # Initialize builder.
      # @param [String] internal_key Internal public key with hex format.
      # @param [Array[Bitcoin::Script]] scripts Scripts for each lock condition.
      # @param [Integer] leaf_ver (Optional) The leaf version of tapscript.
      # @raise [Bitcoin::Taproot::Builder] +internal_pubkey+ dose not xonly public key or script in +scripts+ does not instance of Bitcoin::Script.
      # @return [Bitcoin::Taproot::SimpleBuilder]
      def initialize(internal_key, *scripts, leaf_ver: Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        raise Error, 'Internal public key must be 32 bytes' unless internal_key.htb.bytesize == 32
        @leaves = scripts.map { |script| LeafNode.new(script, leaf_ver) }
        @internal_key = internal_key
      end

      # Add lock script to leaf node.
      # @param [Bitcoin::Script] script lock script.
      # @param [Integer] leaf_ver (Optional) The leaf version of tapscript.
      # @raise [Bitcoin::Taproot::Builder] If +script+ does not instance of Bitcoin::Script.
      # @return [Bitcoin::Taproot::SimpleBuilder] self
      def <<(script, leaf_ver: Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        leaves << LeafNode.new(script, leaf_ver)
        self
      end

      # Build P2TR script.
      # @return [Bitcoin::Script] P2TR script.
      def build
        q = tweak_public_key
        Bitcoin::Script.new << OP_1 << q.xonly_pubkey
      end

      # Compute the tweaked public key.
      # @return [Bitcoin::Key] the tweaked public key
      def tweak_public_key
        key = Bitcoin::Key.new(priv_key: tweak.bth, key_type: Key::TYPES[:compressed])
        Bitcoin::Key.from_point(key.to_point + Bitcoin::Key.from_xonly_pubkey(internal_key).to_point)
      end

      # Compute the secret key for a tweaked public key.
      # @param [Bitcoin::Key] key key object contains private key.
      # @return [Bitcoin::Key] secret key for a tweaked public key
      def tweak_private_key(key)
        raise Error, 'Requires private key' unless key.priv_key
        p = key.to_point
        private_key = p.has_even_y? ? key.priv_key.to_i(16) : ECDSA::Group::Secp256k1.order - key.priv_key.to_i(16)
        Bitcoin::Key.new(priv_key: ((tweak.bti + private_key) % ECDSA::Group::Secp256k1.order).to_even_length_hex)
      end

      # Generate control block needed to unlock with script-path.
      # @param [Bitcoin::Script] script Script to use for unlocking.
      # @param [Integer] leaf_ver leaf version of script.
      # @return [String] control block with binary format.
      def control_block(script, leaf_ver: Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        path = inclusion_proof(script, leaf_ver: leaf_ver)
        parity = tweak_public_key.to_point.has_even_y? ? 0 : 1
        [parity + leaf_ver].pack("C") + internal_key.htb + path.join
      end

      # Generate inclusion proof for +script+.
      # @param [Bitcoin::Script] script The script in script tree.
      # @param [Integer] leaf_ver (Optional) The leaf version of tapscript.
      # @return [Array[String]] Inclusion proof.
      def inclusion_proof(script, leaf_ver: Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        parents = leaves
        parent_hash = leaf_hash(script, leaf_ver: leaf_ver)
        proofs = []
        until parents.size == 1
          parents = parents.each_slice(2).map do |pair|
            combined = combine_hash(pair)
            unless pair.size == 1
              if hash_value(pair[0]) == parent_hash
                proofs << hash_value(pair[1])
                parent_hash = combined
              elsif hash_value(pair[1]) == parent_hash
                proofs << hash_value(pair[0])
                parent_hash = combined
              end
            end
            combined
          end
        end
        proofs
      end

      # Computes leaf hash
      # @param [Bitcoin::Script] script
      # @param [Integer] leaf_ver leaf version
      # @@return [String] leaf hash with binary format.
      def leaf_hash(script, leaf_ver: Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        raise Error, 'script does not exist' unless leaves.find{ |leaf| leaf.script == script}
        LeafNode.new(script, leaf_ver).leaf_hash
      end

      private

      # Compute tweak from script tree.
      # @return [String] tweak with binary format.
      def tweak
        parents = leaves
        if parents.empty?
          parents = ['']
        else
          parents = parents.each_slice(2).map { |pair| combine_hash(pair) } until parents.size == 1
        end
        t = Bitcoin.tagged_hash('TapTweak', internal_key.htb + parents.first)
        raise Error, 'tweak value exceeds the curve order' if t.bti >= ECDSA::Group::Secp256k1.order
        t
      end

      def combine_hash(pair)
        if pair.size == 1
          hash_value(pair[0])
        else
          hash1 = hash_value(pair[0])
          hash2 = hash_value(pair[1])

          # Lexicographically sort a and b's hash, and compute parent hash.
          payload = hash1.bth < hash2.bth ? hash1 + hash2 : hash2 + hash1
          Bitcoin.tagged_hash('TapBranch', payload)
        end
      end

      def hash_value(leaf_or_branch)
        leaf_or_branch.is_a?(LeafNode) ? leaf_or_branch.leaf_hash : leaf_or_branch
      end
    end
  end

end
