module Bitcoin
  module Taproot

    # Utility class to construct Taproot outputs from internal key and script tree.
    # SimpleBuilder builds a script tree that places all lock scripts, in the order they are added, as leaf nodes.
    # It is not possible to specify the depth of the locking script or to insert any intermediate nodes.
    class SimpleBuilder
      include Bitcoin::Opcodes

      attr_reader :internal_key # String with hex format
      attr_reader :branches # List of branch that has two child leaves

      # Initialize builder.
      # @param [String] internal_key Internal public key with hex format.
      # @param [Array[Bitcoin::Taproot::LeafNode]] leaves (Optional) Array of leaf nodes for each lock condition.
      # @raise [Bitcoin::Taproot::Builder] +internal_pubkey+ dose not xonly public key or leaf in +leaves+ does not instance of Bitcoin::Taproot::LeafNode.
      # @return [Bitcoin::Taproot::SimpleBuilder]
      def initialize(internal_key, leaves = [])
        raise Error, 'Internal public key must be 32 bytes' unless internal_key.htb.bytesize == 32
        raise Error, 'leaf must be Bitcoin::Taproot::LeafNode object' if leaves.find{ |leaf| !leaf.is_a?(Bitcoin::Taproot::LeafNode)}

        @leaves = leaves
        @branches = leaves.each_slice(2).map.to_a
        @internal_key = internal_key
      end

      # Add a leaf node to the end of the current branch.
      # @param [Bitcoin::Taproot::LeafNode] leaf Leaf node to be added.
      def add_leaf(leaf)
        raise Error, 'leaf must be Bitcoin::Taproot::LeafNode object' unless leaf.is_a?(Bitcoin::Taproot::LeafNode)

        if branches.last&.size == 1
          branches.last << leaf
        else
          branches << [leaf]
        end
        self
      end

      # Add a pair of leaf nodes as a branch. If there is only one, add a branch with only one child.
      # @param [Bitcoin::Taproot::LeafNode] leaf1 Leaf node to be added.
      # @param [Bitcoin::Taproot::LeafNode] leaf2 Leaf node to be added.
      def add_branch(leaf1, leaf2 = nil)
        raise Error, 'leaf1 must be Bitcoin::Taproot::LeafNode object' unless leaf1.is_a?(Bitcoin::Taproot::LeafNode)
        raise Error, 'leaf2 must be Bitcoin::Taproot::LeafNode object' if leaf2 && !leaf2.is_a?(Bitcoin::Taproot::LeafNode)

        branches << (leaf2.nil? ? [leaf1] : [leaf1, leaf2])
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
      # @param [Bitcoin::Taproot::LeafNode] leaf Leaf to use for unlocking.
      # @return [String] control block with binary format.
      def control_block(leaf)
        path = inclusion_proof(leaf)
        parity = tweak_public_key.to_point.has_even_y? ? 0 : 1
        [parity + leaf.leaf_ver].pack("C") + internal_key.htb + path.join
      end

      # Generate inclusion proof for +leaf+.
      # @param [Bitcoin::Taproot::LeafNode] leaf The leaf node in script tree.
      # @return [Array[String]] Inclusion proof.
      # @raise [Bitcoin::Taproot::Error] If the specified +leaf+ does not exist
      def inclusion_proof(leaf)
        proofs = []
        target_branch = branches.find{|b| b.include?(leaf)}
        raise Error 'Specified leaf does not exist' unless target_branch

        # flatten each branch
        proofs << hash_value(target_branch.find{|b| b != leaf}) if target_branch.size == 2
        parent_hash = combine_hash(target_branch)
        parents = branches.map {|pair| combine_hash(pair)}

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

      private

      # Compute tweak from script tree.
      # @return [String] tweak with binary format.
      def tweak
        parents = branches.map {|pair| combine_hash(pair)}
        if parents.empty?
          parents = ['']
        elsif parents.size == 1
          parents = [combine_hash(parents)]
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
