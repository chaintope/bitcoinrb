module Bitcoin
  module Taproot

    # Utility class to construct Taproot outputs from internal key and script tree.keyPathSpending
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
        raise ArgumentError, "Internal public key must be string." unless internal_key.is_a?(String)
        raise Error, "Internal public key must be #{X_ONLY_PUBKEY_SIZE} bytes" unless internal_key.htb.bytesize == X_ONLY_PUBKEY_SIZE
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
        Taproot.tweak_public_key(Bitcoin::Key.from_xonly_pubkey(internal_key), merkle_root)
      end

      # Compute the secret key for a tweaked public key.
      # @param [Bitcoin::Key] key key object contains private key.
      # @return [Bitcoin::Key] secret key for a tweaked public key
      def tweak_private_key(key)
        raise Error, 'Requires private key' unless key.priv_key

        Taproot.tweak_private_key(key, merkle_root)
      end

      # Generate control block needed to unlock with script-path.
      # @param [Bitcoin::Taproot::LeafNode] leaf Leaf to use for unlocking.
      # @return [Bitcoin::Taproot::ControlBlock] control block.
      def control_block(leaf)
        path = inclusion_proof(leaf).siblings
        parity = tweak_public_key.to_point.has_even_y? ? 0 : 1
        ControlBlock.new(parity, leaf.leaf_ver, internal_key, path)
      end

      # Generate inclusion proof for +leaf+.
      # @param [Bitcoin::Taproot::LeafNode] leaf The leaf node in script tree.
      # @return [Merkle::Proof] Inclusion proof.
      # @raise [Bitcoin::Taproot::Error] If the specified +leaf+ does not exist
      def inclusion_proof(leaf)
        tree = script_tree
        leaf_index = 0
        branches.each.with_index do |branch, i|
          if branch.include?(leaf)
            leaf_index += (branch[0] == leaf ? 0 : 1)
            break
          else
            leaf_index += branch.length
          end
        end
        tree.generate_proof(leaf_index)
      end

      private

      def script_tree
        leaves = []
        branches.each do |pair|
          if leaves.empty? || leaves.length == 1
            leaves << pair.map(&:leaf_hash)
          elsif leaves.length == 2
            leaves = [leaves, pair.map(&:leaf_hash)]
          end
        end
        Merkle::CustomTree.new(config: Merkle::Config.taptree, leaves: leaves)
      end

      def merkle_root
        return '' if branches.empty?
        script_tree.compute_root
      end
    end
  end

end
