module Bitcoin
  module Taproot
    # A class that takes the script tree configuration as a nested array and constructs the Taproot output.
    # TODO WIP
    class CustomDepthBuilder < SimpleBuilder

      attr_reader :tree

      # Constructor
      # @param [String] internal_key Internal public key with hex format.
      # @param [Array] tree Script tree configuration as a nested array.
      # @return [Bitcoin::Taproot::CustomDepthBuilder]
      def initialize(internal_key, tree)
        super(internal_key, [])
        raise ArgumentError, "tree must be an array." unless tree.is_a?(Array)
        raise ArgumentError, "tree must be binary tree." unless tree.length == 2
        tree.each do |item|
          unless item.is_a?(Array) || item.is_a?(Bitcoin::Taproot::LeafNode)
            raise ArgumentError, "tree must consist of either an array or LeafNode."
          end
          raise ArgumentError, "tree must be binary tree." if item.is_a?(Array) && item.length != 2
        end
        @tree = tree
      end

      def add_leaf(leaf)
        raise NotImplementedError
      end

      def add_branch(leaf1, leaf2 = nil)
        raise NotImplementedError
      end

      private

      def merkle_root
        return '' if tree.empty?
        script_tree = Merkle::CustomTree.new(config: Merkle::Config.taptree, leaves: extract_leaves(tree))
        script_tree.compute_root
      end

      def extract_leaves(leaves)
        leaves.map do |leaf|
          if leaf.is_a?(Bitcoin::Taproot::LeafNode)
            leaf.leaf_hash
          elsif leaf.is_a?(Array)
            extract_leaves(leaf)
          end
        end
      end
    end
  end
end