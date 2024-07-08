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

      def control_block(leaf)
        raise NotImplementedError # TODO
      end

      def inclusion_proof(leaf)
        raise NotImplementedError # TODO
      end

      private

      def merkle_root
        build_tree(tree).bth
      end

      def build_tree(tree)
        left, right = tree
        left_hash = if left.is_a?(Array)
                      build_tree(left)
                    else
                      left
                    end
        right_hash = if right.is_a?(Array)
                       build_tree(right)
                     else
                       right
                     end
        combine_hash([left_hash, right_hash])
      end
    end
  end
end