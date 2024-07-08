module Bitcoin
  module Descriptor
    # tr() expression.
    # @see https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki
    class Tr < Expression

      attr_reader :key
      attr_reader :tree

      # Constructor.
      def initialize(key, tree = nil)
        raise ArgumentError, "Key must be string." unless key.is_a?(String)
        k = extract_pubkey(key)
        raise ArgumentError, "Uncompressed key are not allowed." unless k.compressed?
        @key = key
        @tree = tree
      end

      def type
        :tr
      end

      def top_level?
        true
      end

      def args
        tree.nil? ? key : "#{key},#{tree}"
      end

      def to_script
        builder = build_tree_scripts
        builder.build
      end

      private

      def build_tree_scripts
        internal_key = extract_pubkey(key)
        return Bitcoin::Taproot::SimpleBuilder.new(internal_key.xonly_pubkey) if tree.nil?
        if tree.is_a?(Expression)
          tree.xonly = true
          Bitcoin::Taproot::SimpleBuilder.new(internal_key.xonly_pubkey, [Bitcoin::Taproot::LeafNode.new(tree.to_script)])
        elsif tree.is_a?(Array)
          Bitcoin::Taproot::CustomDepthBuilder.new(internal_key.xonly_pubkey, parse_tree_items(tree))
        end
      end

      def parse_tree_items(arry)
        items = []
        arry.each do |item|
          if item.is_a?(Array)
            items << parse_tree_items(item)
          elsif item.is_a?(Expression)
            item.xonly = true
            items << Bitcoin::Taproot::LeafNode.new(item.to_script)
          else
            raise RuntimeError, "Unsupported item #{item}"
          end
        end
        items
      end

    end
  end
end