module Bitcoin
  module Descriptor
    # tr() expression.
    # @see https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki
    class Tr < KeyExpression

      attr_reader :key
      attr_reader :tree

      # Constructor.
      def initialize(key, tree = nil)
        super(key)
        validate_tree!(tree)
        raise ArgumentError, "Uncompressed key are not allowed." unless extracted_key.compressed?
        @tree = tree
      end

      def type
        :tr
      end

      def top_level?
        true
      end

      def args
        if tree.nil?
          key
        else
          tree.is_a?(Array) ? "#{key},#{tree_string(tree)}" : "#{key},#{tree}"
        end
      end

      def to_script
        builder = build_tree_scripts
        builder.build
      end

      private

      def build_tree_scripts
        internal_key = extracted_key
        return Bitcoin::Taproot::SimpleBuilder.new(internal_key.xonly_pubkey) if tree.nil?
        if tree.is_a?(Expression)
          tree.xonly = true if tree.respond_to?(:xonly)
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

      def validate_tree!(tree)
        return if tree.nil? || tree.is_a?(Expression)
        if tree.is_a?(Array)
          tree.each do |item|
            validate_tree!(item)
          end
        else
          raise ArgumentError, "tree must be a expression or array of expression."
        end
      end

      def tree_string(tree)
        buffer = '{'
        left, right = tree
        buffer << (left.is_a?(Array) ? tree_string(left) : left.to_s)
        buffer << ","
        buffer << (right.is_a?(Array) ? tree_string(right) : right.to_s)
        buffer << '}'
        buffer
      end
    end
  end
end