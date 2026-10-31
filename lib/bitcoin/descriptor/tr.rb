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
            item.xonly = true if item.respond_to?(:xonly=)
            items << Bitcoin::Taproot::LeafNode.new(item.to_script)
          else
            raise RuntimeError, "Unsupported item #{item}"
          end
        end
        items
      end

      def validate_tree!(tree)
        return if tree.nil?
        if tree.is_a?(Expression)
          validate_leaf!(tree)
        elsif tree.is_a?(Array)
          tree.each do |item|
            validate_tree!(item)
          end
        else
          raise ArgumentError, "tree must be a expression or array of expression."
        end
      end

      # Check that +leaf+ can be a tapscript leaf. Bitcoin Core allows pk(), multi_a(), sortedmulti_a() and
      # miniscript inside tr(); miniscript is not supported here. Any other expression, such as a wrapper
      # which produces a scriptPubKey, would end up as a tapleaf nobody can spend.
      # @param [Bitcoin::Descriptor::Expression] leaf
      # @raise [ArgumentError]
      def validate_leaf!(leaf)
        message = case leaf.type
                  when :pk, :multi_a, :sortedmulti_a then nil
                  when :multi, :sortedmulti then 'Can only have multi/sortedmulti at top level, in sh(), or in wsh().'
                  when :wpkh then 'Can only have wpkh() at top level or inside sh().'
                  when :sh then 'Can only have sh() at top level.'
                  when :wsh then 'Can only have wsh() at top level or inside sh().'
                  when :addr then 'Can only have addr() at top level.'
                  when :combo then 'Can only have combo() at top level.'
                  when :raw then 'Can only have raw() at top level.'
                  when :tr then 'Can only have tr() at top level.'
                  when :rawtr then 'Can only have rawtr() at top level.'
                  else "#{leaf.type}() is not allowed in a tr() tree."
                  end
        raise ArgumentError, message if message
        keys = leaf.is_a?(KeyExpression) ? [leaf.extracted_key] : leaf.keys.map { |k| leaf.extract_pubkey(k) }
        raise ArgumentError, "Uncompressed key are not allowed." unless keys.all?(&:compressed?)
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