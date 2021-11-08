module Bitcoin
  module Taproot
    class LeafNode

      attr_reader :script, :leaf_ver

      # Initialize
      # @param [Bitcoin::Script] script Locking script
      # @param [Integer] leaf_ver The leaf version of this script.
      def initialize(script, leaf_ver = Bitcoin::TAPROOT_LEAF_TAPSCRIPT)
        raise Taproot::Error, 'script must be Bitcoin::Script object' unless script.is_a?(Bitcoin::Script)
        @script = script
        @leaf_ver = leaf_ver
      end

      # Calculate leaf hash.
      # @return [String] leaf hash.
      def leaf_hash
        @hash_value ||= Bitcoin.tagged_hash('TapLeaf', [leaf_ver].pack('C') + Bitcoin.pack_var_string(script.to_payload))
      end
    end
  end
end
