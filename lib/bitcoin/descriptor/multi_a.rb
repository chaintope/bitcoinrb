module Bitcoin
  module Descriptor
    # multi_a() expression
    # @see https://github.com/bitcoin/bips/blob/master/bip-0387.mediawiki
    class MultiA < Multi
      include Bitcoin::Opcodes

      def type
        :multi_a
      end

      def to_hex
        raise RuntimeError, "Can only have multi_a/sortedmulti_a inside tr()."
      end

      def to_script
        multisig_script(keys.map{|k| extract_pubkey(k).xonly_pubkey})
      end

      private

      def multisig_script(keys)
        script = Bitcoin::Script.new
        keys.each.with_index do |k, i|
          script << k
          script << (i == 0 ? OP_CHECKSIG : OP_CHECKSIGADD)
        end
        script << threshold << OP_NUMEQUAL
      end

      def validate!(threshold, keys)
        raise ArgumentError, "Multisig threshold '#{threshold}' is not valid." unless threshold.is_a?(Integer)
        raise ArgumentError, 'Multisig threshold cannot be 0, must be at least 1.' unless threshold > 0
        raise ArgumentError, 'Multisig threshold cannot be larger than the number of keys.' if threshold > keys.size
        raise ArgumentError, "Multisig must have between 1 and 999 keys, inclusive." if keys.size > 999
        keys.each do |key|
          k = extract_pubkey(key)
          raise ArgumentError, "Uncompressed key are not allowed." unless k.compressed?
        end
      end
    end
  end
end