module Bitcoin
  module Descriptor
    # multi() expression
    class Multi < Expression

      attr_reader :threshold
      attr_reader :keys

      def initialize(threshold, keys)
        validate!(threshold, keys)
        @threshold = threshold
        @keys = keys
      end

      def type
        :multi
      end

      def to_script
        Script.to_multisig_script(threshold, keys.map{|key| extract_pubkey(key) }, sort: false)
      end

      def to_hex
        result = to_script
        if result.multisig?
          pubkey_count = result.get_pubkeys.length
          raise RuntimeError, "Cannot have #{pubkey_count} pubkeys in bare multisig; only at most 3 pubkeys." if pubkey_count > 3
        end
        super
      end

      def args
        "#{threshold},#{keys.join(',')}"
      end

      def top_level?
        false
      end

      private

      def validate!(threshold, keys)
        raise ArgumentError, "Multisig threshold '#{threshold}' is not valid." unless threshold.is_a?(Integer)
        raise ArgumentError, 'Multisig threshold cannot be 0, must be at least 1.' unless threshold > 0
        raise ArgumentError, 'Multisig threshold cannot be larger than the number of keys.' if threshold > keys.size
        raise ArgumentError, "Multisig must have between 1 and #{Bitcoin::MAX_PUBKEYS_PER_MULTISIG} keys, inclusive." if keys.size > Bitcoin::MAX_PUBKEYS_PER_MULTISIG
        keys.map{|key| extract_pubkey(key) }
      end
    end
  end
end