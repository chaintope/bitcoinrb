module Bitcoin
  module Descriptor
    # combo() expression
    class Combo < KeyExpression

      def type
        :combo
      end

      def initialize(key)
        super(key)
        validate_not_xonly!(key)
      end

      # combo() stands for several scripts, see #to_scripts.
      # @raise [ArgumentError] always.
      def to_script
        raise ArgumentError, 'musig() is not allowed in top-level combo().' if musig?
        raise ArgumentError, 'combo() expands to several scripts. Use #to_scripts.'
      end

      def to_hex
        to_script
      end

      def to_scripts
        candidates = [Pk.new(key), Pkh.new(key)]
        pubkey = extracted_key
        if pubkey.compressed?
          candidates << Wpkh.new(pubkey.pubkey)
          candidates << Sh.new(candidates.last)
        end
        candidates.map(&:to_script)
      end

      def ==(other)
        return false unless other.is_a?(Combo)
        type == other.type && to_scripts == other.to_scripts
      end

      def top_level?
        true
      end
    end
  end
end