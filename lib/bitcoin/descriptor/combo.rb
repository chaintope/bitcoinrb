module Bitcoin
  module Descriptor
    # combo() expression
    class Combo < KeyExpression

      def type
        :combo
      end

      def to_scripts
        candidates = [Pk.new(key), Pkh.new(key)]
        pubkey = extract_pubkey(key)
        if compressed_key?(pubkey)
          candidates << Wpkh.new(pubkey)
          candidates << Sh.new(candidates.last)
        end
        candidates.map(&:to_script)
      end

      def ==(other)
        return false unless other.is_a?(Combo)
        type == other.type && to_scripts == other.to_scripts
      end
    end
  end
end