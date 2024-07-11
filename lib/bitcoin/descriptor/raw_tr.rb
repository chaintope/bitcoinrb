module Bitcoin
  module Descriptor
    # rawtr() expression
    class RawTr < KeyExpression
      include Bitcoin::Opcodes

      def type
        :rawtr
      end

      def top_level?
        true
      end

      def to_script
        k = extract_pubkey(key)
        Bitcoin::Script.new << OP_1 << k.xonly_pubkey
      end
    end
  end
end