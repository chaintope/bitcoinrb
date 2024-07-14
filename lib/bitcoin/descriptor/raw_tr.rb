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
        Bitcoin::Script.new << OP_1 << extract_pubkey(key).xonly_pubkey
      end
    end
  end
end