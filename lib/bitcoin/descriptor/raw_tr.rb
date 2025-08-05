module Bitcoin
  module Descriptor
    # rawtr() descriptor
    # @see
    class RawTr < KeyExpression
      include Bitcoin::Opcodes

      def type
        :rawtr
      end

      def top_level?
        true
      end

      def to_script
        Bitcoin::Script.new << OP_1 << extracted_key.xonly_pubkey
      end
    end
  end
end