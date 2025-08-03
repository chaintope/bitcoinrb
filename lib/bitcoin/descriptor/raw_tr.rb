module Bitcoin
  module Descriptor
    # rawtr() descriptor
    # @see
    class RawTr < KeyExpression
      include Bitcoin::Opcodes

      # Constructor
      # @raise [ArgumentError] If +key+ is invalid.
      def initialize(key)
        key = key.to_hex if key.is_a?(MuSig)
        super(key)
      end

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