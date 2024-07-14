module Bitcoin
  module Descriptor
    # wpkh() expression
    class Wpkh < KeyExpression
      def initialize(key)
        super(key)
        raise ArgumentError, "Uncompressed key are not allowed." unless extract_pubkey(key).compressed?
      end

      def type
        :wpkh
      end

      def to_script
        Script.to_p2wpkh(extracted_key.hash160)
      end
    end
  end
end