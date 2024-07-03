module Bitcoin
  module Descriptor
    # wpkh() expression
    class Wpkh < KeyExpression
      def initialize(key)
        super(key)
        raise ArgumentError, "Uncompressed key are not allowed." unless compressed_key?(extract_pubkey(key))
      end

      def type
        :wpkh
      end

      def to_script
        Script.to_p2wpkh(Bitcoin.hash160(extract_pubkey(key)))
      end
    end
  end
end