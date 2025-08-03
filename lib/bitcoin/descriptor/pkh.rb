module Bitcoin
  module Descriptor
    # pkh() expression
    class Pkh < KeyExpression

      def type
        :pkh
      end

      def to_hex
        raise ArgumentError, 'musig() is not allowed in top-level pkh().' if musig?
        super
      end

      def to_script
        Script.to_p2pkh(extracted_key.hash160)
      end
    end
  end
end