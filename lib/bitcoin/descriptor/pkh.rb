module Bitcoin
  module Descriptor
    # pkh() expression
    class Pkh < KeyExpression

      def type
        :pkh
      end

      def to_script
        Script.to_p2pkh(extracted_key.hash160)
      end
    end
  end
end