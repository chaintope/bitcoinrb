module Bitcoin
  module Descriptor
    # pkh() expression
    class Pkh < KeyExpression

      def type
        :pkh
      end

      def to_script
        Script.to_p2pkh(Bitcoin.hash160(extract_pubkey(key)))
      end
    end
  end
end