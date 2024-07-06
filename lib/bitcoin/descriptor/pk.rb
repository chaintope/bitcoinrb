module Bitcoin
  module Descriptor
    # pk() expression
    class Pk < KeyExpression
      include Bitcoin::Opcodes

      def type
        :pk
      end

      # Convert to bitcoin script.
      # @return [Bitcoin::Script]
      def to_script
        Bitcoin::Script.new << extract_pubkey(key).pubkey << OP_CHECKSIG
      end

    end

  end
end