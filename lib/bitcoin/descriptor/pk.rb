module Bitcoin
  module Descriptor
    # pk() expression
    class Pk < KeyExpression
      include Bitcoin::Opcodes

      attr_accessor :xonly

      def initialize(key)
        super(key)
        @xonly = false
      end

      def type
        :pk
      end

      def to_hex
        raise ArgumentError, 'musig() is not allowed in top-level pk().' if musig?
        validate_not_xonly!(key)
        super
      end

      # Whether the key is given as an x-only key, which only a tr() tree can hold.
      # @return [Boolean]
      def xonly_key?(k = key)
        super(k)
      end

      # Convert to bitcoin script.
      # @return [Bitcoin::Script]
      def to_script
        k = extracted_key
        target_key = xonly ? k.xonly_pubkey : k.pubkey
        Bitcoin::Script.new << target_key << OP_CHECKSIG
      end
    end
  end
end