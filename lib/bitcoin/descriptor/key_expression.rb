module Bitcoin
  module Descriptor
    class KeyExpression < Expression
      attr_reader :key

      # Constructor
      # @raise [ArgumentError] If +key+ is invalid.
      def initialize(key)
        raise ArgumentError, "Key must be string or MuSig." unless key.is_a?(String) || key.is_a?(MuSig)
        @key = key
        extracted_key
      end

      def args
        key
      end

      def top_level?
        false
      end

      # Get extracted key.
      # @return [Bitcoin::Key] Extracted key.
      def extracted_key
        extract_pubkey(musig? ? key.to_hex : key)
      end

      # Key is musig or not?
      # @return [Boolean]
      def musig?
        key.is_a?(MuSig)
      end
    end
  end
end