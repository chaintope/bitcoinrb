module Bitcoin
  module Descriptor
    class KeyExpression < Expression
      attr_reader :key

      # Constructor
      # @raise [ArgumentError] If +key+ is invalid.
      def initialize(key)
        raise ArgumentError, "Key must be string." unless key.is_a? String
        extract_pubkey(key)
        @key = key
      end

      def args
        key
      end

      def top_level?
        false
      end
    end
  end
end