module Bitcoin
  module Descriptor
    class KeyExpression < Expression
      attr_reader :key

      # Constructor
      # @raise [ArgumentError] If +key+ is invalid.
      def initialize(key)
        raise ArgumentError, "key must be string." unless key.is_a? String
        extract_pubkey(key)
        @key = key
      end

      def to_s
        "#{type.to_s}(#{key})"
      end
    end
  end
end