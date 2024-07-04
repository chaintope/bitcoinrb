module Bitcoin
  module Descriptor
    class Raw < Expression

      attr_reader :hex

      # Constructor
      # @param [String] hex
      def initialize(hex)
        raise ArgumentError, "Raw script must be string." unless hex.is_a?(String)
        raise ArgumentError, "Raw script is not hex." unless hex.valid_hex?
        @hex = hex
      end

      def type
        :raw
      end

      def to_script
        Bitcoin::Script.parse_from_payload(hex.htb)
      end

      def args
        hex
      end

      def top_level?
        true
      end
    end
  end
end