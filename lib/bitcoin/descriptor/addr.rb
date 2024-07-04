module Bitcoin
  module Descriptor
    class Addr < Expression
      include Bitcoin::Util

      attr_reader :addr

      def initialize(addr)
        raise ArgumentError, "Address must be string." unless addr.is_a?(String)
        raise ArgumentError, "Address is not valid." unless valid_address?(addr)
        @addr = addr
      end

      def type
        :addr
      end

      def to_script
        Bitcoin::Script.parse_from_addr(addr)
      end

      def top_level?
        true
      end

      def args
        addr
      end
    end
  end
end