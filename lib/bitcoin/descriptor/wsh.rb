module Bitcoin
  module Descriptor
    # wsh() expression
    class Wsh < ScriptExpression

      def type
        :wsh
      end

      def to_script
        Script.to_p2wsh(script.to_script)
      end

      def top_level?
        false
      end

      def validate!(script)
        super(script)
        raise ArgumentError, 'A function is needed within P2WSH.' unless script.is_a?(Expression)
        if script.is_a?(Wpkh) || script.is_a?(Wsh)
          raise ArgumentError, "Can only have #{script.type}() at top level or inside sh()."
        end
        if script.to_script.get_pubkeys.any?{|p|!compressed_key?(p)}
          raise ArgumentError, "Uncompressed key are not allowed."
        end
      end
    end
  end
end