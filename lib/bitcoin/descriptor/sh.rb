module Bitcoin
  module Descriptor
    # sh expression
    class Sh < ScriptExpression

      def type
        :sh
      end

      def to_script
        script.to_script.to_p2sh
      end

      private

      def validate!(script)
        super(script)
        raise ArgumentError, 'A function is needed within P2SH.' unless script.is_a?(Expression)
        script_size = script.to_script.size
        if script_size > Bitcoin::MAX_SCRIPT_ELEMENT_SIZE
          raise ArgumentError,
                "P2SH script is too large, #{script_size} bytes is larger than #{Bitcoin::MAX_SCRIPT_ELEMENT_SIZE} bytes."
        end
      end
    end
  end
end