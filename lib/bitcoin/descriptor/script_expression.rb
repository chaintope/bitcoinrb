module Bitcoin
  module Descriptor
    class ScriptExpression < Expression

      attr_reader :script

      def initialize(script)
        validate!(script)
        @script = script
      end

      def args
        script.to_s
      end

      private

      def validate!(script)
        raise ArgumentError, "Can only have #{script.type.to_s}() at top level." if script.is_a?(Expression) && script.top_level?
      end
    end
  end
end