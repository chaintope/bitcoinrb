module Bitcoin
  module Descriptor
    class ScriptExpression < Expression

      attr_reader :script

      def initialize(script)
        validate!(script)
        @script = script
      end

      private

      def validate!(script)
        raise ArgumentError, 'Can only have combo() at top level.' if script.is_a?(Combo)
        raise ArgumentError, 'Can only have sh() at top level.' if script.is_a?(Sh)
      end
    end
  end
end