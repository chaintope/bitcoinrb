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
        raise ArgumentError, "musig() is not allowed in #{type.to_s}()." if script.is_a?(MuSig) || (script.is_a?(KeyExpression) && script.musig?)
        raise ArgumentError, "Can only have #{script.type.to_s}() at top level." if script.is_a?(Expression) && script.top_level?
        raise ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().' if script.is_a?(MultiA) || script.is_a?(SortedMultiA)
      end
    end
  end
end