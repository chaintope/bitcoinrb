module Bitcoin
  module Taproot

    class BuildError < StandardError; end

    # Utility class to construct Taproot outputs from internal key and script tree.
    class Builder

      attr_reader :internal_key, :scripts

      # Initialize builder.
      # @param [String] internal_key Internal public key with hex format.
      # @param [Array[Bitcoin::Script]] scripts Scripts for each unlock condition.
      # @return Bitcoin::TaprootBuilder
      def initialize(internal_key, *scripts)
        raise BuildError, 'Internal public key must be 32 bytes' unless internal_key.htb.bytesize == 32
        scripts.each do |script|
          raise BuildError, 'script must be Bitcoin::Script object' unless script.is_a?(Bitcoin::Script)
        end
        @internal_key = internal_key
        @scripts = scripts
      end

      # Add script to leaf node.
      def <<(script)
        raise BuildError, 'script must be Bitcoin::Script object' unless script.is_a?(Bitcoin::Script)
        scripts << script
        self
      end

    end
  end

end