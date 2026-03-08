module Bitcoin
  module SilentPayment
    # Represents a detected silent payment output.
    class Output
      # @return [Bitcoin::TxOut] The detected transaction output.
      attr_reader :tx_out

      # @return [String] The tweak value (t_k) used to derive the output key (32 bytes binary).
      attr_reader :tweak

      # @return [Integer, nil] The label used for this output, or nil if no label was used.
      attr_reader :label

      # @param [Bitcoin::TxOut] tx_out The detected transaction output.
      # @param [String] tweak The tweak value (t_k) as 32 bytes binary.
      # @param [Integer, nil] label The label integer, or nil if no label was used.
      # @raise [ArgumentError] If any parameter has an invalid type.
      def initialize(tx_out, tweak, label = nil)
        raise ArgumentError, "tx_out must be a Bitcoin::TxOut." unless tx_out.is_a?(Bitcoin::TxOut)
        raise ArgumentError, "tweak must be a 32-byte String." unless tweak.is_a?(String) && tweak.bytesize == 32
        raise ArgumentError, "label must be an Integer or nil." unless label.nil? || label.is_a?(Integer)
        @tx_out = tx_out
        @tweak = tweak
        @label = label
      end

      # Returns the x-only public key of the output.
      # @return [String] The x-only public key as hex string.
      def pubkey
        tx_out.script_pubkey.witness_data[1].bth
      end

      # Returns the tweak as hex string.
      # @return [String] The tweak value as hex string.
      def tweak_hex
        tweak.bth
      end

      # Returns whether this output was detected using a label.
      # @return [Boolean]
      def labeled?
        !label.nil?
      end
    end
  end
end