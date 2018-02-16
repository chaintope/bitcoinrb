module Refinements
  module EvenLengthHex
    refine Integer do
      def to_even_length_hex
        hex = to_s(16)
        hex.rjust((hex.length / 2.0).ceil * 2, '0')
      end
    end
  end
end
