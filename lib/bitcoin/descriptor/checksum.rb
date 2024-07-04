module Bitcoin
  module Descriptor
    # Descriptor checksum.
    # https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#checksum
    module Checksum

      INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
      CHECKSUM_CHARSET = Bech32::CHARSET
      GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]

      module_function

      # Verify that the checksum is correct in a descriptor
      # @param [String] s Descriptor string.
      # @return [Boolean]
      def descsum_check(s)
        return false unless s[-9] == '#'
        s[-8..-1].each_char do |c|
          return false unless CHECKSUM_CHARSET.include?(c)
        end
        symbols = descsum_expand(s[0...-9]) + s[-8..-1].each_char.map{|c|CHECKSUM_CHARSET.index(c)}
        descsum_polymod(symbols) == 1
      end

      # Add a checksum to a descriptor without
      # @param [String] s Descriptor string without checksum.
      # @return [String] Descriptor string with checksum.
      def descsum_create(s)
        symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
        checksum = descsum_polymod(symbols) ^ 1
        result = 8.times.map do |i|
          CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31]
        end.join
        "#{s}##{result}"
      end

      # Internal function that does the character to symbol expansion.
      # @param [String] s Descriptor string without checksum.
      # @return [Array] symbols. An array of integer.
      def descsum_expand(s)
        groups = []
        symbols = []
        s.each_char do |c|
          return nil unless INPUT_CHARSET.include?(c)
          v = INPUT_CHARSET.index(c)
          symbols << (v & 31)
          groups << (v >> 5)
          if groups.length == 3
            symbols << (groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
          end
        end
        symbols << groups[0] if groups.length == 1
        symbols << (groups[0] * 3 + groups[1]) if groups.length == 2
        symbols
      end

      # Internal function that computes the descriptor checksum.
      # @param [Array] symbols
      # @return [Integer]
      def descsum_polymod(symbols)
        chk = 1
        symbols.each do |value|
          top = chk >> 35
          chk = (chk & 0x7FFFFFFFF) << 5 ^ value
          5.times do |i|
            chk ^= GENERATOR[i] if ((top >> i) & 1) == 1
          end
        end
        chk
      end
    end
  end
end