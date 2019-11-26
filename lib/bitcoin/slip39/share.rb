module Bitcoin
  module SLIP39

    # Share of Shamir's Secret Sharing Scheme
    class Share

      attr_accessor :id               # 15 bits, Integer
      attr_accessor :iteration_exp    # 5 bits, Integer
      attr_accessor :group_index      # 4 bits, Integer
      attr_accessor :group_threshold  # 4 bits, Integer
      attr_accessor :group_count      # 4 bits, Integer
      attr_accessor :member_index     # 4 bits, Integer
      attr_accessor :member_threshold # 4 bits, Integer
      attr_accessor :padded_value     # padding + 8n bits, bit string.
      attr_accessor :checksum         # 30 bits, Integer

      # Recover Share from the mnemonic words
      # @param [Array{String}] words the mnemonic words
      # @return [Bitcoin::SLIP39::Share] a share
      def self.from_words(words)
        raise ArgumentError, 'Mnemonics should be an array of strings' unless words.is_a?(Array)
        indices = words.map do |word|
          index = Bitcoin::SLIP39::WORDS.index(word.downcase)
          raise IndexError, 'word not found in words list.' unless index
          index
        end

        raise ArgumentError, 'Invalid mnemonic length.' if indices.size < MIN_MNEMONIC_LENGTH_WORDS
        raise ArgumentError, 'Invalid mnemonic checksum.' unless verify_rs1024_checksum(indices)

        padding_length = (RADIX_BITS * (indices.size - METADATA_LENGTH_WORDS)) % 16
        raise ArgumentError, 'Invalid mnemonic length.' if padding_length > 8
        data = indices.map{|i|i.to_s(2).rjust(10, '0')}.join

        s = self.new
        s.id = data[0...15].to_i(2)
        s.iteration_exp = data[15...20].to_i(2)
        s.group_index = data[20...24].to_i(2)
        s.group_threshold = data[24...28].to_i(2) + 1
        s.group_count = data[28...32].to_i(2) + 1
        raise ArgumentError, "Invalid mnemonic. Group threshold(#{s.group_threshold}) cannot be greater than group count(#{s.group_count})." if s.group_threshold > s.group_count
        s.member_index = data[32...36].to_i(2)
        s.member_threshold = data[36...40].to_i(2) + 1
        value_length = data.length - 70
        start_index = 40 + padding_length
        end_index = start_index + value_length - padding_length
        padding_value = data[40...(40 + padding_length)]
        raise ArgumentError, "Invalid mnemonic. padding must only zero." unless padding_value.to_i(2) == 0
        s.padded_value = data[start_index...end_index].to_i(2).to_even_length_hex
        s.checksum = data[(40 + value_length)..-1].to_i(2)
        s
      end

      private

      def self.rs1024_polymod(values)
        gen = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120]
        chk = 1
        values.each do |v|
          b = (chk >> 20)
          chk = (chk & 0xfffff) << 10 ^ v
          10.times do |i|
            chk ^= (((b >> i) & 1 == 1) ? gen[i] : 0)
          end
        end
        chk
      end

      # Verify RS1024 checksum
      # @param [Integer] data the data part as a list of 10-bit integers, each corresponding to one word of the mnemonic.
      # @return [Boolean] verify result
      def self.verify_rs1024_checksum(data)
        rs1024_polymod(CUSTOMIZATION_STRING + data) == 1
      end

      # Converts a list of base 1024 indices in big endian order to an integer value.
      # @param [Array[Integer]] array of index.
      # @return [Integer] converted value.
      def self.int_from_indices(indices)
        value = 0
        indices.each do |index|
          value = value * RADIX + index
        end
        value
      end

      # Converts an integer value to indices in big endian order.
      # @param [Integer] value
      # @param [Integer] length
      # @param [Integer] bits
      # @return []
      def self.int_to_indices(value, length, bits)
        mask = (1 << bits) - 1
        0.upto(length).map do |i|
          (value >> (i * bits)) & mask
        end
      end

    end
  end
end