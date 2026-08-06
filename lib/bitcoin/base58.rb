module Bitcoin

  # Base58Check encoding
  # https://en.bitcoin.it/wiki/Base58Check_encoding
  module Base58
    module_function

    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    SIZE = ALPHABET.size

    # Upper bound for #decode. Decoding is quadratic in the length of the input, and the
    # longest value Bitcoin encodes with Base58 is an extended key, at 111 characters.
    MAX_LENGTH = 256

    # encode hex value to base58 string.
    def encode(hex)
      leading_zero_bytes = (hex.match(/^([0]+)/) ? $1 : '').size / 2
      int_val = hex.to_i(16)
      base58_val = ''
      while int_val > 0
        int_val, remainder = int_val.divmod(SIZE)
        base58_val = ALPHABET[remainder] + base58_val
      end
      ('1' * leading_zero_bytes) + base58_val
    end

    # decode base58 string to hex value.
    # @param [String] base58_val Base58 string.
    # @return [String] Decoded value with hex format.
    # @raise [ArgumentError] If +base58_val+ is longer than MAX_LENGTH or holds a character
    # which is not in the alphabet.
    def decode(base58_val)
      if base58_val.length > MAX_LENGTH
        raise ArgumentError, "Base58 string must not be longer than #{MAX_LENGTH} characters."
      end
      int_val = 0
      base58_val.each_char do |char|
        char_index = ALPHABET.index(char)
        raise ArgumentError, 'Value passed not a valid Base58 String.' if char_index.nil?
        int_val = int_val * SIZE + char_index
      end
      s = int_val.to_even_length_hex
      s = '' if s == '00'
      leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
      s = ('00' * leading_zero_bytes) + s if leading_zero_bytes > 0
      s
    end

  end
end
