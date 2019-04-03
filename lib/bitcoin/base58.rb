module Bitcoin

  # Base58Check encoding
  # https://en.bitcoin.it/wiki/Base58Check_encoding
  module Base58
    module_function

    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    SIZE = ALPHABET.size

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
    def decode(base58_val)
      int_val = 0
      base58_val.reverse.split(//).each_with_index do |char,index|
        raise ArgumentError, 'Value passed not a valid Base58 String.' if (char_index = ALPHABET.index(char)).nil?
        int_val += char_index * (SIZE ** index)
      end
      s = int_val.to_even_length_hex
      s = '' if s == '00'
      leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
      s = ('00' * leading_zero_bytes) + s if leading_zero_bytes > 0
      s
    end

  end
end
