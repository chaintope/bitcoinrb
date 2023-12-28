module Bitcoin
  # BIP 324 module
  # https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
  module BIP324
    autoload :EllSwiftPubkey, 'bitcoin/bip324/ell_swift_pubkey'

    FIELD_SIZE = 2**256 - 2**32 - 977
    FIELD = ECDSA::PrimeField.new(FIELD_SIZE)
    MINUS_3_SQRT = FIELD.square_roots(FIELD.mod(-3)).first

    module_function

    # Decode field elements (u, t) to an X coordinate on the curve.
    # @param [Integer] u
    # @param [Integer] t
    # @return [String] x coordinate with hex format.
    def xswiftec(u, t)
      u = FIELD.mod(u)
      t = FIELD.mod(t)
      u = 1 if u == 0
      t = 1 if t == 0
      t = FIELD.mod(2 * t) if FIELD.mod(FIELD.power(u, 3) + FIELD.power(t, 2) + 7) == 0
      x = FIELD.mod(FIELD.mod(FIELD.power(u, 3) + 7 - FIELD.power(t, 2)) * FIELD.inverse(2 * t))
      y = FIELD.mod((x + t) * FIELD.inverse(MINUS_3_SQRT * u))
      x1 = FIELD.mod(u + 4 * FIELD.power(y, 2))
      x2 = FIELD.mod(FIELD.mod(FIELD.mod(-x) * FIELD.inverse(y) - u) * FIELD.inverse(2))
      x3 = FIELD.mod(FIELD.mod(x * FIELD.inverse(y) - u) * FIELD.inverse(2))
      [x1, x2, x3].each do |x|
        unless ECDSA::Group::Secp256k1.solve_for_y(x).empty?
          return ECDSA::Format::IntegerOctetString.encode(x, 32).bth
        end
      end
      raise ArgumentError, 'Decode failed.'
    end
  end
end
