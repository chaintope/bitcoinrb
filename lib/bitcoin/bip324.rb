module Bitcoin
  # BIP 324 module
  # https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
  module BIP324
    autoload :EllSwiftPubkey, 'bitcoin/bip324/ell_swift_pubkey'
    autoload :Cipher, 'bitcoin/bip324/cipher'

    FIELD_SIZE = 2**256 - 2**32 - 977
    FIELD = ECDSA::PrimeField.new(FIELD_SIZE)

    REKEY_INTERVAL = 224 # packets

    module_function

    def sqrt(n)
      candidate = FIELD.power(n, (FIELD.prime + 1) / 4)
      return nil unless FIELD.square(candidate) == n
      candidate
    end

    MINUS_3_SQRT = sqrt(FIELD.mod(-3))

    # Decode field elements (u, t) to an X coordinate on the curve.
    # @param [String] u u of ElligatorSwift encoding with hex format.
    # @param [String] t t of ElligatorSwift encoding with hex format.
    # @return [String] x coordinate with hex format.
    def xswiftec(u, t)
      u = FIELD.mod(u.hex)
      t = FIELD.mod(t.hex)
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

    # Inverse map for ElligatorSwift. Given x and u, find t such that xswiftec(u, t) = x, or return nil.
    # @param [String] x x coordinate with hex format
    # @param [String] u u of ElligatorSwift encoding with hex format
    # @param [Integer] c Case selects which of the up to 8 results to return.
    # @return [String] Inverse of xswiftec(u, t) with hex format or nil.
    def xswiftec_inv(x, u, c)
      x = FIELD.mod(x.hex)
      u = FIELD.mod(u.hex)
      if c & 2 == 0
        return nil unless ECDSA::Group::Secp256k1.solve_for_y(FIELD.mod(-x - u)).empty?
        v = x
        s = FIELD.mod(
          -FIELD.mod(FIELD.power(u, 3) + 7) *
            FIELD.inverse(FIELD.mod(FIELD.power(u, 2) + u * v + FIELD.power(v, 2))))
      else
        s = FIELD.mod(x - u)
        return nil if s == 0
        r = sqrt(FIELD.mod(-s * (4 * (FIELD.power(u, 3) + 7) + 3 * s * FIELD.power(u, 2))))
        return nil if r.nil?
        return nil if c & 1 == 1 && r == 0
        v = FIELD.mod(FIELD.mod(-u + r * FIELD.inverse(s)) * FIELD.inverse(2))
      end
      w = sqrt(s)
      return nil if w.nil?
      result = if c & 5 == 0
                 FIELD.mod(-w * FIELD.mod(u * (1 - MINUS_3_SQRT) * FIELD.inverse(2) + v))
               elsif c & 5 == 1
                 FIELD.mod(w * FIELD.mod(u * (1 + MINUS_3_SQRT) * FIELD.inverse(2) + v))
               elsif c & 5 == 4
                 FIELD.mod(w * FIELD.mod(u * (1 - MINUS_3_SQRT) * FIELD.inverse(2) + v))
               elsif c & 5 == 5
                 FIELD.mod(-w * FIELD.mod(u * (1 + MINUS_3_SQRT) * FIELD.inverse(2) + v))
               else
                 return nil
                 end
      ECDSA::Format::IntegerOctetString.encode(result, 32).bth
    end

    # Given a field element X on the curve, find (u, t) that encode them.
    # @param [String] x coordinate with hex format.
    # @return [String] ElligatorSwift public key with hex format.
    def xelligatorswift(x)
      loop do
        u = SecureRandom.random_number(1..ECDSA::Group::Secp256k1.order).to_s(16)
        c = Random.rand(0..8)
        t = xswiftec_inv(x, u, c)
        unless t.nil?
          return (ECDSA::Format::IntegerOctetString.encode(u.hex, 32) +
            ECDSA::Format::IntegerOctetString.encode(t.hex, 32)).bth
        end
      end
    end

    # Compute x coordinate of shared ECDH point between +ellswift_theirs+ and +priv_key+.
    # @param [Bitcoin::BIP324::EllSwiftPubkey] ellswift_theirs Their EllSwift public key.
    # @param [String] priv_key Private key with hex format.
    # @return [String] x coordinate of shared ECDH point with hex format.
    # @raise ArgumentError
    def ellswift_ecdh_xonly(ellswift_theirs, priv_key)
      raise ArgumentError, "ellswift_theirs must be a Bitcoin::BIP324::EllSwiftPubkey" unless ellswift_theirs.is_a?(Bitcoin::BIP324::EllSwiftPubkey)
      d = priv_key.hex
      x = ellswift_theirs.decode.to_point.x
      field = BIP324::FIELD
      y = BIP324.sqrt(field.mod(field.power(x, 3) + 7))
      return nil unless y
      point = ECDSA::Point.new(ECDSA::Group::Secp256k1, x, y) * d
      ECDSA::Format::FieldElementOctetString.encode(point.x, point.group.field).bth
    end

    # Compute BIP324 shared secret.
    # @param [String] priv_key Private key with hex format.
    # @param [Bitcoin::BIP324::EllSwiftPubkey] ellswift_theirs Their EllSwift public key.
    # @param [Bitcoin::BIP324::EllSwiftPubkey] ellswift_ours Our EllSwift public key.
    # @param [Boolean] initiating Whether your initiator or not.
    # @return [String] Shared secret with hex format.
    # @raise ArgumentError
    def v2_ecdh(priv_key, ellswift_theirs, ellswift_ours, initiating)
      raise ArgumentError, "ellswift_theirs must be a Bitcoin::BIP324::EllSwiftPubkey" unless ellswift_theirs.is_a?(Bitcoin::BIP324::EllSwiftPubkey)
      raise ArgumentError, "ellswift_ours must be a Bitcoin::BIP324::EllSwiftPubkey" unless ellswift_ours.is_a?(Bitcoin::BIP324::EllSwiftPubkey)

      if Bitcoin.secp_impl.is_a?(Bitcoin::Secp256k1::Native)
        Bitcoin::Secp256k1::Native.ellswift_ecdh_xonly(ellswift_theirs, ellswift_ours, priv_key, initiating)
      else
        ecdh_point_x32 = ellswift_ecdh_xonly(ellswift_theirs, priv_key).htb
        content = initiating ? ellswift_ours.key + ellswift_theirs.key + ecdh_point_x32 :
                    ellswift_theirs.key + ellswift_ours.key + ecdh_point_x32
        Bitcoin.tagged_hash('bip324_ellswift_xonly_ecdh', content).bth
      end
    end
  end
end
