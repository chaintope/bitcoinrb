module Bitcoin
  module Secp256k1

    # secp256 module using ecdsa gem
    # https://github.com/DavidEGrayson/ruby_ecdsa
    module Ruby

      module_function

      # generate ec private key and public key
      def generate_key_pair(compressed: true)
        private_key = 1 + SecureRandom.random_number(GROUP.order - 1)
        public_key = GROUP.generator.multiply_by_scalar(private_key)
        privkey = ECDSA::Format::IntegerOctetString.encode(private_key, 32)
        pubkey = ECDSA::Format::PointOctetString.encode(public_key, compression: compressed)
        [privkey.bth, pubkey.bth]
      end

      # generate bitcoin key object
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Bitcoin::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      # sign data.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign
      # @return [String] signature data with binary format
      def sign_data(data, privkey)
        privkey = privkey.htb
        private_key = ECDSA::Format::IntegerOctetString.decode(privkey)
        nonce = generate_rfc6979_nonce(data, privkey)

        # port form ecdsa gem.
        r_point = GROUP.new_point(nonce)

        point_field = ECDSA::PrimeField.new(GROUP.order)
        r = point_field.mod(r_point.x)
        return nil if r.zero?

        e = ECDSA.normalize_digest(data, GROUP.bit_length)
        s = point_field.mod(point_field.inverse(nonce) * (e + r * private_key))

        if s > (GROUP.order / 2) # convert low-s
          s = GROUP.order - s
        end

        return nil if s.zero?

        signature = ECDSA::Signature.new(r, s).to_der
        public_key = Bitcoin::Key.new(priv_key: privkey.bth).pubkey
        raise 'Creation of signature failed.' unless Bitcoin::Secp256k1::Ruby.verify_sig(data, signature, public_key)
        signature
      end

      # verify signature using public key
      # @param [String] digest a SHA-256 message digest with binary format
      # @param [String] sig a signature for +data+ with binary format
      # @param [String] pubkey a public key corresponding to the private key used for sign
      # @return [Boolean] verify result
      def verify_sig(digest, sig, pubkey)
        begin
          k = ECDSA::Format::PointOctetString.decode(repack_pubkey(pubkey), GROUP)
          signature = ECDSA::Format::SignatureDerString.decode(sig)
          ECDSA.valid_signature?(k, digest, signature)
        rescue Exception
          false
        end
      end

      # if +pubkey+ is hybrid public key format, it convert uncompressed format.
      # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2012-June/001578.html
      def repack_pubkey(pubkey)
        p = pubkey.htb
        case p[0]
          when "\x06", "\x07"
            p[0] = "\x04"
            p
          else
            pubkey.htb
        end
      end

      # generate temporary key k to be used when ECDSA sign.
      # https://tools.ietf.org/html/rfc6979#section-3.2
      def generate_rfc6979_nonce(data, privkey)
        v = ('01' * 32).htb
        k = ('00' * 32).htb
        # 3.2.d
        k = Bitcoin.hmac_sha256(k, v + '00'.htb + privkey + data)
        # 3.2.e
        v = Bitcoin.hmac_sha256(k, v)
        # 3.2.f
        k = Bitcoin.hmac_sha256(k, v + '01'.htb + privkey + data)
        # 3.2.g
        v = Bitcoin.hmac_sha256(k, v)
        # 3.2.h
        t = ''
        10000.times do
          v = Bitcoin.hmac_sha256(k, v)
          t = (t + v)
          t_num = t.bth.to_i(16)
          return t_num if 1 <= t_num && t_num < GROUP.order
          k = Bitcoin.hmac_sha256(k, v + '00'.htb)
          v = Bitcoin.hmac_sha256(k, v)
        end
        raise 'A valid nonce was not found.'
      end
    end

  end
end
