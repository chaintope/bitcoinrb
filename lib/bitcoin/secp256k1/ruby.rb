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
        pubkey = public_key.to_hex(compressed)
        [privkey.bth, pubkey]
      end

      # generate bitcoin key object
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Bitcoin::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      def generate_pubkey(privkey, compressed: true)
        public_key = ECDSA::Group::Secp256k1.generator.multiply_by_scalar(privkey.to_i(16))
        public_key.to_hex(compressed)
      end

      # Check whether valid x-only public key or not.
      # @param [String] pub_key x-only public key with hex format(32 bytes).
      # @return [Boolean] result.
      def valid_xonly_pubkey?(pub_key)
        pubkey = pub_key.htb
        return false unless pubkey.bytesize == 32
        begin
          ECDSA::Format::PointOctetString.decode(pubkey, ECDSA::Group::Secp256k1)
        rescue Exception
          return false
        end
        true
      end

      # sign data.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign
      # @param [String] extra_entropy a extra entropy with binary format for rfc6979
      # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
      # @return [String] signature data with binary format
      def sign_data(data, privkey, extra_entropy = nil, algo: :ecdsa)
        case algo
        when :ecdsa
          sign_ecdsa(data, privkey, extra_entropy)
        when :schnorr
          sign_schnorr(data, privkey, extra_entropy)
        else
          nil
        end
      end

      # verify signature using public key
      # @param [String] data a SHA-256 message digest with binary format
      # @param [String] sig a signature for +data+ with binary format
      # @param [String] pubkey a public key with hex format.
      # @return [Boolean] verify result
      def verify_sig(data, sig, pubkey, algo: :ecdsa)
        case algo
        when :ecdsa
          verify_ecdsa(data, sig, pubkey)
        when :schnorr
          verify_schnorr(data, sig, pubkey)
        else
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

      # validate whether this is a valid public key (more expensive than IsValid())
      # @param [String] pubkey public key with hex format.
      # @param [Boolean] allow_hybrid whether support hybrid public key.
      # @return [Boolean] If valid public key return true, otherwise false.
      def parse_ec_pubkey?(pubkey, allow_hybrid = false)
        begin
          point = ECDSA::Format::PointOctetString.decode(pubkey.htb, ECDSA::Group::Secp256k1, allow_hybrid: allow_hybrid)
          ECDSA::Group::Secp256k1.valid_public_key?(point)
        rescue ECDSA::Format::DecodeError
          false
        end
      end

      def sign_ecdsa(data, privkey, extra_entropy)
        privkey = privkey.htb
        private_key = ECDSA::Format::IntegerOctetString.decode(privkey)
        extra_entropy ||= ''
        nonce = RFC6979.generate_rfc6979_nonce(privkey + data, extra_entropy)

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

      def sign_schnorr(data, privkey, aux_rand)
        aux_rand ? Schnorr.sign(data, privkey.htb, aux_rand).encode : Schnorr.sign(data, privkey.htb).encode
      end

      def verify_ecdsa(data, sig, pubkey)
        begin
          k = ECDSA::Format::PointOctetString.decode(repack_pubkey(pubkey), GROUP)
          signature = ECDSA::Format::SignatureDerString.decode(sig)
          ECDSA.valid_signature?(k, data, signature)
        rescue Exception
          false
        end
      end

      def verify_schnorr(data, sig, pubkey)
        Schnorr.valid_sig?(data, pubkey.htb, sig)
      end

    end
  end
end
