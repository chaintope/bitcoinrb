module Bitcoin
  module Secp256k1

    GROUP = ECDSA::Group::Secp256k1

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
      # @param [String] data a data to be signed
      # @param [String] privkey a private key using sign
      # @return [String] signature data with binary format
      def sign_data(data, privkey)
        # digest = Digest::SHA2.digest(data)
        private_key = ECDSA::Format::IntegerOctetString.decode(privkey.htb)
        signature = nil
        while signature.nil?
          # TODO support rfc 6979 https://tools.ietf.org/html/rfc6979
          temp_key = 1 + SecureRandom.random_number(GROUP.order - 1)
          signature = ECDSA.sign(GROUP, private_key, data, temp_key)
        end
        ECDSA::Format::SignatureDerString.encode(signature) # signature with DER format
      end

      # verify signature using public key
      # @param [String] digest a SHA-256 message digest with binary format
      # @param [String] sig a signature for +data+ with binary format
      # @param [String] pubkey a public key corresponding to the private key used for sign
      # @return [Boolean] verify result
      def verify_sig(digest, sig, pubkey)
        begin
          k = ECDSA::Format::PointOctetString.decode(repack_pubkey(pubkey), GROUP)
          signature = repack_sig(sig)
          ECDSA.valid_signature?(k, digest, signature)
        rescue Exception
          false
        end
      end

      # repack signature for OpenSSL 1.0.1k handling of DER signatures
      # https://github.com/bitcoin/bitcoin/pull/5634/files
      def repack_sig(sig)
        sig_array = sig.unpack('C*')
        len_r = sig_array[3]
        r = sig_array[4...(len_r+4)].pack('C*').bth
        len_s = sig_array[len_r + 5]
        s = sig_array[(len_r + 6)...(len_r + 6 + len_s)].pack('C*').bth
        ECDSA::Signature.new(r.to_i(16), s.to_i(16))
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

    end

  end
end
