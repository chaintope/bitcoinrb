module Bitcoin
  module Secp256k1

    GROUP = ECDSA::Group::Secp256k1

    # secp256 module using ecdsa gem
    # https://github.com/DavidEGrayson/ruby_ecdsa
    module Ruby

      module_function

      # generate ecdsa private key and public key
      def generate_key_pair(compressed: true)
        private_key = 1 + SecureRandom.random_number(GROUP.order - 1)
        public_key = GROUP.generator.multiply_by_scalar(private_key)
        privkey = ECDSA::Format::IntegerOctetString.encode(private_key, 32)
        pubkey = ECDSA::Format::PointOctetString.encode(public_key, compression: compressed)
        [privkey.bth, pubkey.bth]
      end

      # generate bitcoin key
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Bitcoin::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      # generate publick key from private key
      # @param [String] privkey a private key with string format
      # @param [Boolean] compressed pubkey compressed?
      # @return [String] a pubkey which generate from privkey
      def generate_pubkey(privkey, compressed: true)
        private_key = ECDSA::Format::IntegerOctetString.decode(privkey.htb)
        public_key = GROUP.generator.multiply_by_scalar(private_key)
        pubkey = ECDSA::Format::PointOctetString.encode(public_key, compression: compressed)
        pubkey.bth
      end

      # sign data.
      # @param [String] data a data to be signed
      # @param [String] privkey a private key using sign
      # @return [String] signature data with binary format
      def sign_data(data, privkey)
        digest = Digest::SHA2.digest(data)
        private_key = ECDSA::Format::IntegerOctetString.decode(privkey.htb)
        signature = nil
        while signature.nil?
          # TODO support rfc 6979 https://tools.ietf.org/html/rfc6979
          temp_key = 1 + SecureRandom.random_number(GROUP.order - 1)
          signature = ECDSA.sign(GROUP, private_key, digest, temp_key)
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
          k = ECDSA::Format::PointOctetString.decode(pubkey.htb, GROUP)
          signature = ECDSA::Format::SignatureDerString.decode(sig)
          ECDSA.valid_signature?(k, digest, signature)
        rescue Exception
          false
        end
      end

    end

  end
end
