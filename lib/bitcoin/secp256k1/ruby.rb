require 'ecdsa'

module Bitcoin
  module Secp256k1

    # secp256 module using ecdsa gem
    # https://github.com/DavidEGrayson/ruby_ecdsa
    module Ruby

      GROUP = ECDSA::Group::Secp256k1

      module_function

      # generete ecdsa private key and public key
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

    end

  end
end
