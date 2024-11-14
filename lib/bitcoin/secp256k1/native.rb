# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING
require 'secp256k1'

module Bitcoin
  module Secp256k1

    # binding for secp256k1 (https://github.com/bitcoin-core/secp256k1/)
    # tag: v0.4.0
    # this is not included by default, to enable set shared object path to ENV['SECP256K1_LIB_PATH']
    # for linux, ENV['SECP256K1_LIB_PATH'] = '/usr/local/lib/libsecp256k1.so' or '/usr/lib64/libsecp256k1.so'
    # for mac,
    module Native

      module_function

      extend ::Secp256k1

      # Whether this module is native c wrapper or not?
      # @return [Boolean]
      def native?
        true
      end

      # generate bitcoin key object
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Bitcoin::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      # Sign data with compact format.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign with hex format
      # @return [Array[signature, recovery id]]
      def sign_compact(data, privkey)
        sig, rec_id = sign_recoverable(data, privkey)
        [ECDSA::Signature.new(sig[0...64].to_i(16), sig[64..-1].to_i(16)), rec_id]
      end

      # Recover public key from compact signature.
      # @param [String] data message digest using signature.
      # @param [String] signature signature with binary format(65 bytes).
      # @param [Boolean] compressed whether compressed public key or not.
      # @return [Bitcoin::Key] Recovered public key.
      def recover_compact(data, signature, compressed)
        pubkey = recover(data, signature, compressed)
        Bitcoin::Key.new(pubkey: pubkey, compressed: compressed)
      end

      # Sign to data.
      # @param [String] data The 32-byte message hash being signed with binary format.
      # @param [String] private_key a private key with hex format using sign.
      # @param [String] extra_entropy a extra entropy with binary format for rfc6979.
      # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
      # @return [String] signature data with binary format. If unsupported algorithm specified, return nil.
      # @raise [ArgumentError] If invalid arguments specified.
      def sign_data(data, private_key, extra_entropy = nil, algo: :ecdsa)
        case algo
        when :ecdsa
          begin
            sign_ecdsa(data, private_key, extra_entropy)
          rescue ArgumentError
            false
          end
        when :schnorr
          begin
            sign_schnorr(data, private_key, extra_entropy)
          rescue ArgumentError
            false
          end
        else
          raise ArgumentError, "unknown algo: #{algo}"
        end
      end

      # Verify signature.
      # @param [String] data The 32-byte message hash assumed to be signed.
      # @param [String] signature signature data with binary format
      # @param [String] pubkey a public key with hex format using verify.
      # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
      # @return [Boolean] verification result.
      # @raise [ArgumentError] If invalid arguments specified.
      def verify_sig(data, signature, pubkey, algo: :ecdsa)
        case algo
        when :ecdsa
          begin
            verify_ecdsa(data, signature, pubkey)
          rescue ArgumentError
            false
          end
        when :schnorr
          begin
            verify_schnorr(data, signature, pubkey)
          rescue ArgumentError
            false
          end
        else
          raise ArgumentError, "unknown algo: #{algo}"
        end
      end
    end
  end
end
