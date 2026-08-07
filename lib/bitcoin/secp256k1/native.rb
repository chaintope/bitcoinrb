# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING
require 'secp256k1'

module Bitcoin
  module Secp256k1

    # binding for secp256k1 (https://github.com/bitcoin-core/secp256k1/)
    # tag: v0.8.0, which secp256k1rb 0.8.0 binds the public API of. An older library is missing
    # symbols the gem attaches, such as secp256k1_ec_pubkey_sort and the musig module.
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

      # Whether the loaded library supports BIP-352 silent payments.
      # The module exists in libsecp256k1 v0.8.0 or later.
      # @return [Boolean]
      def sp_available?
        silentpayments_available?
      end

      # Create the silent payment outputs for +recipients+.
      # @param [Array] recipients An array of [scan public key, spend public key], both with hex
      # format(33 bytes). A recipient may appear more than once.
      # @param [String] outpoint_smallest The lexicographically smallest outpoint of the tx inputs
      # with hex format(36 bytes).
      # @param [Array] plain_seckeys Private keys of the non-taproot inputs with hex format.
      # @param [Array] taproot_seckeys Private keys of the taproot inputs with hex format.
      # @return [Array] An x-only public key with hex format for each recipient, in the same order.
      # @raise [Secp256k1::Error] If the outputs could not be created.
      def sp_create_outputs(recipients, outpoint_smallest, plain_seckeys: [], taproot_seckeys: [])
        silentpayments_sender_create_outputs(
          recipients, outpoint_smallest, plain_seckeys: plain_seckeys, taproot_seckeys: taproot_seckeys)
      end

      # Create the label and the label tweak of the +m+ th label of +scan_key+.
      # @param [String] scan_key The recipient's scan private key with hex format(32 bytes).
      # @param [Integer] m The label index.
      # @return [Array] The serialized label(33 bytes) and its tweak(32 bytes), both with hex format.
      def sp_create_label(scan_key, m)
        silentpayments_create_label(scan_key, m)
      end

      # Scan +tx_outputs+ for the silent payment outputs of the recipient.
      # @param [Array] tx_outputs The x-only public key of each taproot output with hex format.
      # @param [String] scan_key The recipient's scan private key with hex format(32 bytes).
      # @param [String] outpoint_smallest The lexicographically smallest outpoint of the tx inputs
      # with hex format(36 bytes).
      # @param [String] spend_pubkey The recipient's spend public key with hex format(33 bytes).
      # @param [Array] plain_pubkeys Public keys of the non-taproot inputs with hex format(33 bytes).
      # @param [Array] xonly_pubkeys X-only public keys of the taproot inputs with hex format.
      # @param [Hash] labels A serialized label to label tweak map, both with hex format.
      # @return [Array] A hash per found output, with the :output, :tweak and :label keys.
      # @raise [Secp256k1::Error] If the tx is not a silent payment transaction.
      def sp_scan_outputs(tx_outputs, scan_key, outpoint_smallest, spend_pubkey,
                          plain_pubkeys: [], xonly_pubkeys: [], labels: {})
        summary = silentpayments_create_prevouts_summary(
          outpoint_smallest, plain_pubkeys: plain_pubkeys, xonly_pubkeys: xonly_pubkeys)
        silentpayments_scan_outputs(
          tx_outputs, scan_key, summary, spend_pubkey, labels: labels.empty? ? nil : labels)
      end
    end
  end
end
