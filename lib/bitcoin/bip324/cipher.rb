module Bitcoin
  module BIP324
    # The BIP324 packet cipher, encapsulating its key derivation, stream cipher, and AEAD.
    class Cipher
      include Bitcoin::Util

      attr_reader :key
      attr_reader :our_pubkey

      attr_accessor :session_id
      attr_accessor :send_garbage_terminator
      attr_accessor :recv_garbage_terminator
      attr_accessor :send_l_cipher
      attr_accessor :send_p_cipher
      attr_accessor :recv_l_cipher
      attr_accessor :recv_p_cipher

      # Constructor
      # @param [Bitcoin::Key] key Private key.
      # @param [Bitcoin::BIP324::EllSwiftPubkey] our_pubkey Ellswift public key for testing.
      def initialize(key, our_pubkey = nil)
        raise ArgumentError, "key must be Bitcoin::Key" unless key.is_a?(Bitcoin::Key)
        raise ArgumentError, "our_pubkey must be Bitcoin::BIP324::EllSwiftPubkey" if our_pubkey && !our_pubkey.is_a?(Bitcoin::BIP324::EllSwiftPubkey)
        @our_pubkey = our_pubkey ? our_pubkey : key.create_ell_pubkey
        @key = key
      end

      # Setup when the other side's public key is received.
      # @param [Bitcoin::BIP324::EllSwiftPubkey] their_pubkey
      # @param [Boolean] initiator Set true if we are the initiator establishing the v2 P2P connection.
      def setup(their_pubkey, initiator)
        salt = 'bitcoin_v2_shared_secret' + Bitcoin.chain_params.magic_head.htb
        ecdh_secret = BIP324.v2_ecdh(key.priv_key, their_pubkey, our_pubkey, initiator).htb
        terminator = hkdf_sha256(ecdh_secret, salt, 'garbage_terminators')
        if initiator
          self.send_l_cipher = hkdf_sha256(ecdh_secret, salt, 'initiator_L').bth
          self.send_p_cipher = hkdf_sha256(ecdh_secret, salt, 'initiator_P').bth
          self.recv_l_cipher = hkdf_sha256(ecdh_secret, salt, 'responder_L').bth
          self.recv_p_cipher = hkdf_sha256(ecdh_secret, salt, 'responder_P').bth
          self.send_garbage_terminator = terminator[0...16].bth
          self.recv_garbage_terminator = terminator[16..-1].bth
        else
          self.recv_l_cipher = hkdf_sha256(ecdh_secret, salt, 'initiator_L').bth
          self.recv_p_cipher = hkdf_sha256(ecdh_secret, salt, 'initiator_P').bth
          self.send_l_cipher = hkdf_sha256(ecdh_secret, salt, 'responder_L').bth
          self.send_p_cipher = hkdf_sha256(ecdh_secret, salt, 'responder_P').bth
          self.recv_garbage_terminator = terminator[0...16].bth
          self.send_garbage_terminator = terminator[16..-1].bth
        end
        self.session_id = hkdf_sha256(ecdh_secret, salt, 'session_id').bth
      end
    end
  end
end