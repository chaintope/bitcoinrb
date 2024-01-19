module Bitcoin
  module BIP324
    # The BIP324 packet cipher, encapsulating its key derivation, stream cipher, and AEAD.
    class Cipher
      include Bitcoin::Util

      HEADER = [1 << 7].pack('C')

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
          self.send_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'initiator_L'))
          self.send_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'initiator_P'))
          self.recv_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'responder_L'))
          self.recv_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'responder_P'))
          self.send_garbage_terminator = terminator[0...16].bth
          self.recv_garbage_terminator = terminator[16..-1].bth
        else
          self.recv_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'initiator_L'))
          self.recv_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'initiator_P'))
          self.send_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'responder_L'))
          self.send_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'responder_P'))
          self.recv_garbage_terminator = terminator[0...16].bth
          self.send_garbage_terminator = terminator[16..-1].bth
        end
        self.session_id = hkdf_sha256(ecdh_secret, salt, 'session_id').bth
      end

      # Encrypt a packet. Only after setup.
      #
      def encrypt(contents, aad: '', ignore: false)
        raise RuntimeError, "contents size over." unless contents.bytesize <= (2**24 - 1)

        # encrypt length
        len = Array.new(3)
        len[0] = contents.bytesize & 0xff
        len[1] = (contents.bytesize >> 8) & 0xff
        len[2] = (contents.bytesize >> 16) & 0xff
        enc_plaintext_len = send_l_cipher.encrypt(len.pack('C*'))

        # encrypt contents
        header = ignore ? HEADER : "00".htb
        plaintext = header + contents
        aead_ciphertext = send_p_cipher.encrypt(aad, plaintext)
        enc_plaintext_len + aead_ciphertext
      end

      def decrypt

      end
    end
  end
end