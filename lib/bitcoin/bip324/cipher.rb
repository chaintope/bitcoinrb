module Bitcoin
  module BIP324
    # The BIP324 packet cipher, encapsulating its key derivation, stream cipher, and AEAD.
    class Cipher
      include Bitcoin::Util

      HEADER = [1 << 7].pack('C')
      HEADER_LEN = 1
      LENGTH_LEN = 3
      EXPANSION = LENGTH_LEN + HEADER_LEN + 16

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
      # @raise ArgumentError
      def initialize(key, our_pubkey = nil)
        raise ArgumentError, "key must be Bitcoin::Key" unless key.is_a?(Bitcoin::Key)
        raise ArgumentError, "our_pubkey must be Bitcoin::BIP324::EllSwiftPubkey" if our_pubkey && !our_pubkey.is_a?(Bitcoin::BIP324::EllSwiftPubkey)
        @our_pubkey = our_pubkey ? our_pubkey : key.create_ell_pubkey
        @key = key
      end

      # Setup when the other side's public key is received.
      # @param [Bitcoin::BIP324::EllSwiftPubkey] their_pubkey
      # @param [Boolean] initiator Set true if we are the initiator establishing the v2 P2P connection.
      # @param [Boolean] self_decrypt only for testing, and swaps encryption/decryption keys, so that encryption
      # and decryption can be tested without knowing the other side's private key.
      def setup(their_pubkey, initiator, self_decrypt = false)
        salt = 'bitcoin_v2_shared_secret' + Bitcoin.chain_params.magic_head.htb
        ecdh_secret = BIP324.v2_ecdh(key.priv_key, their_pubkey, our_pubkey, initiator).htb
        terminator = hkdf_sha256(ecdh_secret, salt, 'garbage_terminators')
        side = initiator != self_decrypt
        if side
          self.send_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'initiator_L'))
          self.send_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'initiator_P'))
          self.recv_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'responder_L'))
          self.recv_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'responder_P'))
        else
          self.recv_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'initiator_L'))
          self.recv_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'initiator_P'))
          self.send_l_cipher = FSChaCha20.new(hkdf_sha256(ecdh_secret, salt, 'responder_L'))
          self.send_p_cipher = FSChaCha20Poly1305.new(hkdf_sha256(ecdh_secret, salt, 'responder_P'))
        end
        if initiator
          self.send_garbage_terminator = terminator[0...16].bth
          self.recv_garbage_terminator = terminator[16..-1].bth
        else
          self.recv_garbage_terminator = terminator[0...16].bth
          self.send_garbage_terminator = terminator[16..-1].bth
        end
        self.session_id = hkdf_sha256(ecdh_secret, salt, 'session_id').bth
      end

      # Encrypt a packet. Only after setup.
      # @param [String] contents Packet with binary format.
      # @param [String] aad AAD
      # @param [Boolean] ignore Whether contains ignore bit or not.
      # @raise Bitcoin::BIP324::TooLargeContent
      def encrypt(contents, aad: '', ignore: false)
        raise Bitcoin::BIP324::TooLargeContent unless contents.bytesize <= (2**24 - 1)

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

      # Decrypt a packet. Only after setup.
      # @param [String] input Packet to be decrypt.
      # @param [String] aad AAD
      # @param [Boolean] ignore Whether contains ignore bit or not.
      # @return [String] Plaintext
      # @raise Bitcoin::BIP324::InvalidPaketLength
      def decrypt(input, aad: '', ignore: false)
        len = decrypt_length(input[0...Bitcoin::BIP324::Cipher::LENGTH_LEN])
        raise Bitcoin::BIP324::InvalidPaketLength unless input.bytesize == len + EXPANSION
        recv_p_cipher.decrypt(aad, input[Bitcoin::BIP324::Cipher::LENGTH_LEN..-1])
      end

      private

      # Decrypt the length of a packet. Only after setup.
      # @param [String] input Length packet with binary format.
      # @return [Integer] length
      # @raise Bitcoin::BIP324::InvalidPaketLength
      def decrypt_length(input)
        raise Bitcoin::BIP324::InvalidPaketLength unless input.bytesize == LENGTH_LEN
        ret = recv_l_cipher.decrypt(input)
        b0, b1, b2 = ret.unpack('CCC')
        b0 + (b1 << 8) + (b2 << 16)
      end
    end
  end
end