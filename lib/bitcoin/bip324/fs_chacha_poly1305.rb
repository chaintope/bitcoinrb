module Bitcoin
  module BIP324
    # Class representing a running poly1305 computation.
    class Poly1305

      MODULUS = 2**130 - 5
      TAG_LEN = 16

      attr_reader :r
      attr_reader :s
      attr_accessor :acc

      # Constructor
      #
      def initialize(key)
        @r = key[0...16].reverse.bti & 0xffffffc0ffffffc0ffffffc0fffffff
        @s = key[16..-1].reverse.bti
        @acc = 0
      end

      # Add a message of any length. Input so far must be a multiple of 16 bytes.
      # @param [String] msg A message with binary format.
      # @return [Poly1305] self
      def add(msg, length: nil, padding: false)
        len = length ? length : msg.bytesize
        ((len + 15) / 16).times do |i|
          chunk = msg[(i * 16)...(i * 16 + [16, len - i * 16].min)]
          val = chunk.reverse.bti + 256**(padding ? 16 : chunk.bytesize)
          self.acc = r * (acc + val) % MODULUS
        end
        self
      end

      # Compute the poly1305 tag.
      # @return Poly1305 tag wit binary format.
      def tag
        ECDSA::Format::IntegerOctetString.encode((acc + s) & 0xffffffffffffffffffffffffffffffff, TAG_LEN).reverse
      end
    end

    # Forward-secure wrapper around AEADChaCha20Poly1305.
    class FSChaCha20Poly1305
      attr_accessor :aead
      attr_reader :rekey_interval
      attr_accessor :packet_counter
      attr_accessor :key

      def initialize(initial_key, rekey_interval = REKEY_INTERVAL)
        @packet_counter = 0
        @rekey_interval = rekey_interval
        @key = initial_key
      end

      # Encrypt a +plaintext+ with a specified +aad+.
      # @param [String] aad AAD
      # @param [String] plaintext Data to be encrypted with binary format.
      # @return [String] Ciphertext
      def encrypt(aad, plaintext)
        crypt(aad, plaintext, false)
      end

      # Decrypt a *ciphertext* with a specified +aad+.
      # @param [String] aad AAD
      # @param [String] ciphertext Data to be decrypted with binary format.
      # @return [Array] [header, plaintext]
      def decrypt(aad, ciphertext)
        contents = crypt(aad, ciphertext, true)
        [contents[0], contents[1..-1]]
      end

      private

      # Encrypt or decrypt the specified (plain/cipher)text.
      def crypt(aad, text, is_decrypt)
        nonce = [packet_counter % rekey_interval, packet_counter / rekey_interval].pack("VQ<")
        ret = if is_decrypt
                chacha20_poly1305_decrypt(key, nonce, aad, text)
              else
                chacha20_poly1305_encrypt(key, nonce, aad, text)
              end
        if (packet_counter + 1) % rekey_interval == 0
          rekey_nonce = "ffffffff".htb + nonce[4..-1]
          newkey1 = chacha20_poly1305_encrypt(key, rekey_nonce, "", "00".htb * 32)[0...32]
          newkey2 = ChaCha20.block(key, rekey_nonce, 1)[0...32]
          raise Bitcoin::BIP324::Error, "newkey1 != newkey2" unless newkey1 == newkey2
          self.key = newkey1
        end
        self.packet_counter += 1
        ret
      end

      # Encrypt a plaintext using ChaCha20Poly1305.
      def chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
        msg_len = plaintext.bytesize
        ret = ((msg_len + 63) / 64).times.map do |i|
          now = [64, msg_len - 64 * i].min
          keystream = ChaCha20.block(key, nonce, i + 1)
          now.times.map do |j|
            plaintext[j + 64 * i].unpack1('C') ^ keystream[j].unpack1('C')
          end
        end
        ret = ret.flatten.pack('C*')
        poly1305 = Poly1305.new(ChaCha20.block(key, nonce, 0)[0...32])
        poly1305.add(aad, padding: true).add(ret, padding: true)
        poly1305.add([aad.bytesize, msg_len].pack("Q<Q<"))
        ret + poly1305.tag
      end

      # Decrypt a ChaCha20Poly1305 ciphertext.
      def chacha20_poly1305_decrypt(key, nonce, aad, ciphertext)
        return nil if ciphertext.bytesize < 16
        msg_len = ciphertext.bytesize - 16
        poly1305 = Poly1305.new(ChaCha20.block(key, nonce, 0)[0...32])
        poly1305.add(aad, padding: true)
        poly1305.add(ciphertext, length: msg_len, padding: true)
        poly1305.add([aad.bytesize, msg_len].pack("Q<Q<"))
        return nil unless ciphertext[-16..-1] == poly1305.tag
        ret = ((msg_len + 63) / 64).times.map do |i|
          now = [64, msg_len - 64 * i].min
          keystream = ChaCha20.block(key, nonce, i + 1)
          now.times.map do |j|
            ciphertext[j + 64 * i].unpack1('C') ^ keystream[j].unpack1('C')
          end
        end
        ret.flatten.pack('C*')
      end
    end
  end
end