module Bitcoin
  module BIP324

    module ChaCha20
      module_function

      INDICES = [
        [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
        [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]
      ]

      CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

      # Rotate the 32-bit value v left by bits bits.
      # @param [Integer] v
      # @param [Integer] bits
      # @return [Integer]
      def rotl32(v, bits)
        raise Bitcoin::BIP324::Error, "v must be integer" unless v.is_a?(Integer)
        raise Bitcoin::BIP324::Error, "bits must be integer" unless bits.is_a?(Integer)
        ((v << bits) & 0xffffffff) | (v >> (32 - bits))
      end

      # Apply a ChaCha20 double round to 16-element state array +s+.
      # @param [Array[Integer]] s
      # @return
      def double_round(s)
        raise Bitcoin::BIP324::Error, "s must be Array" unless s.is_a?(Array)
        INDICES.each do |a, b, c, d|
          s[a] = (s[a] + s[b]) & 0xffffffff
          s[d] = rotl32(s[d] ^ s[a], 16)
          s[c] = (s[c] + s[d]) & 0xffffffff
          s[b] = rotl32(s[b] ^ s[c], 12)
          s[a] = (s[a] + s[b]) & 0xffffffff
          s[d] = rotl32(s[d] ^ s[a], 8)
          s[c] = (s[c] + s[d]) & 0xffffffff
          s[b] = rotl32(s[b] ^ s[c], 7)
        end
        s
      end

      # Compute the 64-byte output of the ChaCha20 block function.
      # @param [String] key 32-bytes key with binary format.
      # @param [String] nonce 12-byte nonce with binary format.
      # @param [Integer] count 32-bit integer counter.
      # @return [String] 64-byte output.
      def block(key, nonce, count)
        raise Bitcoin::BIP324::Error, "key must be 32 byte string" if !key.is_a?(String) || key.bytesize != 32
        raise Bitcoin::BIP324::Error, "nonce must be 12 byte string" if !nonce.is_a?(String) || nonce.bytesize != 12
        raise Bitcoin::BIP324::Error, "count must be integer" unless count.is_a?(Integer)
        # Initialize state
        init = Array.new(16, 0)
        4.times {|i| init[i] = CONSTANTS[i]}
        key = key.unpack("V*")
        8.times {|i| init[4 + i] = key[i]}
        init[12] = count
        nonce = nonce.unpack("V*")
        3.times {|i| init[13 + i] = nonce[i]}
        # Perform 20 rounds
        state = init.dup
        10.times do
          state = double_round(state)
        end
        # Add initial values back into state.
        16.times do |i|
          state[i] = (state[i] + init[i]) & 0xffffffff
        end
        state.pack("V16")
      end
    end

    # Rekeying wrapper stream cipher around ChaCha20.
    class FSChaCha20
      attr_accessor :key
      attr_reader :rekey_interval
      attr_accessor :chunk_counter
      attr_accessor :block_counter
      attr_accessor :key_stream

      def initialize(initial_key, rekey_interval = BIP324::REKEY_INTERVAL)
        @block_counter = 0
        @chunk_counter = 0
        @key = initial_key
        @rekey_interval = rekey_interval
        @key_stream = ''
      end

      # Encrypt a chunk
      # @param [String] chunk Chunk data with binary format.
      # @return [String] Encrypted data with binary format.
      def encrypt(chunk)
        crypt(chunk)
      end

      # Decrypt a chunk
      # @param [String] chunk Chunk data with binary format.
      # @return [String] Decrypted data with binary format.
      def decrypt(chunk)
        crypt(chunk)
      end

      private

      def key_stream_bytes(n_bytes)
        while key_stream.bytesize < n_bytes
          nonce = [0, (chunk_counter / REKEY_INTERVAL)].pack("VQ<")
          self.key_stream << ChaCha20.block(key, nonce, block_counter)
          self.block_counter += 1
        end
        ret = self.key_stream[0...n_bytes]
        self.key_stream = self.key_stream[n_bytes..-1]
        ret
      end

      # Encrypt or decrypt a chunk.
      # @param [String] chunk Chunk data with binary format.
      # @return [String]
      def crypt(chunk)
        ks = key_stream_bytes(chunk.bytesize)
        ret = chunk.unpack("C*").zip(ks.unpack("C*")).map do |c, k|
          c ^ k
        end.pack("C*")
        if (self.chunk_counter + 1) % rekey_interval == 0
          self.key = key_stream_bytes(32)
          self.block_counter = 0
        end
        self.chunk_counter += 1
        ret
      end
    end
  end
end
