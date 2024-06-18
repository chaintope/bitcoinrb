# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

module Bitcoin
  module Secp256k1

    # binding for secp256k1 (https://github.com/bitcoin-core/secp256k1/)
    # tag: v0.4.0
    # this is not included by default, to enable set shared object path to ENV['SECP256K1_LIB_PATH']
    # for linux, ENV['SECP256K1_LIB_PATH'] = '/usr/local/lib/libsecp256k1.so' or '/usr/lib64/libsecp256k1.so'
    # for mac,
    module Native
      include ::FFI::Library
      extend self

      SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
      SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
      SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)

      SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
      SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
      SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

      # Flags to pass to secp256k1_context_create.
      SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
      SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)

      # Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export.
      SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
      SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)

      module_function

      def init
        raise 'secp256k1 library dose not found.' unless File.exist?(ENV['SECP256K1_LIB_PATH'])
        ffi_lib(ENV['SECP256K1_LIB_PATH'])
        load_functions
      end

      def load_functions
        attach_function(:secp256k1_context_create, [:uint], :pointer)
        attach_function(:secp256k1_context_destroy, [:pointer], :void)
        attach_function(:secp256k1_context_randomize, [:pointer, :pointer], :int)
        attach_function(:secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ec_seckey_verify, [:pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int)
        attach_function(:secp256k1_ecdsa_signature_serialize_der, [:pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int)
        attach_function(:secp256k1_ecdsa_signature_parse_der, [:pointer, :pointer, :pointer, :size_t], :int)
        attach_function(:secp256k1_ecdsa_signature_normalize, [:pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_schnorrsig_sign32, [:pointer, :pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_schnorrsig_verify, [:pointer, :pointer, :pointer, :size_t, :pointer], :int)
        attach_function(:secp256k1_keypair_create, [:pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_xonly_pubkey_parse, [:pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_sign_recoverable, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_recoverable_signature_serialize_compact, [:pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_recover, [:pointer, :pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ecdsa_recoverable_signature_parse_compact, [:pointer, :pointer, :pointer, :int], :int)
        attach_function(:secp256k1_ellswift_decode, [:pointer, :pointer, :pointer], :int)
        attach_function(:secp256k1_ellswift_create, [:pointer, :pointer, :pointer, :pointer], :int)
        # Define function pointer
        callback(:secp256k1_ellswift_xdh_hash_function, [:pointer, :pointer, :pointer, :pointer, :pointer], :int)
        attach_variable(:secp256k1_ellswift_xdh_hash_function_bip324, :secp256k1_ellswift_xdh_hash_function)
        attach_function(:secp256k1_ellswift_xdh, [:pointer, :pointer, :pointer, :pointer, :pointer, :int, :pointer, :pointer], :int)
      end

      def with_context(flags: (SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
        init
        begin
          context = secp256k1_context_create(flags)
          ret, tries, max = 0, 0, 20
          while ret != 1
            raise 'secp256k1_context_randomize failed.' if tries >= max
            tries += 1
            ret = secp256k1_context_randomize(context, FFI::MemoryPointer.from_string(SecureRandom.random_bytes(32)))
          end
          yield(context) if block_given?
        ensure
          secp256k1_context_destroy(context)
        end
      end

      # generate ec private key and public key
      def generate_key_pair(compressed: true)
        with_context do |context|
          ret, tries, max = 0, 0, 20
          while ret != 1
            raise 'secp256k1_ec_seckey_verify in generate_key_pair failed.' if tries >= max
            tries += 1
            priv_key = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.random_bytes(32))
            ret = secp256k1_ec_seckey_verify(context, priv_key)
          end
          private_key =  priv_key.read_string(32).bth
          [private_key , generate_pubkey_in_context(context,  private_key, compressed: compressed) ]
        end
      end

      # generate bitcoin key object
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Bitcoin::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      def generate_pubkey(priv_key, compressed: true)
        with_context do |context|
          generate_pubkey_in_context(context, priv_key, compressed: compressed)
        end
      end

      # sign data.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key with hex format using sign
      # @param [String] extra_entropy a extra entropy with binary format for rfc6979
      # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
      # @return [String] signature data with binary format
      def sign_data(data, privkey, extra_entropy = nil, algo: :ecdsa)
        case algo
        when :ecdsa
          sign_ecdsa(data, privkey, extra_entropy)
        when :schnorr
          sign_schnorr(data, privkey, extra_entropy)
        else
          nil
        end
      end

      # Sign data with compact format.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign with hex format
      # @return [Array[signature, recovery id]]
      def sign_compact(data, privkey)
        with_context do |context|
          sig = FFI::MemoryPointer.new(:uchar, 65)
          hash =FFI::MemoryPointer.new(:uchar, data.bytesize).put_bytes(0, data)
          priv_key = privkey.htb
          sec_key = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
          result = secp256k1_ecdsa_sign_recoverable(context, sig, hash, sec_key, nil, nil)
          raise 'secp256k1_ecdsa_sign_recoverable failed.' if result == 0

          output = FFI::MemoryPointer.new(:uchar, 64)
          rec = FFI::MemoryPointer.new(:uint64)
          result = secp256k1_ecdsa_recoverable_signature_serialize_compact(context, output, rec, sig)
          raise 'secp256k1_ecdsa_recoverable_signature_serialize_compact failed.' unless result == 1

          raw_sig = output.read_string(64)
          [ECDSA::Signature.new(raw_sig[0...32].bti, raw_sig[32..-1].bti), rec.read(:int)]
        end
      end

      # Recover public key from compact signature.
      # @param [String] data message digest using signature.
      # @param [String] signature signature with binary format.
      # @param [Integer] rec recovery id.
      # @param [Boolean] compressed whether compressed public key or not.
      # @return [Bitcoin::Key] Recovered public key.
      def recover_compact(data, signature, rec, compressed)
        with_context do |context|
          sig = FFI::MemoryPointer.new(:uchar, 65)
          input = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, signature[1..-1])
          result = secp256k1_ecdsa_recoverable_signature_parse_compact(context, sig, input, rec)
          raise 'secp256k1_ecdsa_recoverable_signature_parse_compact failed.' unless result == 1

          pubkey = FFI::MemoryPointer.new(:uchar, 64)
          msg = FFI::MemoryPointer.new(:uchar, data.bytesize).put_bytes(0, data)
          result = secp256k1_ecdsa_recover(context, pubkey, sig, msg)
          raise 'secp256k1_ecdsa_recover failed.' unless result == 1

          pubkey = serialize_pubkey_internal(context, pubkey.read_string(64), compressed)
          Bitcoin::Key.new(pubkey: pubkey, compressed: compressed)
        end
      end

      # verify signature
      # @param [String] data a data with binary format.
      # @param [String] sig signature data with binary format
      # @param [String] pubkey a public key with hex format using verify.
      # # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
      # @return [Boolean] verification result.
      def verify_sig(data, sig, pubkey, algo: :ecdsa)
        case algo
        when :ecdsa
          verify_ecdsa(data, sig, pubkey)
        when :schnorr
          verify_schnorr(data, sig, pubkey)
        else
          false
        end
      end

      # # validate whether this is a valid public key (more expensive than IsValid())
      # @param [String] pub_key public key with hex format.
      # @param [Boolean] allow_hybrid whether support hybrid public key.
      # @return [Boolean] If valid public key return true, otherwise false.
      def parse_ec_pubkey?(pub_key, allow_hybrid = false)
        pub_key = pub_key.htb
        return false if !allow_hybrid && ![0x02, 0x03, 0x04].include?(pub_key[0].ord)
        with_context do |context|
          pubkey = FFI::MemoryPointer.new(:uchar, pub_key.bytesize).put_bytes(0, pub_key)
          internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pub_key.bytesize)
          result == 1
        end
      end

      # Create key pair data from private key.
      # @param [String] priv_key with hex format
      # @return [String] key pair data with hex format. data  = private key(32 bytes) | public key(64 bytes).
      def create_keypair(priv_key)
        with_context do |context|
          priv_key = priv_key.htb
          secret = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
          raise 'priv_key is invalid.' unless secp256k1_ec_seckey_verify(context, secret)
          keypair = FFI::MemoryPointer.new(:uchar, 96)
          raise 'priv_key is invalid.' unless secp256k1_keypair_create(context, keypair, secret) == 1
          keypair.read_string(96).bth
        end
      end

      # Check whether valid x-only public key or not.
      # @param [String] pub_key x-only public key with hex format(32 bytes).
      # @return [Boolean] result.
      def valid_xonly_pubkey?(pub_key)
        begin
          full_pubkey_from_xonly_pubkey(pub_key)
        rescue Exception
          return false
        end
        true
      end

      # Decode ellswift public key.
      # @param [String] ell_key ElligatorSwift key with binary format.
      # @return [String] Decoded public key with hex format
      def ellswift_decode(ell_key)
        with_context do |context|
          ell64 = FFI::MemoryPointer.new(:uchar, ell_key.bytesize).put_bytes(0, ell_key)
          internal = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ellswift_decode(context, internal, ell64)
          raise ArgumentError, 'Decode failed.' unless result == 1
          serialize_pubkey_internal(context, internal, true)
        end
      end

      # Compute an ElligatorSwift public key for a secret key.
      # @param [String] priv_key private key with hex format
      # @return [String] ElligatorSwift public key with hex format.
      def ellswift_create(priv_key)
        with_context(flags: SECP256K1_CONTEXT_SIGN) do |context|
          ell64 = FFI::MemoryPointer.new(:uchar, 64)
          seckey32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, priv_key.htb)
          result = secp256k1_ellswift_create(context, ell64, seckey32, nil)
          raise ArgumentError, 'Failed to create ElligatorSwift public key.' unless result == 1
          ell64.read_string(64).bth
        end
      end

      # Compute X coordinate of shared ECDH point between elswift pubkey and privkey.
      # @param [Bitcoin::BIP324::EllSwiftPubkey] their_ell_pubkey Their EllSwift public key.
      # @param [Bitcoin::BIP324::EllSwiftPubkey] our_ell_pubkey Our EllSwift public key.
      # @param [String] priv_key private key with hex format.
      # @param [Boolean] initiating Whether your initiator or not.
      # @return [String] x coordinate with hex format.
      def ellswift_ecdh_xonly(their_ell_pubkey, our_ell_pubkey, priv_key, initiating)
        with_context(flags: SECP256K1_CONTEXT_SIGN) do |context|
          output = FFI::MemoryPointer.new(:uchar, 32)
          our_ell_ptr = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, our_ell_pubkey.key)
          their_ell_ptr = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, their_ell_pubkey.key)
          seckey32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, priv_key.htb)
          hashfp = secp256k1_ellswift_xdh_hash_function_bip324
          result = secp256k1_ellswift_xdh(context, output,
                                          initiating ? our_ell_ptr : their_ell_ptr,
                                          initiating ? their_ell_ptr : our_ell_ptr,
                                          seckey32,
                                          initiating ? 0 : 1,
                                          hashfp, nil)
          raise ArgumentError, "secret was invalid or hashfp returned 0" unless result == 1
          output.read_string(32).bth
        end
      end

      private

      # Calculate full public key(64 bytes) from public key(32 bytes).
      # @param [String] pub_key x-only public key with hex format(32 bytes).
      # @return [String] x-only public key with hex format(64 bytes).
      def full_pubkey_from_xonly_pubkey(pub_key)
        with_context do |context|
          pubkey = pub_key.htb
          raise ArgumentError, "Pubkey size must be #{X_ONLY_PUBKEY_SIZE} bytes." unless pubkey.bytesize == X_ONLY_PUBKEY_SIZE
          xonly_pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
          full_pubkey = FFI::MemoryPointer.new(:uchar, 64)
          raise ArgumentError, 'An invalid public key was specified.' unless secp256k1_xonly_pubkey_parse(context, full_pubkey, xonly_pubkey) == 1
          full_pubkey.read_string(64).bth
        end
      end

      def generate_pubkey_in_context(context, privkey, compressed: true)
        internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
        result = secp256k1_ec_pubkey_create(context, internal_pubkey, privkey.htb)
        raise 'error creating pubkey' unless result
        serialize_pubkey_internal(context, internal_pubkey, compressed)
      end

      def sign_ecdsa(data, privkey, extra_entropy)
        with_context do |context|
          secret = FFI::MemoryPointer.new(:uchar, privkey.htb.bytesize).put_bytes(0, privkey.htb)
          raise 'priv_key is invalid' unless secp256k1_ec_seckey_verify(context, secret)

          internal_signature = FFI::MemoryPointer.new(:uchar, 64)
          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          entropy = extra_entropy ? FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, extra_entropy) : nil

          ret, tries, max = 0, 0, 20

          while ret != 1
            raise 'secp256k1_ecdsa_sign failed.' if tries >= max
            tries += 1
            ret = secp256k1_ecdsa_sign(context, internal_signature, msg32, secret, nil, entropy)
          end

          signature = FFI::MemoryPointer.new(:uchar, 72)
          signature_len = FFI::MemoryPointer.new(:uint64).put_uint64(0, 72)
          result = secp256k1_ecdsa_signature_serialize_der(context, signature, signature_len, internal_signature)
          raise 'secp256k1_ecdsa_signature_serialize_der failed' unless result

          signature.read_string(signature_len.read_uint64)
        end
      end

      def sign_schnorr(data, privkey, aux_rand = nil)
        with_context do |context|
          keypair = create_keypair(privkey).htb
          keypair = FFI::MemoryPointer.new(:uchar, 96).put_bytes(0, keypair)
          signature = FFI::MemoryPointer.new(:uchar, 64)
          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          aux_rand = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, aux_rand) if aux_rand
          raise 'Failed to generate schnorr signature.' unless secp256k1_schnorrsig_sign32(context, signature, msg32, keypair, aux_rand) == 1
          signature.read_string(64)
        end
      end

      def verify_ecdsa(data, sig, pubkey)
        with_context do |context|
          return false if data.bytesize == 0
          pubkey = pubkey.htb
          pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
          internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pubkey.size)
          return false unless result

          signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)
          internal_signature = FFI::MemoryPointer.new(:uchar, 64)
          result = secp256k1_ecdsa_signature_parse_der(context, internal_signature, signature, signature.size)
          return false unless result

          # libsecp256k1's ECDSA verification requires lower-S signatures, which have not historically been enforced in Bitcoin, so normalize them first.
          secp256k1_ecdsa_signature_normalize(context, internal_signature, internal_signature)

          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          result = secp256k1_ecdsa_verify(context, internal_signature, msg32, internal_pubkey)

          result == 1
        end
      end

      def verify_schnorr(data, sig, pubkey)
        with_context do |context|
          return false if data.bytesize == 0
          pubkey = full_pubkey_from_xonly_pubkey(pubkey).htb
          xonly_pubkey = FFI::MemoryPointer.new(:uchar, pubkey.bytesize).put_bytes(0, pubkey)
          signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)
          msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
          result = secp256k1_schnorrsig_verify(context, signature, msg32, 32, xonly_pubkey)
          result == 1
        end
      end

      # Serialize public key.
      def serialize_pubkey_internal(context, pubkey_input, compressed)
        pubkey = FFI::MemoryPointer.new(:uchar, 65)
        pubkey_len = FFI::MemoryPointer.new(:uint64)
        result = if compressed
                   pubkey_len.put_uint64(0, 33)
                   secp256k1_ec_pubkey_serialize(context, pubkey, pubkey_len, pubkey_input, SECP256K1_EC_COMPRESSED)
                 else
                   pubkey_len.put_uint64(0, 65)
                   secp256k1_ec_pubkey_serialize(context, pubkey, pubkey_len, pubkey_input, SECP256K1_EC_UNCOMPRESSED)
                 end
        raise 'error serialize pubkey' unless result || pubkey_len.read_uint64 > 0
        pubkey.read_string(pubkey_len.read_uint64).bth
      end

    end
  end
end
