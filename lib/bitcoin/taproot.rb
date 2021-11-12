module Bitcoin
  module Taproot

    class Error < StandardError; end

    autoload :LeafNode, 'bitcoin/taproot/leaf_node'
    autoload :SimpleBuilder, 'bitcoin/taproot/simple_builder'

    module_function

    # Calculate tweak value from +internal_pubkey+ and +merkle_root+.
    # @param [Bitcoin::Key] internal_key Internal key with hex format(x-only public key).
    # @param [String] merkle_root Merkle root value of script tree with hex format.
    # @return [String] teak value with binary format.
    def tweak(internal_key, merkle_root)
      raise Error, 'internal_key must be Bitcoin::Key object.' unless internal_key.is_a?(Bitcoin::Key)

      merkle_root ||= ''
      t = Bitcoin.tagged_hash('TapTweak', internal_key.xonly_pubkey.htb + merkle_root.htb)
      raise Error, 'tweak value exceeds the curve order' if t.bti >= ECDSA::Group::Secp256k1.order

      t
    end

    # Generate tweak public key form +internal_pubkey+ and +merkle_root+.
    # @param [Bitcoin::Key] internal_key Internal key with hex format(x-only public key).
    # @param [String] merkle_root Merkle root value of script tree with hex format.
    # @return [Bitcoin::Key] Tweaked public key.
    def tweak_public_key(internal_key, merkle_root)
      t = tweak(internal_key, merkle_root)
      key = Bitcoin::Key.new(priv_key: t.bth, key_type: Key::TYPES[:compressed])
      Bitcoin::Key.from_point(key.to_point + internal_key.to_point)
    end

    # Generate tweak private key
    #
    def tweak_private_key(internal_private_key, merkle_root)
      p = internal_private_key.to_point
      private_key = p.has_even_y? ? internal_private_key.priv_key.to_i(16) :
                      ECDSA::Group::Secp256k1.order - internal_private_key.priv_key.to_i(16)
      t = tweak(internal_private_key, merkle_root)
      Bitcoin::Key.new(priv_key: ((t.bti + private_key) % ECDSA::Group::Secp256k1.order).to_even_length_hex)
    end
  end
end
