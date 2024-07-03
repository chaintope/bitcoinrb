module Bitcoin

  module Descriptor

    include Bitcoin::Opcodes
    autoload :Expression, 'bitcoin/descriptor/expression'
    autoload :KeyExpression, 'bitcoin/descriptor/key_expression'
    autoload :ScriptExpression, 'bitcoin/descriptor/script_expression'
    autoload :Pk, 'bitcoin/descriptor/pk'
    autoload :Pkh, 'bitcoin/descriptor/pkh'
    autoload :Wpkh, 'bitcoin/descriptor/wpkh'
    autoload :Sh, 'bitcoin/descriptor/sh'
    autoload :Wsh, 'bitcoin/descriptor/wsh'
    autoload :Combo, 'bitcoin/descriptor/combo'
    autoload :Multi, 'bitcoin/descriptor/multi'
    autoload :SortedMulti, 'bitcoin/descriptor/sorted_multi'

    # generate P2PK output for the given public key.
    # @param [String] key private key or public key with hex format
    # @return [Bitcoin::Descriptor::Pk]
    def pk(key)
      Pk.new(key)
    end

    # generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Pkh]
    def pkh(key)
      Pkh.new(key)
    end

    # generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Wpkh]
    def wpkh(key)
      Wpkh.new(key)
    end

    # generate P2SH embed the argument.
    # @param [Bitcoin::Descriptor::Base] exp script expression to be embed.
    # @return [Bitcoin::Descriptor::Sh]
    def sh(exp)
      Sh.new(exp)
    end

    # generate P2WSH embed the argument.
    # @param [Bitcoin::Descriptor::Expression] exp script expression to be embed.
    # @return [Bitcoin::Descriptor::Wsh]
    def wsh(exp)
      Wsh.new(exp)
    end

    # An alias for the collection of `pk(KEY)` and `pkh(KEY)`.
    # If the key is compressed, it also includes `wpkh(KEY)` and `sh(wpkh(KEY))`.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Combo]
    def combo(key)
      Combo.new(key)
    end

    # generate multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::Multi] multisig script.
    def multi(threshold, *keys)
      Multi.new(threshold, keys)
    end

    # generate sorted multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::SortedMulti]
    def sortedmulti(threshold, *keys)
      SortedMulti.new(threshold, keys)
    end
  end
end