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
    autoload :Raw, 'bitcoin/descriptor/raw'
    autoload :Addr,  'bitcoin/descriptor/addr'
    autoload :Tr,  'bitcoin/descriptor/tr'
    autoload :Checksum, 'bitcoin/descriptor/checksum'

    module_function

    # Generate P2PK output for the given public key.
    # @param [String] key private key or public key with hex format
    # @return [Bitcoin::Descriptor::Pk]
    def pk(key)
      Pk.new(key)
    end

    # Generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Pkh]
    def pkh(key)
      Pkh.new(key)
    end

    # Generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Wpkh]
    def wpkh(key)
      Wpkh.new(key)
    end

    # Generate P2SH embed the argument.
    # @param [Bitcoin::Descriptor::Base] exp script expression to be embed.
    # @return [Bitcoin::Descriptor::Sh]
    def sh(exp)
      Sh.new(exp)
    end

    # Generate P2WSH embed the argument.
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

    # Generate multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::Multi] multisig script.
    def multi(threshold, *keys)
      Multi.new(threshold, keys)
    end

    # Generate sorted multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::SortedMulti]
    def sortedmulti(threshold, *keys)
      SortedMulti.new(threshold, keys)
    end

    # Generate raw output script about +hex+.
    # @param [String] hex Hex string of bitcoin script.
    # @return [Bitcoin::Descriptor::Raw]
    def raw(hex)
      Raw.new(hex)
    end

    # Generate raw output script about +hex+.
    # @param [String] addr Bitcoin address.
    # @return [Bitcoin::Descriptor::Addr]
    def addr(addr)
      Addr.new(addr)
    end

    # Generate taproot output script descriptor.
    # @param [String] key
    # @param [String] tree
    # @return [Bitcoin::Descriptor::Tr]
    def tr(key, tree = nil)
      Tr.new(key, tree)
    end

    # Parse descriptor string.
    # @param [String] string Descriptor string.
    # @return [Bitcoin::Descriptor::Expression]
    def parse(string)
      validate_checksum!(string)
      content, _ = string.split('#')
      exp, args_str = content.match(/(\w+)\((.+)\)/).captures
      case exp
      when 'pk'
        pk(args_str)
      when 'pkh'
        pkh(args_str)
      when 'wpkh'
        wpkh(args_str)
      when 'sh'
        sh(parse(args_str))
      when 'wsh'
        wsh(parse(args_str))
      when 'combo'
        combo(args_str)
      when 'multi', 'sortedmulti'
        args = args_str.split(',')
        threshold = args[0].to_i
        keys = args[1..-1]
        exp == 'multi' ? multi(threshold, *keys) : sortedmulti(threshold, *keys)
      when 'raw'
        raw(args_str)
      when 'addr'
        addr(args_str)
      when 'tr'
        key, tree = args_str.split(',')
        tr(key, tree)
      else
        raise ArgumentError, "Parse failed: #{string}"
      end
    end

    # Validate descriptor checksum.
    # @raise [ArgumentError] If +descriptor+ has invalid checksum.
    def validate_checksum!(descriptor)
      return unless descriptor.include?("#")
      content, *checksums = descriptor.split("#")
      raise ArgumentError, "Multiple '#' symbols." if checksums.length > 1
      checksum = checksums.first
      len = checksum.nil? ? 0 : checksum.length
      raise ArgumentError, "Expected 8 character checksum, not #{len} characters." unless len == 8
      _, calc_checksum = Checksum.descsum_create(content).split('#')
      unless calc_checksum == checksum
        raise ArgumentError, "Provided checksum '#{checksum}' does not match computed checksum '#{calc_checksum}'."
      end
    end
  end
end