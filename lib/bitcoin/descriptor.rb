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
    autoload :MultiA,  'bitcoin/descriptor/multi_a'
    autoload :SortedMultiA, 'bitcoin/descriptor/sorted_multi_a'
    autoload :RawTr,  'bitcoin/descriptor/raw_tr'
    autoload :Checksum, 'bitcoin/descriptor/checksum'

    module_function

    # Generate pk() descriptor.
    # @param [String] key private key or public key with hex format
    # @return [Bitcoin::Descriptor::Pk]
    def pk(key)
      Pk.new(key)
    end

    # Generate pkh() descriptor.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Pkh]
    def pkh(key)
      Pkh.new(key)
    end

    # Generate wpkh() descriptor.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Wpkh]
    def wpkh(key)
      Wpkh.new(key)
    end

    # Generate sh() descriptor.
    # @param [Bitcoin::Descriptor::Base] exp script expression to be embed.
    # @return [Bitcoin::Descriptor::Sh]
    def sh(exp)
      Sh.new(exp)
    end

    # Generate wsh() descriptor.
    # @param [Bitcoin::Descriptor::Expression] exp script expression to be embed.
    # @return [Bitcoin::Descriptor::Wsh]
    def wsh(exp)
      Wsh.new(exp)
    end

    # Generate combo() descriptor.
    # If the key is compressed, it also includes `wpkh(KEY)` and `sh(wpkh(KEY))`.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Combo]
    def combo(key)
      Combo.new(key)
    end

    # Generate multi() descriptor.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::Multi] multisig script.
    def multi(threshold, *keys)
      Multi.new(threshold, keys)
    end

    # Generate sortedmulti() descriptor.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::SortedMulti]
    def sortedmulti(threshold, *keys)
      SortedMulti.new(threshold, keys)
    end

    # Generate raw() descriptor.
    # @param [String] hex Hex string of bitcoin script.
    # @return [Bitcoin::Descriptor::Raw]
    def raw(hex)
      Raw.new(hex)
    end

    # Generate addr() descriptor.
    # @param [String] addr Bitcoin address.
    # @return [Bitcoin::Descriptor::Addr]
    def addr(addr)
      Addr.new(addr)
    end

    # Generate tr() descriptor.
    # @param [String] key
    # @param [String] tree
    # @return [Bitcoin::Descriptor::Tr]
    def tr(key, tree = nil)
      Tr.new(key, tree)
    end

    # Generate rawtr() descriptor.
    # @param [String] key
    # @return [Bitcoin::Descriptor::RawTr]
    def rawtr(key)
      RawTr.new(key)
    end

    # Generate multi_a() descriptor.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::MultiA] multisig script.
    def multi_a(threshold, *keys)
      MultiA.new(threshold, keys)
    end

    # Generate sortedmulti_a() descriptor.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::SortedMulti]
    def sortedmulti_a(threshold, *keys)
      SortedMultiA.new(threshold, keys)
    end

    # Parse descriptor string.
    # @param [String] string Descriptor string.
    # @return [Bitcoin::Descriptor::Expression]
    def parse(string, top_level = true)
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
        sh(parse(args_str, false))
      when 'wsh'
        wsh(parse(args_str, false))
      when 'combo'
        combo(args_str)
      when 'multi', 'sortedmulti', 'multi_a', 'sortedmulti_a'
        args = args_str.split(',')
        threshold = args[0].to_i
        keys = args[1..-1]
        case exp
        when 'multi'
          multi(threshold, *keys)
        when 'sortedmulti'
          sortedmulti(threshold, *keys)
        when 'multi_a'
          raise ArgumentError, "Can only have multi_a/sortedmulti_a inside tr()." if top_level
          multi_a(threshold, *keys)
        when 'sortedmulti_a'
          raise ArgumentError, "Can only have multi_a/sortedmulti_a inside tr()." if top_level
          sortedmulti_a(threshold, *keys)
        end
      when 'raw'
        raw(args_str)
      when 'addr'
        addr(args_str)
      when 'tr'
        key, rest = args_str.split(',', 2)
        if rest.nil?
          tr(key)
        elsif rest.start_with?('{')
          tr(key, parse_nested_string(rest))
        else
          tr(key, parse(rest, false))
        end
      when 'rawtr'
        rawtr(args_str)
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

    def parse_nested_string(string)
      return nil if string.nil?
      stack = []
      current = []
      buffer = ""
      string.each_char do |c|
        case c
        when '{'
          stack << current
          current = []
        when '}'
          unless buffer.empty?
            current << parse(buffer, false)
            buffer = ""
          end
          nested = current
          current = stack.pop
          current << nested
        when ','
          unless buffer.empty?
            current << parse(buffer, false)
            buffer = ""
          end
        else
          buffer << c
        end
      end
      current << parse(buffer, false) unless buffer.empty?
      current.first
    end
  end
end