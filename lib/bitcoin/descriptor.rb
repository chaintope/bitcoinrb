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
    autoload :MuSig, 'bitcoin/descriptor/musig'
    autoload :Sp, 'bitcoin/descriptor/sp'

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

    # Generate musig() descriptor.
    # @param [Array] keys An array fo keys.
    # @param [String] path
    # @return [Bitcoin::Descriptor::MuSig]
    def musig(*keys, path: nil)
      MuSig.new(keys, path)
    end

    # Generate sp() descriptor for Silent Payment.
    # @param [String] key_or_scan_key Either a spscan/spspend encoded key (single-argument form),
    #   or the scan key for two-argument form.
    # @param [String, Expression, nil] spend_key The spend key (for two-argument form) or nil for single-argument form.
    # @return [Bitcoin::Descriptor::Sp]
    def sp(key_or_scan_key, spend_key = nil)
      Sp.new(key_or_scan_key, spend_key)
    end

    # Parse descriptor string.
    # @param [String] string Descriptor string.
    # @return [Bitcoin::Descriptor::Expression]
    def parse(string, top_level = true)
      validate_checksum!(string)
      content, _ = string.split('#')
      matched = content.to_s.match(/\A(\w+)\((.*)\)(.*)\z/) # split "tag(10, 20)/0/1"
      raise ArgumentError, "Invalid descriptor format: '#{string}'." unless matched
      exp, args_str, path = matched.captures
      raise ArgumentError, 'Invalid format.' if exp != 'musig' && !path.empty?
      if %w[pk pkh wpkh sh wsh combo raw addr rawtr].include?(exp) && split_two(args_str)[1]
        raise ArgumentError, "#{exp}() takes one argument."
      end

      case exp
      when 'pk'
        if args_str.include?('(')
          pk(parse(args_str))
        else
          pk(args_str)
        end
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
        # Only a plain decimal number, as ToIntegral in Bitcoin Core: no sign, no space, no other characters.
        raise ArgumentError, "Multisig threshold '#{args[0]}' is not valid." unless args[0] =~ /\A[0-9]+\z/
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
        key, tree = split_two(args_str)
        key = parse(key) if key.include?('(')
        tree.nil? ? tr(key) : tr(key, parse_tree_string(tree))
      when 'rawtr'
        if args_str.include?('(')
          rawtr(parse(args_str, false))
        else
          rawtr(args_str)
        end
      when 'musig'
        keys = args_str.split(',')
        path.empty? ? musig(*keys) : musig(*keys, path: path)
      when 'sp'
        scan_key, spend_key_str = split_two(args_str)
        if spend_key_str.nil?
          # Single argument form: spscan or spspend encoded key
          sp(scan_key)
        else
          # Two argument form: separate scan and spend keys
          spend_key = spend_key_str.include?('(') ? parse(spend_key_str, false) : spend_key_str
          sp(scan_key, spend_key)
        end
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

    # Parse the script tree of a tr() expression the way Bitcoin Core does. A tree is a script expression or
    # '{' tree ',' tree '}', and nothing may follow it.
    # @param [String] string The arguments of tr() after the key.
    # @return [Bitcoin::Descriptor::Expression, Array] A leaf, or a two element Array of subtrees.
    # @raise [ArgumentError] If +string+ is not a tree.
    def parse_tree_string(string)
      rest = string
      branches = [] # one entry per open brace: false while in its left subtree, true while in its right one
      lefts = []    # the finished left subtree of every brace which is in its right subtree
      tree = loop do
        while rest.start_with?('{')
          rest = rest[1..]
          branches << false
          raise ArgumentError, "tr() supports at most #{TAPROOT_CONTROL_MAX_NODE_COUNT} nesting levels." if branches.size > TAPROOT_CONTROL_MAX_NODE_COUNT
        end
        leaf, rest = take_expression(rest)
        raise ArgumentError, 'tr(): expected script expression.' if leaf.empty?
        node = parse(leaf, false)
        # Close every brace whose right subtree this finishes.
        while branches.any? && branches.last
          raise ArgumentError, "tr(): expected '}' after script expression." unless rest.start_with?('}')
          rest = rest[1..]
          branches.pop
          node = [lefts.pop, node]
        end
        break node if branches.empty?
        # This finishes the left subtree of a brace, so its right one follows a comma.
        raise ArgumentError, "tr(): expected ',' after script expression." unless rest.start_with?(',')
        rest = rest[1..]
        branches[-1] = true
        lefts << node
      end
      raise ArgumentError, "tr(): expected ')' after script expression." unless rest.empty?
      tree
    end

    # Split off the leading script or key expression of +string+. It ends at the first ',', ')' or '}'
    # outside any parentheses or braces, as Expr does in Bitcoin Core.
    # @param [String] string
    # @return [Array] The expression and the rest of +string+.
    def take_expression(string)
      level = 0
      string.each_char.with_index do |c, i|
        if c == '(' || c == '{'
          level += 1
        elsif level > 0 && (c == ')' || c == '}')
          level -= 1
        elsif level.zero? && (c == ')' || c == '}' || c == ',')
          return [string[0...i], string[i..]]
        end
      end
      [string, '']
    end

    def split_two(content)
      paren_depth = 0
      split_pos = content.chars.find_index do |char|
        case char
        when '(' then paren_depth += 1; false
        when ')' then paren_depth -= 1; false
        when ',' then paren_depth == 0
        else false
        end
      end

      if split_pos
        [content[0...split_pos], content[split_pos+1..-1]]
      else
        [content, nil]
      end
    end
  end
end