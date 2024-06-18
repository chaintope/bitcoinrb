# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

module Bitcoin

  # bitcoin script
  class Script
    include Bitcoin::Opcodes
    include Bitcoin::HexConverter

    attr_accessor :chunks

    def initialize
      @chunks = []
    end

    # generate P2PKH script
    # @param [String] pubkey_hash public key hash with hex format
    def self.to_p2pkh(pubkey_hash)
      new << OP_DUP << OP_HASH160 << pubkey_hash << OP_EQUALVERIFY << OP_CHECKSIG
    end

    # generate P2WPKH script
    # @param [String] pubkey_hash public key hash with hex format
    # @return [Bitcoin::Script]
    def self.to_p2wpkh(pubkey_hash)
      new << WITNESS_VERSION_V0 << pubkey_hash
    end

    # Generate P2TR script
    # @param [String or Bitcoin::Key] xonly_pubkey public key with hex format or Bitcoin::Key
    # @return [Bitcoin::Script]
    # @raise ArgumentError
    def self.to_p2tr(xonly_pubkey)
      xonly_pubkey = xonly_pubkey.xonly_pubkey if xonly_pubkey.is_a?(Bitcoin::Key)
      raise ArgumentError, 'Invalid public key size' unless xonly_pubkey.htb.bytesize == Bitcoin::WITNESS_V1_TAPROOT_SIZE
      new << OP_1 << xonly_pubkey
    end

    # generate m of n multisig p2sh script
    # @param [String] m the number of signatures required for multisig
    # @param [Array] pubkeys array of public keys that compose multisig
    # @return [Script, Script] first element is p2sh script, second one is redeem script.
    def self.to_p2sh_multisig_script(m, pubkeys)
      redeem_script = to_multisig_script(m, pubkeys)
      [redeem_script.to_p2sh, redeem_script]
    end

    # generate p2sh script.
    # @param [String] script_hash script hash for P2SH
    # @return [Script] P2SH script
    def self.to_p2sh(script_hash)
      Script.new << OP_HASH160 << script_hash << OP_EQUAL
    end

    # generate p2sh script with this as a redeem script
    # @return [Script] P2SH script
    def to_p2sh
      Script.to_p2sh(to_hash160)
    end

    def get_multisig_pubkeys
      num = Bitcoin::Opcodes.opcode_to_small_int(chunks[-2].bth.to_i(16))
      (1..num).map{ |i| chunks[i].pushed_data }
    end

    # generate m of n multisig script
    # @param [Integer] m the number of signatures required for multisig
    # @param [Array] pubkeys array of public keys that compose multisig
    # @return [Script] multisig script.
    def self.to_multisig_script(m, pubkeys, sort: false)
      pubkeys = pubkeys.sort if sort
      new << m << pubkeys << pubkeys.size << OP_CHECKMULTISIG
    end

    # generate p2wsh script for +redeem_script+
    # @param [Script] redeem_script target redeem script
    # @param [Script] p2wsh script
    def self.to_p2wsh(redeem_script)
      new << WITNESS_VERSION_V0 << redeem_script.to_sha256
    end

    # generate script from string.
    def self.from_string(string)
      script = new
      string.split(' ').each do |v|
        opcode = Opcodes.name_to_opcode(v)
        if opcode
          script << (v =~ /^\d/ && Opcodes.small_int_to_opcode(v.ord) ? v.ord : opcode)
        else
          script << (v =~ /^[0-9]+$/ ? v.to_i : v)
        end
      end
      script
    end

    # generate script from addr.
    # @param [String] addr address.
    # @return [Bitcoin::Script] parsed script.
    def self.parse_from_addr(addr)
      begin
        segwit_addr = Bech32::SegwitAddr.new(addr)
        raise ArgumentError, 'Invalid address.' unless Bitcoin.chain_params.bech32_hrp == segwit_addr.hrp
        Bitcoin::Script.parse_from_payload(segwit_addr.to_script_pubkey.htb)
      rescue Exception => e
        begin
        hex, addr_version = Bitcoin.decode_base58_address(addr)
        rescue
          raise ArgumentError, 'Invalid address.'
        end
        case addr_version
        when Bitcoin.chain_params.address_version
          Bitcoin::Script.to_p2pkh(hex)
        when Bitcoin.chain_params.p2sh_version
          Bitcoin::Script.to_p2sh(hex)
        else
          raise ArgumentError, 'Invalid address.'
        end
      end
    end

    def self.parse_from_payload(payload)
      s = new
      buf = StringIO.new(payload)
      until buf.eof?
        opcode = buf.read(1)
        if opcode.pushdata?
          pushcode = opcode.ord
          packed_size = nil
          if buf.eof?
            s.chunks << opcode
            return s
          end
          len = case pushcode
                  when OP_PUSHDATA1
                    packed_size = buf.read(1)
                    packed_size.unpack1('C')
                  when OP_PUSHDATA2
                    packed_size = buf.read(2)
                    packed_size.unpack1('v')
                  when OP_PUSHDATA4
                    packed_size = buf.read(4)
                    packed_size.unpack1('V')
                  else
                    pushcode < OP_PUSHDATA1 ? pushcode : 0
                end
          if buf.eof?
            s.chunks << [len].pack('C')
          else
            chunk = (packed_size ? (opcode + packed_size) : (opcode)) + buf.read(len)
            s.chunks << chunk
          end
        else
          if Opcodes.defined?(opcode.ord)
            s << opcode.ord
          else
            s.chunks << (opcode + buf.read) # If opcode is invalid, put all remaining data in last chunk.
          end
        end
      end
      s
    end

    # Output script payload.
    # @param [Boolean] length_prefixed Flag whether the length of the payload should be given at the beginning.(default: false)
    # @return [String] payload
    def to_payload(length_prefixed = false)
      p = chunks.join
      length_prefixed ? (Bitcoin.pack_var_int(p.length) << p) : p
    end

    def empty?
      chunks.size == 0
    end

    # @deprecated
    def addresses
      puts "WARNING: Bitcoin::Script#addresses is deprecated. Use Bitcoin::Script#to_addr instead."
      return [p2pkh_addr] if p2pkh?
      return [p2sh_addr] if p2sh?
      return [bech32_addr] if witness_program?
      return get_multisig_pubkeys.map{|pubkey| Bitcoin::Key.new(pubkey: pubkey.bth).to_p2pkh} if multisig?
      []
    end

    # convert to address
    # @return [String] if script type is p2pkh or p2sh or witness program, return address, otherwise nil.
    def to_addr
      return p2pkh_addr if p2pkh?
      return p2sh_addr if p2sh?
      return bech32_addr if witness_program?
      nil
    end

    # check whether standard script.
    def standard?
      p2pkh? | p2sh? | p2wpkh? | p2wsh? | p2tr? | multisig? | standard_op_return?
    end

    # Check whether this script is a P2PKH format script.
    # @return [Boolean] if P2PKH return true, otherwise false
    def p2pkh?
      return false unless chunks.size == 5
      [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] ==
          (chunks[0..1]+ chunks[3..4]).map(&:ord) && chunks[2].bytesize == 21
    end

    # Check whether this script is a P2WPKH format script.
    # @return [Boolean] if P2WPKH return true, otherwise false
    def p2wpkh?
      return false unless chunks.size == 2
      chunks[0].ord == WITNESS_VERSION_V0 && chunks[1].bytesize == 21
    end

    # Check whether this script is a P2WPSH format script.
    # @return [Boolean] if P2WPSH return true, otherwise false
    def p2wsh?
      return false unless chunks.size == 2
      chunks[0].ord == WITNESS_VERSION_V0 && chunks[1].bytesize == 33
    end

    # Check whether this script is a P2TR format script.
    # @return [Boolean] if P2TR return true, otherwise false
    def p2tr?
      return false unless chunks.size == 2
      chunks[0].ord == WITNESS_VERSION_V1 && chunks[1].bytesize == 33
    end

    # Check whether this script is a P2SH format script.
    # @return [Boolean] if P2SH return true, otherwise false
    def p2sh?
      return false unless chunks.size == 3
      OP_HASH160 == chunks[0].ord && OP_EQUAL == chunks[2].ord && chunks[1].bytesize == 21
    end

    # Check whether this script is a P2PK format script.
    # @return [Boolean] if P2PK return true, otherwise false
    def p2pk?
      return false unless chunks.size == 2
      return false unless chunks[0].pushdata?
      key_type = chunks[0].pushed_data[0].ord
      case key_type
      when 0x02, 0x03
        return false unless chunks[0].pushed_data.bytesize == 33
      when 0x04
        return false unless chunks[0].pushed_data.bytesize == 65
      else
        return false
      end
      chunks[1].ord == OP_CHECKSIG
    end

    def multisig?
      return false if chunks.size < 4 || chunks.last.ord != OP_CHECKMULTISIG
      pubkey_count = Opcodes.opcode_to_small_int(chunks[-2].opcode)
      sig_count = Opcodes.opcode_to_small_int(chunks[0].opcode)
      return false if pubkey_count.nil? || sig_count.nil?
      sig_count <= pubkey_count
    end

    def op_return?
      chunks.size >= 1 && chunks[0].ord == OP_RETURN
    end

    def standard_op_return?
      op_return? && size <= MAX_OP_RETURN_RELAY &&
          (chunks.size == 1 || chunks[1].opcode <= OP_16)
    end

    def op_return_data
      return nil unless op_return?
      return nil if chunks.size == 1
      chunks[1].pushed_data
    end

    # whether data push only script which dose not include other opcode
    def push_only?
      chunks.each do |c|
        return false if !c.opcode.nil? && c.opcode > OP_16
      end
      true
    end

    # get public keys in the stack.
    # @return[Array[String]] an array of the pubkeys with hex format.
    def get_pubkeys
      chunks.select{|c|c.pushdata? && [33, 65].include?(c.pushed_data.bytesize) && [2, 3, 4, 6, 7].include?(c.pushed_data[0].bth.to_i(16))}.map{|c|c.pushed_data.bth}
    end

    # A witness program is any valid Script that consists of a 1-byte push opcode followed by a data push between 2 and 40 bytes.
    def witness_program?
      return false if size < 4 || size > 42 || chunks.size < 2

      opcode = chunks[0].opcode

      return false if opcode != OP_0 && (opcode < OP_1 || opcode > OP_16)
      return false unless chunks[1].pushdata?

      if size == (chunks[1][0].unpack1('C') + 2)
        program_size = chunks[1].pushed_data.bytesize
        return program_size >= 2 && program_size <= 40
      end

      false
    end

    # get witness commitment
    def witness_commitment
      return nil if !op_return? || op_return_data.bytesize < 36
      buf = StringIO.new(op_return_data)
      return nil unless buf.read(4).bth == WITNESS_COMMITMENT_HEADER
      buf.read(32).bth
    end

    # If this script is witness program, return its script code,
    # otherwise returns the self payload. ScriptInterpreter does not use this.
    def to_script_code(skip_separator_index = 0)
      payload = to_payload
      if p2wpkh?
        payload = Script.to_p2pkh(chunks[1].pushed_data.bth).to_payload
      elsif skip_separator_index > 0
        payload = subscript_codeseparator(skip_separator_index)
      end
      Bitcoin.pack_var_string(payload)
    end

    # get witness version and witness program
    def witness_data
      version = opcode_to_small_int(chunks[0].opcode)
      program = chunks[1].pushed_data
      [version, program]
    end

    # append object to payload
    def <<(obj)
      if obj.is_a?(Integer)
        push_int(obj)
      elsif obj.is_a?(String)
        append_data(obj)
      elsif obj.is_a?(Array)
        obj.each { |o| self.<< o}
        self
      end
    end

    # push integer to stack.
    def push_int(n)
      begin
        append_opcode(n)
      rescue ArgumentError
        append_data(Script.encode_number(n))
      end
      self
    end

    # append opcode to payload
    # @param [Integer] opcode append opcode which defined by Bitcoin::Opcodes
    # @return [Script] return self
    def append_opcode(opcode)
      opcode = Opcodes.small_int_to_opcode(opcode) if -1 <= opcode && opcode <= 16
      raise ArgumentError, "specified invalid opcode #{opcode}." unless Opcodes.defined?(opcode)
      chunks << opcode.chr
      self
    end

    # append data to payload with pushdata opcode
    # @param [String] data append data. this data is not binary
    # @return [Script] return self
    def append_data(data)
      data = Encoding::ASCII_8BIT == data.encoding ? data : data.htb
      chunks << Bitcoin::Script.pack_pushdata(data)
      self
    end

    # Check the item is in the chunk of the script.
    def include?(item)
      chunk_item = if item.is_a?(Integer)
                     item.chr
                   elsif item.is_a?(String)
                     data = Encoding::ASCII_8BIT == item.encoding ? item : item.htb
                     Bitcoin::Script.pack_pushdata(data)
                   end
      return false unless chunk_item
      chunks.include?(chunk_item)
    end

    def to_s
      chunks.map { |c|
        case c
        when Integer
          opcode_to_name(c)
        when String
          return c if c.empty?
          if c.pushdata?
            v = Opcodes.opcode_to_small_int(c.ord)
            if v
              v
            else
              data = c.pushed_data
              if data
                if data.bytesize <= 4
                  Script.decode_number(data.bth) # for scriptnum
                else
                  data.bth
                end
              else
                c.bth
              end
            end
          else
            opcode = Opcodes.opcode_to_name(c.ord)
            opcode ? opcode : 'OP_UNKNOWN [error]'
          end
        end
      }.join(' ')
    end

    # generate sha-256 hash for payload
    def to_sha256
      Bitcoin.sha256(to_payload).bth
    end

    # generate hash160 hash for payload
    def to_hash160
      Bitcoin.hash160(to_hex)
    end

    # script size
    def size
      to_payload.bytesize
    end

    # execute script interpreter using this script for development.
    def run
      Bitcoin::ScriptInterpreter.eval(Bitcoin::Script.new, self.dup)
    end

    # encode int value to script number hex.
    # The stacks hold byte vectors.
    # When used as numbers, byte vectors are interpreted as little-endian variable-length integers
    # with the most significant bit determining the sign of the integer.
    # Thus 0x81 represents -1. 0x80 is another representation of zero (so called negative 0).
    # Positive 0 is represented by a null-length vector.
    # Byte vectors are interpreted as Booleans where False is represented by any representation of zero,
    # and True is represented by any representation of non-zero.
    def self.encode_number(i)
      return '' if i == 0
      negative = i < 0

      hex = i.abs.to_even_length_hex
      hex = '0' + hex unless (hex.length % 2).zero?
      v = hex.htb.reverse # change endian

      v = v << (negative ? 0x80 : 0x00) unless (v[-1].unpack1('C') & 0x80) == 0
      v[-1] = [v[-1].unpack1('C') | 0x80].pack('C') if negative
      v.bth
    end

    # decode script number hex to int value
    def self.decode_number(s)
      v = s.htb.reverse
      return 0 if v.length.zero?
      mbs = v[0].unpack1('C')
      v[0] = [mbs - 0x80].pack('C') unless (mbs & 0x80) == 0
      result = v.bth.to_i(16)
      result = -result unless (mbs & 0x80) == 0
      result
    end

    # binary +data+ convert pushdata which contains data length and append PUSHDATA opcode if necessary.
    def self.pack_pushdata(data)
      size = data.bytesize
      header = if size < OP_PUSHDATA1
                 [size].pack('C')
               elsif size < 0xff
                 [OP_PUSHDATA1, size].pack('CC')
               elsif size < 0xffff
                 [OP_PUSHDATA2, size].pack('Cv')
               elsif size < 0xffffffff
                 [OP_PUSHDATA4, size].pack('CV')
               else
                 raise ArgumentError, 'data size is too big.'
               end
      header + data
    end

    # subscript this script to the specified range.
    def subscript(*args)
      s = self.class.new
      s.chunks = chunks[*args]
      s
    end

    # removes chunks matching subscript byte-for-byte and returns as a new object.
    def find_and_delete(subscript)
      raise ArgumentError, 'subscript must be Bitcoin::Script' unless subscript.is_a?(Script)
      return self if subscript.chunks.empty?
      buf = []
      i = 0
      result = Script.new
      chunks.each do |chunk|
        sub_chunk = subscript.chunks[i]
        if chunk.start_with?(sub_chunk)
          if chunk == sub_chunk
            buf << chunk
            i += 1
            (i = 0; buf.clear) if i == subscript.chunks.size # matched the whole subscript
          else # matched the part of head
            i = 0
            tmp = chunk.dup
            tmp.slice!(sub_chunk)
            result.chunks << tmp
          end
        else
          result.chunks << buf.join unless buf.empty?
          if buf.first == chunk
            i = 1
            buf = [chunk]
          else
            i = 0
            result.chunks << chunk
          end
        end
      end
      result
    end

    # remove all occurences of opcode. Typically it's OP_CODESEPARATOR.
    def delete_opcode(opcode)
      @chunks = chunks.select{|chunk| chunk.ord != opcode}
      self
    end

    # Returns a script that deleted the script before the index specified by separator_index.
    def subscript_codeseparator(separator_index)
      buf = []
      process_separator_index = 0
      chunks.each{|chunk|
        buf << chunk if process_separator_index == separator_index
        if chunk.ord == OP_CODESEPARATOR && process_separator_index < separator_index
          process_separator_index += 1
        end
      }
      buf.join
    end

    def ==(other)
      return false unless other.is_a?(Script)
      chunks == other.chunks
    end

    def type
      return 'pubkeyhash' if p2pkh?
      return 'scripthash' if p2sh?
      return 'multisig' if multisig?
      return 'witness_v0_keyhash' if p2wpkh?
      return 'witness_v0_scripthash' if p2wsh?
      return 'witness_v1_taproot' if p2tr?
      'nonstandard'
    end

    def to_h
      h = {asm: to_s, hex: to_hex, type: type}
      addr = to_addr
      h[:address] = addr if addr
      h
    end

    # Returns whether the script is guaranteed to fail at execution, regardless of the initial stack.
    # This allows outputs to be pruned instantly when entering the UTXO set.
    # @return [Boolean] whether the script is guaranteed to fail at execution
    def unspendable?
      (size > 0 && op_return?) || size > Bitcoin::MAX_SCRIPT_SIZE
    end

    private

    # generate p2pkh address. if script dose not p2pkh, return nil.
    def p2pkh_addr
      return nil unless p2pkh?
      hash160 = chunks[2].pushed_data.bth
      return nil unless hash160.htb.bytesize == RIPEMD160_SIZE
      Bitcoin.encode_base58_address(hash160, Bitcoin.chain_params.address_version)
    end

    # generate p2wpkh address. if script dose not p2wpkh, return nil.
    def p2wpkh_addr
      p2wpkh? ? bech32_addr : nil
    end

    # generate p2sh address. if script dose not p2sh, return nil.
    def p2sh_addr
      return nil unless p2sh?
      hash160 = chunks[1].pushed_data.bth
      return nil unless hash160.htb.bytesize == RIPEMD160_SIZE
      Bitcoin.encode_base58_address(hash160, Bitcoin.chain_params.p2sh_version)
    end

    # generate p2wsh address. if script dose not p2wsh, return nil.
    def p2wsh_addr
      p2wsh? ? bech32_addr : nil
    end

    # return bech32 address for payload
    def bech32_addr
      segwit_addr = Bech32::SegwitAddr.new
      segwit_addr.hrp = Bitcoin.chain_params.bech32_hrp
      segwit_addr.script_pubkey = to_hex
      segwit_addr.addr
    end

    # Check whether push data length is valid.
    # @return [Boolean] if valid return true, otherwise false.
    def valid_pushdata_length?(chunk)
      buf = StringIO.new(chunk)
      opcode = buf.read(1).ord
      offset = 1
      len = case opcode
            when OP_PUSHDATA1
              offset += 1
              buf.read(1).unpack1('C')
            when OP_PUSHDATA2
              offset += 2
              buf.read(2).unpack1('v')
            when OP_PUSHDATA4
              offset += 4
              buf.read(4).unpack1('V')
            else
              opcode
            end
      chunk.bytesize == len + offset
    end

  end

end
