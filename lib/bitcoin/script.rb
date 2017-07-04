module Bitcoin

  # bitcoin script
  class Script

    include Bitcoin::Opcodes

    attr_accessor :chunks

    def initialize
      @chunks = []
    end

    def self.to_p2pkh(pubkey_hash)
      new << OP_DUP << OP_HASH160 << pubkey_hash << OP_EQUALVERIFY << OP_CHECKSIG
    end

    def self.parse_from_payload(payload)
      s = new
      buf = StringIO.new(payload)
      until buf.eof?
        opcode = buf.read(1)
        if opcode?(opcode)
          s << opcode.ord
        else
          pushcode = opcode.ord
          len = case pushcode
                when OP_PUSHDATA1
                  buf.read(1)
                when OP_PUSHDATA2
                  buf.read(2)
                when OP_PUSHDATA4
                  buf.read(4)
                else
                  pushcode if pushcode < OP_PUSHDATA1
                end
          s << buf.read(len).bth if len
        end
      end
      s
    end

    def to_payload
      chunks.join
    end

    def to_addr
      return p2pkh_addr if p2pkh?
      return nil if p2wpkh?
      return nil if p2sh?
    end

    def p2pkh?
      return false unless chunks.size == 5
      [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] ==
          (chunks[0..1]+ chunks[3..4]).map(&:ord) && chunks[2].bytesize == 21
    end

    def p2wpkh?
      false
    end

    def p2sh?
      false
    end

    # append object to payload
    def <<(obj)
      if obj.is_a?(Integer)
        append_opcode(obj)
      elsif obj.is_a?(String)
        append_data(obj.b)
      end
    end

    # append opcode to payload
    # @param [Integer] opcode append opcode which defined by Bitcoin::Opcodes
    # @return [Script] return self
    def append_opcode(opcode)
      raise ArgumentError, "specified invalid opcode #{opcode}." unless Opcodes.defined?(opcode)
      chunks << opcode.chr
      self
    end

    # append data to payload with pushdata opcode
    # @param [String] data append data. this data is not binary
    # @return [Script] return self
    def append_data(data)
      data = data.htb
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
      chunks << (header + data)
      self
    end

    def to_s
      chunks.map { |c| Script.opcode?(c) ? Opcodes.opcode_to_name(c.ord) : Script.pushed_data(c) }.join(' ')
    end

    # determine where the data is an opcode.
    def self.opcode?(data)
      !pushdata?(data)
    end

    # determine where the data is a pushdadta.
    def self.pushdata?(data)
      # the minimum value of opcode is pushdata operation.
      data.each_byte.next <= OP_PUSHDATA4
    end

    # get pushed data in pushdata bytes
    def self.pushed_data(data)
      opcode = data.each_byte.next
      offset = 1
      case opcode
        when OP_PUSHDATA1
          offset += 1
        when OP_PUSHDATA2
          offset += 2
        when OP_PUSHDATA4
          offset += 4
      end
      data[offset..-1].bth
    end

    private

    # generate p2pkh address. if script dose not p2pkh, return nil.
    def p2pkh_addr
      return nil unless p2pkh?
      hash160 = Script.pushed_data(chunks[2])
      return nil unless hash160.htb.bytesize == 20
      hex = Bitcoin.chain_params.address_version + hash160
      Bitcoin.encode_base58_address(hex)
    end

  end

end
