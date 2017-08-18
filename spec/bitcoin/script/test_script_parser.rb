module Bitcoin

  # parse script spec data (script_test.json data).
  module TestScriptParser

    include Bitcoin::Opcodes

    module_function

    def parse_script(script_string)
      puts "script_string = #{script_string}"
      script = Bitcoin::Script.new
      words = script_string.split(' ')
      words.each do |w|
        next if w.empty?
        latest_chunk = script.chunks.last
        puts "latest_chunk = #{latest_chunk.bth}" if latest_chunk
        if sufficient_length?(latest_chunk)
          if w =~ /^-?\d+$/ # when integer
            num = w.to_i
            data = (num >= -1 && num <= 16) ? num : Bitcoin::Script.encode_number( num)
            script << data
          elsif w.start_with?('0x') && w[2..-1].length > 0 && hex?(w[2..-1]) # when hex
            buf = StringIO.new(w[2..-1].htb)
            until buf.eof?
              head = buf.read(1)
              script.chunks << head
            end
          elsif w.size >= 2 && w.start_with?("'") && w.end_with?("'")
            script << w[1..-2].bth
          elsif Bitcoin::Opcodes.name_to_opcode('OP_' + w)
            script << Bitcoin::Opcodes.name_to_opcode('OP_' + w)
          else
            raise 'script parse error'
          end
        else
          # if last chunk does not has sufficient data.
          if w.start_with?('0x') && w[2..-1].length > 0 && hex?(w[2..-1])
            append_data = parse_hex(w[2..-1]).htb
          elsif Bitcoin::Opcodes.name_to_opcode('OP_' + w)
            append_data = Bitcoin::Opcodes.name_to_opcode('OP_' + w).to_s(16).htb
          end
          script.chunks[-1] = latest_chunk + append_data
        end

      end
      puts "payload = #{script.to_payload.bth}"
      puts "to_s = #{script.to_s}"
      script
    end

    def parse_hex(hex)
      hex
    end

    def hex?(str)
      str.scan(/.{1, 3}/).each do |s|
        return false if s.hex == 0
      end
      !str.empty? && str.length % 2 == 0
    end

    # checks whether there is enough length for the specified PUSHDATA.
    # if chunk does not pushdata, return true.
    def sufficient_length?(chunk)
      return true unless chunk
      return true unless chunk.pushdata?
      buf = StringIO.new(chunk)
      opcode = buf.read(1).ord
      return false if OP_PUSHDATA1 <= opcode && opcode <= OP_PUSHDATA4 && buf.eof?
      len = read_length(opcode, buf)
      rest = (buf.size - buf.pos)
      rest == len
    end

    def read_length(opcode, buf)
      case opcode
        when OP_PUSHDATA1
          buf.read(1).unpack('C').first
        when OP_PUSHDATA2
          buf.read(2).unpack('v').first
        when OP_PUSHDATA4
          buf.read(4).unpack('V').first
        else
          opcode if opcode < OP_PUSHDATA1
      end
    end

  end
end