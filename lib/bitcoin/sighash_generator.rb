module Bitcoin

  module SigHashGenerator

    def self.load(sig_ver)
      case sig_ver
      when :base
        LegacySigHashGenerator.new
      when :witness_v0
        SegwitSigHashGenerator.new
      else
        raise ArgumentError, "Unsupported sig version specified. #{sig_ver}"
      end
    end

    # Legacy SigHash Generator
    class LegacySigHashGenerator

      def generate(tx, input_index, output_script, hash_type, amount, skip_separator_index)
        ins = tx.inputs.map.with_index do |i, idx|
          if idx == input_index
            i.to_payload(output_script.delete_opcode(Bitcoin::Opcodes::OP_CODESEPARATOR))
          else
            case hash_type & 0x1f
            when SIGHASH_TYPE[:none], SIGHASH_TYPE[:single]
              i.to_payload(Bitcoin::Script.new, 0)
            else
              i.to_payload(Bitcoin::Script.new)
            end
          end
        end

        outs = tx.outputs.map(&:to_payload)
        out_size = Bitcoin.pack_var_int(tx.outputs.size)

        case hash_type & 0x1f
        when SIGHASH_TYPE[:none]
          outs = ''
          out_size = Bitcoin.pack_var_int(0)
        when SIGHASH_TYPE[:single]
          return "\x01".ljust(32, "\x00") if input_index >= tx.outputs.size
          outs = tx.outputs[0...(input_index + 1)].map.with_index { |o, idx| (idx == input_index) ? o.to_payload : o.to_empty_payload }.join
          out_size = Bitcoin.pack_var_int(input_index + 1)
        end

        ins = [ins[input_index]] unless hash_type & SIGHASH_TYPE[:anyonecanpay] == 0

        buf = [[tx.version].pack('V'), Bitcoin.pack_var_int(ins.size),
               ins, out_size, outs, [tx.lock_time, hash_type].pack('VV')].join

        Bitcoin.double_sha256(buf)
      end

    end

    # V0 witness sighash generator.
    # see: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    class SegwitSigHashGenerator

      def generate(tx, input_index, output_script, hash_type, amount, skip_separator_index)
        hash_prevouts = Bitcoin.double_sha256(tx.inputs.map{|i|i.out_point.to_payload}.join)
        hash_sequence = Bitcoin.double_sha256(tx.inputs.map{|i|[i.sequence].pack('V')}.join)
        outpoint = tx.inputs[input_index].out_point.to_payload
        amount = [amount].pack('Q')
        nsequence = [tx.inputs[input_index].sequence].pack('V')
        hash_outputs = Bitcoin.double_sha256(tx.outputs.map{|o|o.to_payload}.join)

        script_code = output_script.to_script_code(skip_separator_index)

        case (hash_type & 0x1f)
        when SIGHASH_TYPE[:single]
          hash_outputs = input_index >= tx.outputs.size ? "\x00".ljust(32, "\x00") : Bitcoin.double_sha256(tx.outputs[input_index].to_payload)
          hash_sequence = "\x00".ljust(32, "\x00")
        when SIGHASH_TYPE[:none]
          hash_sequence = hash_outputs = "\x00".ljust(32, "\x00")
        end

        unless (hash_type & SIGHASH_TYPE[:anyonecanpay]) == 0
          hash_prevouts = hash_sequence ="\x00".ljust(32, "\x00")
        end

        buf = [ [tx.version].pack('V'), hash_prevouts, hash_sequence, outpoint,
                script_code ,amount, nsequence, hash_outputs, [tx.lock_time, hash_type].pack('VV')].join
        Bitcoin.double_sha256(buf)
      end

    end

  end

end