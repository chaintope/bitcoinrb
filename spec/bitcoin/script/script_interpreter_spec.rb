require 'spec_helper'

describe Bitcoin::ScriptInterpreter do

  describe 'run' do
    script_json = fixture_file('script_tests.json').select{ |j|j.size > 3}
    script_json = [
        ["", "DEPTH 0 EQUAL", "P2SH,STRICTENC", "OK", "Test the test: we should have an empty stack after scriptSig evaluation"],
        ["1 2", "2 EQUALVERIFY 1 EQUAL", "P2SH,STRICTENC", "OK", "Similarly whitespace around and between symbols"],
        ["0x01 0x0b", "11 EQUAL", "P2SH,STRICTENC", "OK", "push 1 byte"],
        ["0x02 0x417a", "'Az' EQUAL", "P2SH,STRICTENC", "OK"],
        ["0x4f 1000 ADD","999 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0x4c 0x01 0x07","7 EQUAL", "P2SH,STRICTENC", "OK", "0x4c is OP_PUSHDATA1"],
        ["0", "IF 0x50 ENDIF 1", "P2SH,STRICTENC", "OK", "0x50 is reserved (ok if not executed)"],
        ["1","NOP", "P2SH,STRICTENC", "OK"],
        ["0", "IF VER ELSE 1 ENDIF", "P2SH,STRICTENC", "OK", "VER non-functional (ok if not executed)"],
        ["1", "DUP IF ENDIF", "P2SH,STRICTENC", "OK"],
        ["1 0", "NOTIF IF 1 ELSE 0 ENDIF ENDIF", "P2SH,STRICTENC", "OK"],
        ["1", "IF 1 ELSE 0 ELSE 1 ENDIF ADD 2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 0", "IF IF 1 ELSE 0 ENDIF ENDIF", "P2SH,STRICTENC", "OK"],
        ["'' 1", "IF SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ELSE ELSE SHA1 ENDIF 0x14 0x68ca4fec736264c13b859bac43d5173df6871682 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0", "IF 1 IF RETURN ELSE RETURN ELSE RETURN ENDIF ELSE 1 IF 1 ELSE RETURN ELSE 1 ENDIF ELSE RETURN ENDIF ADD 2 EQUAL", "P2SH,STRICTENC", "OK", "Nested ELSE ELSE"],
        ["1 1", "VERIFY", "P2SH,STRICTENC", "OK"],
        ["10 0 11 TOALTSTACK DROP FROMALTSTACK", "ADD 21 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 IFDUP", "DEPTH 1 EQUALVERIFY 0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 IFDUP", "DEPTH 2 EQUALVERIFY 1 EQUALVERIFY 1 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 1", "NIP", "P2SH,STRICTENC", "OK"],
        ["1 0", "OVER DEPTH 3 EQUALVERIFY", "P2SH,STRICTENC", "OK"],
        ["22 21 20", "0 PICK 20 EQUALVERIFY DEPTH 3 EQUAL", "P2SH,STRICTENC", "OK"],
        ["22 21 20", "0 ROLL 20 EQUALVERIFY DEPTH 2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["22 21 20", "ROT 22 EQUAL", "P2SH,STRICTENC", "OK"],
        ["25 24 23 22 21 20", "2ROT 24 EQUAL", "P2SH,STRICTENC", "OK"],
        ["25 24 23 22 21 20", "2ROT 2DROP 20 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 0", "SWAP 1 EQUALVERIFY 0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 1", "TUCK DEPTH 3 EQUALVERIFY SWAP 2DROP", "P2SH,STRICTENC", "OK"],
        ["13 14", "2DUP ROT EQUALVERIFY EQUAL", "P2SH,STRICTENC", "OK"],
        ["-1 0 1 2", "3DUP DEPTH 7 EQUALVERIFY ADD ADD 3 EQUALVERIFY 2DROP 0 EQUALVERIFY", "P2SH,STRICTENC", "OK"],
        ["1 2 3 5", "2OVER ADD ADD 8 EQUALVERIFY ADD ADD 6 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 3 5 7", "2SWAP ADD 4 EQUALVERIFY ADD 12 EQUAL", "P2SH,STRICTENC", "OK"],
        ["0 ABS", "0 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 1 BOOLAND", "NOP", "P2SH,STRICTENC", "OK"],
        ["1 1ADD", "2 EQUAL", "P2SH,STRICTENC", "OK"],
        ["111 1SUB", "110 EQUAL", "P2SH,STRICTENC", "OK"],
        ["1 1 BOOLOR", "NOP", "P2SH,STRICTENC", "OK"],
        ["11 10 1 ADD", "NUMEQUAL", "P2SH,STRICTENC", "OK"],
        ["0 0 BOOLOR", "NOT", "P2SH,STRICTENC", "OK"],
        ["11 10 1 ADD", "NUMEQUALVERIFY 1", "P2SH,STRICTENC", "OK"],
        ["11 10", "LESSTHAN NOT", "P2SH,STRICTENC", "OK"],
        ["4 4", "GREATERTHAN NOT", "P2SH,STRICTENC", "OK"]
    ]
    script_json.each do| r |
      it "should validate script #{r.inspect}" do
        script_sig = parse_json_script(r[0])
        script_pubkey = parse_json_script(r[1])
        flags = r[2].split(',').map {|s| Bitcoin.const_get("SCRIPT_VERIFY_#{s}")}
        expected_err_code = Bitcoin::ScriptError.name_to_code('SCRIPT_ERR_' + r[3])
        i = Bitcoin::ScriptInterpreter.new(flags: flags)
        result = i.verify(script_sig, script_pubkey)
        puts i.error.to_s
        expect(result).to be expected_err_code == Bitcoin::ScriptError::SCRIPT_ERR_OK
        expect(i.error.code).to eq(expected_err_code) unless result
      end
    end
  end

  def parse_json_script(json_script)
    oldsize = json_script.size + 1
    while json_script.size != oldsize
      oldsize = json_script.size
      json_script.gsub!(/0x([0-9a-fA-F]+)\s+0x/, "0x\\1")
    end
    script = Bitcoin::Script.new
    json_script.split(' ').map do |v|
      if v[0, 2] == '0x'
        data = v[2..-1].htb
        if data.pushed_data
          code = data.pushed_data.bth.to_i(16)
          opcode = Bitcoin::Opcodes.name_to_opcode('OP_' + code.to_s)
          if opcode
            script << code
          else
            script.chunks << data
          end
        else
          script.chunks << data
        end
      elsif v =~ /^'.*'$/
        script << v[1..-2].bth
      elsif v =~ /^-?\d+$/
        v = v.to_i
        if -1 <= v && v <= 16
          script << Bitcoin::Opcodes.small_int_to_opcode(v)
        else
          script << Bitcoin::Script.encode_number(v)
        end
      else
        opcode = Bitcoin::Opcodes.name_to_opcode(v)
        opcode = Bitcoin::Opcodes.name_to_opcode('OP_' + v) unless opcode
        script << opcode
      end
    end
    script
  end

end