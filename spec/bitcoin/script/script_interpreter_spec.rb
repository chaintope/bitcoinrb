require 'spec_helper'

describe Bitcoin::ScriptInterpreter do

  describe 'run' do
    script_json = fixture_file('script_tests.json').select{ |j|j.size > 3}
    script_json = [
        ["", "DEPTH 0 EQUAL", "P2SH,STRICTENC", "OK", "Test the test: we should have an empty stack after scriptSig evaluation"],
        ["1 2", "2 EQUALVERIFY 1 EQUAL", "P2SH,STRICTENC", "OK", "Similarly whitespace around and between symbols"],
        ["0x01 0x0b", "11 EQUAL", "P2SH,STRICTENC", "OK", "push 1 byte"]
    ]
    script_json.each do| r |
      it r[4] do
        script_sig = parse_json_script(r[0])
        script_pubkey = parse_json_script(r[1])
        flags = r[2]
        expected_err_code = Bitcoin::ScriptError.name_to_code('SCRIPT_ERR_' + r[3])
        i = Bitcoin::ScriptInterpreter.new
        result = i.verify(script_sig, script_pubkey)
        expect(result).to be expected_err_code == Bitcoin::ScriptError::SCRIPT_ERR_OK
        expect(i.error.code).to eq(expected_err_code) unless result
      end
    end
  end

  def parse_json_script(json_script)
    script = json_script.split(' ').map do |v|
      if v[0, 2] == '0x'
        v[2..-1].to_i(16)
      else
        Bitcoin::Opcodes.name_to_opcode(v) ? v : 'OP_' + v
      end
    end.join(' ')
    Bitcoin::Script.from_string(script)
  end

end