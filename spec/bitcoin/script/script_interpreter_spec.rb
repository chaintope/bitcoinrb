require 'spec_helper'

describe Bitcoin::ScriptInterpreter, use_secp256k1: true do

  KEY0 = "0000000000000000000000000000000000000000000000000000000000000001"

  describe 'check script_test.json' do
    script_json = fixture_file('script_tests.json').select{ |j|j.size > 3}
    script_json.each do| r |
      it "should validate script #{r.inspect}" do
        builder = nil
        if r[0].is_a?(Array)
          last_item = nil
          payloads = r[0][0..-2].map do |v|
            last_item = if v.start_with?("#SCRIPT#")
                          Bitcoin::TestScriptParser.parse_script(v.split("#SCRIPT# ").last).to_payload
                        elsif v == "#CONTROLBLOCK#"
                          leaf = Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.parse_from_payload(last_item))
                          builder = Bitcoin::Taproot::SimpleBuilder.new(KEY0, [leaf])
                          builder.control_block(leaf).to_payload
                        else
                          v.htb
                        end
            last_item
          end
          witness = Bitcoin::ScriptWitness.new(payloads)
          sig, pubkey, flags, error_code = r[1], r[2], r[3], r[4]
          amount = (r[0][-1] * 100_000_000).to_i
        else
          witness, sig, pubkey, flags, error_code = Bitcoin::ScriptWitness.new, r[0], r[1], r[2], r[3]
          amount = 0
        end

        script_sig = Bitcoin::TestScriptParser.parse_script(sig)
        script_pubkey = if pubkey == "0x51 0x20 #TAPROOTOUTPUT#"
                          builder.build
                        else
                          Bitcoin::TestScriptParser.parse_script(pubkey)
                        end
        credit_tx = build_credit_tx(script_pubkey, amount)
        tx = build_spending_tx(script_sig, credit_tx, witness, amount)
        script_flags = parse_flags(flags)
        expected_err_code = find_error_code(error_code)
        i = Bitcoin::ScriptInterpreter.new(flags: script_flags, checker: Bitcoin::TxChecker.new(tx: tx, input_index: 0, amount: amount))
        result = i.verify_script(script_sig, script_pubkey, witness)
        expect(result).to be expected_err_code == Bitcoin::SCRIPT_ERR_OK
        expect(i.error.code).to eq(expected_err_code) unless result

        # Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
        16.times do
          extra_flags = rand(32768) # 16 bit unsigned integer
          combined_flags = result ? (script_flags & ~extra_flags)  : (script_flags | extra_flags)
          next if combined_flags & Bitcoin::SCRIPT_VERIFY_CLEANSTACK && ~combined_flags & (Bitcoin::SCRIPT_VERIFY_P2SH | Bitcoin::SCRIPT_VERIFY_WITNESS)
          next if combined_flags & Bitcoin::SCRIPT_VERIFY_WITNESS && ~combined_flags & Bitcoin::SCRIPT_VERIFY_P2SH
          i = Bitcoin::ScriptInterpreter.new(flags: combined_flags, checker: Bitcoin::TxChecker.new(tx: tx, input_index: 0, amount: amount))
          extra_result = i.verify_script(script_sig, script_pubkey, witness)
          expect(extra_result).to be expected_err_code == Bitcoin::SCRIPT_ERR_OK
          expect(i.error.code).to eq(expected_err_code) unless extra_result
        end
      end
    end
  end

  describe '#verify_script' do

    def verify(script_sig, script_pubkey, flags, witness: Bitcoin::ScriptWitness.new, amount: 0)
      credit_tx = build_credit_tx(script_pubkey, amount)
      tx = build_spending_tx(script_sig, credit_tx, witness, amount)
      checker = Bitcoin::TxChecker.new(tx: tx, input_index: 0, amount: amount, prevouts: credit_tx.out)
      i = Bitcoin::ScriptInterpreter.new(flags: flags, checker: checker)
      [i.verify_script(script_sig, script_pubkey, witness), i.error&.code]
    end

    def raw(hex)
      Bitcoin::Script.parse_from_payload(hex.htb)
    end

    let(:flags) { Bitcoin::SCRIPT_VERIFY_P2SH | Bitcoin::SCRIPT_VERIFY_WITNESS | Bitcoin::SCRIPT_VERIFY_CLEANSTACK }

    it 'should treat a zero left by a P2SH redeem script or a P2WSH witness script as false' do
      # The stack holds hex strings, and the final check of a redeem script and of a witness script
      # used to inspect the hex characters, so any encoding of zero other than the empty vector passed.
      ['0100', '0180', '020000'].each do |push_zero|
        redeem = raw(push_zero)
        expect(verify(Bitcoin::Script.new << redeem.to_hex, redeem.to_p2sh, flags)).to eq([false, Bitcoin::SCRIPT_ERR_EVAL_FALSE])
        witness = Bitcoin::ScriptWitness.new([redeem.to_payload])
        expect(verify(Bitcoin::Script.new, Bitcoin::Script.to_p2wsh(redeem), flags, witness: witness)).to eq([false, Bitcoin::SCRIPT_ERR_EVAL_FALSE])
      end
      one = raw('51')
      expect(verify(Bitcoin::Script.new << one.to_hex, one.to_p2sh, flags)).to eq([true, Bitcoin::SCRIPT_ERR_OK])
    end

    it 'should not duplicate a zero with OP_IFDUP' do
      # <0x00> OP_IFDUP OP_DEPTH OP_1 OP_EQUAL
      expect(verify(Bitcoin::Script.new, raw('0100737451 87'.delete(' ')), Bitcoin::SCRIPT_VERIFY_NONE)).to eq([true, Bitcoin::SCRIPT_ERR_OK])
      # <0x01> OP_IFDUP OP_DEPTH OP_2 OP_EQUAL
      expect(verify(Bitcoin::Script.new, raw('0101737452 87'.delete(' ')), Bitcoin::SCRIPT_VERIFY_NONE)).to eq([true, Bitcoin::SCRIPT_ERR_OK])
    end

    it 'should reject OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY in tapscript' do
      internal = Bitcoin::Key.from_xonly_pubkey('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
      {
        (Bitcoin::Script.new << Bitcoin::Opcodes::OP_0 << Bitcoin::Opcodes::OP_0 << Bitcoin::Opcodes::OP_0 << Bitcoin::Opcodes::OP_CHECKMULTISIG) => [false, Bitcoin::SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG],
        (Bitcoin::Script.new << Bitcoin::Opcodes::OP_0 << Bitcoin::Opcodes::OP_0 << Bitcoin::Opcodes::OP_0 << Bitcoin::Opcodes::OP_CHECKMULTISIGVERIFY << Bitcoin::Opcodes::OP_1) => [false, Bitcoin::SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG],
        # Not executed, so allowed.
        (Bitcoin::Script.new << Bitcoin::Opcodes::OP_0 << Bitcoin::Opcodes::OP_IF << Bitcoin::Opcodes::OP_CHECKMULTISIG << Bitcoin::Opcodes::OP_ENDIF << Bitcoin::Opcodes::OP_1) => [true, Bitcoin::SCRIPT_ERR_OK]
      }.each do |script, expected|
        leaf = Bitcoin::Taproot::LeafNode.new(script)
        builder = Bitcoin::Taproot::SimpleBuilder.new(internal.xonly_pubkey, [leaf])
        witness = Bitcoin::ScriptWitness.new([script.to_payload, builder.control_block(leaf).to_payload])
        expect(verify(Bitcoin::Script.new, builder.build, Bitcoin::STANDARD_SCRIPT_VERIFY_FLAGS, witness: witness, amount: 1000)).to eq(expected)
      end
    end

  end

  describe '#eval' do
    it 'should be verified.' do
      script_pubkey = Bitcoin::Script.from_string('1 OP_ADD 7 OP_EQUAL')
      script_sig = Bitcoin::Script.from_string('6')
      expect(Bitcoin::ScriptInterpreter.eval(script_sig, script_pubkey)).to be true
    end
  end

  # using script_assets_test.json provided by Bitcoin Core.
  # generate script_assets_test.json by following steps:
  # 1. cd bitcoin (bitcoin core dir)
  # 2. mkdir dump
  # 3. for N in $(seq 1 10); do TEST_DUMP_DIR=dump test/functional/feature_taproot.py --dumptests; done
  # 4. (cat dump/*/* | head -c -2;) > script_assets_test.json
  # 5. copy script_assets_test.json into this spec/fixtures/ dir.
  describe 'script assets test' do
    it 'should be passed.' do
      Parallel.each(File.open(fixture_path('taproot/script_assets_test.json')).each_line.with_index) do |row, done|
        row.chomp!
        v = JSON.parse(row[-1] == ',' ? row[0...-1] : row)
        tx = Bitcoin::Tx.parse_from_payload(v['tx'].htb)
        prevouts = v['prevouts'].map{|o|Bitcoin::TxOut.parse_from_payload(o.htb)}
        expect(tx.in.size).to eq(prevouts.size)

        index = v['index']
        test_flags = parse_flags(v['flags'])
        checker = Bitcoin::TxChecker.new(tx: tx, input_index: index, prevouts: prevouts)

        if v.key?('success')
          i = Bitcoin::ScriptInterpreter.new(flags: test_flags, checker: checker)
          tx.in[index].script_witness = Bitcoin::ScriptWitness.new
          tx.in[index].script_sig = Bitcoin::Script.parse_from_payload(v['success']['scriptSig'].htb)
          v['success']['witness'].each {|w|tx.in[index].script_witness.stack << w.htb}
          result = i.verify_script(tx.in[index].script_sig, prevouts[index].script_pubkey, tx.in[index].script_witness)
          expect(result).to be true
          result = tx.verify_input_sig(index, prevouts[index].script_pubkey, amount: prevouts[index].value, flags: test_flags, prevouts: prevouts)
          puts v unless result
          expect(result).to be true
        end
        if v.key?('failure')
          i = Bitcoin::ScriptInterpreter.new(flags: test_flags, checker: checker)
          tx.in[index].script_witness = Bitcoin::ScriptWitness.new
          tx.in[index].script_sig = Bitcoin::Script.parse_from_payload(v['failure']['scriptSig'].htb)
          v['failure']['witness'].each {|w|tx.in[index].script_witness.stack << w.htb}
          result = i.verify_script(tx.in[index].script_sig, prevouts[index].script_pubkey, tx.in[index].script_witness)
          expect(result).to be false
          result = tx.verify_input_sig(index, prevouts[index].script_pubkey, amount: prevouts[index].value, flags: test_flags, prevouts: prevouts)
          expect(result).to be false
        end
        puts "#{done} tests done" if done > 0 && done % 200 == 0
      end
    end
  end

  def build_credit_tx(script_pubkey, amount)
    tx = Bitcoin::Tx.new
    tx.version = 1
    tx.lock_time = 0
    coinbase = Bitcoin::Script.new << 0 << 0
    tx.inputs << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.create_coinbase_outpoint, script_sig: coinbase)
    tx.outputs << Bitcoin::TxOut.new(script_pubkey: script_pubkey, value: amount)
    tx
  end

  def build_spending_tx(script_sig, locked_tx, witness, amount)
    tx = Bitcoin::Tx.new
    tx.version = 1
    tx.lock_time = 0
    tx.inputs << Bitcoin::TxIn.new(
      out_point: Bitcoin::OutPoint.new(locked_tx.tx_hash, 0),
      script_sig: script_sig,
      script_witness: witness
    )
    tx.outputs << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.new, value: amount)
    tx
  end

  def find_error_code(error_code)
    error_code = 'SIG_NULLFAIL' if error_code == 'NULLFAIL'
    Bitcoin::ScriptError.name_to_code('SCRIPT_ERR_' + error_code)
  end

  def parse_flags(flags)
    flags.split(',').map {|s| Bitcoin.const_get("SCRIPT_VERIFY_#{s}")}.inject(Bitcoin::SCRIPT_VERIFY_NONE){|flags, f| flags |= f}
  end

end