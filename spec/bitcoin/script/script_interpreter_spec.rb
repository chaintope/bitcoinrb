require 'spec_helper'

describe Bitcoin::ScriptInterpreter do

  describe 'check script_test.json' do
    script_json = fixture_file('script_tests.json').select{ |j|j.size > 3}
    script_json.each do| r |
      it "should validate script #{r.inspect}" do
        puts r.inspect
        if r[0].is_a?(Array)
          witness = Bitcoin::ScriptWitness.new(r[0][0..-2].map{ |v| v.htb })
          sig, pubkey, flags, error_code = r[1], r[2], r[3], r[4]
          amount = (r[0][-1] * 100_000_000).to_i
        else
          witness, sig, pubkey, flags, error_code = Bitcoin::ScriptWitness.new, r[0], r[1], r[2], r[3]
          amount = 0
        end
        script_sig = Bitcoin::TestScriptParser.parse_script(sig)
        script_pubkey = Bitcoin::TestScriptParser.parse_script(pubkey)
        credit_tx = build_credit_tx(script_pubkey, amount)
        tx = build_spending_tx(script_sig, credit_tx, witness, amount)
        flags = flags.split(',').map {|s| Bitcoin.const_get("SCRIPT_VERIFY_#{s}")}
        expected_err_code = find_error_code(error_code)
        i = Bitcoin::ScriptInterpreter.new(flags: flags, checker: Bitcoin::TxChecker.new(tx: tx, input_index: 0, amount: amount))
        result = i.verify_script(script_sig, script_pubkey, witness)
        puts i.error.to_s
        expect(result).to be expected_err_code == Bitcoin::SCRIPT_ERR_OK
        expect(i.error.code).to eq(expected_err_code) unless result
      end
    end
  end

  def build_dummy_tx(script_sig, txid)
    tx = Bitcoin::Tx.new
    tx.inputs << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.new(txid, 0), script_sig: script_sig)
    tx.outputs << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.new)
    tx
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
      out_point: Bitcoin::OutPoint.new(locked_tx.txid, 0),
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

end