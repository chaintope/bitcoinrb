# using script_assets_test.json provided by Bitcoin Core.
# generate script_assets_test_*.json by following steps:
# 1. cd bitcoin (bitcoin core dir)
# 2. mkdir dump
# 3. for N in $(seq 1 10); do TEST_DUMP_DIR=dump test/functional/feature_taproot.py --dumptests; done
# 4. cd dump
# 5. (cat 0/* | head -c -2;) > script_assets_test_0.json
# ... to f.
# 6. copy script_assets_test_*.json into this spec/fixtures/taproot/ dir.

def test_script_assets(path)
  File.open(path).each_line.with_index do |row, done|
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
    end
    if v.key?('failure')
      i = Bitcoin::ScriptInterpreter.new(flags: test_flags, checker: checker)
      tx.in[index].script_witness = Bitcoin::ScriptWitness.new
      tx.in[index].script_sig = Bitcoin::Script.parse_from_payload(v['failure']['scriptSig'].htb)
      v['failure']['witness'].each {|w|tx.in[index].script_witness.stack << w.htb}
      result = i.verify_script(tx.in[index].script_sig, prevouts[index].script_pubkey, tx.in[index].script_witness)
      expect(result).to be false
    end
    puts "#{done} tests done" if done > 0 && done % 200 == 0
  end
end
