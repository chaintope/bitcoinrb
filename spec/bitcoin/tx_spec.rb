require 'spec_helper'
include Bitcoin::Opcodes

describe Bitcoin::Tx do
  include Bitcoin::Opcodes
  describe 'parse from payload' do
    context 'coinbase tx' do
      subject {
        Bitcoin::Tx.parse_from_payload('010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2a038c7f110411bd48592f244d696e65642062792037706f6f6c2e636f6d2f0100000bd807000000000000ffffffff0340597307000000001976a91489893957178347e87e2bb3850e6f6937de7372b288ac50d6dc01000000001976a914ca560088c0fb5e6f028faa11085e643e343a8f5c88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000'.htb)
      }
      it 'should be parsed' do
        expect(subject.inputs.length).to eq(1)
        expect(subject.coinbase_tx?).to be true
        expect(subject.to_payload.bth).to eq('010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2a038c7f110411bd48592f244d696e65642062792037706f6f6c2e636f6d2f0100000bd807000000000000ffffffff0340597307000000001976a91489893957178347e87e2bb3850e6f6937de7372b288ac50d6dc01000000001976a914ca560088c0fb5e6f028faa11085e643e343a8f5c88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000')
        expect(subject.txid).to eq('2da1db11dea21799d0b8f351a4516b5e3f8f6729da5aee2d43176a188045e2e4')
        expect(subject.wtxid).to eq('f15033791b455b7ae2c3af844796ec5996d205cbaf417c63946a53489a52ec9a')
      end
    end

    context 'standard tx' do
      subject {
        Bitcoin::Tx.parse_from_payload('0100000005294f9022539669658a5d685ba1d446a990de155e8d7eb978a7680286c92d05f9ce0400006a473044022008dfc5d3bf5aa25c4588334d471e83b7dc17ee20c777959710be08e3c21e037302202d0fb34c25ac11af9dd756ecb5eeeba3c2296c1ddc5e85a105da11a922e8fae3012102dd4b77b9baebd48fd6cfbd6038f54442e69bc628b18640a8bac40fb55624ac08ffffffff294f9022539669658a5d685ba1d446a990de155e8d7eb978a7680286c92d05f9cf0400006b483045022100e6d1faacdbdd0562266c9e8ceff6c5d67094fa52ff74be8b74052fecd99c0f7702203457f157810fa886c09bdc42a87cc2145dca9807efe6e623f9d21b907619eaac012102d69f753f4517b9a9bd2ffeb6ad63a2e6d220b4a8db9632a51f740f240663c69affffffff294f9022539669658a5d685ba1d446a990de155e8d7eb978a7680286c92d05f9d00400006a473044022079c6fa01326b14748be66e8a5ccb01de47ef19ea8d79f368703ce93ddd8df8a0022008dad075dcc27fd1a22062c6e7dcb527e9ccff1c19f517977bba1a1bd981d9e2012103b586a8a8bea0864b4c4895a09803e1ac531ad08880eeed07797c4e31ad574dc2ffffffff294f9022539669658a5d685ba1d446a990de155e8d7eb978a7680286c92d05f9d10400006c493046022100f1157996e5a1f45ed2b21eb7bb1578a7b5f41aa0c67e7360adb0de8b862fbc19022100d0b252449686ce0ff250a22b20fc47e77962ee47ea4b04fce59a308801ab7d91012103cdbcb10cea5780f48bb4bb7cd48a38569bc71d1bd84c5870af4dd86593c1a9f0ffffffff294f9022539669658a5d685ba1d446a990de155e8d7eb978a7680286c92d05f9d60400006b483045022100d8ef2555a6a7d4b13105782115863654004e51f95e656c116bf7607ea2343bad0220099aa941dea08190f3975aea43c65b5ecd25e9fb7a5a4fc69bc4a896cf2c43aa012102c5b4b1b0be5584ce8005e1330ffab609986f92ad505d4bae6cd016c1dceb74dbffffffff0200cb4c00010000001976a91424dfc7897d2579c7cbf9b6f7690a20f68ef3efa188ac002c3301040000001976a914b5cf2104dc0c646cf1dd20334b09c730ba5f472d88ac00000000'.htb)
      }
      it 'should be parsed' do
        expect(subject.txid).to eq('9ae1fd1572ffe82e2670e2edd1e2431b37bbb0bb6493e64546447ca8827d1375')
        expect(subject.wtxid).to eq('9ae1fd1572ffe82e2670e2edd1e2431b37bbb0bb6493e64546447ca8827d1375')
        expect(subject.coinbase_tx?).to be false
        expect(subject.version).to eq(1)
        expect(subject.lock_time).to eq(0)
        expect(subject.inputs.length).to eq(5)
        expect(subject.outputs.length).to eq(2)
      end
    end

    context 'empty tx' do
      subject {
        Bitcoin::Tx.parse_from_payload('01000000000000000000'.htb)
      }
      it 'should generate empty payload and parse it.' do
        expect(subject.version).to eq(1)
        expect(subject.inputs.size).to eq(0)
        expect(subject.outputs.size).to eq(0)
        expect(subject.lock_time).to eq(0)
        expect(subject.to_payload.bth).to eq('01000000000000000000')
        expect(Bitcoin::Tx.new.to_payload.bth).to eq('01000000000000000000')
      end
    end
  end

  describe '#sighash_for_input' do
    context 'non witness' do
      it 'should be generate' do
        # sighash all
        tx = Bitcoin::Tx.parse_from_payload('0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'.htb)
        script_pubkey = Bitcoin::Script.parse_from_payload('410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac'.htb)
        expect(tx.sighash_for_input(0, script_pubkey).bth).to eq('7a05c6145f10101e9d6325494245adf1297d80f8f38d4d576d57cdba220bcb19')

        # sighash single
        tx = Bitcoin::Tx.parse_from_payload('0100000002dc38e9359bd7da3b58386204e186d9408685f427f5e513666db735aa8a6b2169000000006a47304402205d8feeb312478e468d0b514e63e113958d7214fa572acd87079a7f0cc026fc5c02200fa76ea05bf243af6d0f9177f241caf606d01fcfd5e62d6befbca24e569e5c27032102100a1a9ca2c18932d6577c58f225580184d0e08226d41959874ac963e3c1b2feffffffffdc38e9359bd7da3b58386204e186d9408685f427f5e513666db735aa8a6b2169010000006b4830450220087ede38729e6d35e4f515505018e659222031273b7366920f393ee3ab17bc1e022100ca43164b757d1a6d1235f13200d4b5f76dd8fda4ec9fc28546b2df5b1211e8df03210275983913e60093b767e85597ca9397fb2f418e57f998d6afbbc536116085b1cbffffffff0140899500000000001976a914fcc9b36d38cf55d7d5b4ee4dddb6b2c17612f48c88ac00000000'.htb)
        script_pubkey = Bitcoin::Script.parse_from_payload('76a914fcc9b36d38cf55d7d5b4ee4dddb6b2c17612f48c88ac'.htb)
        expect(tx.sighash_for_input(0, script_pubkey,
                                    hash_type: Bitcoin::SIGHASH_TYPE[:single]).bth).to eq('23563c6b270661cc38e940cd6f8908177b9c9de7ff5111e73481ec42a112a557')

        # sighash all | anyonecanpay
        tx = Bitcoin::Tx.parse_from_payload('0100000002f6044c0ad485f633b41f97d0d793eb2837ae40f738ff6d5f50fdfd10528c1d76010000006b48304502205853c7f1395785bfabb03c57e962eb076ff24d8e4e573b04db13b45ed3ed6ee20221009dc82ae43be9d4b1fe2847754e1d36dad48ba801817d485dc529afc516c2ddb481210305584980367b321fad7f1c1f4d5d723d0ac80c1d80c8ba12343965b48364537affffffff9c6af0df6669bcded19e317e25bebc8c78e48df8ae1fe02a7f030818e71ecd40010000006c4930460221008269c9d7ba0a7e730dd16f4082d29e3684fb7463ba064fd093afc170ad6e0388022100bc6d76373916a3ff6ee41b2c752001fda3c9e048bcff0d81d05b39ff0f4217b2812103aae303d825421545c5bc7ccd5ac87dd5add3bcc3a432ba7aa2f2661699f9f659ffffffff01e0930400000000001976a9145c11f917883b927eef77dc57707aeb853f6d389488ac00000000'.htb)
        script_pubkey = Bitcoin::Script.parse_from_payload('76a9148551e48a53decd1cfc63079a4581bcccfad1a93c88ac'.htb)
        expect(tx.sighash_for_input(0, script_pubkey, hash_type:
            Bitcoin::SIGHASH_TYPE[:all] | Bitcoin::SIGHASH_TYPE[:anyonecanpay]).bth).to eq('acf290d5617704f1aad0a0d00a93b60886dac5df3c46b2e49d0344a94670d537')

        # sighash single | anyonecanpay
        tx = Bitcoin::Tx.parse_from_payload('0100000001774431e6ccca53548400e2e8bb66865ca2feef7885f09a0199b5fdd0eeb7583e01000000dc004930460221008662e2bfcc4741d92531f566c5765d849e24b45c289607593584fbba938d88cc022100d718e710d5991bdfbdc5b0d52ae8e4d9c1c1c719bcc348003c5e80524a04e16283483045022100fbdbea6b614989b210d269dbf171746a9507bb3dae292bdaf85848a7aa091eca02205d23a46269a904c40076c76eadfdb8f98e7d0349c0bfe5915cca3f8835a4a41683475221034758cefcb75e16e4dfafb32383b709fa632086ea5ca982712de6add93060b17a2103fe96237629128a0ae8c3825af8a4be8fe3109b16f62af19cec0b1eb93b8717e252aeffffffff0280969800000000001976a914f164a82c9b3c5d217c83380792d56a6261f2d17688ac609df200000000001976a9142ab55d985e552653c189b1530aac817c0223cb4c88ac00000000'.htb)
        script_pubkey = Bitcoin::Script.parse_from_payload('a914d0c15a7d41500976056b3345f542d8c944077c8a87'.htb)
        expect(tx.sighash_for_input(0, script_pubkey, hash_type:
            Bitcoin::SIGHASH_TYPE[:single] | Bitcoin::SIGHASH_TYPE[:anyonecanpay]).bth).to eq('5e7f5c6e6a9f1a751a1686a88a42416223cccaed0898992961c498901a40dbb1')

        # sighash none
        expect(tx.sighash_for_input(0, script_pubkey, hash_type:
            Bitcoin::SIGHASH_TYPE[:none]).bth).to eq('736918827173aa332b97c1ebe2f2cdae046034a553932a303238a34609e8b31a')

        # sighash none | anyonecanpay
        expect(tx.sighash_for_input(0, script_pubkey, hash_type:
            Bitcoin::SIGHASH_TYPE[:none] | Bitcoin::SIGHASH_TYPE[:anyonecanpay]).bth).to eq('a94ba0fd2c08b5b753282f15483901714bb862fd37b9339b38dec31e6d4c793d')
      end
    end

    context 'witness' do
      # TODO
    end

  end

  describe 'check tx_valid.json' do
    tx_json = fixture_file('tx_valid.json').select{ |j|j.size > 2}
    tx_json.each do |json|
      it "should validate tx #{json.inspect}" do

        prevout_script_pubkeys = {}
        prevout_script_values = {}

        json[0].each do |i|
          outpoint = Bitcoin::OutPoint.new(i[0], i[1])
          prevout_script_pubkeys[outpoint.to_payload] = Bitcoin::TestScriptParser.parse_script(i[2])
          prevout_script_values[outpoint.to_payload] = i[3] if i.size >= 4
        end

        tx = Bitcoin::Tx.parse_from_payload(json[1].htb)

        state = Bitcoin::ValidationState.new
        validation = Bitcoin::Validation.new

        expect(validation.check_tx(tx, state)).to be true
        expect(state.valid?).to be true

        tx.inputs.each_with_index do |i, index|
          amount = prevout_script_values[i.out_point.to_payload]
          amount |= 0
          flags = json[2].split(',').map {|s| Bitcoin.const_get("SCRIPT_VERIFY_#{s}")}
          witness = i.script_witness
          checker = Bitcoin::TxChecker.new(tx: tx, input_index: index, amount: amount)
          interpreter = Bitcoin::ScriptInterpreter.new(flags: flags, checker: checker)
          script_pubkey = prevout_script_pubkeys[i.out_point.to_payload]
          result = interpreter.verify_script(i.script_sig, script_pubkey, witness)
          expect(result).to be true
          expect(interpreter.error.code).to eq(Bitcoin::SCRIPT_ERR_OK)
        end
      end
    end
  end

  describe 'check tx_invalid.json' do
    invalid_tx_json = fixture_file('tx_invalid.json').select{ |j|j.size > 2}
    invalid_tx_json.each do |json|
      it "should validate tx #{json.inspect}" do

        prevout_script_pubkeys = {}
        prevout_script_values = {}

        json[0].each do |i|
          outpoint = Bitcoin::OutPoint.new(i[0], i[1])
          prevout_script_pubkeys[outpoint.to_payload] = Bitcoin::TestScriptParser.parse_script(i[2])
          prevout_script_values[outpoint.to_payload] = i[3] if i.size >= 4
        end

        tx = Bitcoin::Tx.parse_from_payload(json[1].htb)
        state = Bitcoin::ValidationState.new
        validation = Bitcoin::Validation.new

        valid = validation.check_tx(tx, state) && state.valid?

        if valid
          tx.inputs.each_with_index do |i, index|
            amount = prevout_script_values[i.out_point.to_payload]
            amount |= 0
            flags = json[2].split(',').map {|s| Bitcoin.const_get("SCRIPT_VERIFY_#{s}")}
            witness = i.script_witness
            checker = Bitcoin::TxChecker.new(tx: tx, input_index: index, amount: amount)
            interpreter = Bitcoin::ScriptInterpreter.new(flags: flags, checker: checker)
            script_pubkey = prevout_script_pubkeys[i.out_point.to_payload]
            valid = interpreter.verify_script(i.script_sig, script_pubkey, witness)
            break unless valid
          end
        end

        expect(valid).to be false
      end
    end
  end

  describe '#standard?' do
    it 'should be checked' do
      tx = Bitcoin::Tx.parse_from_payload('0200000001bd3e71da6a6ec11d022d599fe815eb5395f89b62df8bc189c5b285f499b794b50100000042410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01804a5d05000000001976a9143101929f93833bd9298b189cf272dc71d5e50ad388ac00000000'.htb)
      expect(tx.standard?).to be true

      # MAX_OP_RETURN_RELAY-byte TX_NULL_DATA (standard)
      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38'
      expect(tx.standard?).to be true

      # MAX_OP_RETURN_RELAY+1-byte TX_NULL_DATA (non-standard)
      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3800'
      expect(tx.standard?).to be false

      # Data payload can be encoded in any way...
      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << ''
      expect(tx.standard?).to be true

      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << '00' << '01'
      expect(tx.standard?).to be true

      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << -1 << 0 << '01' << 2 << 3 << 4 << 5 << 6 << 7 << 8 << 9 << 10 << 11 << 12 << 13 << 14 << 15 << 16
      expect(tx.standard?).to be true

      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << 0 << '01' << 2 << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      expect(tx.standard?).to be true

      # ...so long as it only contains PUSHDATA's
      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << OP_RETURN
      expect(tx.standard?).to be false

      # TX_NULL_DATA w/o PUSHDATA
      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN
      expect(tx.standard?).to be true

      # Only one TX_NULL_DATA permitted in all cases
      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38'
      tx.outputs << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38')
      expect(tx.standard?).to be false

      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38'
      tx.outputs[1].script_pubkey = Bitcoin::Script.new << OP_RETURN
      expect(tx.standard?).to be false

      tx.outputs[0].script_pubkey = Bitcoin::Script.new << OP_RETURN
      tx.outputs[1].script_pubkey = Bitcoin::Script.new << OP_RETURN
      expect(tx.standard?).to be false
    end
  end

  describe 'calculate size' do
    it 'should be calculate' do
      # P2WPKH
      tx = Bitcoin::Tx.parse_from_payload('010000000001018015516590902931d31f650f7e0e79a931e01bcb2f73d4ca49195aed2854b5fd0000000000ffffffff0170460d00000000001976a9148911455a265235b2d356a1324af000d4dae0326288ac02473044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda7420012102effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa00000000'.htb)
      expect(tx.vsize).to eq(113)
      expect(tx.size).to eq(194)

      # non-segwit tx
      tx = Bitcoin::Tx.parse_from_payload('010000000201e4a0f1fa83c642b91feafae36a0f8fded4158dfa6fd650e046b4364b805684000000006b483045022045c65646abc12c71352335dbec2824b2dbdef9253366b4b83439b2190ce098d2022100eed0b70371d3892f865b43e2bb713ec9e887a50d38f47e8416220daf826d0ab201210259f6658325c4e3ca6fb38f657ffcbf4b1c45ef4f0c1dd86d5f6c0cebb0e09520ffffffff31137db564a7fad07c9db5b6b862786589977c68d1270819030a9079941ca6c9010000006b48304502204354565632eedd30fb9ca5c22bb70ef848afd74f7bed354d267705a6e71ea885022100e6ea6250d29dc109cb59ac66318f1cb2768c13fb0daca7c3d91a3b8d0991e0cb01210259f6658325c4e3ca6fb38f657ffcbf4b1c45ef4f0c1dd86d5f6c0cebb0e09520ffffffff02801d2c04000000001976a914322653c91d6038e08b6d971e4560842c155c8a8888ac80248706000000001976a9143b9722f91a2e50d913dadc3a6a8a88a58a7b859788ac00000000'.htb)
      expect(tx.vsize).to eq(374)
      expect(tx.size).to eq(374)
    end
  end

  describe 'generate sighash' do
    sighash_json = fixture_file('sighash.json').select{ |j|j.size > 2}
    sighash_json.each do |json|
      it "should validate tx #{json.inspect}" do
        tx = Bitcoin::Tx.parse_from_payload(json[0].htb)
        script = Bitcoin::Script.parse_from_payload(json[1].htb)
        index, hash_type, sighash = json[2], json[3], json[4]
        expect(tx.sighash_for_input(index, script, hash_type: hash_type).bth).to eq(sighash.htb.reverse.bth)
      end
    end
  end

end