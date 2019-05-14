require 'spec_helper'

describe Bitcoin::Store::UtxoDB do 
  describe 'verify test setup' do
    let(:wallet) do
      wallet = create_test_wallet(1, Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy])
    end

    let(:addresses) do
      addresses = []
      # 0 to select receive key
      keys = wallet.db.get_keys_type(wallet.accounts[0], 0)      
      keys.each do |key|
        k = Bitcoin::Key.new(pubkey: key, key_type: Bitcoin::Key::TYPES[:compressed])
        addresses.push(k.to_p2pkh)
      end
      addresses
    end
  
    subject { create_test_utxo_db(wallet) }
    after do
      subject.close
    end

    it 'should have initialized correctly' do
      a = addresses
      expect(wallet.wallet_id).to eq(1)
      expect(subject.version).to eq(1)
    end

    it 'should has ONE account' do
      expect(wallet.accounts.length).to eq(1)
    end

    it 'should has the expected account type' do
      expect(wallet.accounts[0].purpose).to eq(Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy])
    end
  end

  describe 'handles P2PKH' do
    let(:wallet) do
      wallet = create_test_wallet(1, Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy])
      wallet
    end

    let(:addresses) do
      addresses = []
      keys = wallet.db.get_keys(wallet.accounts[0])
      keys.each do |key|
        k = Bitcoin::Key.new(pubkey: key, key_type: Bitcoin::Key::TYPES[:p2pkh])
        addresses.push(k.to_p2pkh)
      end
      addresses
    end

    let(:hashes) do
      hashes = []
      keys = wallet.db.get_keys(wallet.accounts[0])
      keys.each do |key|
        k = Bitcoin::Key.new(pubkey: key, key_type: Bitcoin::Key::TYPES[:p2pkh])
        hashes.push(k.hash160)
      end
      hashes
    end

    let(:payloads) do
      payloads = []
      payload = '010000000201e4a0f1fa83c642b91feafae36a0f8fded4158dfa6fd650e046b4364b805684000000006b483045022045c65646abc12c71352335dbec2824b2dbdef9253366b4b83439b2190ce098d2022100eed0b70371d3892f865b43e2bb713ec9e887a50d38f47e8416220daf826d0ab201210259f6658325c4e3ca6fb38f657ffcbf4b1c45ef4f0c1dd86d5f6c0cebb0e09520ffffffff31137db564a7fad07c9db5b6b862786589977c68d1270819030a9079941ca6c9010000006b48304502204354565632eedd30fb9ca5c22bb70ef848afd74f7bed354d267705a6e71ea885022100e6ea6250d29dc109cb59ac66318f1cb2768c13fb0daca7c3d91a3b8d0991e0cb01210259f6658325c4e3ca6fb38f657ffcbf4b1c45ef4f0c1dd86d5f6c0cebb0e09520ffffffff02801d2c04000000001976a914322653c91d6038e08b6d971e4560842c155c8a8888ac80248706000000001976a9143b9722f91a2e50d913dadc3a6a8a88a58a7b859788ac00000000'
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)
      tx.outputs[0].script_pubkey = Bitcoin::Script.to_p2pkh(hashes[0])
      payload = tx.to_payload.bth
      payloads.push(payload)
      payloads
    end
  
    subject { create_test_utxo_db(wallet) }
    after do
      subject.close
    end

    it 'should replace script_pubkey correctly' do
      payload = payloads[0]

      payload = '010000000001018015516590902931d31f650f7e0e79a931e01bcb2f73d4ca49195aed2854b5fd0000000000ffffffff0170460d00000000001976a9148911455a265235b2d356a1324af000d4dae0326288ac02473044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda7420012102effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa00000000'
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)
      
      # original payload was valid
      state = Bitcoin::ValidationState.new
      validation = Bitcoin::Validation.new
      valid = validation.check_tx(tx, state) && state.valid?
      expect(valid).to eq(true)
      expect(tx.to_payload).to eq(payload.htb)
      expect(tx.to_payload.bth).to eq(payload)

      # check new script_pubkey
      hashes.each do |address|
        tx.outputs[0].script_pubkey = Bitcoin::Script.to_p2pkh(address)
        payload = tx.to_payload.bth

        tx = Bitcoin::Tx.parse_from_payload(payload.htb)
        state = Bitcoin::ValidationState.new
        validation = Bitcoin::Validation.new
        valid = validation.check_tx(tx, state) && state.valid?
        expect(valid).to eq(true)
        expect(tx.outputs[0].script_pubkey.type).not_to eq('')

        script_pubkey = tx.outputs[0].script_pubkey
        expect(script_pubkey.include?(address)).to be true
     end
    end

    it 'should save p2pkh to utxo' do
      payload = payloads[0]
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)

      hashes = wallet.db.get_keys_and_addresses(wallet.accounts[0])
      out = subject.filter_and_save_tx(hashes, tx)
      expect(out.length).to eq(1)

      out_point = out[0]
      value = tx.outputs[0].value;
      script_pubkey = tx.outputs[0].script_pubkey
      block_height = nil
      utxo = Bitcoin::Utxo.new(out_point.hash, out_point.index, value, script_pubkey, block_height)
      got_utxo = subject.get_utxo(out_point)
      expect(got_utxo.to_payload.unpack('H*')).to eq(utxo.to_payload.unpack('H*'))
    end

    it 'should save p2pkh to utxo (with block height) and expected CRUD operations' do
      block_height = 12345

      payload = payloads[0]
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)

      # save utxo
      hashes = wallet.db.get_keys_and_addresses(wallet.accounts[0])
      out = subject.filter_and_save_tx(hashes, tx, block_height)
      expect(out.length).to eq(1)

      # retrieve utxo
      out_point = out[0]
      value = tx.outputs[0].value;
      script_pubkey = tx.outputs[0].script_pubkey      
      utxo = Bitcoin::Utxo.new(out_point.hash, out_point.index, value, script_pubkey, block_height)
      got_utxo = subject.get_utxo(out_point)
      expect(got_utxo.to_payload.unpack('H*')).to eq(utxo.to_payload.unpack('H*'))

      # retrieve by tx_hash
      out = subject.get_tx(utxo.tx_hash)
      expect(out.length).to eq(3)

      # retrieve all unspent
      out = subject.list_unspent()
      expect(out.length).to eq(1)

      # retrieve unspent by account
      out = subject.list_unspent_in_account(wallet.accounts[0])
      expect(out.length).to eq(1)

      # retrieve balance
      out = subject.get_balance(wallet.accounts[0])
      expect(out).to eq(value)
      
      # retrieve unspent by address
      out = subject.list_unspent(addresses:addresses)
      expect(out.length).to eq(1)
      
      # delete utxo(s) correctly
      subject.delete_utxo(out_point)
      out = subject.level_db.keys
      expect(out.length).to eq(0)
    end
  end

  # -----------------------------------------------------

  describe 'handles P2WPKH' do
    let(:wallet) do
      wallet = create_test_wallet(1, Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit])
      wallet
    end

    let(:hashes) do
      hashes = []     
      keys = wallet.db.get_keys(wallet.accounts[0])
      keys.each do |key|
        k = Bitcoin::Key.new(pubkey: key, key_type: Bitcoin::Key::TYPES[:p2wpkh])
        hashes.push(Bitcoin::Script.to_p2wpkh(k.hash160))
      end
      hashes
    end

    let(:payloads) do
      payloads = []
      payload = '010000000001018015516590902931d31f650f7e0e79a931e01bcb2f73d4ca49195aed2854b5fd0000000000ffffffff0170460d00000000001976a9148911455a265235b2d356a1324af000d4dae0326288ac02473044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda7420012102effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa00000000'
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)
      tx.outputs[0].script_pubkey = hashes[0]
      payload = tx.to_payload.bth
      payloads.push(payload)
      payloads
    end
  
    subject { create_test_utxo_db(wallet) }
    after do
      subject.close
    end

    it 'should save p2wpkh to utxo' do
      payload = payloads[0]
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)

      hashes = wallet.db.get_keys_and_addresses(wallet.accounts[0])
      out = subject.filter_and_save_tx(hashes, tx)
      expect(out.length).to eq(1)

      out_point = out[0]
      value = tx.outputs[0].value;
      script_pubkey = tx.outputs[0].script_pubkey
      block_height = nil
      utxo = Bitcoin::Utxo.new(out_point.hash, out_point.index, value, script_pubkey, block_height)
      got_utxo = subject.get_utxo(out_point)
      expect(got_utxo.to_payload.unpack('H*')).to eq(utxo.to_payload.unpack('H*'))
    end
  end

  # -----------------------------------------------------

  describe 'handles P2SH' do
    let(:wallet) do
      wallet = create_test_wallet(1, Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy])
      wallet
    end

    let(:hashes) do
      k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
      hashes = []     
      keys = wallet.db.get_keys(wallet.accounts[0])
      keys.each do |key|
        script = Bitcoin::Script.to_p2sh_multisig_script(1, [k1, key])
        hashes.push(script)
      end
      hashes
    end

    let(:payloads) do
      payloads = []
      payload = '010000000001018015516590902931d31f650f7e0e79a931e01bcb2f73d4ca49195aed2854b5fd0000000000ffffffff0170460d00000000001976a9148911455a265235b2d356a1324af000d4dae0326288ac02473044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda7420012102effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa00000000'
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)
      tx.outputs[0].script_pubkey = hashes[0][0]
      payload = tx.to_payload.bth
      payloads.push(payload)
      payloads
    end
  
    subject { create_test_utxo_db(wallet) }
    after do
      subject.close
    end

    it 'should save p2sh to utxo' do
      payload = payloads[0]
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)
      musig = hashes.map {|h| h[0].to_s}
      out = subject.filter_and_save_tx(musig, tx)
      expect(out.length).to eq(1)

      out_point = out[0]
      value = tx.outputs[0].value;
      script_pubkey = tx.outputs[0].script_pubkey
      block_height = nil
      utxo = Bitcoin::Utxo.new(out_point.hash, out_point.index, value, script_pubkey, block_height)
      got_utxo = subject.get_utxo(out_point)
      expect(got_utxo.to_payload.unpack('H*')).to eq(utxo.to_payload.unpack('H*'))
    end
  end

  # -----------------------------------------------------

  describe 'handles P2WSH' do
    let(:wallet) do
      wallet = create_test_wallet(1, Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit])
      wallet
    end

    let(:hashes) do
      k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
      hashes = []     
      keys = wallet.db.get_keys(wallet.accounts[0])
      keys.each do |key|
        redeem_script = Bitcoin::Script.to_multisig_script(1, [k1, key])
        script = Bitcoin::Script.to_p2wsh(redeem_script)
        hashes.push(script)
      end
      hashes
    end

    let(:payloads) do
      payloads = []
      payload = '010000000001018015516590902931d31f650f7e0e79a931e01bcb2f73d4ca49195aed2854b5fd0000000000ffffffff0170460d00000000001976a9148911455a265235b2d356a1324af000d4dae0326288ac02473044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda7420012102effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa00000000'
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)
      tx.outputs[0].script_pubkey = hashes[0]
      payload = tx.to_payload.bth
      payloads.push(payload)
      payloads
    end
  
    subject { create_test_utxo_db(wallet) }
    after do
      subject.close
    end

    it 'should save p2wsh to utxo' do
      payload = payloads[0]
      tx = Bitcoin::Tx.parse_from_payload(payload.htb)
      musig = []
      hashes.each do |h|
        musig.push(h.to_s)
      end

      out = subject.filter_and_save_tx(musig, tx)
      expect(out.length).to eq(1)

      out_point = out[0]
      value = tx.outputs[0].value;
      script_pubkey = tx.outputs[0].script_pubkey
      block_height = nil
      utxo = Bitcoin::Utxo.new(out_point.hash, out_point.index, value, script_pubkey, block_height)
      got_utxo = subject.get_utxo(out_point)
      expect(got_utxo.to_payload.unpack('H*')).to eq(utxo.to_payload.unpack('H*'))
    end
  end

  # -----------------------------------------------------

  describe 'handles P2SH-P2WPKH' do
    # Todo: there is an error with this wallet type
    # let(:wallet) do
    #   wallet = create_test_wallet(1, Bitcoin::Wallet::Account::PURPOSE_TYPE[:nested_segwit])
    #   wallet
    # end
  end
end