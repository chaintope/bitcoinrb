require 'spec_helper'

describe Bitcoin::Store::UtxoDB do 
  let(:utxo_db) { create_test_utxo_db() }

  let(:wallet) { create_test_wallet(1, Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy]) }

  after do
    utxo_db.close
    wallet.close
  end

  describe 'save and get transaction' do
    it do
      # https://www.blockchain.com/ja/btctest/tx/4484ec8b4801ada92fc4d9a90bb7d9336d02058e9547d027fa0a5fc9d2c9cc77
      tx = Bitcoin::Tx.parse_from_payload('0100000001449d45bbbfe7fc93bbe649bb7b6106b248a15da5dbd6fdc9bdfc7efede83235e010000006b483045022100e15a8ead9013d1de55e71f195c9dc613483f07c8a0692a2144ffa90506436822022062bc9466b9e1941037fc23e1cfadf24c8833f96942beb8f4340df60d506f784b012103969a4ac9b1521cfae44a929a614193b0467a20e0a15973cae9ba1efb9627d830ffffffff014062b007000000001976a914f86f0bc0a2232970ccdf4569815db500f126836188ac00000000'.htb)
      utxo_db.save_tx(tx.tx_hash, tx.to_payload)
      utxo_db.save_tx_position(tx.tx_hash, 1_351_985, 1)

      # P2PKH output(n4AYuETorj4gYKendz2ndm9QhjUuruZnfk)
      script_pubkey = Bitcoin::Script.parse_from_payload('76a914f86f0bc0a2232970ccdf4569815db500f126836188ac'.htb)
      utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 0), 129_000_000, script_pubkey, 1_351_985)

      out_point = Bitcoin::OutPoint.new(tx.tx_hash, 0)
      utxo = utxo_db.get_utxo(out_point)

      expect(utxo).not_to be_nil
      expect(utxo.tx_hash).to eq '4484ec8b4801ada92fc4d9a90bb7d9336d02058e9547d027fa0a5fc9d2c9cc77'.rhex
      expect(utxo.index).to eq 0
      expect(utxo.value).to eq 129_000_000
      expect(utxo.script_pubkey.to_payload.bth).to eq '76a914f86f0bc0a2232970ccdf4569815db500f126836188ac'
      expect(utxo.block_height).to eq 1_351_985

      utxo_db.delete_utxo(out_point)
      utxo = utxo_db.get_utxo(out_point)

      expect(utxo).to be_nil
    end
  end

  def save_test_case(utxo_db)
    # https://www.blockchain.com/btctest/tx/4484ec8b4801ada92fc4d9a90bb7d9336d02058e9547d027fa0a5fc9d2c9cc77
    tx = Bitcoin::Tx.parse_from_payload('0100000001449d45bbbfe7fc93bbe649bb7b6106b248a15da5dbd6fdc9bdfc7efede83235e010000006b483045022100e15a8ead9013d1de55e71f195c9dc613483f07c8a0692a2144ffa90506436822022062bc9466b9e1941037fc23e1cfadf24c8833f96942beb8f4340df60d506f784b012103969a4ac9b1521cfae44a929a614193b0467a20e0a15973cae9ba1efb9627d830ffffffff014062b007000000001976a914f86f0bc0a2232970ccdf4569815db500f126836188ac00000000'.htb)
    utxo_db.save_tx(tx.tx_hash, tx.to_payload)
    utxo_db.save_tx_position(tx.tx_hash, 1_351_985, 1)

    # P2PKH output(n4AYuETorj4gYKendz2ndm9QhjUuruZnfk)
    script_pubkey = Bitcoin::Script.parse_from_payload('76a914f86f0bc0a2232970ccdf4569815db500f126836188ac'.htb)
    utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 0), 129_000_000, script_pubkey, 1_351_985)

    # https://www.blockchain.com/btctest/tx/ad244cfa748b8635195abeca81e38b5db261ea2e7d7a39933135a2bc3aff7a85
    tx = Bitcoin::Tx.parse_from_payload('0200000001c2572c7e6987e7f73ae446715d72e57253f858875843333e9ae120468b0a3a7a000000006a473044022010e948d3162d959fab670766b0c97090a908390f3798ede3f13428d13d07e23602201685f655f44e842afb487f5b0456c5ad5a85b7e49edde9e517ccc95413f19ca8012103ad36d20361c4f6b85ee5fe4a0bbf96bb5a7d0351b5b68781a41c4d917a5da6dafeffffff0280a4bf070000000017a9142f15f8cd2f81b30d6f7fc1f9558f134097ce37ea874f507e12000000001976a91458b70116a55effb07a29e6d4086457000af8c65088acbea21400'.htb)
    utxo_db.save_tx(tx.tx_hash, tx.to_payload)
    utxo_db.save_tx_position(tx.tx_hash, 1_352_383, 1)

    # P2SH output(2MwYC4w4xucVYqTRk89u7V2FaBSdrpjmk15)
    script_pubkey = Bitcoin::Script.parse_from_payload('a9142f15f8cd2f81b30d6f7fc1f9558f134097ce37ea87'.htb)
    utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 0), 130_000_000, script_pubkey, 1_352_383)

    # P2PKH output(moc2zHyM2ozqE81vaQGHvoKSmisREDXJVh)
    script_pubkey = Bitcoin::Script.parse_from_payload('76a91458b70116a55effb07a29e6d4086457000af8c65088ac'.htb)
    utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 1), 310_267_983, script_pubkey, 1_352_383)

    # https://www.blockchain.com/btctest/tx/4e70cfb5ca582aeb88924fe74dbcb49503699f0f09adb2493c7439d051668af7
    tx = Bitcoin::Tx.parse_from_payload('0100000001593dc1e033f9040b29eef0715790c5a383ddd3054f98b2418cd7d2ab229fb007000000006a47304402202ecef6c319d65d408d953d9f4dc6c8882e638d6493751c6728448fc14c8d98920220684a2c222c7b5529e6f290ae08ebe07b893de69c3f92b68fc9a9b7f804e027c9012102effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefaffffffff02a086010000000000220020ee6e25ff1fcf33396396cc82bb3702533fb1ad5289711262ed75e0dea34d84e4c0980b00000000001976a9148911455a265235b2d356a1324af000d4dae0326288ac00000000'.htb)
    utxo_db.save_tx(tx.tx_hash, tx.to_payload)
    utxo_db.save_tx_position(tx.tx_hash, 1_088_578, 3)

    # P2WSH output(tb1qaehztlcleuenjcukejptkdcz2vlmrt2j39c3ychdwhsdag6dsnjq33vvgj)
    script_pubkey = Bitcoin::Script.parse_from_payload('0020ee6e25ff1fcf33396396cc82bb3702533fb1ad5289711262ed75e0dea34d84e4'.htb)
    utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 0), 100_000, script_pubkey, 1_088_578)
    # P2PKH output(mt1hZLajqyc63NkWy7qvgiuum5nuTBdVZ6)
    script_pubkey = Bitcoin::Script.parse_from_payload('76a9148911455a265235b2d356a1324af000d4dae0326288ac'.htb)
    output = Bitcoin::TxOut.new(value: 760_000, script_pubkey: script_pubkey)
    utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 1), 760_000, script_pubkey, 1_088_578)

    # https://www.blockchain.com/btctest/tx/fdb55428ed5a1949cad4732fcb1be031a9790e7e0f651fd33129909065511580
    tx = Bitcoin::Tx.parse_from_payload('0100000001f55cb86d8d04d4759fb8b05a198cf4d48d790e6c64d00e072aed98281d0ebff1010000006b483045022100fe718c5f0bb58d86225e1d9370f858b8c864f00112c6a33f9910fa7ea8e9c34b02203cef1a73a0a8e210c6a264446bbb90c86b7b6f6e6f411aa505f0a835ff147204012102effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefaffffffff02806d0d00000000001600148911455a265235b2d356a1324af000d4dae0326250a1c917000000001976a9142c159d64daa0de5ae6abac61a9416c8a54e834bd88ac00000000'.htb)
    utxo_db.save_tx(tx.tx_hash, tx.to_payload)
    utxo_db.save_tx_position(tx.tx_hash, 1_088_191, 43)

    # P2WPKH output(tb1q3yg52k3x2g6m956k5yey4uqq6ndwqvnzk6y257)
    script_pubkey = Bitcoin::Script.parse_from_payload('00148911455a265235b2d356a1324af000d4dae03262'.htb)
    utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 0), 880_000, script_pubkey, 1_088_191)
    # P2PKH output(mjY3vKRzyHkpB5kbEwCxFNmkFb4wKVDVab)
    script_pubkey = Bitcoin::Script.parse_from_payload('76a9142c159d64daa0de5ae6abac61a9416c8a54e834bd88ac'.htb)
    utxo_db.save_utxo(Bitcoin::OutPoint.new(tx.tx_hash, 1), 399_090_000, script_pubkey, 1_088_191)
  end

  describe '#list_unspent' do
    subject { utxo_db.list_unspent(current_block_height: 1_400_000, min: min, max: max, addresses: addresses)}

    before { save_test_case(utxo_db) }

    let(:min) { 0 }
    let(:max) { 999_999 }
    let(:addresses) { nil }

    context 'not filtered' do
      it 'should returns all utxos in wallet' do
        expect(subject.size).to eq 7
      end
    end

    context 'filterd by min' do
      let(:min) { 47_618 }

      it 'should returns utxos with >= 47_618 confirmations' do
        expect(subject.size).to eq 5
        expect(subject.map(&:block_height).sort).to eq [1_088_191, 1_088_191, 1_088_578, 1_088_578, 1_351_985]
      end
    end

    context 'filterd by max' do
      let(:max) { 47_618 }

      it 'should returns utxos with < 47_618 confirmations' do
        expect(subject.size).to eq 2
        expect(subject.map(&:block_height).sort).to eq [1_352_383, 1_352_383]
      end
    end

    context 'filterd by address(P2PKH)' do
      let(:addresses) { ['n4AYuETorj4gYKendz2ndm9QhjUuruZnfk'] }

      it 'should returns p2pkh utxos' do
        expect(subject.size).to eq 1
        expect(subject.first.value).to eq 129_000_000
        expect(subject.first.tx_hash).to eq '4484ec8b4801ada92fc4d9a90bb7d9336d02058e9547d027fa0a5fc9d2c9cc77'.rhex
        expect(subject.first.index).to eq 0
        expect(subject.first.script_pubkey.addresses).to eq ['n4AYuETorj4gYKendz2ndm9QhjUuruZnfk']
        expect(subject.first.block_height).to eq 1_351_985
      end
    end

    context 'filterd by address(P2SH)' do
      let(:addresses) { ['2MwYC4w4xucVYqTRk89u7V2FaBSdrpjmk15'] }

      it 'should returns p2sh utxos' do
        expect(subject.size).to eq 1
        expect(subject.first.value).to eq 130_000_000
        expect(subject.first.tx_hash).to eq 'ad244cfa748b8635195abeca81e38b5db261ea2e7d7a39933135a2bc3aff7a85'.rhex
        expect(subject.first.index).to eq 0
        expect(subject.first.script_pubkey.addresses).to eq ['2MwYC4w4xucVYqTRk89u7V2FaBSdrpjmk15']
        expect(subject.first.block_height).to eq 1_352_383
      end
    end

    context 'filterd by address(P2WPKH)' do
      let(:addresses) { ['tb1q3yg52k3x2g6m956k5yey4uqq6ndwqvnzk6y257'] }

      it 'should returns p2wpkh utxos' do
        expect(subject.size).to eq 1
        expect(subject.first.value).to eq 880_000
        expect(subject.first.tx_hash).to eq 'fdb55428ed5a1949cad4732fcb1be031a9790e7e0f651fd33129909065511580'.rhex
        expect(subject.first.index).to eq 0
        expect(subject.first.script_pubkey.addresses).to eq ['tb1q3yg52k3x2g6m956k5yey4uqq6ndwqvnzk6y257']
        expect(subject.first.block_height).to eq 1_088_191
      end
    end

    context 'filterd by address(P2WSH)' do
      let(:addresses) { ['tb1qaehztlcleuenjcukejptkdcz2vlmrt2j39c3ychdwhsdag6dsnjq33vvgj'] }

      it 'should returns p2wsh utxos' do
        expect(subject.size).to eq 1
        expect(subject.first.value).to eq 100_000
        expect(subject.first.tx_hash).to eq '4e70cfb5ca582aeb88924fe74dbcb49503699f0f09adb2493c7439d051668af7'.rhex
        expect(subject.first.index).to eq 0
        expect(subject.first.script_pubkey.addresses).to eq ['tb1qaehztlcleuenjcukejptkdcz2vlmrt2j39c3ychdwhsdag6dsnjq33vvgj']
        expect(subject.first.block_height).to eq 1_088_578
      end
    end
  end

  describe 'list_unspent_in_account' do
    before { save_test_case(utxo_db) }

    let(:min) { 0 }
    let(:max) { 999_999 }
    let(:account) { wallet.accounts.first }

    it 'should returns utxo in wallet' do
      unspents = utxo_db.list_unspent_in_account(account, current_block_height: 101, min: min, max: max)
      expect(unspents).to eq []

      account.watch_targets.each.with_index do |t, i|
        script_pubkey = Bitcoin::Script.to_p2pkh(t)
        utxo_db.save_utxo(Bitcoin::OutPoint.new("0101010101010101010101010101010101010101010101010101010101010101", i), i * 1_000, script_pubkey, 100)
      end

      unspents = utxo_db.list_unspent_in_account(account, current_block_height: 101, min: min, max: max)
      expect(unspents.size).to eq 2
    end
  end
end
