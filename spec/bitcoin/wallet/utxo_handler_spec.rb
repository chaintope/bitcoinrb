require 'spec_helper'

describe 'Bitcoin::Wallet::UtxoHandler' do
  let(:handler) { Bitcoin::Wallet::UtxoHandler.new(spv, utxo_db) }
  let(:utxo_db) { create_test_utxo_db }
  let(:spv) { create_test_spv }
  let(:wallet) { Bitcoin::Wallet::Base.create(1, 'tmp/wallet_db/') }

  before { allow(spv).to receive(:wallet).and_return(wallet) }

  after do
    utxo_db.close
    wallet.close
    FileUtils.rm_r('tmp/wallet_db/')
  end

  context 'when node receives tx message' do
    subject { handler.update(:tx, message) }

    let(:funding_tx) do
      # create transaction to send to the wallet
      key = wallet.accounts.first.create_receive

      # default script is native_segwit
      script = Bitcoin::Script.to_p2wpkh(Bitcoin.hash160(key.pubkey))
      Bitcoin::Tx.new.tap do |tx|
        tx.inputs << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.new('00' * 32, -1))
        tx.outputs << Bitcoin::TxOut.new(value: 600, script_pubkey: script)
      end
    end
    let(:out_point) { Bitcoin::OutPoint.from_txid(funding_tx.txid, 0)}

    context 'store utxo' do
      let(:message) { Bitcoin::Message::Tx.parse_from_payload(funding_tx.to_payload) }

      it 'should store watching utxo' do
        subject
        utxo = utxo_db.get_utxo(out_point)
        expect(utxo).not_to be_nil

        utxos = utxo_db.list_unspent_in_account(wallet.accounts.first)
        expect(utxos.size).to eq 1
      end
    end

    context 'delete utxo' do
      before do
        output = funding_tx.outputs[0];
        utxo_db.save_utxo(out_point, output.value, output.script_pubkey)
      end

      let(:message) { Bitcoin::Message::Tx.parse_from_payload(spending_tx.to_payload) }
      let(:spending_tx) do
        Bitcoin::Tx.new.tap do |tx|
          tx.inputs << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.from_txid(funding_tx.txid, 0))
          # No outputs
        end
      end

      it 'should delete unspent utxo from utxo_db' do
        expect(utxo_db.get_utxo(out_point)).not_to be_nil
        subject
        expect(utxo_db.get_utxo(out_point)).to be_nil
        utxos = utxo_db.list_unspent_in_account(wallet.accounts.first)
        expect(utxos.size).to eq 0
      end
    end
  end

  context 'when node receives header message' do
    subject { handler.update(:header, {hash: '00' * 32, height: 101}) }

    it { expect { subject }.not_to raise_error }
  end

  context 'when receive merkleblock message' do
    subject { handler.update(:merkleblock, merkle_block) }

    let(:payload) { '0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b852907000000043612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf011d'.htb }
    let(:merkle_block) { Bitcoin::Message::MerkleBlock.parse_from_payload(payload) }

    it { expect { subject }.not_to raise_error }
  end
end
