require 'spec_helper'

describe Bitcoin::Wallet::Account do

  describe '#parse_from_payload' do
    subject {
      Bitcoin::Wallet::Account.parse_from_payload('09e38386e382b9e38388310000000a000000110000000f0000000a000000'.htb)
    }
    it 'generate account instance' do
      expect(subject.purpose).to eq(49)
      expect(subject.index).to eq(10)
      expect(subject.name).to eq('テスト')
      expect(subject.receive_depth).to eq(17)
      expect(subject.change_depth).to eq(15)
      expect(subject.lookahead).to eq(10)
      expect(subject.witness?).to be true
      expect(subject.to_payload.bth).to eq('09e38386e382b9e38388310000000a000000110000000f0000000a000000')
    end
  end

  describe 'bip-49 key derivation' do
    subject {
      words = %w(abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about)
      master_key = Bitcoin::Wallet::MasterKey.recover_from_words(words)
      wallet = double('wallet')
      db = double('walletdb')
      allow(wallet).to receive(:accounts).and_return([])
      allow(wallet).to receive(:master_key).and_return(master_key)
      allow(wallet).to receive(:db).and_return(db)
      allow(db).to receive(:save_account)
      account = Bitcoin::Wallet::Account.new
      account.wallet = wallet
      account.init
      account
    }
    it 'should derive key' do
      expect(subject.send(:account_key).to_base58).to eq('uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n')
      expect(subject.derived_receive_keys.first.priv).to eq('c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8')
    end
  end

end