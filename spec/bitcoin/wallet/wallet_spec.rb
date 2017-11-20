require 'spec_helper'

describe Bitcoin::Wallet do

  let(:wallet) {create_test_wallet}
  after{ wallet.close }

  describe '#create_account' do
    before {
      wallet.create_account('hoge')
      wallet.create_account('fuge')
    }
    subject {wallet.accounts}
    it 'should be created' do
      expect(subject.size).to eq(2)
      expect(subject[0].purpose).to eq(44)
      expect(subject[0].index).to eq(0)
      expect(subject[0].name).to eq('hoge')
      # expect(subject[0].receive_depth).to eq(10)
      # expect(subject[0].change_depth).to eq(10)
      # expect(subject[0].lookahead).to eq(20)
      expect(subject[1].name).to eq('fuge')
      expect(subject[1].index).to eq(1)
    end
  end

end
