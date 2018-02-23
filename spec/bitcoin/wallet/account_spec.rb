require 'spec_helper'

describe Bitcoin::Wallet::Account do

  describe '#parse_from_payload' do
    subject {
      # m/84'/1'/10'
      Bitcoin::Wallet::Account.parse_from_payload('045f1cf6030ef4b1af8000000ad25ad4af81ddaf5f9577f082c333976c67038e0ab1674c2f1ae2c3f531f7198d0352b292231392201da3861e4004ffe41b1432de6f8545a080dde2988b8b8a716b09e38386e382b9e38388540000000a00000001000000010000000a000000'.htb)
    }
    it 'generate account instance' do
      expect(subject.purpose).to eq(84)
      expect(subject.index).to eq(10)
      expect(subject.name).to eq('テスト')
      expect(subject.receive_depth).to eq(1)
      expect(subject.change_depth).to eq(1)
      expect(subject.lookahead).to eq(10)
      expect(subject.witness?).to be true
      expect(subject.account_key.to_base58).to eq('vpub5Y6cjg78GGuNorMWAGjx5ut5eKJxY5Nyq1hMuxswC8xpjZ8ndWj17CUJt3yjFpbMKYfuRgJbVMRsefm9hbc9hMDycx5nYHuakCsVk6ZA1ZV')
      expect(subject.to_payload.bth).to eq('045f1cf6030ef4b1af8000000ad25ad4af81ddaf5f9577f082c333976c67038e0ab1674c2f1ae2c3f531f7198d0352b292231392201da3861e4004ffe41b1432de6f8545a080dde2988b8b8a716b09e38386e382b9e38388540000000a00000001000000010000000a000000')
    end
  end

  describe '#new' do
    subject {
      # bip-44 key m/44'/1'/3'
      test_master_key.key.derive(2**31 + 44).derive(2**31 + 1).derive(3 + 2**31).ext_pubkey
    }
    it 'should check purpose and account key are inconsistent.' do
      expect{Bitcoin::Wallet::Account.new(subject, Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit], 3)}.to raise_error('The purpose and the account key do not match.')
      expect{Bitcoin::Wallet::Account.new(subject, Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy], 1)}.to raise_error('Account key and index does not match.')
    end
  end

end