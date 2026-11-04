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
      expect(subject.to_hex).to eq('045f1cf6030ef4b1af8000000ad25ad4af81ddaf5f9577f082c333976c67038e0ab1674c2f1ae2c3f531f7198d0352b292231392201da3861e4004ffe41b1432de6f8545a080dde2988b8b8a716b09e38386e382b9e38388540000000a00000001000000010000000a000000')
    end

    it 'should reject a truncated payload and data after the account' do
      payload = '045f1cf6030ef4b1af8000000ad25ad4af81ddaf5f9577f082c333976c67038e0ab1674c2f1ae2c3f531f7198d0352b292231392201da3861e4004ffe41b1432de6f8545a080dde2988b8b8a716b09e38386e382b9e38388540000000a00000001000000010000000a000000'.htb
      [0, 77, 78, 80, 88, payload.bytesize - 1].each do |size|
        expect{Bitcoin::Wallet::Account.parse_from_payload(payload[0, size])}.to raise_error(ArgumentError), size.to_s
      end
      expect{Bitcoin::Wallet::Account.parse_from_payload(payload + "\x00".b)}.to raise_error(ArgumentError, 'Account payload has data after the account.')
      expect{Bitcoin::Wallet::Account.parse_from_payload(nil)}.to raise_error(ArgumentError, 'payload must be a String.')
    end
  end

  describe '#new' do
    subject {
      # bip-44 key m/44'/1'/3'
      test_master_key.key.derive(2**31 + 44).derive(2**31 + 1).derive(3 + 2**31).ext_pubkey
    }
    it 'should check purpose and account key are inconsistent.' do
      expect{Bitcoin::Wallet::Account.new(subject, Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit], 3)}.to raise_error(ArgumentError, 'The purpose and the account key do not match.')
      expect{Bitcoin::Wallet::Account.new(subject, Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy], 1)}.to raise_error(ArgumentError, 'Account key and index does not match.')
    end

    it 'should reject an invalid parameter with ArgumentError' do
      legacy = Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy]
      expect(Bitcoin::Wallet::Account.new(subject, legacy, 3).index).to eq(3)
      expect{Bitcoin::Wallet::Account.new(subject.to_base58, legacy, 3)}.to raise_error(ArgumentError, 'account_key must be an instance of Bitcoin::ExtPubkey.')
      [0, 45, nil, '44'].each do |purpose|
        expect{Bitcoin::Wallet::Account.new(subject, purpose, 3)}.to raise_error(ArgumentError, 'purpose must be one of 44, 49, 84.'), purpose.inspect
      end
      [-1, 2**31, nil, '3', 3.0].each do |index|
        expect{Bitcoin::Wallet::Account.new(subject, legacy, index)}.to raise_error(ArgumentError, 'index must be an integer from 0 to 2**31 - 1.'), index.inspect
      end
    end
  end

end