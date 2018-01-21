require 'spec_helper'

describe Bitcoin::Wallet do

  describe '#load' do
    context 'existing wallet' do
      subject {
        wallet = create_test_wallet
        wallet.close
        Bitcoin::Wallet::Base.load(1, TEST_WALLET_PATH)
      }
      it 'should return wallet' do
        expect(subject.wallet_id).to eq(1)
        expect(subject.path).to eq(test_wallet_path(1))
      end
    end

    context 'dose not exist wallet' do
      it 'should raise error' do
        expect{Bitcoin::Wallet::Base.load(2, TEST_WALLET_PATH)}.to raise_error(ArgumentError)
      end
    end
  end

  describe '#create' do
    context 'should create new wallet' do
      subject {Bitcoin::Wallet::Base.create(2, TEST_WALLET_PATH)}
      it 'should be create' do
        expect(subject.wallet_id).to eq(2)
        expect(subject.master_key.mnemonic.size).to eq(24)
      end
      after{
        subject.close
        FileUtils.rm_r(test_wallet_path(2))
      }
    end

    context 'same wallet_id already exist' do
      it 'should raise error' do
        expect{Bitcoin::Wallet::Base.create(1, TEST_WALLET_PATH)}.to raise_error(ArgumentError)
      end
    end
  end

  describe '#wallets_path' do
    subject { Bitcoin::Wallet::Base.wallet_paths(TEST_WALLET_PATH) }
    it 'should return wallet dir.' do
      expect(subject[0]).to eq("#{TEST_WALLET_PATH}wallet1/")
    end
  end

  describe '#create_account' do
    subject {
      wallet = create_test_wallet(3)
      wallet.create_account('hoge')
      wallet.accounts
    }
    it 'should be created' do
      expect(subject.size).to eq(2)
      expect(subject[0].purpose).to eq(49)
      expect(subject[0].index).to eq(0)
      expect(subject[0].name).to eq('Default')
      expect(subject[0].receive_depth).to eq(10)
      receive_keys = subject[0].derived_receive_keys
      expect(receive_keys.size).to eq(10)
      expect(receive_keys[0].hardened?).to be false
      expect(subject[0].change_depth).to eq(10)
      change_keys = subject[0].derived_change_keys
      expect(change_keys.size).to eq(10)
      expect(change_keys[0].hardened?).to be false
      expect(subject[0].lookahead).to eq(10)
      expect(subject[1].name).to eq('hoge')
      expect(subject[1].index).to eq(1)
    end
  end

end
