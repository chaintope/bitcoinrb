require 'spec_helper'

describe Bitcoin::Wallet::DB do
  describe '#save_key' do
    subject { wallet.db.save_key(account, purpose, index, key) }

    let(:wallet) { create_test_wallet }
    let(:account) { wallet.accounts.first }
    let(:purpose) { 1 }
    let(:index) { 2 }
    let(:key) { Bitcoin::ExtKey.generate_master('000102030405060708090a0b0c0d0e0f') }

    after do
      wallet.close
      FileUtils.rm_r(test_wallet_path(1))
    end

    it 'store public key to database' do
      expect{ subject }.to change { wallet.db.get_keys(account).length }.by(1)
    end
  end

  describe '#get_keys' do
    subject { wallet.db.get_keys(account) }

    let(:wallet) { create_test_wallet }
    let(:account) { wallet.accounts.first }
    let(:purpose) { 1 }
    let(:master) { Bitcoin::ExtKey.generate_master('000102030405060708090a0b0c0d0e0f') }

    before do
      wallet.db.save_key(account, purpose, 0xffffffff, master.derive(2))
    end

    after do
      wallet.close
      FileUtils.rm_r(test_wallet_path(1))
    end

    context 'with min/max key' do
      it 'returns 3 records' do
        # First two records are default receive address and change address.
        expect(subject.length).to eq 3
        expect(subject.last).to eq master.derive(2).pub
      end
    end
  end
end
