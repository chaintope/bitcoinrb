require 'spec_helper'

describe Bitcoin::Wallet do

  describe '#default_path_prefix' do
    context 'testnet', network: :testnet do
      subject { Bitcoin::Wallet::Base.default_path_prefix }

      it { is_expected.to eq "#{Dir.home}/.bitcoinrb/testnet/db/wallet/" }
    end

    context 'regtest', network: :regtest do
      subject { Bitcoin::Wallet::Base.default_path_prefix }

      it { is_expected.to eq "#{Dir.home}/.bitcoinrb/regtest/db/wallet/" }
    end

    context 'change network from regtest to testnet', network: :regtest do
      it 'should return path with network prefix' do
        expect(Bitcoin::Wallet::Base.default_path_prefix).to eq "#{Dir.home}/.bitcoinrb/regtest/db/wallet/"
        Bitcoin.chain_params = :testnet
        expect(Bitcoin::Wallet::Base.default_path_prefix).to eq "#{Dir.home}/.bitcoinrb/testnet/db/wallet/"
      end
    end

  end

  describe '#load' do
    context 'existing wallet' do
      subject { Bitcoin::Wallet::Base.load(1, TEST_WALLET_PATH)}

      before do
        wallet = create_test_wallet
        wallet.close
      end
      after { subject.close }

      it 'should return wallet' do
        expect(subject.wallet_id).to eq(1)
        expect(subject.path).to eq(test_wallet_path(1))
        expect(subject.version).to eq(Bitcoin::Wallet::Base::VERSION)
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
        expect(subject.version).to eq(Bitcoin::Wallet::Base::VERSION)
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

    context 'wallet_id which names a directory outside the path prefix' do
      it 'should raise error without creating the directory' do
        message = "wallet_id must be a non-negative integer or a string of letters, digits, '_' and '-'."
        ['/../../escaped', '1/../2', '..', '', "1\n", -1, 1.5, nil].each do |wallet_id|
          expect{Bitcoin::Wallet::Base.create(wallet_id, TEST_WALLET_PATH)}.to raise_error(ArgumentError, message), wallet_id.inspect
          expect{Bitcoin::Wallet::Base.load(wallet_id, TEST_WALLET_PATH)}.to raise_error(ArgumentError, message), wallet_id.inspect
        end
        expect(Dir.exist?("#{TEST_WALLET_PATH}wallet/../../escaped")).to be false
        expect(Dir.glob("#{TEST_WALLET_PATH}../escaped*")).to be_empty
      end
    end
  end

  describe '#wallets_path' do
    subject { Bitcoin::Wallet::Base.wallet_paths(TEST_WALLET_PATH) }
    it 'should return wallet dir.' do
      expect(subject[0]).to eq("#{TEST_WALLET_PATH}wallet1/")
    end
  end

  describe '#create_account', network: :mainnet do
    subject {
      allow(Bitcoin::Wallet::MasterKey).to receive(:generate).and_return(test_master_key)
      wallet = create_test_wallet(3)
      wallet.create_account('hoge')
      wallet
    }
    it 'should be created' do
      accounts = subject.accounts
      expect(accounts.size).to eq(2)
      expect(accounts[0].purpose).to eq(84)
      expect(accounts[0].index).to eq(0)
      expect(accounts[0].name).to eq('Default')
      expect(accounts[0].receive_depth).to eq(0)
      receive_keys = accounts[0].derived_receive_keys
      expect(receive_keys[0].addr).to eq('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')
      expect(receive_keys.size).to eq(1)
      expect(receive_keys[0].hardened?).to be false
      expect(accounts[0].change_depth).to eq(0)
      change_keys = accounts[0].derived_change_keys
      expect(change_keys[0].addr).to eq('bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')
      expect(change_keys.size).to eq(1)
      expect(change_keys[0].hardened?).to be false
      expect(accounts[0].lookahead).to eq(10)
      expect(accounts[1].name).to eq('hoge')
      expect(accounts[1].index).to eq(1)

      # Account with same name can not be registered
      expect{subject.create_account('hoge')}.to raise_error(ArgumentError)
    end
  end

  describe '#accounts' do
    subject {
      wallet = create_test_wallet(4)
      wallet.create_account('native segwit1')
      wallet.create_account(Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy], 'legacy')
      wallet.create_account('native segwit2')
      wallet
    }
    it 'should return target accounts' do
      expect(subject.accounts.size).to eq(4)
      expect(subject.accounts(Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy]).size).to eq(1)
      expect(subject.accounts(Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit]).size).to eq(3)
    end
  end

  describe '#generate_new_address' do
    subject {
      allow(Bitcoin::Wallet::MasterKey).to receive(:generate).and_return(test_master_key)
      create_test_wallet(5)
    }
    it 'should return new address' do
      expect(subject.generate_new_address('Default')).to eq('tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97')
      expect(subject.generate_new_address('Default')).to eq('tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct')
      # account name does not exist.
      expect{subject.generate_new_address('hoge')}.to raise_error(ArgumentError)
    end
  end

  describe 'account names' do
    subject {
      allow(Bitcoin::Wallet::MasterKey).to receive(:generate).and_return(test_master_key)
      create_test_wallet(7)
    }
    let(:legacy) { Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy] }
    after { subject.close }

    it 'should reject the name of an existing account with a different purpose' do
      expect{subject.create_account(legacy, 'Default')}.to raise_error(ArgumentError, 'Account already exists.')
      expect(subject.accounts.size).to eq(1)
    end

    it 'should ask for the purpose when accounts of an older wallet share the name' do
      path = "m/#{legacy}'/#{Bitcoin.chain_params.bip44_coin_type}'/1'"
      account = Bitcoin::Wallet::Account.new(subject.master_key.derive(path).ext_pubkey, legacy, 1, 'Default')
      account.wallet = subject
      account.save
      expect{subject.generate_new_address('Default')}.to raise_error(ArgumentError, 'More than one account has the name, specify the purpose.')
      expect(subject.generate_new_address('Default', Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit])).to eq('tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97')
      expect(Bitcoin::Script.parse_from_addr(subject.generate_new_address('Default', legacy)).p2pkh?).to be true
    end

    it 'should load accounts whose name an older version stored without valid UTF-8' do
      path = "m/#{legacy}'/#{Bitcoin.chain_params.bip44_coin_type}'/1'"
      account = Bitcoin::Wallet::Account.new(subject.master_key.derive(path).ext_pubkey, legacy, 1)
      account.instance_variable_set(:@name, "\x83e\x83X\x83g".dup.force_encoding('UTF-8')) # Shift_JIS bytes.
      account.wallet = subject
      account.save
      expect(subject.accounts.size).to eq(2)
      expect(subject.generate_new_address('Default')).to eq('tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97')
    end

    it 'should reject a name which is not valid UTF-8' do
      expect{subject.create_account("\xff".b)}.to raise_error(ArgumentError, 'name must be valid UTF-8.')
      expect{subject.create_account("\xff".dup.force_encoding('UTF-8'))}.to raise_error(ArgumentError, 'name must be valid UTF-8.')
      expect{subject.create_account(nil)}.to raise_error(ArgumentError, 'name must be a String.')
      account = subject.create_account('テスト'.encode('Shift_JIS'))
      expect(account.name).to eq('テスト')
      expect(subject.accounts.map(&:name)).to eq(['Default', 'テスト'])
    end
  end

  describe '#get_balance' do
    it 'should return the balance in satoshis' do
      wallet = create_test_wallet(8)
      expect(wallet.get_balance(wallet.accounts.first)).to eql(0)
      wallet.close
    end
  end

  describe '#decrypt' do
    it 'should decrypt the seed and store it unencrypted' do
      wallet = create_test_wallet(8)
      seed = wallet.master_key.seed
      wallet.encrypt('passphrase')
      expect{wallet.decrypt('wrong')}.to raise_error(ArgumentError, 'Invalid passphrase.')
      expect(wallet.master_key.encrypted).to be true
      wallet.decrypt('passphrase')
      expect(wallet.master_key.encrypted).to be false
      expect(wallet.master_key.seed).to eq(seed)
      wallet.close
      loaded = Bitcoin::Wallet::Base.load(8, TEST_WALLET_PATH)
      expect(loaded.master_key.encrypted).to be false
      expect(loaded.master_key.seed).to eq(seed)
      loaded.close
    end
  end

  describe '#watch_targets' do
    subject {
      # TODO add utxo outpoints data
      allow(Bitcoin::Wallet::MasterKey).to receive(:generate).and_return(test_master_key)
      wallet = create_test_wallet(6)
      account1 = wallet.create_account('native segwit1')
      account1.create_receive
      account1.create_receive
      account1.create_change
      wallet.watch_targets
    }
    it 'should return pubkey hash in the wallet.' do
      expect(subject.size).to eq(7)
      expect(subject[0]).to eq('d0c4a3ef09e997b6e99e397e518fe3e41a118ca1') # m/84'/1'/0'/0/0 default
      expect(subject[1]).to eq('2f34aa1cf00a53b055a291a03a7d45f0a6988b52') # m/84'/1'/0'/1/0 default
      expect(subject[2]).to eq('0fa17461c68ec2241a4c4a5edf799cbe2f8fb449') # m/84'/1'/1'/0/0 account1
      expect(subject[3]).to eq('24d6a2ce123c8be57fb5ff2394f2aadd3905419b') # m/84'/1'/1'/0/1 account1
    end
  end

  describe '#current_wallet' do
    subject {
      if Bitcoin::Wallet::Base.wallet_paths(TEST_WALLET_PATH).empty?
        wallet = create_test_wallet
        wallet.close
      end
      Bitcoin::Wallet::Base.current_wallet(TEST_WALLET_PATH)
    }
    it 'should return wallet' do
      expect(subject.path).to start_with TEST_WALLET_PATH
    end
  end

end
