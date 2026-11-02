require 'spec_helper'

describe Bitcoin::BIP85Entropy, network: :mainnet do

  XRPV = 'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb'

  master = Bitcoin::BIP85Entropy.from_base58(XRPV)

  describe 'Test Vector' do
    it 'should generate entropy.' do
      k1 = master.derive("m/83696968'/0'/0'")
      expect(k1.first).to eq("efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7")

      k2 = master.derive("m/83696968'/0'/1'")
      expect(k2.first).to eq("70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e")
    end
  end

  describe 'BIP39 Application' do
    context '12 words' do
      subject { master.derive("m/83696968'/39'/0'/12'/0'") }
      it 'should derive entropy for 12 mnemonic words' do
        expect(subject.first).to eq("6250b68daf746d12a24d58b4787a714b")
        expect(subject[1]).to eq(%w(girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose))
      end
    end

    context '18 words' do
      subject { master.derive("m/83696968'/39'/0'/18'/0'") }
      it 'should derive entropy for 18 mnemonic words' do
        expect(subject.first).to eq("938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc")
        expect(subject[1]).to eq(%w(near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token))
      end
    end

    context '24 words' do
      subject { master.derive("m/83696968'/39'/0'/24'/0'") }
      it 'should derive entropy for 24 mnemonic words' do
        expect(subject.first).to eq("ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f")
        expect(subject[1]).to eq(%w(puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano))
      end
    end
  end

  describe 'HD-Seed WIF' do
    subject { master.derive("m/83696968'/2'/0'") }
    it 'should derive entropy for HD-Seed WIF' do
      expect(subject.first).to eq("7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1")
      expect(subject[1]).to eq("Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp")
    end
  end

  describe 'XPRV' do
    subject { master.derive("m/83696968'/32'/0'") }
    it 'should derive entropy fo XPRV' do
      expect(subject.first).to eq("52405cd0dd21c5be78314a7c1a3c65ffd8d896536cc7dee3157db5824f0c92e2ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682")
      expect(subject[1]).to eq("xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX")
    end
  end

  describe 'HEX' do
    subject { master.derive("m/83696968'/128169'/64'/0'") }
    it 'should derive entropy fo HEX' do
      expect(subject.first).to eq("492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c")
    end

    it 'should truncate the entropy to num_bytes, which is 16 to 64' do
      entropy, result = master.derive("m/83696968'/128169'/32'/0'")
      expect(entropy.size).to eq(64)
      expect(result).to eq(entropy)
      expect(master.derive("m/83696968'/128169'/16'/0'").first.size).to eq(32)
      expect { master.derive("m/83696968'/128169'/15'/0'") }.to raise_error(ArgumentError, "num_bytes 15' must be between 16 and 64.")
      expect { master.derive("m/83696968'/128169'/65'/0'") }.to raise_error(ArgumentError, "num_bytes 65' must be between 16 and 64.")
    end
  end

  describe 'PWD BASE64' do
    it 'should derive the password of the BIP-85 test vector' do
      entropy, pwd = master.derive("m/83696968'/707764'/21'/0'")
      expect(entropy).to eq('74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9')
      expect(pwd).to eq('dKLoepugzdVJvdL56ogNV')
      expect(master.derive("m/83696968'/707764'/86'/0'").last.size).to eq(86)
      expect { master.derive("m/83696968'/707764'/19'/0'") }.to raise_error(ArgumentError, "pwd_len 19' must be between 20 and 86.")
      expect { master.derive("m/83696968'/707764'/87'/0'") }.to raise_error(ArgumentError, "pwd_len 87' must be between 20 and 86.")
    end
  end

  describe 'PWD BASE85' do
    it 'should derive the password of the BIP-85 test vector' do
      entropy, pwd = master.derive("m/83696968'/707785'/12'/0'")
      expect(entropy).to eq('f7cfe56f63dca2490f65fcbf9ee63dcd85d18f751b6b5e1c1b8733af6459c904a75e82b4a22efff9b9e69de2144b293aa8714319a054b6cb55826a8e51425209')
      expect(pwd).to eq('_s`{TW89)i4`')
      expect(master.derive("m/83696968'/707785'/80'/0'").last.size).to eq(80)
      expect { master.derive("m/83696968'/707785'/9'/0'") }.to raise_error(ArgumentError, "pwd_len 9' must be between 10 and 80.")
      expect { master.derive("m/83696968'/707785'/81'/0'") }.to raise_error(ArgumentError, "pwd_len 81' must be between 10 and 80.")
    end
  end

  describe 'BIP39 Application with 15 and 21 words' do
    it 'should derive a mnemonic of the requested length' do
      mnemonic = Bitcoin::Mnemonic.new('english')
      entropy, words = master.derive("m/83696968'/39'/0'/15'/0'")
      expect(entropy.size).to eq(40)
      expect(words.size).to eq(15)
      expect(mnemonic.to_entropy(words)).to eq(entropy)
      entropy, words = master.derive("m/83696968'/39'/0'/21'/0'")
      expect(entropy.size).to eq(56)
      expect(words.size).to eq(21)
      expect(mnemonic.to_entropy(words)).to eq(entropy)
      expect { master.derive("m/83696968'/39'/0'/13'/0'") }.to raise_error(ArgumentError, "Word length 13' does not supported.")
      expect { master.derive("m/83696968'/39'/2'/12'/0'") }.to raise_error(ArgumentError, "bitcoinrb does not support language: 2'")
    end
  end

  describe 'derive' do
    context 'invalid path' do
      it 'should raise error.' do
        # not 83696968'
        expect{master.derive("m/83696968/0'/0'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
        expect{master.derive("m/0'/0'/0'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
        # Every index has to be hardened, and an application takes a fixed number of parameters.
        expect{master.derive("m/83696968'/39'/0'/12'/0")}.to raise_error(ArgumentError, 'Every index of a BIP85 path must be hardened.')
        expect{master.derive("m/83696968'/39'/0'/12'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
        expect{master.derive("m/83696968'/39'/0'/12'/0'/7'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
        expect{master.derive("m/83696968'/2'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
        expect{master.derive("m/83696968'/32'/0'/1'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
        expect{master.derive("m/83696968'/128169'/64'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
      end
    end

    context 'an application this class does not know' do
      it 'should return the 64 byte entropy as it is' do
        entropy, result = master.derive("m/83696968'/828365'/0'")
        expect(entropy.size).to eq(128)
        expect(result).to eq(entropy)
      end
    end
  end

end