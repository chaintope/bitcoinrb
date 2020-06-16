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
  end

  describe 'derive' do
    context 'invalid path' do
      it 'should raise error.' do
        # not 83696968'
        expect{master.derive("m/83696968/0'/0'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
        expect{master.derive("m/0'/0'/0'")}.to raise_error(ArgumentError, 'Invalid BIP85 path format.')
      end
    end
  end

end