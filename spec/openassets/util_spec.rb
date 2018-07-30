# frozen_string_literal: true

require 'spec_helper'

describe OpenAssets::Util do
  describe  '.script_to_asset_id' do
    before { Bitcoin.chain_params = chain }

    context 'mainnet' do
      let(:chain) { :mainnet }

      it 'script_to_asset_id' do
        # OP_DUP OP_HASH160 010966776006953d5567439e5e39f86a0d273bee OP_EQUALVERIFY OP_CHECKSIG
        expect(described_class.script_to_asset_id('76a914010966776006953d5567439e5e39f86a0d273bee88ac')).to eq('ALn3aK1fSuG27N96UGYB1kUYUpGKRhBuBC')
      end
    end

    context 'testnet' do
      let(:chain) { :testnet }

      it 'script_to_asset_id' do
        # OP_HASH160 f9d499817e88ef7b10a88673296c6d6df2f4292d OP_EQUAL
        expect(described_class.script_to_asset_id('a914f9d499817e88ef7b10a88673296c6d6df2f4292d87')).to eq('oMb2yzA542yQgwn8XtmGefTzBv5NJ2nDjh')
      end
    end

    context 'regtest' do
      let(:chain) { :regtest }

      it 'script_to_asset_id' do
        # OP_HASH160 f9d499817e88ef7b10a88673296c6d6df2f4292d OP_EQUAL
        expect(described_class.script_to_asset_id('a914f9d499817e88ef7b10a88673296c6d6df2f4292d87')).to eq('oMb2yzA542yQgwn8XtmGefTzBv5NJ2nDjh')
      end
    end
  end
end
