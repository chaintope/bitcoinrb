require 'spec_helper'
include Bitcoin::Opcodes

describe OpenAssets::MarkerOutput do

  describe '#open_assets_marker?' do
    context 'valid' do
      it 'should be true' do
        script = Bitcoin::Script.new << OP_RETURN << '4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Bitcoin::TxOut.new(script_pubkey: script).open_assets_marker?).to be true
      end
    end

    context 'invalid' do
      it 'should be false' do
        expect(Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.new).open_assets_marker?).to be false

        # p2pkh
        script = Bitcoin::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
        expect(Bitcoin::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # invalid marker
        script = Bitcoin::Script.new << OP_RETURN << '4f4201000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Bitcoin::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # invalid version
        script = Bitcoin::Script.new << OP_RETURN << '4f4100000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Bitcoin::TxOut.new(script_pubkey: script).open_assets_marker?).to be false
        script = Bitcoin::Script.new << OP_RETURN << '4f4102000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'
        expect(Bitcoin::TxOut.new(script_pubkey: script).open_assets_marker?).to be false

        # invalid metadata length
        script = Bitcoin::Script.new << OP_RETURN << '4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d' # short
        expect(Bitcoin::TxOut.new(script_pubkey: script).open_assets_marker?).to be false
      end
    end
  end

end