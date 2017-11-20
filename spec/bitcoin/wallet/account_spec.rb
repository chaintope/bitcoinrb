require 'spec_helper'

describe Bitcoin::Wallet::Account do

  describe '#parse_from_payload' do
    subject {
      Bitcoin::Wallet::Account.parse_from_payload('09e38386e382b9e38388310000000a000000110000000f0000000a000000'.htb)
    }
    it 'generate account instance' do
      expect(subject.purpose).to eq(49)
      expect(subject.index).to eq(10)
      expect(subject.name).to eq('テスト')
      expect(subject.receive_depth).to eq(17)
      expect(subject.change_depth).to eq(15)
      expect(subject.lookahead).to eq(10)
      expect(subject.witness?).to be true
      expect(subject.to_payload.bth).to eq('09e38386e382b9e38388310000000a000000110000000f0000000a000000')
    end
  end

end