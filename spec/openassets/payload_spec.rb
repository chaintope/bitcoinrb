require 'spec_helper'

describe OpenAssets::Payload do

  describe '#parse_from_payload' do
    subject {
      OpenAssets::Payload.parse_from_payload('4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71'.htb)
    }
    it 'should be parsed' do
      expect(subject.quantities.length).to eq(3)
      expect(subject.quantities[0]).to eq(100)
      expect(subject.quantities[1]).to eq(0)
      expect(subject.quantities[2]).to eq(123)
      expect(subject.metadata).to eq('u=https://cpr.sm/5YgSU1Pg-q')
    end
  end

  describe '#to_payload' do
    subject {
      OpenAssets::Payload.new([100, 0, 123], 'u=https://cpr.sm/5YgSU1Pg-q').to_payload
    }
    it 'generate payload' do
      expect(subject.bth).to eq('4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71')
    end
  end

end
