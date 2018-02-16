require 'spec_helper'

describe Refinements::EvenLengthHex do
  using described_class

  describe 'Integer#to_even_length_hex' do
    it { expect(0.to_even_length_hex).to eq('00') }
    it { expect(15.to_even_length_hex).to eq('0f') }
    it { expect(16.to_even_length_hex).to eq('10') }
    it { expect(255.to_even_length_hex).to eq('ff') }
    it { expect(256.to_even_length_hex).to eq('0100') }
  end
end
