require 'spec_helper'

RSpec.describe Bitcoin::Ext::ArrayExt do

  using Bitcoin::Ext::ArrayExt

  describe '#resize' do
    it 'should resize array contents.' do
      array = [0, 1, 2, 3, 4]
      array.resize!(1)
      expect(array).to eq([0])
      array = [0, 1, 2, 3, 4]
      array.resize!(5)
      expect(array).to eq([0, 1, 2, 3, 4])
      array = [0, 1]
      array.resize!(5)
      expect(array).to eq([0, 1, 0, 0, 0])
      array = [0, 1]
      array.resize!(5, '0')
      expect(array).to eq([0, 1, '0', '0', '0'])
    end
  end

end