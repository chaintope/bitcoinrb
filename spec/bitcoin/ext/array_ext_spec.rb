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
      array = [0, 1]
      array.resize!(0)
      expect(array).to eq([])
    end

    it 'should reject a size which is not a non-negative integer.' do
      [-1, 1.5, nil, '1'].each do |new_size|
        array = [0, 1, 2]
        expect{array.resize!(new_size)}.to raise_error(ArgumentError, 'new_size must be a non-negative integer.'), new_size.inspect
        expect(array).to eq([0, 1, 2])
      end
    end
  end

end