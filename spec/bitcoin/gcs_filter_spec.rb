require 'spec_helper'

describe Bitcoin::GCSFilter do

  describe 'filter test' do
    it 'should be matched' do
      included = []
      excluded = []
      (1..100).each do |i|
        element1 = ('0' * 32).htb
        element1[0] = i.to_even_length_hex.htb
        included << element1
        element2 = ('0' * 32).htb
        element2[1] = i.to_even_length_hex.htb
        excluded << element2
      end
      filter = Bitcoin::GCSFilter.new(('0' * 32).htb, 10, 1<<10, included)
      included.each do |i|
        expect(filter.match?(i)).to be true
        excluded << i
        expect(filter.match_any?(excluded)).to be true
        excluded.delete(i)
      end
    end
  end

end