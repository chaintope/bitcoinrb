require 'spec_helper'

describe Bitcoin::GCSFilter do

  describe 'filter test' do
    it 'should be matched' do
      included = []
      excluded = []
      (1..100).each do |i|
        element1 = ('0' * 32).htb
        element1[0] = i.itb
        included << element1
        element2 = ('0' * 32).htb
        element2[1] = i.itb
        excluded << element2
      end
      encoded_filter = Bitcoin::GCSFilter.new(('0' * 32).htb, 10, 1<<10, elements: included).encoded
      filter = Bitcoin::GCSFilter.new(('0' * 32).htb, 10, 1<<10, encoded_filter: encoded_filter)
      expect(encoded_filter).to eq(filter.encoded)
      included.each do |i|
        expect(filter.match?(i)).to be true
        excluded << i
        expect(filter.match_any?(excluded)).to be true
        excluded.delete(i)
      end
    end
  end

  describe 'decoding an encoded filter' do
    let(:key) { '00' * 16 }
    let(:elements) { %w[aa bb cc].map(&:htb) }
    let(:encoded) { Bitcoin::GCSFilter.new(key.htb, 19, 784931, elements: elements).encoded }

    it 'should accept the encoding of exactly N elements, as Bitcoin Core does' do
      filter = Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: encoded)
      expect(filter.n).to eq(3)
      expect(filter.match?('aa'.htb)).to be true
      expect(filter.match?('dd'.htb)).to be false
      expect(Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: '00').match?('aa'.htb)).to be false
    end

    it 'should reject N of 2**32 or more' do
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: 'ff' + [2**32].pack('Q<').bth) }.
        to raise_error(ArgumentError, 'N must be < 2**32.')
    end

    it 'should reject a filter with fewer elements than N' do
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: '05') }.to raise_error(ArgumentError, 'encoded_filter is truncated.')
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: encoded[0...-2]) }.to raise_error(ArgumentError, 'encoded_filter is truncated.')
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: 'ff' + 'ff' * 8) }.to raise_error(ArgumentError)
    end

    it 'should reject data after the last element' do
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: encoded + 'ff') }.
        to raise_error(ArgumentError, 'encoded_filter contains excess data.')
      expect { Bitcoin::BlockFilter.decode(Bitcoin::BlockFilter::TYPE[:basic], '00' * 32, encoded + '00') }.
        to raise_error(ArgumentError, 'encoded_filter contains excess data.')
    end

    it 'should validate its parameters' do
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 784931, encoded_filter: 'zz') }.to raise_error(ArgumentError, 'encoded_filter must be a hex string.')
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 784931) }.to raise_error(ArgumentError, 'specify either elements or encoded_filter.')
      expect { Bitcoin::GCSFilter.new('ab'.htb, 19, 784931, elements: elements) }.to raise_error(ArgumentError, 'key must be 16 bytes.')
      expect { Bitcoin::GCSFilter.new(key.htb, 33, 784931, elements: elements) }.to raise_error(ArgumentError, 'p must be between 0 and 32.')
      expect { Bitcoin::GCSFilter.new(key.htb, -1, 784931, elements: elements) }.to raise_error(ArgumentError, 'p must be between 0 and 32.')
      expect { Bitcoin::GCSFilter.new(key.htb, 19, 0, elements: elements) }.to raise_error(ArgumentError, 'm must be a positive integer.')
      expect { Bitcoin::BlockFilter.decode(99, '00' * 32, '00') }.to raise_error(ArgumentError, 'unknown filter type: 99.')
    end

    it 'should hash an element by its bytes, whatever encoding the string has' do
      filter = Bitcoin::GCSFilter.new(key.htb, 19, 784931, elements: ["\xC3\xA9".b])
      expect(filter.match?("\xC3\xA9".b)).to be true
      expect(filter.match?("\xC3\xA9".dup.force_encoding('UTF-8'))).to be true
    end
  end
end
