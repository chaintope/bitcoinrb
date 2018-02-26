require 'spec_helper'

describe Bitcoin::BloomFilter do

  # see https://github.com/bitcoin/bitcoin/blob/master/src/test/bloom_tests.cpp
  describe '#insert' do
    context "without tweak" do
      subject{ Bitcoin::BloomFilter.create_filter(3, 0.01) }
      it do
        subject.add("99108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)
        subject.add("b5a2c786d9ef4658287ced5914b37a1b4aa32eee".htb)
        subject.add("b9300670b4c5366e95b2699e8b18bc75e5f729c5".htb)
        expect(subject.to_a).to eq [0x61, 0x4e, 0x9b]
        expect(subject.contains?("99108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)).to be true
        expect(subject.contains?("19108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)).to be false
      end
    end

    context "with tweak" do
      subject{ Bitcoin::BloomFilter.create_filter(3, 0.01, 2147483649) }
      it do
        subject.add("99108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)
        subject.add("b5a2c786d9ef4658287ced5914b37a1b4aa32eee".htb)
        subject.add("b9300670b4c5366e95b2699e8b18bc75e5f729c5".htb)
        expect(subject.to_a).to eq [0xce, 0x42, 0x99]
        expect(subject.contains?("99108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)).to be true
        expect(subject.contains?("19108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)).to be false
      end
    end

    context "add key", network: :mainnet do
      subject{ Bitcoin::BloomFilter.create_filter(2, 0.001) }
      it do
        key = Bitcoin::Key.from_wif("5Kg1gnAjaLfKiwhhPpGS3QfRg2m6awQvaj98JCZBZQ5SuS2F15C")
        subject.add(key.pubkey.htb)
        subject.add(Bitcoin.hash160(key.pubkey).htb)
        expect(subject.to_a).to eq [0x8f, 0xc1, 0x6b]
      end
    end
  end

  describe "#clear" do
    subject{ Bitcoin::BloomFilter.create_filter(3, 0.01) }
    it do
      subject.add("99108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)
      expect{subject.clear}.to change{subject.to_a}.to [0x00, 0x00, 0x00]
      expect(subject.contains?("99108ad8ed9bb6274d3980bab5a85c048f0950c8".htb)).to be false
    end
  end
end
