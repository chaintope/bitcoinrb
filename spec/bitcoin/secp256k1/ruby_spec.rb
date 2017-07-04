require 'spec_helper'

describe Bitcoin::Secp256k1::Ruby do

  describe '#generate_key_pair' do
    context 'compressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key_pair }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].htb.bytesize).to eq(32)
        # pubkey
        expect(subject[1].htb.bytesize).to eq(33)
        expect(['02', '03'].include?(subject[1].htb[0].bth)).to be true
      end
    end

    context 'uncompressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key_pair(compressed: false) }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].htb.bytesize).to eq(32)
        # pubkey
        expect(subject[1].htb.bytesize).to eq(65)
        expect(subject[1].htb[0].bth).to eq('04')
      end
    end
  end

  describe '#generate_key' do
    context 'compressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key }
      it 'should be generate' do
        expect(subject.compressed?).to be true
      end
    end

    context 'uncompressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key(compressed: false) }
      it 'should be generate' do
        expect(subject.compressed?).to be false
      end
    end
  end

end