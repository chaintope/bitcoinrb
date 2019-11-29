require 'spec_helper'

describe Bitcoin::SLIP39 do

  let(:master_secret) {'4142434445464748494a4b4c4d4e4f50'}  # 'ABCDEFGHIJKLMNOP'.unpack("H*").first
  let(:passphrase) {'TREZOR'}

  describe 'Test Vector' do
    vectors = fixture_file('slip39/vectors.json')
    vectors.each do |v|
      it "#{v[0]}" do
        if v[2].empty?
          expect{
            shares = v[1].map{|words|Bitcoin::SLIP39::Share.from_words(words.split(' '))}
            Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'TREZOR')
          }.to raise_error(ArgumentError)
        else
          shares = v[1].map{|words|Bitcoin::SLIP39::Share.from_words(words.split(' '))}
          expect(Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'TREZOR')).to eq(v[2])
          words = shares.map{|s|s.to_words.join(' ')}
          expect(words).to eq(v[1])
        end
      end
    end
  end

  describe 'test_basic_sharing_fixed' do
    it 'should reconstruct same secret.' do
      group = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret)
      expect(group.length).to eq(1)
      expect(group.first.length).to eq(5)
      s1 = Bitcoin::SLIP39::SSS.recover_secret(group.first[0..2])
      s2 = Bitcoin::SLIP39::SSS.recover_secret(group.first[2..-1])
      expect(s1).to eq(s2)
      expect(s1).to eq(master_secret)
    end
  end

  describe 'test_passphrase' do
    it 'cannot be restored without a passphrase.' do
      shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret, passphrase: passphrase).first
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[1..3], passphrase: passphrase)).to eq(master_secret)
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[1..3])).not_to eq(master_secret)
    end
  end

  describe 'test_iteration_exponent' do
    it 'should generate with iteration exponent.' do
      shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret, passphrase: passphrase, exp: 1).first
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[2..4], passphrase: passphrase)).to eq(master_secret)
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[2..4])).not_to eq(master_secret)

      shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret, passphrase: passphrase, exp: 2).first
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[2..4], passphrase: passphrase)).to eq(master_secret)
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[2..4])).not_to eq(master_secret)
    end
  end

  describe 'test_group_sharing' do
    it 'should generate group shares.' do
      group_threshold = 2
      groups = [[3, 5], [2, 3], [2, 5], [1, 1]]
      group_shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: group_threshold, groups: groups, secret: master_secret)

      # Test all valid combinations of mnemonics.
      group_shares.combination(group_threshold).each do |multi_groups_shares|
        expect(Bitcoin::SLIP39::SSS.recover_secret(multi_groups_shares.flatten)).to eq(master_secret)
      end

      # Minimal sets of mnemonics.
      expect(Bitcoin::SLIP39::SSS.recover_secret([group_shares[2][0], group_shares[2][2], group_shares[3][0]]))
      expect(Bitcoin::SLIP39::SSS.recover_secret([group_shares[2][3], group_shares[3][0], group_shares[2][4]]))

      # One complete group and one incomplete group out of two groups required.
      shares = group_shares[0][2..-1] + [group_shares[1][0]]
      expect{Bitcoin::SLIP39::SSS.recover_secret(shares)}.to raise_error(ArgumentError, 'Wrong number of mnemonics. Threshold is 2, but share count is 1')

      # One group of two required.
      shares = group_shares[0][1...4]
      expect{Bitcoin::SLIP39::SSS.recover_secret(shares)}.to raise_error(ArgumentError, 'Wrong number of mnemonics. Group threshold is 2, but share count is 1')
    end
  end

  describe 'test_group_sharing_threshold_1' do
    it 'should judge valid combinations.' do
      groups = [[3, 5], [2, 3], [2, 5], [1, 1]]
      group_shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: groups, secret: master_secret)
      group_shares.each.with_index do |group, index|
        member_threshold = groups[index][0]
        group.combination(member_threshold).each do |shares|
          expect(Bitcoin::SLIP39::SSS.recover_secret(shares)).to eq(master_secret)
        end
      end
    end
  end

  describe 'test_all_groups_exist' do
    it 'should generate all shares.' do
      groups = [[3, 5], [1, 1], [2, 3], [2, 5], [3, 5]]
      [1, 2, 5].each do |threshold|
        group_shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: threshold, groups: groups, secret: master_secret)
        expect(group_shares.length).to eq(5)
        expect(group_shares.flatten.length).to eq(19)
      end
    end
  end

  describe 'test_invalid_sharing' do
    it 'should raise error.' do
      # short secret
      expect{Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret[0..14])}.to raise_error(ArgumentError)
      # odd length secret
      expect{Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret + '1')}.to raise_error(ArgumentError)
      # group threshold exceeds number of groups
      expect{Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 3, groups: [[3, 5], [2, 5]], secret: master_secret)}.to raise_error(ArgumentError)
      # invalid group threshold
      expect{Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 0, groups: [[3, 5], [2, 5]], secret: master_secret)}.to raise_error(ArgumentError)
      # member threshold exceeds number of members
      expect{Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 2, groups: [[3, 2], [2, 5]], secret: master_secret)}.to raise_error(ArgumentError)
      # invalid member threshold
      expect{Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 2, groups: [[0, 2], [2, 5]], secret: master_secret)}.to raise_error(ArgumentError)
      # group with multiple members and threshold 1
      expect{Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 2, groups: [[3, 5], [1, 3], [2, 5]], secret: master_secret)}.to raise_error(ArgumentError)
    end
  end

end