require 'spec_helper'

describe Bitcoin::SLIP39 do

  let(:master_secret) {'4142434445464748494a4b4c4d4e4f50'}  # 'ABCDEFGHIJKLMNOP'.unpack1("H*")
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

  # Generated with the reference implementation (python shamir-mnemonic 0.3.0), with the extendable backup flag
  # off, an iteration exponent of 0 and the passphrase 'TREZOR'.
  describe 'Test Vector with an identifier below 256' do
    vectors = fixture_file('slip39/vectors_short_identifier.json')
    vectors.each do |v|
      it "#{v[0]}" do
        shares = v[1].map{|words|Bitcoin::SLIP39::Share.from_words(words.split(' '))}
        expect(shares.first.id).to be < 256
        expect(Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'TREZOR')).to eq(v[2])
      end
    end
  end

  describe 'get_salt' do
    it 'should encode the identifier with two bytes.' do
      expect(Bitcoin::SLIP39::SSS.send(:get_salt, 5)).to eq('7368616d69720005'.htb)
      expect(Bitcoin::SLIP39::SSS.send(:get_salt, 256)).to eq('7368616d69720100'.htb)
    end

    it 'should encode the identifier with the minimum number of bytes in legacy mode.' do
      expect(Bitcoin::SLIP39::SSS.send(:get_salt, 5, legacy: true)).to eq('7368616d697205'.htb)
      expect(Bitcoin::SLIP39::SSS.send(:get_salt, 256, legacy: true)).to eq('7368616d69720100'.htb)
    end

    it 'should be empty when the extendable backup flag is set.' do
      expect(Bitcoin::SLIP39::SSS.send(:get_salt, 5, extendable: true)).to eq('')
      expect(Bitcoin::SLIP39::SSS.send(:get_salt, 5, extendable: true, legacy: true)).to eq('')
    end
  end

  describe 'extendable backup flag' do
    it 'should be set by default.' do
      groups = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[2, 3]], secret: master_secret, passphrase: passphrase)
      shares = groups.flatten
      expect(shares.map(&:extendable?)).to all(be true)
      recovered = shares.map{|s| Bitcoin::SLIP39::Share.from_words(s.to_words)}
      expect(recovered.map(&:extendable?)).to all(be true)
      expect(recovered.map(&:iteration_exp)).to all(eq 0)
      expect(Bitcoin::SLIP39::SSS.recover_secret(recovered[0..1], passphrase: passphrase)).to eq(master_secret)
    end

    it 'should generate shares without the flag.' do
      groups = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[2, 3]], secret: master_secret, passphrase: passphrase, extendable: false)
      shares = groups.flatten
      expect(shares.map(&:extendable?)).to all(be false)
      recovered = shares.map{|s| Bitcoin::SLIP39::Share.from_words(s.to_words)}
      expect(recovered.map(&:extendable?)).to all(be false)
      expect(Bitcoin::SLIP39::SSS.recover_secret(recovered[1..2], passphrase: passphrase)).to eq(master_secret)
    end

    it 'should not be set on a share built by hand.' do
      expect(Bitcoin::SLIP39::Share.new.extendable?).to be false
    end

    it 'should not use the identifier in the encryption when set.' do
      ems1 = Bitcoin::SLIP39::SSS.send(:encrypt, master_secret, passphrase, 0, 1, true)
      ems2 = Bitcoin::SLIP39::SSS.send(:encrypt, master_secret, passphrase, 0, 2, true)
      expect(ems1).to eq(ems2)
      expect(Bitcoin::SLIP39::SSS.send(:encrypt, master_secret, passphrase, 0, 1, false)).not_to eq(ems1)
      expect(Bitcoin::SLIP39::SSS.send(:encrypt, master_secret, passphrase, 0, 2, false)).not_to eq(ems1)
    end

    it 'should recover the same master secret from sets of shares with different identifiers.' do
      set1 = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[1, 1]], secret: master_secret, passphrase: passphrase).flatten
      set2 = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[2, 3]], secret: master_secret, passphrase: passphrase).flatten
      expect(set1.first.id).not_to eq(set2.first.id)
      expect(Bitcoin::SLIP39::SSS.recover_secret(set1, passphrase: passphrase)).to eq(master_secret)
      expect(Bitcoin::SLIP39::SSS.recover_secret(set2[0..1], passphrase: passphrase)).to eq(master_secret)
      # The passphrase is applied to the same encrypted master secret in both sets.
      expect(Bitcoin::SLIP39::SSS.recover_secret(set1, passphrase: 'other')).to eq(Bitcoin::SLIP39::SSS.recover_secret(set2[1..2], passphrase: 'other'))
    end

    it 'should reject a set of shares whose flags differ.' do
      with_flag = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[2, 2]], secret: master_secret).flatten
      without_flag = with_flag.map do |s|
        copy = Bitcoin::SLIP39::Share.from_words(s.to_words)
        copy.extendable = false
        copy.checksum = copy.calculate_checksum
        copy
      end
      expect{
        Bitcoin::SLIP39::SSS.recover_secret([with_flag[0], without_flag[1]])
      }.to raise_error(ArgumentError, 'Invalid set of shares. All shares must have the same extendable backup flag.')
    end

    it 'should use its own customization string in the checksum.' do
      share = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[1, 1]], secret: master_secret).flatten.first
      words = share.to_words
      expect(Bitcoin::SLIP39::Share.from_words(words).checksum).to eq(share.checksum)
      # The same data with the flag cleared no longer matches the checksum.
      indices = words.map{|w| Bitcoin::SLIP39::WORDS.index(w)}
      indices[1] &= ~(1 << 4) # The flag is bit 15 of the data, which is bit 4 of the second word.
      expect{
        Bitcoin::SLIP39::Share.from_words(indices.map{|i| Bitcoin::SLIP39::WORDS[i]})
      }.to raise_error(ArgumentError, 'Invalid mnemonic checksum.')
    end

    it 'should limit the iteration exponent to 4 bits.' do
      expect{
        Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[1, 1]], secret: master_secret, exp: 16)
      }.to raise_error(ArgumentError, 'Iteration exponent(16) must be between 0 and 15.')
      # Built by hand, since an exponent of 15 makes the encryption run 2^15 times the base iterations.
      share = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[1, 1]], secret: master_secret).flatten.first
      share.iteration_exp = 15
      share.checksum = share.calculate_checksum
      recovered = Bitcoin::SLIP39::Share.from_words(share.to_words)
      expect(recovered.iteration_exp).to eq(15)
      expect(recovered.extendable?).to be true
      share.iteration_exp = 16
      expect{share.to_words}.to raise_error(ArgumentError, 'Iteration exponent(16) must be between 0 and 15.')
    end
  end

  describe 'legacy_salt option' do
    # 1-of-1 share generated by bitcoinrb 1.14.0, whose identifier is 59.
    let(:words) {'acid stay academic academic cleanup greatest romp plan romantic favorite holy award august exact paid training answer withdraw peanut standard'}
    let(:shares) {[Bitcoin::SLIP39::Share.from_words(words.split(' '))]}
    let(:master_secret_128) {'bb54aac4b89dc868ba37d9cc21b2cece'}

    it 'should recover the master secret.' do
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'TREZOR', legacy_salt: true)).to eq(master_secret_128)
    end

    it 'should return a different secret without the option.' do
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'TREZOR')).not_to eq(master_secret_128)
    end
  end

  describe 'share value with leading zero byte' do
    def build_share(value)
      share = Bitcoin::SLIP39::Share.new
      share.id = 1234
      share.iteration_exp = 0
      share.group_index = 0
      share.group_threshold = 1
      share.group_count = 1
      share.member_index = 0
      share.member_threshold = 1
      share.value = value
      share
    end

    def build_share_with_checksum(value)
      share = build_share(value)
      share.checksum = share.calculate_checksum
      share
    end

    it 'should round trip through mnemonic words.' do
      ['00' + '11' * 15, '0000' + '22' * 30, '00' * 15 + '01'].each do |value|
        share = build_share_with_checksum(value)
        recovered = Bitcoin::SLIP39::Share.from_words(share.to_words)
        expect(recovered.value).to eq(value)
      end
    end

    it 'should generate the same number of words as a value without a leading zero byte.' do
      expect(build_share_with_checksum('00' + '11' * 31).to_words.size).to eq(build_share_with_checksum('ff' * 32).to_words.size)
    end

    it 'should reject a value which is not an even number of bytes.' do
      # A 25-byte value with a leading zero byte is the case this guard exists for. The padding
      # from_words assumes is one byte wider than the one to_words writes, so without the check the
      # value comes back as a different 24-byte value rather than as an error.
      expect{build_share('00' + 'ab' * 24).to_words}.to raise_error(ArgumentError, 'The length of the share value in bytes must be an even number.')
    end
  end

end