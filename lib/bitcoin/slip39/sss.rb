require 'securerandom'

module Bitcoin
  module SLIP39

    # Shamir's Secret Sharing
    class SSS

      include Bitcoin::Util
      extend Bitcoin::Util

      # Create SSS shares.
      #
      # [Usage]
      # 4 groups shares.
      # = two for Alice
      # = one for friends(required 3 of her 5 friends) and
      # = one for family members(required 2 of her 6 family)
      #
      # Two of these group shares are required to reconstruct the master secret.
      # groups = [1, 1], [1, 1], [3, 5], [2, 6]
      #
      # group_shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 2, groups: groups, secret: 'secret with hex format', passphrase: 'xxx')
      # return 4 group array of Bitcoin::SLIP39::Share
      #
      # Get each share word
      # groups[0][1].to_words
      # => ["shadow", "pistol", "academic", "always", "adequate", "wildlife", "fancy", "gross", "oasis", "cylinder", "mustang", "wrist", "rescue", "view", "short", "owner", "flip", "making", "coding", "armed"]
      #
      # @param [Array[Array[Integer, Integer]]] groups
      # @param [Integer] group_threshold threshold number of group shares required to reconstruct the master secret.
      # @param [Integer] exp Iteration exponent. default is 0.
      # @param [String] secret master secret with hex format.
      # @param [String] passphrase the passphrase used for encryption/decryption.
      # @return [Array[Array[Bitcoin::SLIP39::Share]]] array of group shares.
      def self.setup_shares(groups: [], group_threshold: nil, exp: 0, secret: nil, passphrase: '')
        raise ArgumentError, 'Groups is empty.' if groups.empty?
        raise ArgumentError, 'Group threshold must be greater than 0.' if group_threshold.nil? || group_threshold < 1
        raise ArgumentError, 'Master secret does not specified.' unless secret
        raise ArgumentError, "The length of the master secret (#{secret.htb.bytesize} bytes) must be at least #{MIN_STRENGTH_BITS / 8} bytes." if (secret.htb.bytesize * 8) < MIN_STRENGTH_BITS
        raise ArgumentError, 'The length of the master secret in bytes must be an even number.' unless secret.bytesize.even?
        raise ArgumentError, 'The passphrase must contain only printable ASCII characters (code points 32-126).' unless passphrase.ascii_only?
        raise ArgumentError, "The requested group threshold (#{group_threshold}) must not exceed the number of groups (#{groups.length})." if group_threshold > groups.length
        groups.each do |threshold, count|
          raise ArgumentError, 'Group threshold must be greater than 0.' if threshold.nil? || threshold < 1
          raise ArgumentError, "The requested member threshold (#{threshold}) must not exceed the number of share (#{count})." if threshold > count
          raise ArgumentError, "Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead." if threshold == 1 && count > 1
        end

        id = SecureRandom.random_number(32767) # 32767 is max number for 15 bits.
        ems = encrypt(secret, passphrase, exp, id)

        group_shares = split_secret(group_threshold, groups.length, ems)

        shares = group_shares.map.with_index do |s, i|
          group_index, group_share = s[0], s[1]
          member_threshold, member_count = groups[i][0], groups[i][1]
          shares = split_secret(member_threshold, member_count, group_share)
          shares.map do |member_index, member_share|
            share = Bitcoin::SLIP39::Share.new
            share.id = id
            share.iteration_exp = exp
            share.group_index = group_index
            share.group_threshold = group_threshold
            share.group_count = groups.length
            share.member_index = member_index
            share.member_threshold = member_threshold
            share.value = member_share
            share.checksum = share.calculate_checksum
            share
          end
        end
        shares
      end

      # recovery master secret form shares.
      #
      # [Usage]
      # shares: An array of shares required for recovery.
      # master_secret = Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'xxx')
      #
      # @param [Array[Bitcoin::SLIP30::Share]] shares an array of shares.
      # @param [String] passphrase the passphrase using decrypt master secret.
      # @return [String] a master secret.
      def self.recover_secret(shares, passphrase: '')
        raise ArgumentError, 'share is empty.' if shares.nil? || shares.empty?
        groups = {}
        id = shares[0].id
        exp = shares[0].iteration_exp
        group_threshold = shares.first.group_threshold
        group_count = shares.first.group_count

        shares.each do |share|
          raise ArgumentError, 'Invalid set of shares. All shares must have the same id.' unless id == share.id
          raise ArgumentError, 'Invalid set of shares. All shares must have the same group threshold.' unless group_threshold == share.group_threshold
          raise ArgumentError, 'Invalid set of shares. All shares must have the same group count.' unless group_count == share.group_count
          raise ArgumentError, 'Invalid set of shares. All Shares must have the same iteration exponent.' unless exp == share.iteration_exp
          groups[share.group_index] ||= []
          groups[share.group_index] << share
        end

        group_shares = {}
        groups.each do |group_index, shares|
          member_threshold = shares.first.member_threshold
          raise ArgumentError, "Wrong number of mnemonics. Threshold is #{member_threshold}, but share count is #{shares.length}" if shares.length < member_threshold
          if shares.length == 1 && member_threshold == 1
            group_shares[group_index] = shares.first.value
          else
            value_length = shares.first.value.length
            x_coordinates = []
            shares.each do |share|
              raise ArgumentError, 'Invalid set of shares. All shares in a group must have the same member threshold.' unless member_threshold == share.member_threshold
              raise ArgumentError, 'Invalid set of shares. All share values must have the same length.' unless value_length == share.value.length
              x_coordinates << share.member_index
            end
            x_coordinates.uniq!
            raise ArgumentError, 'Invalid set of shares. Share indices must be unique.' unless x_coordinates.size == shares.size
            interpolate_shares = shares.map{|s|[s.member_index, s.value]}

            secret = interpolate(interpolate_shares, SECRET_INDEX)
            digest_value = interpolate(interpolate_shares, DIGEST_INDEX).htb
            digest, random_value = digest_value[0...DIGEST_LENGTH_BYTES].bth, digest_value[DIGEST_LENGTH_BYTES..-1].bth
            recover_digest = create_digest(secret, random_value)
            raise ArgumentError, 'Invalid digest of the shared secret.' unless digest == recover_digest

            group_shares[group_index] = secret
          end
        end

        return decrypt(group_shares.values.first, passphrase, exp, id) if group_threshold == 1

        raise ArgumentError, "Wrong number of mnemonics. Group threshold is #{group_threshold}, but share count is #{group_shares.length}" if group_shares.length < group_threshold

        interpolate_shares = group_shares.map{|k, v|[k, v]}
        secret = interpolate(interpolate_shares, SECRET_INDEX)
        digest_value = interpolate(interpolate_shares, DIGEST_INDEX).htb
        digest, random_value = digest_value[0...DIGEST_LENGTH_BYTES].bth, digest_value[DIGEST_LENGTH_BYTES..-1].bth
        recover_digest = create_digest(secret, random_value)
        raise ArgumentError, 'Invalid digest of the shared secret.' unless digest == recover_digest

        decrypt(secret, passphrase, exp, id)
      end

      private

      # Calculate f(x) from given shamir shares.
      # @param [Array[index, value]] shares the array of shamir shares.
      # @param [Integer] x the x coordinate of the result.
      # @return [String] f(x) value with hex format.
      def self.interpolate(shares, x)
        s = shares.find{|s|s[0] == x}
        return s[1] if s

        log_prod = shares.sum{|s|LOG_TABLE[s[0] ^ x]}

        result = ('00' * shares.first[1].length).htb
        shares.each do |share|
          log_basis_eval = (log_prod - LOG_TABLE[share[0] ^ x] - shares.sum{|s|LOG_TABLE[share[0] ^ s[0]]}) % 255
          result = share[1].htb.bytes.each.map.with_index do |v, i|
            (result[i].bti ^ (v == 0 ? 0 : (EXP_TABLE[(LOG_TABLE[v] + log_basis_eval) % 255]))).itb
          end.join
        end
        result.bth
      end

      # Decrypt encrypted master secret using passphrase.
      # @param [String] ems an encrypted master secret with hex format.
      # @param [String] passphrase the passphrase when using encrypt master secret with binary format.
      # @param [Integer] exp iteration exponent
      # @param [Integer] id identifier
      def self.decrypt(ems, passphrase, exp, id)
        l, r = ems[0...(ems.length / 2)].htb, ems[(ems.length / 2)..-1].htb
        salt = get_salt(id)
        e = (Bitcoin::SLIP39::BASE_ITERATION_COUNT << exp) / Bitcoin::SLIP39::ROUND_COUNT
        Bitcoin::SLIP39::ROUND_COUNT.times.to_a.reverse.each do |i|
          f = OpenSSL::PKCS5.pbkdf2_hmac((i.itb + passphrase), salt + r, e, r.bytesize, 'sha256')
          l, r = padding_zero(r, r.bytesize), padding_zero((l.bti ^ f.bti).itb, r.bytesize)
        end
        (r + l).bth
      end

      # Encrypt master secret using passphrase
      # @param [String] secret master secret with hex format.
      # @param [String] passphrase the passphrase when using encrypt master secret with binary format.
      # @param [Integer] exp iteration exponent
      # @param [Integer] id identifier
      # @return [String] encrypted master secret with hex format.
      def self.encrypt(secret, passphrase, exp, id)
        s = secret.htb
        l, r = s[0...(s.bytesize / 2)], s[(s.bytesize / 2)..-1]
        salt = get_salt(id)
        e = (Bitcoin::SLIP39::BASE_ITERATION_COUNT << exp) / Bitcoin::SLIP39::ROUND_COUNT
        Bitcoin::SLIP39::ROUND_COUNT.times.to_a.each do |i|
          f = OpenSSL::PKCS5.pbkdf2_hmac((i.itb + passphrase), salt + r, e, r.bytesize, 'sha256')
          l, r = padding_zero(r, r.bytesize), padding_zero((l.bti ^ f.bti).itb, r.bytesize)
        end
        (r + l).bth
      end

      # Create digest of the shared secret.
      # @param [String] secret the shared secret with hex format.
      # @param [String] random value (n-4 bytes) with hex format.
      # @return [String] digest value(4 bytes) with hex format.
      def self.create_digest(secret, random)
        h = Bitcoin.hmac_sha256(random.htb, secret.htb)
        h[0...4].bth
      end

      # get salt using encryption/decryption form id.
      # @param [Integer] id id
      # @return [String] salt with binary format.
      def self.get_salt(id)
        (Bitcoin::SLIP39::CUSTOMIZATION_STRING.pack('c*') + id.itb)
      end

      # Split the share into +count+ with threshold +threshold+.
      # @param [Integer] threshold the threshold.
      # @param [Integer] count split count.
      # @param [Integer] secret the secret to be split.
      # @return [Array[Integer, String]] the array of split secret.
      def self.split_secret(threshold, count, secret)
        raise ArgumentError, "The requested threshold (#{threshold}) must be a positive integer." if threshold < 1
        raise ArgumentError, "The requested threshold (#{threshold}) must not exceed the number of shares (#{count})." if threshold > count
        raise ArgumentError, "The requested number of shares (#{count}) must not exceed #{MAX_SHARE_COUNT}." if count > MAX_SHARE_COUNT

        return count.times.map{|i|[i, secret]} if threshold == 1 # if the threshold is 1, digest of the share is not used.

        random_share_count = threshold - 2

        shares = random_share_count.times.map{|i|[i, SecureRandom.hex(secret.htb.bytesize)]}
        random_part = SecureRandom.hex(secret.htb.bytesize - DIGEST_LENGTH_BYTES)
        digest = create_digest(secret, random_part)

        base_shares = shares + [[DIGEST_INDEX, digest + random_part], [SECRET_INDEX, secret]]

        (random_share_count...count).each { |i| shares << [i, interpolate(base_shares, i)]}

        shares
      end

      private_class_method :split_secret, :get_salt, :interpolate, :encrypt, :decrypt, :create_digest

    end
  end
end