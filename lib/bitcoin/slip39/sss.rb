module Bitcoin
  module SLIP39

    # Shamir's Secret Sharing
    class SSS

      # recovery master secret form shares.
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
      # @param [Integer] iteration_exp iteration exponent
      # @param [Integer] id identifier
      def self.decrypt(ems, passphrase, iteration_exp, id)
        l = ems[0...(ems.length / 2)].htb
        r = ems[(ems.length / 2)..-1].htb
        salt = (Bitcoin::SLIP39::CUSTOMIZATION_STRING.pack('c*') + id.itb)
        e = (Bitcoin::SLIP39::BASE_ITERATION_COUNT << iteration_exp) / Bitcoin::SLIP39::ROUND_COUNT
        Bitcoin::SLIP39::ROUND_COUNT.times.to_a.reverse.each do |i|
          f = OpenSSL::PKCS5.pbkdf2_hmac((i.itb + passphrase), salt + r, e, r.bytesize, 'sha256')
          l, r = r, (l.bti ^ f.bti).itb
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

    end
  end
end