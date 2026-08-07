require 'ecdsa_ext'
require 'ecdsa/ext/sign_verify'

module Bitcoin
  module Secp256k1

    # secp256 module using ecdsa gem
    # https://github.com/DavidEGrayson/ruby_ecdsa
    module Ruby

      module_function
      extend Schnorr::Util

      # Whether this module is native c wrapper or not?
      # @return [Boolean]
      def native?
        false
      end

      # generate ec private key and public key
      def generate_key_pair(compressed: true)
        private_key = 1 + SecureRandom.random_number(GROUP.order - 1)
        public_key = GROUP.generator.to_jacobian * private_key
        privkey = ECDSA::Format::IntegerOctetString.encode(private_key, 32)
        pubkey = public_key.to_affine.to_hex(compressed)
        [privkey.bth, pubkey]
      end

      # generate bitcoin key object
      def generate_key(compressed: true)
        privkey, pubkey = generate_key_pair(compressed: compressed)
        Bitcoin::Key.new(priv_key: privkey, pubkey: pubkey, compressed: compressed)
      end

      def generate_pubkey(privkey, compressed: true)
        public_key = GROUP.generator.to_jacobian * privkey.to_i(16)
        public_key.to_affine.to_hex(compressed)
      end

      # Check whether valid x-only public key or not.
      # @param [String] pub_key x-only public key with hex format(32 bytes).
      # @return [Boolean] result.
      def valid_xonly_pubkey?(pub_key)
        pubkey = pub_key.htb
        return false unless pubkey.bytesize == X_ONLY_PUBKEY_SIZE
        begin
          ECDSA::Format::PointOctetString.decode(pubkey, ECDSA::Group::Secp256k1)
        rescue StandardError
          return false
        end
        true
      end

      # sign data.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign with hex format
      # @param [String] extra_entropy a extra entropy with binary format for rfc6979
      # @param [Symbol] algo signature algorithm. ecdsa(default) or schnorr.
      # @return [String] signature data with binary format
      def sign_data(data, privkey, extra_entropy = nil, algo: :ecdsa)
        case algo
        when :ecdsa
          sign_ecdsa(data, privkey, extra_entropy)&.first
        when :schnorr
          sign_schnorr(data, privkey, extra_entropy)
        else
          nil
        end
      end

      # Sign data with compact format.
      # @param [String] data a data to be signed with binary format
      # @param [String] privkey a private key using sign with hex format
      # @return [Array[signature, recovery id]]
      def sign_compact(data, privkey)
        sig, rec = sign_ecdsa(data, privkey, nil)
        [ECDSA::Format::SignatureDerString.decode(sig), rec]
      end

      # Recover public key from compact signature.
      # @param [String] data message digest using signature.
      # @param [String] signature signature with binary format(65 bytes).
      # @param [Boolean] compressed whether compressed public key or not.
      # @return [Bitcoin::Key] Recovered public key.
      # @raise [ArgumentError] If invalid arguments specified.
      def recover_compact(data, signature, compressed)
        raise ArgumentError, "data must be String." unless data.is_a?(String)
        raise ArgumentError, "signature must be String." unless signature.is_a?(String)
        signature = hex2bin(signature)
        raise ArgumentError, "signature must be 64 bytes." unless signature.bytesize == 65
        data = hex2bin(data)
        raise ArgumentError, "data must be 32 bytes." unless data.bytesize == 32
        rec = (signature[0].ord - 0x1b) & 3
        raise ArgumentError, "rec must be between 0 and 3." if rec < 0 || rec > 3

        group = Bitcoin::Secp256k1::GROUP
        r = ECDSA::Format::IntegerOctetString.decode(signature[1...33])
        s = ECDSA::Format::IntegerOctetString.decode(signature[33..-1])
        return nil if r.zero?
        return nil if s.zero?

        digest = ECDSA.normalize_digest(data, group.bit_length)
        field = ECDSA::PrimeField.new(group.order)

        unless rec & 2 == 0
          r = field.mod(r + group.order)
        end

        is_odd = (rec & 1 == 1)
        y_coordinate = group.solve_for_y(r).find{|y| is_odd ? y.odd? : y.even?}

        p = group.new_point([r, y_coordinate])

        inv_r = field.inverse(r)
        u1 = field.mod(inv_r * digest)
        u2 = field.mod(inv_r * s)
        q = p * u2 + (group.new_point(u1)).negate
        return nil if q.infinity?
        Bitcoin::Key.from_point(q, compressed: compressed)
      end

      # verify signature using public key
      # @param [String] data a SHA-256 message digest with binary format
      # @param [String] sig a signature for +data+ with binary format
      # @param [String] pubkey a public key with hex format.
      # @return [Boolean] verify result
      def verify_sig(data, sig, pubkey, algo: :ecdsa)
        case algo
        when :ecdsa
          verify_ecdsa(data, sig, pubkey)
        when :schnorr
          verify_schnorr(data, sig, pubkey)
        else
          false
        end
      end

      # if +pubkey+ is hybrid public key format, it convert uncompressed format.
      # https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2012-June/001578.html
      def repack_pubkey(pubkey)
        p = pubkey.htb
        case p[0]
          when "\x06", "\x07"
            p[0] = "\x04"
            p
          else
            pubkey.htb
        end
      end

      # validate whether this is a valid public key (more expensive than IsValid())
      # @param [String] pubkey public key with hex format.
      # @param [Boolean] allow_hybrid whether support hybrid public key.
      # @return [Boolean] If valid public key return true, otherwise false.
      def parse_ec_pubkey?(pubkey, allow_hybrid = false)
        begin
          point = ECDSA::Format::PointOctetString.decode(pubkey.htb, ECDSA::Group::Secp256k1, allow_hybrid: allow_hybrid)
          ECDSA::Group::Secp256k1.valid_public_key?(point)
        rescue ECDSA::Format::DecodeError
          false
        end
      end

      def sign_ecdsa(data, privkey, extra_entropy)
        privkey = privkey.htb
        private_key = ECDSA::Format::IntegerOctetString.decode(privkey)
        extra_entropy ||= ''
        nonce = RFC6979.generate_rfc6979_nonce(privkey + data, extra_entropy)

        # port form ecdsa gem.
        r_point = (GROUP.generator.to_jacobian * nonce).to_affine

        point_field = ECDSA::PrimeField.new(GROUP.order)
        r = point_field.mod(r_point.x)
        return nil if r.zero?

        rec = r_point.y & 1

        e = ECDSA.normalize_digest(data, GROUP.bit_length)
        s = point_field.mod(point_field.inverse(nonce) * (e + r * private_key))

        if s > (GROUP.order / 2) # convert low-s
          s = GROUP.order - s
          rec ^= 1
        end

        return nil if s.zero?

        signature = ECDSA::Signature.new(r, s).to_der
        public_key = Bitcoin::Key.new(priv_key: privkey.bth).pubkey
        raise 'Creation of signature failed.' unless Bitcoin::Secp256k1::Ruby.verify_sig(data, signature, public_key)
        [signature, rec]
      end

      def sign_schnorr(data, privkey, aux_rand)
        aux_rand ? Schnorr.sign(data, privkey.htb, aux_rand).encode : Schnorr.sign(data, privkey.htb).encode
      end

      def verify_ecdsa(data, sig, pubkey)
        begin
          k = ECDSA::Format::PointOctetString.decode(repack_pubkey(pubkey), GROUP)
          signature = ECDSA::Format::SignatureDerString.decode(sig)
          ECDSA.valid_signature?(k, data, signature)
        rescue StandardError
          false
        end
      end

      def verify_schnorr(data, sig, pubkey)
        Schnorr.valid_sig?(data, pubkey.htb, sig)
      end

      # Whether this module supports BIP-352 silent payments.
      # @return [Boolean]
      def sp_available?
        true
      end

      # Create the silent payment outputs for +recipients+.
      # See Bitcoin::Secp256k1::Native#sp_create_outputs for the parameters.
      # @return [Array] An x-only public key with hex format for each recipient, in the same order.
      # @raise [ArgumentError] If the input private keys sum to zero.
      def sp_create_outputs(recipients, outpoint_smallest, plain_seckeys: [], taproot_seckeys: [])
        field = ECDSA::PrimeField.new(GROUP.order)
        sum = sp_sum_seckeys(plain_seckeys, taproot_seckeys, field)
        raise ArgumentError, 'The input private keys sum to zero.' if sum.zero?
        agg_pubkey = (GROUP.generator.to_jacobian * sum).to_affine
        input_hash = Bitcoin.tagged_hash('BIP0352/Inputs', outpoint_smallest.htb + agg_pubkey.to_hex.htb)

        # k counts up within the group of recipients sharing a scan key, but an output keeps the
        # position of the recipient it pays.
        groups = {}
        recipients.each_with_index do |(scan_pubkey, spend_pubkey), index|
          (groups[scan_pubkey] ||= []) << [spend_pubkey, index]
        end
        results = Array.new(recipients.length)
        groups.each do |scan_pubkey, spends|
          scan_point = Bitcoin::Key.new(pubkey: scan_pubkey).to_point.to_jacobian
          shared_secret = (scan_point * field.mod(input_hash.bti * sum)).to_affine.to_hex.htb
          spends.each_with_index do |(spend_pubkey, index), k|
            t_k = Bitcoin.tagged_hash('BIP0352/SharedSecret', shared_secret + [k].pack('N'))
            spend_point = Bitcoin::Key.new(pubkey: spend_pubkey).to_point.to_jacobian
            output = (spend_point + GROUP.generator.to_jacobian * t_k.bti).to_affine
            results[index] = sp_xonly(output.x)
          end
        end
        results
      end

      # Create the label and the label tweak of the +m+ th label of +scan_key+.
      # See Bitcoin::Secp256k1::Native#sp_create_label for the parameters.
      # @return [Array] The serialized label(33 bytes) and its tweak(32 bytes), both with hex format.
      def sp_create_label(scan_key, m)
        tweak = Bitcoin.tagged_hash('BIP0352/Label', scan_key.htb + [m].pack('N'))
        [(GROUP.generator.to_jacobian * tweak.bti).to_affine.to_hex(true), tweak.bth]
      end

      # Scan +tx_outputs+ for the silent payment outputs of the recipient.
      # See Bitcoin::Secp256k1::Native#sp_scan_outputs for the parameters.
      # @return [Array] A hash per found output, with the :output, :tweak and :label keys.
      # @raise [ArgumentError] If the input public keys sum to the point at infinity.
      def sp_scan_outputs(tx_outputs, scan_key, outpoint_smallest, spend_pubkey,
                          plain_pubkeys: [], xonly_pubkeys: [], labels: {})
        field = ECDSA::PrimeField.new(GROUP.order)
        sum_pubkeys = GROUP.infinity.to_jacobian
        plain_pubkeys.each { |p| sum_pubkeys += Bitcoin::Key.new(pubkey: p).to_point.to_jacobian }
        xonly_pubkeys.each { |p| sum_pubkeys += Bitcoin::Key.from_xonly_pubkey(p).to_point.to_jacobian }
        raise ArgumentError, 'The input public keys sum to the point at infinity.' if sum_pubkeys.infinity?

        input_hash = Bitcoin.tagged_hash(
          'BIP0352/Inputs', outpoint_smallest.htb + sum_pubkeys.to_affine.to_hex.htb)
        shared_secret = (sum_pubkeys * field.mod(input_hash.bti * scan_key.to_i(16))).to_affine.to_hex.htb
        spend_point = Bitcoin::Key.new(pubkey: spend_pubkey).to_point.to_jacobian
        # A labeled output is P_k + label. Only the x coordinate is compared, which covers the
        # label of either parity without negating the output.
        label_points = labels.map do |label, tweak|
          [label, tweak, Bitcoin::Key.new(pubkey: label).to_point.to_jacobian]
        end

        results = []
        remaining = tx_outputs.map(&:downcase)
        k = 0
        while k < Bitcoin::SilentPayment::K_MAX
          t_k = Bitcoin.tagged_hash('BIP0352/SharedSecret', shared_secret + [k].pack('N'))
          p_k = GROUP.generator.to_jacobian * t_k.bti + spend_point
          index = remaining.index(sp_xonly(p_k.to_affine.x))
          found = if index
                    {output: remaining.delete_at(index), tweak: t_k.bth, label: nil}
                  else
                    sp_find_labeled(p_k, remaining, label_points, t_k, field)
                  end
          break unless found
          results << found
          k += 1
        end
        results
      end

      # Sum the private keys of the inputs, negating a taproot key whose public key has odd y.
      def sp_sum_seckeys(plain_seckeys, taproot_seckeys, field)
        sum = plain_seckeys.inject(0) { |total, sk| field.mod(total + sk.to_i(16)) }
        taproot_seckeys.inject(sum) do |total, sk|
          d = sk.to_i(16)
          d = field.mod(-d) unless (GROUP.generator.to_jacobian * d).to_affine.has_even_y?
          field.mod(total + d)
        end
      end

      # Find the output +p_k+ pays through one of +label_points+, or nil.
      def sp_find_labeled(p_k, remaining, label_points, t_k, field)
        label_points.each do |label, tweak, point|
          index = remaining.index(sp_xonly((p_k + point).to_affine.x))
          next unless index
          return {output: remaining.delete_at(index),
                  tweak: sp_xonly(field.mod(t_k.bti + tweak.to_i(16))),
                  label: label}
        end
        nil
      end

      # Serialize a field element as a 32 byte value with hex format.
      def sp_xonly(value)
        ECDSA::Format::IntegerOctetString.encode(value, 32).bth
      end

    end
  end
end
