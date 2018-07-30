module Bitcoin
  module PSBT

    # Class for PSBTs which contains per output information
    class Output

      attr_accessor :redeem_script
      attr_accessor :witness_script
      attr_accessor :hd_key_paths
      attr_accessor :unknowns

      def initialize
        @hd_key_paths = {}
        @unknowns = {}
      end

      # parse PSBT output data form buffer.
      # @param [StringIO] buf psbt buffer.
      # @return [Bitcoin::PSBTOutput] psbt output.
      def self.parse_from_buf(buf)
        output = self.new
        until buf.eof?
          key_len = Bitcoin.unpack_var_int_from_io(buf)
          break if key_len == 0
          key_type = buf.read(1).unpack('C').first
          key = buf.read(key_len - 1)
          value = buf.read(Bitcoin.unpack_var_int_from_io(buf))
          case key_type
          when PSBT_OUT_TYPES[:redeem_script]
            raise ArgumentError, 'Duplicate Key, output redeemScript already provided' if output.redeem_script
            output.redeem_script = value
          when PSBT_OUT_TYPES[:witness_script]
            raise ArgumentError, 'Duplicate Key, output witnessScript already provided' if output.witness_script
            output.witness_script = value
          when PSBT_OUT_TYPES[:bip32_derivation]
            raise ArgumentError, 'Duplicate Key, pubkey derivation path already provided' if output.hd_key_paths[key.bth]
            output.hd_key_paths[key.bth] = Bitcoin::PSBT::HDKeyPath.parse_from_payload(key, value)
          else
            unknown_key = ([key_type].pack('C') + key).bth
            raise ArgumentError, 'Duplicate Key, key for unknown value already provided' if output.unknowns[unknown_key]
            output.unknowns[unknown_key] = value
          end
        end
        output
      end

      def to_payload
        payload = ''
        payload << PSBT.serialize_to_vector(PSBT_OUT_TYPES[:redeem_script], value: redeem_script) if redeem_script
        payload << PSBT.serialize_to_vector(PSBT_OUT_TYPES[:witness_script], value: witness_script) if witness_script
        payload << hd_key_paths.values.map{|v|v.to_payload(PSBT_OUT_TYPES[:bip32_derivation])}.join
        payload << unknowns.map {|k,v|Bitcoin.pack_var_int(k.htb.bytesize) << k.htb << Bitcoin.pack_var_int(v.bytesize) << v}.join
        payload << PSBT_SEPARATOR.to_even_length_hex.htb
        payload
      end

      # merge two PSBT outputs to create one PSBT.
      # @param [Bitcoin::PSBT::Output] psbo PSBT output to be combined which must have same property in PSBT Output.
      # @return [Bitcoin::PSBT::Output] combined object.
      def merge(psbo)
        raise ArgumentError, 'The argument psbt must be an instance of Bitcoin::PSBT::Output.' unless psbo.is_a?(Bitcoin::PSBT::Output)
        raise ArgumentError, 'The Partially Signed Output\'s redeem_script are different.' unless redeem_script == psbo.redeem_script
        raise ArgumentError, 'The Partially Signed Output\'s witness_script are different.' unless witness_script == psbo.witness_script
        combined = Bitcoin::PSBT::Output.new
        combined.redeem_script = redeem_script
        combined.witness_script = witness_script
        combined.unknowns = unknowns.merge(psbo.unknowns)
        combined.hd_key_paths = hd_key_paths.merge(psbo.hd_key_paths)
        combined
      end

    end

  end
end