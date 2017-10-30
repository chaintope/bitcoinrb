module Bitcoin

  # utility for multisig
  class Multisig
    include Bitcoin::Opcodes

    def self.prefix
      [OP_0].pack("C*")
    end

    # generate input script sig spending a multisig output script.
    # returns a raw binary script sig of the form:
    #  OP_0 <sig> [<sig> ...]
    # @param [[String]] array of signatures
    # @return [String] script_sig for multisig
    def self.to_multisig_script_sig(*sigs)
      hash_type = sigs.last.is_a?(Numeric) ? sigs.pop : SIGHASH_TYPE[:all]
      sigs.reverse.inject(prefix) { |joined, sig| add_sig_to_multisig_script_sig(sig, joined, hash_type) }
    end

    # take a multisig script sig (or p2sh multisig script sig) and add
    # another signature to it after the OP_0. Used to sign a tx by
    # multiple parties. Signatures must be in the same order as the
    # pubkeys in the output script being redeemed.
    def self.add_sig_to_multisig_script_sig(sig_to_add, script_sig, hash_type = SIGHASH_TYPE[:all])
      signature = sig_to_add + [hash_type].pack("C*")
      offset = script_sig.empty? ? 0 : 1
      script_sig.insert(offset, Bitcoin::Script.pack_pushdata(signature))
    end

    # generate input script sig spending a p2sh-multisig output script.
    # returns a raw binary script sig of the form:
    #  OP_0 <sig> [<sig> ...] <redeem_script>
    # @param [Script] redeem_script
    # @param [[String]] array of signatures
    # @return [String] script_sig for multisig
    def self.to_p2sh_multisig_script_sig(redeem_script, *sigs)
      to_multisig_script_sig(*sigs.flatten) + Bitcoin::Script.pack_pushdata(redeem_script)
    end

    # Sort signatures in the given +script_sig+ according to the order of pubkeys in
    # the redeem script. Also needs the +sig_hash+ to match signatures to pubkeys.
    # @param [String] signature for multisig.
    # @param [String] sig_hash to be signed.
    # @return [String] sorted sig_hash.
    def self.sort_p2sh_multisig_signatures(script_sig, sig_hash)
      script = Bitcoin::Script.new(script_sig)
      redeem_script = Bitcoin::Script.new(script.chunks[-1])
      pubkeys = redeem_script.get_multisig_pubkeys

      # find the pubkey for each signature by trying to verify it
      # puts script.chunks[1...-1]
      sigs = Hash[script.chunks[1...-1].map.with_index do |sig, idx|
        pubkey = pubkeys.map do |key|
          Bitcoin::Key.new(pubkey: key.bth).verify(sig, sig_hash) ? key : nil
        end.compact.first
        raise "Key for signature ##{idx} not found in redeem script!"  unless pubkey
        [pubkey, sig]
      end]

      prefix + pubkeys.map { |k| sigs[k] ? Bitcoin::Script.pack_pushdata(sigs[k]) : nil }.join +
        Bitcoin::Script.pack_pushdata(script.chunks[-1])
    end
  end
end