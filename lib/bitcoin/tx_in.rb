module Bitcoin

  # transaction input
  class TxIn

    attr_accessor :out_point
    attr_accessor :script_sig
    attr_accessor :sequence
    attr_accessor :script_witness

    # Setting nSequence to this value for every input in a transaction disables nLockTime.
    SEQUENCE_FINAL = 0xffffffff

    # If this flag set, TxIn#sequence is NOT interpreted as a relative lock-time.
    SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)

    # If TxIn#sequence encodes a relative lock-time and this flag is set, the relative lock-time has units of 512 seconds,
    # otherwise it specifies blocks with a granularity of 1.
    SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)

    # If TxIn#sequence encodes a relative lock-time, this mask is applied to extract that lock-time from the sequence field.
    SEQUENCE_LOCKTIME_MASK = 0x0000ffff

    def initialize(out_point: nil, script_sig: Bitcoin::Script.new, script_witness: ScriptWitness.new, sequence: SEQUENCE_FINAL)
      @out_point = out_point
      @script_sig = script_sig
      @script_witness = script_witness
      @sequence = sequence
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      i = new
      hash, index = buf.read(36).unpack('a32V')
      i.out_point = OutPoint.new(hash.reverse.bth, index)
      sig_length = Bitcoin.unpack_var_int_from_io(buf)
      sig = buf.read(sig_length)
      if i.coinbase?
        i.script_sig.chunks[0] = sig
      else
        i.script_sig = Script.parse_from_payload(sig)
      end
      i.sequence = buf.read(4).unpack('V').first
      i
    end

    def coinbase?
      out_point.coinbase?
    end

    def to_payload(script_sig = @script_sig, sequence = @sequence)
      p = out_point.to_payload
      p << Bitcoin.pack_var_int(script_sig.to_payload.bytesize)
      p << script_sig.to_payload << [sequence].pack('V')
      p
    end

    def has_witness?
      !script_witness.empty?
    end

  end

end
