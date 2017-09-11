module Bitcoin
  class Block

    attr_accessor :header
    attr_accessor :transactions

    def initialize(header, transactions = [])
      @header = header
      @transactions = transactions
    end

    # calculate block weight
    def weight
      stripped_size * (WITNESS_SCALE_FACTOR - 1) + size
    end

    # calculate total size (include witness data.)
    def size
      80 + Bitcoin.pack_var_int(transactions.size).bytesize +
          transactions.inject(0){|sum, tx| sum + (tx.witness? ? tx.serialize_witness_format.bytesize : tx.serialize_old_format.bytesize)}
    end

    # calculate base size (not include witness data.)
    def stripped_size
      80 + Bitcoin.pack_var_int(transactions.size).bytesize +
          transactions.inject(0){|sum, tx| sum + tx.serialize_old_format.bytesize}
    end

  end
end