module Bitcoin
  module Wallet
    class UtxoHandler
      attr_reader :watchings, :spv, :utxo_db, :pendings

      # @param spv [Bitcoin::Node::SPV]
      # @utxo_db [Bitcoin::Store::UtxoDb]
      def initialize(spv, utxo_db)
        @spv = spv
        @spv.add_observer(self)
        @utxo_db = utxo_db
        @logger = Bitcoin::Logger.create(:debug)
      end

      def update(event, data)
        @logger.debug "UtxoHandler#update: #{event}, #{data}"
        send(event, data)
      end

      private

      # Called when receiving `tx` message from other node.
      #
      # - Store utxo if the output of received tx is in the watch list
      # - Delete from utxo_db for spent output.
      def tx(data)
        tx = data.tx
        tx.outputs.each_with_index do |output, index|
          next unless watching?(output)
          out_point = Bitcoin::OutPoint.new(tx.tx_hash, index)
          utxo_db.save_utxo(out_point, output.value, output.script_pubkey)
        end

        tx.inputs.each do |input|
          utxo_db.delete_utxo(input.out_point)
        end
      end

      def header(data)
        # No implementation
      end

      def merkleblock(data)
        # No implementation
      end

      # Return if specified output is contained in watch_targets
      def watching?(output)
        return false unless spv.wallet
        watch_targets = spv.wallet.watch_targets
        watch_targets.find do |target|
          output.script_pubkey.to_hex.include?(target)
        end
      end
    end
  end
end
