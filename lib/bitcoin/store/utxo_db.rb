require 'leveldb-native'

module Bitcoin
  module Store
    class UtxoDB

      KEY_PREFIX = {
        out_point: 'o',        # key: out_point(tx_hash and index), value: Utxo
        script: 's',           # key: script_pubkey and out_point(tx_hash and index), value: Utxo
        height: 'h',           # key: block_height and out_point, value: Utxo
        tx_hash: 't',          # key: tx_hash of transaction, value: [block_height, tx_index]
        block: 'b',            # key: block_height and tx_index, value: tx_hash
        tx_payload: 'p',       # key: tx_hash, value: Tx
      }

      attr_reader :level_db, :logger

      def initialize(path = "#{Bitcoin.base_dir}/db/utxo")
        FileUtils.mkdir_p(path)
        @level_db = ::LevelDBNative::DB.new(path)
        @logger = Bitcoin::Logger.create(:debug)
      end

      def close
        level_db.close
      end




      # @param  [String] tx_hash
      # @param  [String] tx_payload
      def save_tx(tx_hash, tx_payload)
        logger.info("UtxoDB#save_tx:#{[tx_hash, tx_payload]}")
        level_db.batch do
          # tx_hash -> [block_height, tx_index]
          key = KEY_PREFIX[:tx_payload] + tx_hash
          level_db.put(key, tx_payload)
        end
      end

      # @param  [String] tx_hash
      # @param  [Integer] block_height
      # @param  [Integer] tx_index
      def save_tx_position(tx_hash, block_height, tx_index)
        logger.info("UtxoDB#save_tx_position:#{[tx_hash, block_height, tx_index]}")
        level_db.batch do
          # tx_hash -> [block_height, tx_index]
          key = KEY_PREFIX[:tx_hash] + tx_hash
          level_db.put(key, [block_height, tx_index].pack('N2').bth)

          # block_hash and tx_index -> tx_hash
          key = KEY_PREFIX[:block] + [block_height, tx_index].pack('N2').bth
          level_db.put(key, tx_hash)
        end
      end

      # @param [Bitcoin::OutPoint] out_point
      # @param [Double] value
      # @param [Bitcoin::Script] script_pubkey
      # @param [Integer] block_height
      def save_utxo(out_point, value, script_pubkey, block_height=nil)
        logger.info("UtxoDB#save_utxo:#{[out_point, value, script_pubkey, block_height]}")
        level_db.batch do
          utxo = Bitcoin::Wallet::Utxo.new(out_point.tx_hash, out_point.index, value, script_pubkey, block_height)
          payload = utxo.to_payload

          # out_point
          key = KEY_PREFIX[:out_point] + out_point.to_payload.bth
          return if level_db.contains?(key)
          level_db.put(key, payload)

          # script_pubkey
          if script_pubkey
            key = KEY_PREFIX[:script] + script_pubkey.to_payload.bth + out_point.to_payload.bth
            level_db.put(key, payload)
          end

          # height
          if !block_height.nil?
            key = KEY_PREFIX[:height] + [block_height].pack('N').bth + out_point.to_payload.bth
            level_db.put(key, payload)
          end

          return utxo
        end
      end

      # @param  [string] tx_hash
      # @return [block_height, tx_index, tx_payload]
      def get_tx(tx_hash)
        key = KEY_PREFIX[:tx_hash] + tx_hash
        return [] unless level_db.contains?(key)
        block_height, tx_index = level_db.get(key).htb.unpack('N2')
        key = KEY_PREFIX[:tx_payload] + tx_hash
        tx_payload = level_db.get(key)
        [block_height, tx_index, tx_payload]
      end

      # @param  [Bitcoin::Outpoint] out_point
      # @return [Bitcoin::Wallet::Utxo] 
      def delete_utxo(out_point)
        level_db.batch do
          # [:out_point]
          key = KEY_PREFIX[:out_point] + out_point.to_payload.bth
          return unless level_db.contains?(key)
          utxo = Bitcoin::Wallet::Utxo.parse_from_payload(level_db.get(key))
          level_db.delete(key)

          # [:script]
          if utxo.script_pubkey
            key = KEY_PREFIX[:script] + utxo.script_pubkey.to_payload.bth + out_point.to_payload.bth
            level_db.delete(key)
          end

          if utxo.block_height
            # [:height]
            key = KEY_PREFIX[:height] + [utxo.block_height].pack('N').bth + out_point.to_payload.bth
            level_db.delete(key)

            # [:block]
            key = KEY_PREFIX[:block] + [utxo.block_height, utxo.index].pack('N2').bth
            level_db.delete(key)
          end

          # handles both [:tx_hash] and [:tx_payload]
          if utxo.tx_hash
            key = KEY_PREFIX[:tx_hash] + utxo.tx_hash
            level_db.delete(key)

            key = KEY_PREFIX[:tx_payload] + utxo.tx_hash
            level_db.delete(key)
          end

          return utxo
        end
      end

      # @param  [Bitcoin::Outpoint] out_point
      # @return [Bitcoin::Wallet::Utxo]
      def get_utxo(out_point)
        level_db.batch do
          key = KEY_PREFIX[:out_point] + out_point.to_payload.bth
          return unless level_db.contains?(key)
          return Bitcoin::Wallet::Utxo.parse_from_payload(level_db.get(key))
        end
      end

      # return [Bitcoin::Wallet::Utxo ...]
      def list_unspent(current_block_height: 9999999, min: 0, max: 9999999, addresses: nil)
        if addresses
          list_unspent_by_addresses(current_block_height, min: min, max: max, addresses: addresses)
        else
          list_unspent_by_block_height(current_block_height, min: min, max: max)
        end
      end

      # @param [Bitcoin::Wallet::Account]
      # return [Bitcoin::Wallet::Utxo ...]
      def list_unspent_in_account(account, current_block_height: 9999999, min: 0, max: 9999999)
        return [] unless account
        return [] unless account.purpose == Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy] or account.purpose == Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit]

        script_pubkeys = nil
        if account.purpose == Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy]
          script_pubkeys = account.watch_targets.map { |t| Bitcoin::Script.to_p2pkh(t).to_payload.bth }
        elsif account.purpose == Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit]
          script_pubkeys = account.watch_targets.map { |t| Bitcoin::Script.to_p2wpkh(t).to_payload.bth }
        end
        
        list_unspent_by_script_pubkeys(current_block_height, min: min, max: max, script_pubkeys: script_pubkeys)
      end

      # @param [Bitcoin::Wallet::Account]
      # return [Bitcoin::Wallet::Utxo ...]
      def get_balance(account, current_block_height: 9999999, min: 0, max: 9999999)
        list_unspent_in_account(account, current_block_height: current_block_height, min: min, max: max).sum { |u| u.value }
      end

      private

      def utxos_between(from, to)
        level_db.each(from: from, to: to).map { |k, v| Bitcoin::Wallet::Utxo.parse_from_payload(v) }
      end

      class ::Array
        def with_height(min, max)
          select { |u| u.block_height >= min && u.block_height <= max }
        end
      end

      def list_unspent_by_block_height(current_block_height, min: 0, max: 9999999)
        max_height = [current_block_height - min, 0].max
        min_height = [current_block_height - max, 0].max
        from = KEY_PREFIX[:height] + [min_height].pack('N').bth + '000000000000000000000000000000000000000000000000000000000000000000000000'
        to = KEY_PREFIX[:height] + [max_height].pack('N').bth + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        utxos_between(from, to)
      end

      def list_unspent_by_addresses(current_block_height, min: 0, max: 9999999, addresses: [])
        script_pubkeys = addresses.map { |a| Bitcoin::Script.parse_from_addr(a).to_payload.bth }
        list_unspent_by_script_pubkeys(current_block_height, min: min, max: max, script_pubkeys: script_pubkeys)
      end

      def list_unspent_by_script_pubkeys(current_block_height, min: 0, max: 9999999, script_pubkeys: [])
        max_height = current_block_height - min
        min_height = current_block_height - max
        script_pubkeys.map do |key|
          from = KEY_PREFIX[:script] + key + '000000000000000000000000000000000000000000000000000000000000000000000000'
          to = KEY_PREFIX[:script] + key + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
          utxos_between(from, to).with_height(min_height, max_height)
        end.flatten
      end
    end
  end
end
