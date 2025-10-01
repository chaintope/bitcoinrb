require 'uri'

module Bitcoin
  # BIP-21 URI
  # @see https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
  class BIP21URI

    attr_reader :address
    attr_reader :amount
    attr_reader :label
    attr_reader :message
    attr_reader :other_params

    # Constructor
    # @param [String] address
    # @param [BigDecimal, Integer] amount
    # @param [String] label
    # @param [String] message
    # @param [Hash] other_params
    def initialize(address: nil, amount: nil, label: nil, message: nil, other_params: {})
      if address
        Bitcoin::Script.parse_from_addr(address)
        @address = address
      end
      if amount
        amount = BigDecimal(amount) if amount.is_a?(Integer)
        raise ArgumentError, "amount must be BigDecimal or integer." unless amount.is_a?(BigDecimal)
        @amount = amount
      end
      @label = label
      @message = message
      raise ArgumentError, "other_params must be Hash." unless other_params.is_a?(Hash)
      other_params.keys.each do |key|
        raise ArgumentError, 'An unsupported reqparam is included.' if key.start_with?('req-')
      end
      @other_params = other_params
    end

    # Parse BIP-21 URI string.
    # @param [String] BIP-21 URI.
    # @return [Bitcoin::BIP21URI]
    # @raise [ArgumentError]
    def self.parse(uri)
      raise ArgumentError, "uri must be string." unless uri.is_a?(String)
      raise ArgumentError, "Invalid uri scheme." unless uri.downcase.start_with?('bitcoin:')
      uri = uri[8..-1]
      addr, params = uri.split('?', 2)
      params = params ? URI.decode_www_form(params).to_h : {}
      addr = nil if addr.empty?
      amount = params['amount'] ? BigDecimal(params['amount']) : nil
      excluded_keys = %w[amount label message]
      others = params.except(*excluded_keys)
      BIP21URI.new(address: addr, amount: amount,
                   label: params['label'], message: params['message'], other_params: others)
    end

    # Payment amount (satoshi unit)
    # @return [Integer, nil]
    def satoshi
      amount.nil? ? nil : (amount * 100_000_000).to_i
    end

    def to_s
      uri = 'bitcoin:'
      uri << address if address
      base_params = {}
      base_params['amount'] = amount.to_s('f').sub(/\.0+$/, '') if amount
      base_params['label'] = label if label
      base_params['message'] = message if message
      all_params = base_params.merge other_params
      unless all_params.empty?
        uri << "?#{URI.encode_www_form(all_params)}".gsub('+', '%20')
      end
      uri
    end
  end
end