module OpenAssets

  module MarkerOutput

    # whether this output is marker output for open assets.
    def open_assets_marker?
      return false unless script_pubkey.op_return?
      payload = Payload.parse_from_payload(script_pubkey.op_return_data)
      !payload.nil?
    end

  end

end
