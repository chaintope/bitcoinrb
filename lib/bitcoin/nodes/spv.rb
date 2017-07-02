module Bitcoin
  module Nodes

    # SPV module
    module SPV

      autoload :CLI, 'bitcoin/nodes/spv/cli'
      autoload :Daemon, 'bitcoin/nodes/spv/daemon'

    end

  end
end
