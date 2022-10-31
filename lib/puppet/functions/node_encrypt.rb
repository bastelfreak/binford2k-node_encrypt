require_relative '../../puppet_x/binford2k/node_encrypt'
require 'digest'

# @summary
#   Encrypt data with node_encrypt.
#
Puppet::Functions.create_function(:node_encrypt) do
  dispatch :simple_encrypt do
    param 'String', :content
  end

  dispatch :sensitive_encrypt do
    param 'Sensitive', :content
  end

  def simple_encrypt(content)
    certname = closure_scope['clientcert']
    if ! closure_scope['trusted'].nil? && closure_scope['trusted']['certname'] == 'catalog-diff'
      sha256 = Digest::SHA2.hexdigest(content)
      "SHA256: #{sha256}"
    else
      Puppet_X::Binford2k::NodeEncrypt.encrypt(content, certname)
    end
  end

  def sensitive_encrypt(content)
    simple_encrypt(content.unwrap)
  end

end
