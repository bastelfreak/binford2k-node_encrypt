module Puppet_X
  module Binford2k
    class NodeEncrypt

      def self.encrypted?(data)
        raise ArgumentError, 'Only strings can be encrypted' unless data.class == String
        # ridiculously faster than a regex
        data.start_with?("-----BEGIN PKCS7-----")
      end

      def self.encrypt(data, destination)
        raise ArgumentError, 'Can only encrypt strings' unless data.class == String
        raise ArgumentError, 'Need a node name to encrypt for' unless destination.class == String

        certpath = Puppet.settings[:hostcert]
        keypath  = Puppet.settings[:hostprivkey]

        # A dummy password with at least 4 characters is required here
        # since Ruby 2.4 which enforces a minimum password length
        # of 4 bytes. This is true even if the key has no password
        # at all--in which case the password we supply is ignored.
        # We can pass in a dummy here, since we know the certificate
        # has no password.
        key  = OpenSSL::PKey::RSA.new(File.read(keypath), '1234')
        cert = OpenSSL::X509::Certificate.new(File.read(certpath))

        # if we're on the CA, we've got a copy of the clientcert from the start.
        # This allows the module to work with no classification at all on single
        # monolithic server setups
        destpath = [
          "#{Puppet.settings[:signeddir]}/#{destination}.pem",
          "#{Puppet.settings[:certdir]}/#{destination}.pem",
        ].find {|path| File.exist? path }

        # for safer upgrades, let's default to the known good pathway for now
        if destpath
          target = OpenSSL::X509::Certificate.new(File.read(destpath))
        else
          # if we don't have a cert, check for it in $facts
          scope = Puppet.lookup(:global_scope)

          if scope.exist?('clientcert_pem')
            hostcert = scope.lookupvar('clientcert_pem')
            target   = OpenSSL::X509::Certificate.new(hostcert)
          else
            url = 'https://github.com/binford2k/binford2k-node_encrypt#automatically-distributing-certificates-to-compile-servers'
            raise ArgumentError, "Client certificate does not exist. See #{url} for more info."
          end
        end

        signed = OpenSSL::PKCS7::sign(cert, key, data, [], OpenSSL::PKCS7::BINARY)
        cipher = OpenSSL::Cipher::new("AES-128-CFB")

        # As for every good code, pieces are copied from stackoverflow
        # https://stackoverflow.com/a/16726864
        # why and what do we do here?
        # We encrypt the string `data` with aes-128-cfb, that's basically some XOR with random data called IV
        # Encrypting the same data twice, with different IV (that's the default) will result in different PKCS#7 output
        # This will be stored in the PuppetDB and causes catalog updates on every puppet run. The resource on the node won't change though
        # (because it decrypts it before applying, and the decrypted string doesn't change)
        # As a workaround, we generate and IV that's basically SHA256(FQDN + data.length). That means we:
        # * Still have many different IVs, even per node
        # * An IV doesn't need to be secret
        # * Bonus: It's not easily predictable because it contains the length of the unencrypted data
        #   * Yes, different data could have the same length, but reusing an IV for different data isn't bad
        # This is the solution for PE support ticket 49675 - huge PuppetDB growth caused by an exploding resource_params table
        # Further resources:
        # * https://security.stackexchange.com/q/42642
        # * https://stackoverflow.com/q/9049789
        # * https://stackoverflow.com/q/53150381
        # * https://dzone.com/articles/encrypting-data-ruby-and
        # * https://stackoverflow.com/q/16648543
        # * https://stuff-things.net/2015/02/12/symmetric-encryption-with-ruby-and-rails/

        # get the desired IV/key length, can very based on the CPU architecture, usually 16 byte
        iv_len = cipher.iv_len
        key_len = cipher.key_len
        # generate a random 256bit (32byte) string. it's identical per node per resource
        # copied from the fqdn_rand() function
        # https://github.com/puppetlabs/puppet/blob/main/lib/puppet/parser/functions/fqdn_rand.rb
        # fqdn_rand = Digest::SHA256.hexdigest([cert.subject.to_s,data.length].join(':'))
        fqdn_rand = Digest::SHA256.hexdigest([destination,data.length].join(':'))
        # split the checksum into to pieces, 16 byte/32chars each
        iv_seed, key_seed = fqdn_rand.partition(/.{32}/)[1,2]
        # Get correct length in the correct format
        iv = iv_seed.unpack('a2'*key_len).map{|x| x.hex}.pack('c'*key_len)
        key = key_seed.unpack('a2'*key_len).map{|x| x.hex}.pack('c'*key_len)
        # for reasons the docs don't explain, we've to configure if we want to encrypt/decrypt *before we set IV/key*
        # https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/Cipher.html#method-i-encrypt
        cipher.encrypt
        cipher.iv=(iv)
        cipher.key=(key)

        OpenSSL::PKCS7::encrypt([target], signed.to_der, cipher, OpenSSL::PKCS7::BINARY).to_s
      end

      def self.decrypt(data)
        raise ArgumentError, 'Can only decrypt strings' unless data.class == String

        cert   = OpenSSL::X509::Certificate.new(File.read(Puppet.settings[:hostcert]))
        # Same dummy password as above.
        key    = OpenSSL::PKey::RSA.new(File.read(Puppet.settings[:hostprivkey]), '1234')
        source = OpenSSL::X509::Certificate.new(File.read(Puppet.settings[:localcacert]))

        store = OpenSSL::X509::Store.new
        store.add_cert(source)

        blob      = OpenSSL::PKCS7.new(data)
        decrypted = blob.decrypt(key, cert)
        verified  = OpenSSL::PKCS7.new(decrypted)

        unless verified.verify(nil, store, nil, OpenSSL::PKCS7::NOVERIFY)
          raise ArgumentError, 'Signature verification failed'
        end
        verified.data
      end


    end
  end
end
