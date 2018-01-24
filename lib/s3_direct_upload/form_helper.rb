module S3DirectUpload
  module UploadHelper
    def s3_uploader_form(options = {}, &block)
      uploader = S3Uploader.new(options)
      form_tag(uploader.url, uploader.wrapper_options) do
        uploader.fields.map do |name, value|
          hidden_field_tag(name, value)
        end.join.html_safe + capture(&block)
      end
    end

    alias_method :s3_uploader, :s3_uploader_form

    def s3_uploader_url ssl = true
      S3DirectUpload.config.url || "http#{ssl ? 's' : ''}://#{S3DirectUpload.config.region || "s3"}.amazonaws.com/#{S3DirectUpload.config.bucket}/"
    end

    class S3Uploader
      def initialize(options)
        @key_starts_with = options[:key_starts_with] || "uploads/"
        @options = options.reverse_merge(
          aws_access_key_id: S3DirectUpload.config.access_key_id,
          aws_secret_access_key: S3DirectUpload.config.secret_access_key,
          bucket: options[:bucket] || S3DirectUpload.config.bucket,
          region: S3DirectUpload.config.region || "us-east-1",
          url: S3DirectUpload.config.url,
          ssl: true,
          acl: "public-read",
          expiration: 10.hours.from_now.utc.iso8601,
          max_file_size: 500.megabytes,
          callback_method: "POST",
          callback_param: "file",
          key_starts_with: @key_starts_with,
          key: key,
          server_side_encryption: nil,
          security_token: options[:security_token],
          date: Time.now.utc.strftime("%Y%m%d"),
          timestamp: Time.now.utc.strftime("%Y%m%dT%H%M%SZ")
        )
      end

      def wrapper_options
        {
          id: @options[:id],
          class: @options[:class],
          authenticity_token: false,
          data: {
            callback_url: @options[:callback_url],
            callback_method: @options[:callback_method],
            callback_param: @options[:callback_param]
          }.reverse_merge(@options[:data] || {})
        }
      end

      def fields
        {
          :acl => @options[:acl],
          :key => @options[:key] || key,
          :policy => policy,
          :success_action_status => "201",
          'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
          'X-Amz-Credential' => "#{@options[:aws_access_key_id]}/#{@options[:date]}/#{@options[:region]}/s3/aws4_request",
          'X-Amz-Date' => @options[:timestamp],
          'X-Amz-Signature' => signature,
          'X-Requested-With' => 'xhr',
          "x-amz-server-side-encryption" => @options[:server_side_encryption],
          "x-amz-security-token" => @options[:security_token]
        }.delete_if { |k, v| v.nil? }
      end

      def key
        @key ||= "#{@key_starts_with}{timestamp}-{unique_id}-#{SecureRandom.hex}/${filename}"
      end

      def hostname
        if @options[:region] == "us-east-1"
          "#{@options[:bucket]}.s3.amazonaws.com"
        else
          "#{@options[:bucket]}.s3-#{@options[:region]}.amazonaws.com"
        end
      end

      def url
        @options[:url] || "http#{@options[:ssl] ? 's' : ''}://#{hostname}/"
      end

      def policy
        Base64.encode64(policy_data.to_json).gsub("\n", "")
      end

      def policy_data
        {
          expiration: @options[:expiration],
          conditions: [
            ["starts-with", "$utf8", ""],
            ["starts-with", "$key", @options[:key_starts_with]],
            ["starts-with", "$x-requested-with", ""],
            ["content-length-range", 0, @options[:max_file_size]],
            ["starts-with","$content-type", @options[:content_type_starts_with] ||""],
            {"x-amz-algorithm" => 'AWS4-HMAC-SHA256'},
            {"x-amz-credential" => "#{@options[:aws_access_key_id]}/#{@options[:date]}/#{@options[:region]}/s3/aws4_request"},
            {"x-amz-date" => @options[:timestamp]},
            {bucket: @options[:bucket]},
            {acl: @options[:acl]},
            {success_action_status: "201"}
          ] + server_side_encryption + security_token + (@options[:conditions] || [])
        }
      end

      def server_side_encryption
        if @options[:server_side_encryption]
          [ { "x-amz-server-side-encryption" => @options[:server_side_encryption] } ]
        else
          []
        end
      end

      def security_token
        if @options[:security_token]
          [ { "x-amz-security-token" => @options[:security_token] } ]
        else
          []
        end
      end

      def signature
        OpenSSL::HMAC.hexdigest('sha256', signature_key, policy)
      end

      private

      def signature_key
        #AWS Signature Version 4
        k_date = OpenSSL::HMAC.digest('sha256', "AWS4" + @options[:aws_secret_access_key], @options[:date])
        k_region = OpenSSL::HMAC.digest('sha256', k_date, @options[:region])
        k_service = OpenSSL::HMAC.digest('sha256', k_region, "s3")
        k_signing = OpenSSL::HMAC.digest('sha256', k_service, "aws4_request")
        k_signing
      end
    end
  end
end
