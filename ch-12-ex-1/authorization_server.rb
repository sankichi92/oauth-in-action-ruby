# frozen_string_literal: true

require 'securerandom'
require 'uri'

require 'rack/auth/basic'
require 'rack/contrib'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

require_relative '../lib/pseudo_database'

Client = Struct.new(
  :client_id,
  :client_secret,
  :token_endpoint_auth_method,
  :grant_types,
  :response_types,
  :redirect_uris,
  :client_name,
  :client_uri,
  :logo_uri,
  :scope,
  :client_id_created_at,
  :client_secret_expires_at,
  keyword_init: true,
)

AVAILABLE_TOKEN_ENDPOINT_AUTH_METHODS = %w[client_secret_basic client_secret_post none].freeze
AVAILABLE_GRANT_TYPES = %w[authorization_code refresh_token].freeze
AVAILABLE_RESPONSE_TYPES = %w[code].freeze

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-12-ex-1/database.nosql', __dir__)).tap(&:reset)
$requests = {}
$codes = {}
$clients = []

use Rack::PostBodyContentTypeParser

set :port, 9001

template :approve do
  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Authorization Server</title>
      </head>
      <body>
        <p>Approve this client?</p>
        <ul>
          <li>ID: <%= @client.client_id %></li>
        </ul>
        <form action="/approve" method="POST">
          <input type="hidden" name="request_id" value="<%= @request_id %>">
          <p>The client is requesting access to the following:</p>
          <ul>
            <% @scope.each do |scope| %>
              <li><label><input type="checkbox" name="scope[]" value="<%= scope %>" checked><%= scope %></label></li>
            <% end %>
          </ul>
          <input type="submit" name="approve" value="Approve">
          <input type="submit" name="deny" value="Deny">
        </form>
      </body>
    </html>
  HTML
end

helpers do
  def authenticate_client!
    auth = Rack::Auth::Basic::Request.new(request.env)
    client_id, client_secret = if auth.provided? && auth.basic?
                                 auth.credentials
                               else
                                 required_params :client_id, :client_secret
                                 [params[:client_id], params[:client_secret]]
                               end
    @client = get_client(client_id)
    halt 401, json(error: 'invalid_client') if @client.nil? || client_secret != @client.client_secret
  end

  def get_client(client_id)
    $clients.find { |client| client.client_id == client_id }
  end

  def generate_token
    SecureRandom.urlsafe_base64
  end
end

get '/authorize' do
  required_params :response_type, :client_id, :redirect_uri, :scope

  @client = get_client(params[:client_id])
  halt 400, "Unknown client: #{escape(params[:client_id])}" if @client.nil?
  halt 400, "Invalid redirect URI: #{escape(params[:redirect_uri])}" unless @client.redirect_uris.include?(params[:redirect_uri])

  @scope = params[:scope].split
  unless @scope.difference(@client.scope.split).empty?
    redirect_uri = URI.parse(params[:redirect_uri])
    redirect_uri.query = build_query({ error: 'invalid_scope', state: params[:state] }.compact)
    redirect redirect_uri
  end

  @request_id = SecureRandom.uuid
  $requests[@request_id] = params

  erb :approve
end

post '/approve' do
  required_params :request_id

  original_params = $requests.delete(params[:request_id])
  halt 403, "No matching authorization request: #{escape(params[:request_id])}" if original_params.nil?

  query_hash = if params[:approve]
                 case original_params[:response_type]
                 when 'code'
                   client = get_client(original_params[:client_id])
                   if params[:scope].difference(client.scope.split).empty?
                     code = SecureRandom.alphanumeric(8)
                     $codes[code] = { request: original_params, scope: params[:scope] }
                     { code: code }
                   else
                     { error: 'invalid_scope' }
                   end
                 else
                   { error: 'unsupported_response_type' }
                 end
               else
                 { error: 'access_denied' }
               end

  redirect_uri = URI.parse(original_params[:redirect_uri])
  redirect_uri.query = build_query(query_hash.merge(state: original_params[:state]).compact)
  redirect redirect_uri
end

post '/token' do
  authenticate_client!

  required_params :grant_type

  case params[:grant_type]
  when 'authorization_code'
    required_params :code

    code = $codes.delete(params[:code])
    if code && code[:request][:client_id] == @client.client_id
      access_token = generate_token
      refresh_token = generate_token

      $db.insert(
        { access_token: access_token, client_id: @client.client_id, scope: code[:scope] },
        { refresh_token: refresh_token, client_id: @client.client_id, scope: code[:scope] },
      )

      json access_token: access_token, token_type: 'Bearer', refresh_token: refresh_token, scope: code[:scope].join(' ')
    else
      halt 400, json(error: 'invalid_grant')
    end
  when 'refresh_token'
    required_params :refresh_token

    token_hashes = $db.to_a
    token_hashes.each_with_index do |token_hash, i|
      if params[:refresh_token] == token_hash[:refresh_token]
        if @client.client_id == token_hash[:client_id]
          access_token = generate_token
          token_hashes << { access_token: access_token, client_id: @client.client_id, scope: token_hash[:scope] }
          halt json(access_token: access_token, token_type: 'Bearer', refresh_token: token_hash[:refresh_token], scope: token_hash[:scope])
        else
          token_hashes.delete_at(i)
          halt 400, json(error: 'invalid_grant')
        end
      end
    ensure
      $db.replace(*token_hashes)
    end
  else
    halt 400, json(error: 'unsupported_grant_type')
  end
end

post '/register' do
  logger.info "params: #{params}"

  client = Client.new(**params.slice(:token_endpoint_auth_method, :grant_types, :response_types, :redirect_uris, :client_name, :client_uri, :logo_uri, :scope))

  client.token_endpoint_auth_method ||= 'client_secret_basic'
  halt 400, json(error: 'invalid_client_metadata') unless AVAILABLE_TOKEN_ENDPOINT_AUTH_METHODS.include?(client.token_endpoint_auth_method)

  client.grant_types ||= %w[authorization_code]
  halt 400, json(error: 'invalid_client_metadata') unless client.grant_types.difference(AVAILABLE_GRANT_TYPES).empty?

  client.response_types ||= %w[code]
  halt 400, json(error: 'invalid_client_metadata') unless client.response_types.difference(AVAILABLE_RESPONSE_TYPES).empty?

  client.response_types << 'code' if client.grant_types.include?('authorization_code') && !client.response_types.include?('code')
  client.grant_types << 'authorization_code' if client.response_types.include?('code') && !client.grant_types.include?('authorization_code')

  halt 400, json(error: 'invalid_client_metadata') if !client.redirect_uris.is_a?(Array) || client.redirect_uris.empty?

  client.client_id = SecureRandom.uuid
  client.client_secret = SecureRandom.urlsafe_base64 if client.token_endpoint_auth_method != 'none'

  client.client_id_created_at = Time.now.to_i
  client.client_secret_expires_at = 0

  $clients << client
  logger.info "Registered client: #{client.inspect}"

  halt 201, json(client.to_h)
end
