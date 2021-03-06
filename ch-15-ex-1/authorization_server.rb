# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'
require 'uri'

require 'jwt'
require 'rack/auth/basic'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

require_relative '../lib/pseudo_database'

Client = Struct.new(:id, :secret, :redirect_uris, :scope, keyword_init: true)
Resource = Struct.new(:id, :secret, keyword_init: true)

CLIENTS = [
  Client.new(
    id: 'oauth-client-1',
    secret: 'oauth-client-secret-1',
    redirect_uris: %w[http://localhost:9000/callback],
    scope: %w[foo bar],
  ),
].freeze

RESOURCES = [
  Resource.new(
    id: 'protected-resource-1',
    secret: 'protected-resource-secret-1',
  ),
].freeze

$db = PseudoDatabase.new(File.expand_path('./database.nosql', __dir__)).tap(&:reset)
$requests = {}
$codes = {}

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
          <li>ID: <%= @client.id %></li>
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
  def basic_auth!(&authenticator)
    auth = Rack::Auth::Basic::Request.new(request.env)
    halt 401, { 'WWW-Authenticate' => %(Basic realm="#{settings.bind}:#{settings.port}") }, nil unless auth.provided?
    halt 400 unless auth.basic?
    halt 401, { 'WWW-Authenticate' => %(Basic realm="#{settings.bind}:#{settings.port}") }, nil unless authenticator.call(*auth.credentials)
  end

  def get_client(client_id)
    CLIENTS.find { |client| client.id == client_id }
  end

  def get_protected_resource(resource_id)
    RESOURCES.find { |resource| resource.id == resource_id }
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
  halt 400, "Invalid scope: #{escape(params[:scope])}" unless @scope.difference(@client.scope).empty?

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
                   if params[:scope].difference(client.scope).empty?
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
  basic_auth! do |id, secret|
    @client = get_client(id)
    @client && secret == @client.secret
  end

  required_params :grant_type

  case params[:grant_type]
  when 'authorization_code'
    required_params :code

    code = $codes.delete(params[:code])
    if code && code[:request][:client_id] == @client.id
      jwk = JWT::JWK.new(OpenSSL::PKey::RSA.new(2048))
      access_token = generate_token
      key_params = jwk.keypair.params.transform_values { |val| Base64.urlsafe_encode64(val.to_s(2), padding: false) }
      access_token_key = {
        kty: 'RSA',
        n: key_params['n'], e: key_params['e'], d: key_params['d'],
        p: key_params['p'], q: key_params['q'],
        dp: key_params['dmp1'], dq: key_params['dmq1'], qi: key_params['iqmp'],
      }

      $db.insert({ access_token: access_token, access_token_key: jwk.export, client_id: @client.id, scope: code[:scope] })
      json access_token: access_token, access_token_key: access_token_key, token_type: 'PoP', alg: 'RS256', scope: code[:scope].join(' ')
    else
      halt 400, json(error: 'invalid_grant')
    end
  else
    halt 400, json(error: 'unsupported_grant_type')
  end
end

post '/introspect' do
  basic_auth! do |id, secret|
    @resource = get_protected_resource(id)
    @resource && secret == @resource.secret
  end

  required_params :token

  token_hash = $db.find { |row| row[:access_token] == params[:token] }

  if token_hash
    json(
      active: true,
      iss: "http://#{settings.bind}:#{settings.port}/",
      aud: 'http://localhost:9002/',
      scope: token_hash[:scope].join(' '),
      client_id: token_hash[:client_id],
      access_token_key: token_hash[:access_token_key],
    )
  else
    json active: false
  end
end
