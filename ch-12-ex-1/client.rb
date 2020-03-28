# frozen_string_literal: true

require 'json'
require 'net/http'
require 'securerandom'
require 'uri'

require 'sinatra'
require 'sinatra/required_params'

AUTHORIZATION_ENDPOINT = 'http://localhost:9001/authorize'
TOKEN_ENDPOINT = 'http://localhost:9001/token'
REGISTRATION_ENDPOINT = 'http://localhost:9001/register'

PROTECTED_RESOURCE = 'http://localhost:9002/resource'

REDIRECT_URI = 'http://localhost:9000/callback'
SCOPE = 'foo'

CLIENT_METADATA = {
  token_endpoint_auth_method: 'client_secret_basic',
  grant_types: %w[authorization_code],
  response_types: %w[code],
  redirect_uris: [REDIRECT_URI],
  client_name: 'OAuth in Action Dynamic Test Client',
  client_uri: "http://#{settings.bind}:#{settings.port}/",
  scope: SCOPE,
}.freeze

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

$client = Client.new

set :port, 9000

enable :sessions

template :index do
  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Client</title>
      </head>
      <body>
        <ul>
          <li>Client ID: <%= $client.client_id %></li>
          <li>Client Secret: <%= $client.client_secret %></li>
        </ul>
        <ul>
          <li>Access token value: <%= session[:access_token] %></li>
          <li>Scope value: <%= session[:scope] %></li>
          <li>Refresh token value: <%= session[:refresh_token] %></li>
        </ul>
        <a href="/authorize">Get OAuth Token</a>
        <a href="/fetch_resource">Get Protected Resource</a>
      </body>
    </html>
  HTML
end

helpers do
  def fetch_and_save_access_token!(**params)
    token_uri = URI.parse(TOKEN_ENDPOINT)
    token_uri.user = $client.client_id
    token_uri.password = $client.client_secret

    logger.info "Requesting access token with params: #{params.inspect}"
    response = Net::HTTP.post_form(token_uri, params)
    response.value

    body = JSON.parse(response.body)

    session[:access_token] = body['access_token']
    session[:refresh_token] = body['refresh_token'] if body['refresh_token']
    session[:scope] = body['scope']
  end

  def register_client!
    register_uri = URI.parse(REGISTRATION_ENDPOINT)
    http = Net::HTTP.new(register_uri.host, register_uri.port)

    logger.info 'Registering client'
    response = http.post(register_uri.path, CLIENT_METADATA.to_json, { 'Content-Type' => 'application/json' })
    response.value
    logger.info "Got registered client: #{response.body}"

    body = JSON.parse(response.body, symbolize_names: true)
    $client = Client.new(**body)
  end
end

get '/' do
  erb :index
end

get '/authorize' do
  if $client.client_id.nil?
    begin
      register_client!
    rescue Net::HTTPExceptions => e
      halt "Unable to register client: #{e.message}\n#{e.response.body}"
    end
  end

  session[:access_token] = nil
  session[:scope] = nil
  session[:state] = SecureRandom.urlsafe_base64

  authorization_uri = URI.parse(AUTHORIZATION_ENDPOINT)
  authorization_uri.query = build_query(
    response_type: 'code',
    client_id: $client.client_id,
    redirect_uri: REDIRECT_URI,
    scope: SCOPE,
    state: session[:state],
  )
  redirect authorization_uri
end

get '/callback' do
  required_params :code, :state

  halt 400, "State does not match: expected '#{session[:state]}' got '#{escape(params[:state])}'" if params[:state] != session[:state]
  halt escape(params[:error]) if params[:error]

  begin
    fetch_and_save_access_token!(
      grant_type: 'authorization_code',
      code: params[:code],
      redirect_uri: REDIRECT_URI,
    )
  rescue Net::HTTPExceptions => e
    halt "Unable to fetch access token: #{e.message}\n#{e.response.body}"
  end

  redirect to('/')
end

get '/fetch_resource' do
  halt 401, 'Missing access token' if session[:access_token].nil? && session[:refresh_token].nil?

  protected_resource_uri = URI.parse(PROTECTED_RESOURCE)
  http = Net::HTTP.new(protected_resource_uri.host, protected_resource_uri.port)
  headers = { 'Authorization' => "Bearer #{session[:access_token]}" }

  logger.info "Requesting protected resource with access token: #{session[:access_token]}"
  response = http.post(protected_resource_uri.path, nil, headers)

  if response.is_a?(Net::HTTPSuccess)
    halt response.body
  elsif response.is_a?(Net::HTTPUnauthorized) && session[:refresh_token]
    session[:access_token] = nil
    begin
      fetch_and_save_access_token!(
        grant_type: 'refresh_token',
        refresh_token: session[:refresh_token],
      )
      redirect to('/fetch_resource')
    rescue Net::HTTPExceptions => e
      session[:refresh_token] = nil
      halt "Unable to refresh access token: #{e.message}\n#{e.response.body}"
    end
  else
    session[:access_token] = nil
    session[:refresh_token] = nil
    halt "Unable to fetch resource: #{response.code} #{response.message}\n#{response.body}"
  end
end
