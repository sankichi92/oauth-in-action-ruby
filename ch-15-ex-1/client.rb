# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'securerandom'
require 'uri'

require 'jwt'
require 'sinatra'
require 'sinatra/required_params'

AUTHORIZATION_ENDPOINT = 'http://localhost:9001/authorize'
TOKEN_ENDPOINT = 'http://localhost:9001/token'

PROTECTED_RESOURCE = 'http://localhost:9002/resource'

CLIENT_ID = 'oauth-client-1'
CLIENT_SECRET = 'oauth-client-secret-1'
REDIRECT_URI = 'http://localhost:9000/callback'
SCOPE = 'foo'

$keys = {} # Key is too large to save in cookie

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
        <dl>
          <dt>Access token</dt>
          <dd><%= session[:access_token] %></dd>
          <dt>Scope</dt>
          <dd><%= session[:scope] %></dd>
          <dt>Access token key</dt>
          <dd>
            <pre><%= JSON.pretty_generate($keys[session[:access_token]]) %></pre>
          </dd>
        </dl>
        <a href="/authorize">Get OAuth Token</a>
        <a href="/fetch_resource">Get Protected Resource</a>
      </body>
    </html>
  HTML
end

helpers do
  def fetch_and_save_access_token!(**params)
    token_uri = URI.parse(TOKEN_ENDPOINT)
    token_uri.user = CLIENT_ID
    token_uri.password = CLIENT_SECRET

    logger.info "Requesting access token with params: #{params.inspect}"
    response = Net::HTTP.post_form(token_uri, params)
    response.value

    body = JSON.parse(response.body, symbolize_names: true)

    session[:access_token] = body[:access_token]
    $keys[body[:access_token]] = body[:access_token_key]
    session[:alg] = body[:alg]
    session[:scope] = body[:scope]
  end
end

get '/' do
  erb :index
end

get '/authorize' do
  session[:access_token] = nil
  session[:scope] = nil
  session[:state] = SecureRandom.urlsafe_base64

  authorization_uri = URI.parse(AUTHORIZATION_ENDPOINT)
  authorization_uri.query = build_query(
    response_type: 'code',
    client_id: CLIENT_ID,
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
  halt 401, 'Missing access token' if session[:access_token].nil?

  protected_resource_uri = URI.parse(PROTECTED_RESOURCE)

  payload = {
    at: session[:access_token],
    ts: Time.now.to_i,
    m: 'POST',
    u: "#{protected_resource_uri.host}:#{protected_resource_uri.port}",
    p: protected_resource_uri.path,
  }
  key_params = $keys[session[:access_token]].transform_values { |val| OpenSSL::BN.new(Base64.urlsafe_decode64(val), 2) }
  key = OpenSSL::PKey::RSA.new.tap do |rsa| # if session[:key][:kty] == 'RSA'
    rsa.set_key(key_params[:n], key_params[:e], key_params[:d])
    rsa.set_factors(key_params[:p], key_params[:q])
    rsa.set_crt_params(key_params[:dp], key_params[:dq], key_params[:qi])
  end
  jwk = JWT::JWK.new(key)
  token = JWT.encode(payload, jwk.keypair, session[:alg], { typ: 'PoP', kid: jwk.kid })

  http = Net::HTTP.new(protected_resource_uri.host, protected_resource_uri.port)
  headers = { 'Authorization' => "PoP #{token}" }

  logger.info "Requesting protected resource with PoP token: #{token}"
  response = http.post(protected_resource_uri.path, nil, headers)

  case response
  when Net::HTTPSuccess
    halt response.body
  else
    $keys.delete(session[:access_token])
    session[:access_token] = nil
    halt "Unable to fetch resource: #{response.code} #{response.message}\n#{response.body}"
  end
end
