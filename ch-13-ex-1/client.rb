# frozen_string_literal: true

require 'json'
require 'net/http'
require 'securerandom'
require 'uri'

require 'jwt'
require 'sinatra'
require 'sinatra/required_params'

AUTHORIZATION_ENDPOINT = 'http://localhost:9001/authorize'
TOKEN_ENDPOINT = 'http://localhost:9001/token'
USERINFO_ENDPOINT = 'http://localhost:9002/userinfo'

PROTECTED_RESOURCE = 'http://localhost:9002/resource'

CLIENT_ID = 'oauth-client-1'
CLIENT_SECRET = 'oauth-client-secret-1'
REDIRECT_URI = 'http://localhost:9000/callback'
SCOPE = 'openid profile email phone address'

RSA_KEY = <<~PEM
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2pZzFsNJZV1pC3TSuD0x
  YbsjgNN+oM1uGjphK/ZOHfmTS/1dSl2icr1bjV/T+oP8uy/LD5JHOxPvZhf9bgLx
  BtkBA19jr3l86k/wKQaThVnoeyE1dhUSd9qDvtWDuyzjg78st8Q9/M5Dk7Kzs/Ha
  VQvZNFkczOnEHGKXWpFKOdlE5WhDLrBFgGeNt+vdvQE9MJGNnPXrRAVDYlkKPpLw
  L8HtmZqY+BeBUlk1MAMoRBn0PT0qzV2OXJnnev5UM2MO9lyMeWJaHw/7k/Ybf6gG
  8C/gc0goZwaavToM5bv2qRHckP/PuqfDsdgMGKVXm9GLLz5RqBqvvYLX263e7THY
  WwIDAQAB
  -----END PUBLIC KEY-----
PEM

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
          <li>Access token value: <%= session[:access_token] %></li>
          <li>Scope value: <%= session[:scope] %></li>
        </ul>
        <a href="/authorize">Get OAuth Token</a>
        <a href="/fetch_resource">Get Protected Resource</a>
      </body>
    </html>
  HTML
end

template :userinfo do
  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Client</title>
      </head>
      <body>
        <dl>
          <dt>Logged in user subject</dt>
          <dd>
            <% if session[:id_token] %>
            <mark><%= session[:id_token]['sub'] %></mark>
            from issuer
            <mark><%= session[:id_token]['iss'] %></mark>
            <% else %>
            NONE
            <% end %>
          </dd>
          <dt>User information</dt>
          <dd>
            <pre><%= JSON.pretty_generate(session[:userinfo]) %></pre>
          </dd>
        </dl>
        <a href="/authorize">Log In</a>
        <a href="/userinfo">Get User Information</a>
      </body>
    </html>
  HTML
end

helpers do
  def fetch_and_save_token!(**params)
    token_uri = URI.parse(TOKEN_ENDPOINT)
    token_uri.user = CLIENT_ID
    token_uri.password = CLIENT_SECRET

    logger.info "Requesting access token with params: #{params.inspect}"
    response = Net::HTTP.post_form(token_uri, params)
    response.value

    body = JSON.parse(response.body)

    session[:access_token] = body['access_token']
    session[:scope] = body['scope']

    return unless body['id_token']

    session[:id_token] = nil
    session[:userinfo] = nil

    payload, _header = JWT.decode(
      body['id_token'],
      OpenSSL::PKey::RSA.new(RSA_KEY),
      true,
      { algorithm: 'RS256', iss: 'http://localhost:9001/', aud: CLIENT_ID, verify_iss: true, verify_aud: true, verify_iat: true },
    )
    session[:id_token] = payload
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
    fetch_and_save_token!(
      grant_type: 'authorization_code',
      code: params[:code],
      redirect_uri: REDIRECT_URI,
    )
  rescue Net::HTTPExceptions => e
    halt "Unable to fetch access token: #{e.message}\n#{e.response.body}"
  rescue JWT::DecodeError => e
    halt "Unable to decode id_token: #{e.inspect}"
  end

  erb :userinfo
end

get '/fetch_resource' do
  halt 401, 'Missing access token' if session[:access_token].nil?

  protected_resource_uri = URI.parse(PROTECTED_RESOURCE)
  http = Net::HTTP.new(protected_resource_uri.host, protected_resource_uri.port)
  headers = { 'Authorization' => "Bearer #{session[:access_token]}" }

  logger.info "Requesting protected resource with access token: #{session[:access_token]}"
  response = http.post(protected_resource_uri.path, nil, headers)

  case response
  when Net::HTTPSuccess
    halt response.body
  else
    session[:access_token] = nil
    halt "Unable to fetch resource: #{response.code} #{response.message}\n#{response.body}"
  end
end

get '/userinfo' do
  halt 401, 'Missing access token' if session[:access_token].nil?

  userinfo_uri = URI.parse(USERINFO_ENDPOINT)
  http = Net::HTTP.new(userinfo_uri.host, userinfo_uri.port)
  headers = { 'Authorization' => "Bearer #{session[:access_token]}" }

  logger.info "Requesting userinfo with access token: #{session[:access_token]}"
  response = http.post(userinfo_uri.path, nil, headers)

  case response
  when Net::HTTPSuccess
    session[:userinfo] = JSON.parse(response.body, symbolize_names: true)
    erb :userinfo
  else
    session[:access_token] = nil
    halt "Unable to fetch userinfo: #{response.code} #{response.message}\n#{response.body}"
  end
end
