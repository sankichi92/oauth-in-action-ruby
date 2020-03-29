# frozen_string_literal: true

require 'json'
require 'net/http'
require 'securerandom'
require 'uri'

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

helpers do
  def fetch_and_save_access_token!(**params)
    token_uri = URI.parse(TOKEN_ENDPOINT)
    token_uri.user = CLIENT_ID
    token_uri.password = CLIENT_SECRET

    logger.info "Requesting access token with params: #{params.inspect}"
    response = Net::HTTP.post_form(token_uri, params)
    response.value

    body = JSON.parse(response.body)

    session[:access_token] = body['access_token']
    session[:scope] = body['scope']
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

end
