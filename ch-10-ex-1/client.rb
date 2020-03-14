# frozen_string_literal: true

require 'json'
require 'net/http'
require 'openssl'
require 'securerandom'
require 'uri'

require 'sinatra'

AUTHORIZATION_ENDPOINT = 'http://localhost:9001/authorize'
TOKEN_ENDPOINT = 'http://localhost:9001/token'

CLIENT_ID = 'oauth-client-1'
CLIENT_SECRET = 'oauth-client-secret-1'

REDIRECT_URI = 'http://localhost:9000/callback'
SCOPE = 'foo'

PROTECTED_RESOURCE = 'http://localhost:9002/resource'

set :port, 9000

enable :sessions

helpers do
  def fetch_and_save_access_token!(**params)
    token_uri = URI.parse(TOKEN_ENDPOINT)
    token_uri.user = CLIENT_ID
    token_uri.password = CLIENT_SECRET

    logger.info "Requesting access token with params: #{params.inspect}"
    response = Net::HTTP.post_form(token_uri, params)
    response.value

    body = JSON.parse(response.body)

    session[:refresh_token] = body['refresh_token'] if body['refresh_token']
    session[:access_token] = body['access_token']
    session[:scope] = body['scope']
  end
end

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
          <li>Refresh token value: <%= session[:refresh_token] %></li>
        </ul>
        <a href="/authorize">Get OAuth Token</a>
        <a href="/fetch_resource">Get Protected Resource</a>
      </body>
    </html>
  HTML
end

get '/' do
  erb :index
end

get '/authorize' do
  session[:access_token] = nil
  session[:scope] = nil
  session[:state] = SecureRandom.urlsafe_base64

  session[:code_verifier] = SecureRandom.alphanumeric(80)
  code_challenge = OpenSSL::Digest::SHA256.base64digest(session[:code_verifier])

  query = build_query(
    response_type: 'code',
    scope: SCOPE,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state: session[:state],
    code_challenge: code_challenge,
    code_challenge_method: 'S256',
  )
  redirect "#{AUTHORIZATION_ENDPOINT}?#{query}"
end

get '/callback' do
  halt escape(params[:error]) if params[:error]
  halt 400, "State does not match: expected '#{session[:state]}' got '#{params[:state]}'" if session[:state].nil? || params[:state] != session[:state]

  begin
    fetch_and_save_access_token!(
      grant_type: 'authorization_code',
      code: params[:code],
      redirect_uri: REDIRECT_URI,
      code_verifier: session[:code_verifier],
    )
    erb :index
  rescue Net::HTTPExceptions => e
    logger.error e
    error "Unable to fetch access token, server response: #{e.response.code}"
  end
end

get '/fetch_resource' do
  protected_resource_uri = URI.parse(PROTECTED_RESOURCE)
  http = Net::HTTP.new(protected_resource_uri.host, protected_resource_uri.port)
  headers = { 'Authorization' => "Bearer #{session[:access_token]}" }

  logger.info "Requesting protected resource with access token: #{session[:access_token]}"
  response = http.post(protected_resource_uri.path, nil, headers)

  if response.is_a?(Net::HTTPSuccess)
    response.body
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
      logger.error e
      error "Unable to refresh access token, server response: #{e.response.code}"
    end
  else
    logger.error response.inspect
    error "Unable to fetch resource, server response: #{response.code}"
  end
end