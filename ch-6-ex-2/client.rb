# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

require 'sinatra'

TOKEN_ENDPOINT = 'http://localhost:9001/token'

PROTECTED_RESOURCE = 'http://localhost:9002/resource'

CLIENT_ID = 'oauth-client-1'
CLIENT_SECRET = 'oauth-client-secret-1'
SCOPE = 'foo bar'

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

  begin
    fetch_and_save_access_token!(
      grant_type: 'client_credentials',
      scope: SCOPE,
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
