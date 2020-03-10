# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

require 'sinatra'
require 'sinatra/required_params'

TOKEN_ENDPOINT = 'http://localhost:9001/token'

CLIENT_ID = 'oauth-client-1'
CLIENT_SECRET = 'oauth-client-secret-1'
SCOPE = %w[foo bar].freeze

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

    session[:access_token] = body['access_token']
    session[:refresh_token] = body['refresh_token']
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

template :username_password do
  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Client</title>
      </head>
      <body>
        <p>Get an access token</p>
        <form action="/username_password" method="POST">
          <input type="text" name="username" placeholder="username">
          <input type="password" name="password" placeholder="password">
          <input type="submit" value="Get an access token">
        </form>
      </body>
    </html>
  HTML
end

get '/' do
  erb :index
end

get '/authorize' do
  erb :username_password
end

post '/username_password' do
  required_params :username, :password

  begin
    fetch_and_save_access_token!(
      grant_type: 'password',
      username: params[:username],
      password: params[:password],
      scope: SCOPE.join(' '),
    )
  rescue Net::HTTPExceptions => e
    logger.error e
    error "Unable to fetch access token, server response: #{e.response.code}"
  end

  erb :index
end

get '/fetch_resource' do
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
      logger.error e
      error "Unable to refresh access token, server response: #{e.response.code}"
    end
  else
    logger.error response.inspect
    error "Unable to fetch resource, server response: #{response.code}"
  end
end
