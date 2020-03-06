require 'json'
require 'net/http'
require 'securerandom'
require 'uri'

require 'sinatra'

AUTHORIZATION_ENDPOINT = 'http://localhost:9001/authorize'
TOKEN_ENDPOINT = 'http://localhost:9001/token'

CLIENT_ID = 'oauth-client-1'
CLIENT_SECRET = 'oauth-client-secret-1'

REDIRECT_URI = 'http://localhost:9000/callback'

PROTECTED_RESOURCE = 'http://localhost:9002/resource'

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
        <p>Access token value: <%= session[:access_token] %></p>
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
  session[:state] = SecureRandom.urlsafe_base64

  query = build_query(
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state: session[:state],
  )
  redirect "#{AUTHORIZATION_ENDPOINT}?#{query}"
end

get '/callback' do
  halt 400, "State does not match: expected '#{session[:state]}' got '#{params[:state]}'" if session[:state].nil? || params[:state] != session[:state]

  token_uri = URI.parse(TOKEN_ENDPOINT)
  token_uri.user = CLIENT_ID
  token_uri.password = CLIENT_SECRET

  logger.info "Requesting access token for code: #{params[:code]}"
  response = Net::HTTP.post_form(
    token_uri,
    grant_type: 'authorization_code',
    code: params[:code],
    redirect_uri: REDIRECT_URI,
  )

  case response
  when Net::HTTPSuccess
    body = JSON.parse(response.body)
    session[:access_token] = body['access_token']
    erb :index
  else
    logger.error response.inspect
    error "Unable to fetch access token, server response: #{response.code}"
  end
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
    logger.error response.inspect
    error "Unable to fetch resource, server response: #{response.code}"
  end
end
