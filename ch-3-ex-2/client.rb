require 'json'
require 'net/http'
require 'securerandom'
require 'uri'

require 'sinatra'

set :port, 9000

AUTHORIZATION_ENDPOINT = 'http://localhost:9001/authorize'
TOKEN_ENDPOINT = 'http://localhost:9001/token'

CLIENT_ID = 'oauth-client-1'
CLIENT_SECRET = 'oauth-client-secret-1'

REDIRECT_URIS = %w[http://localhost:9000/callback]
SCOPE = 'foo'

PROTECTED_RESOURCE = 'http://localhost:9002/resource'

state = nil

access_token = '987tghjkiu6trfghjuytrghj'
scope = nil
refresh_token = 'j2r3oj32r23rmasd98uhjrk2o3i'

get '/' do
  erb :index, locals: { access_token: access_token, scope: scope, refresh_token: refresh_token }
end

get '/authorize' do
  access_token = nil

  scope = nil
  state = SecureRandom.urlsafe_base64

  query = build_query(
    response_type: 'code',
    scope: SCOPE,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URIS.first,
    state: state,
  )
  redirect "#{AUTHORIZATION_ENDPOINT}?#{query}"
end

get '/callback' do
  halt "State does not match: expected '#{state}' got '#{params['state']}'" if params['state'] != state

  token_uri = URI.parse(TOKEN_ENDPOINT)
  token_uri.user = CLIENT_ID
  token_uri.password = CLIENT_SECRET

  logger.info "Requesting access token for code '#{params['code']}'"
  response = Net::HTTP.post_form(
    token_uri,
    grant_type: 'authorization_code',
    code: params['code'],
    redirect_uri: REDIRECT_URIS.first,
  )

  case response
  when Net::HTTPSuccess
    body = JSON.parse(response.body)

    access_token = body['access_token']
    refresh_token = body['refresh_token'] if body['refresh_token']
    scope = body['scope']

    erb :index, locals: { access_token: access_token, scope: scope, refresh_token: refresh_token }
  else
    "Unable to fetch access token, server response: #{response.code}"
  end
end

get '/fetch_resource' do
  protected_resource_uri = URI.parse(PROTECTED_RESOURCE)
  http = Net::HTTP.new(protected_resource_uri.host, protected_resource_uri.port)
  headers = { 'Authorization' => "Bearer #{access_token}" }

  logger.info "Requesting protected resource with access token '#{access_token}'"
  response = http.post(protected_resource_uri.path, nil, headers)

  case response
  when Net::HTTPSuccess
    response.body
  else
    # TODO
    access_token = nil
    "Unable to fetch resource, server response: #{response.code}"
  end
end
